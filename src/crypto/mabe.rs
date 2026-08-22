//! Multi-Authority CP-ABE.
//!
//! This adapts Melissa Chase's multi-authority construction
//! ("Multi-Authority Attribute Based Encryption", TCC 2007,
//!  https://cs.brown.edu/people/mchase/papers/multiabe.pdf) to the
//! ciphertext-policy / threshold-tree engine already used by
//! `crypto::scheme` (BSW07-style), the same way BSW07 itself adapted
//! Sahai-Waters. See README-MULTI-AUTHORITY.md for the design writeup.
//!
//! Trust model (this is a property of Chase's scheme, not a shortcut taken
//! here): attribute authorities are mutually distrusting and only need to
//! know their own PRF seed and their own attribute universe. A single
//! **Central Authority** is required to bind users' keys together across
//! authorities via a global identifier (GID); the Central Authority does
//! *not* see or control any attributes, but it does hold enough secret
//! material to decrypt any ciphertext in the system. That is an inherent
//! limitation of this construction (stated explicitly in the paper), not a
//! bug — if you need to remove the trusted Central Authority entirely, that
//! requires a fundamentally different scheme (e.g. Lewko-Waters,
//! EUROCRYPT 2011), which is a much larger undertaking.
//!
//! Collusion resistance intuition: two different users can never combine
//! their keys, because each authority derives its contribution to a user's
//! key deterministically from `PRF(authority_seed, GID)`. Two different GIDs
//! give unrelated, uncorrelated per-authority secrets, so partial
//! reconstructions from different users' keys don't combine into anything
//! meaningful. Within one authority, keys are still bound together the same
//! way BSW07 already does it (shared exponent across that authority's
//! attributes, blinded per-attribute).

use crate::crypto::policy::{partition_by_authority, parse_policy, AccessNode};
use crate::crypto::scheme::{hash_to_g1, hash_to_g2, sha256_32, wrapping_key_from_gt};
use crate::error::{Result, SecureDropError};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use hkdf::hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Reserved attribute every user automatically receives from every
/// authority. It lets an encryptor write a policy that only touches some
/// authorities (e.g. "clearance>=4 AND department=intelligence" doesn't
/// mention the "role" authority at all) while the scheme's math still sums
/// over *every* registered authority, as required by Chase's construction
/// (see "Leaving out authorities" extension, Section 6 of the paper).
const DUMMY_ATTR_SUFFIX: &str = "__any__";

fn dummy_attr(authority: &str) -> String {
    format!("{}{}", authority, DUMMY_ATTR_SUFFIX)
}

/// A pseudorandom function used to derive each authority's contribution to
/// a user's key from that user's global identifier (GID), without any
/// coordination between authorities. HMAC-SHA-256 is a standard, safe PRF
/// choice here.
fn prf_scalar(seed: &[u8; 32], gid: &str) -> Scalar {
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(b"SecureDrop-MA-PRF-v1");
    mac.update(gid.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&tag);
    // Second block for domain-separated, uniformly-distributed wide input.
    let mut mac2 = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac2.update(b"SecureDrop-MA-PRF-v1-block2");
    mac2.update(gid.as_bytes());
    mac2.update(&tag);
    let tag2 = mac2.finalize().into_bytes();
    wide[32..].copy_from_slice(&tag2);
    Scalar::from_bytes_wide(&wide)
}

// ---------------------------------------------------------------------
// Central Authority
// ---------------------------------------------------------------------

/// Central Authority's secret state. Per Chase's construction it must know
/// `y0` *and* the PRF seed of every registered attribute authority. It can
/// therefore decrypt any ciphertext in the system — keep this offline /
/// HSM-protected even more strictly than a single-authority master secret.
#[derive(Clone)]
pub struct CentralAuthorityKey {
    pub y0: Scalar,
    /// authority id -> that authority's PRF seed, registered at authority
    /// creation time.
    pub authority_seeds: HashMap<String, [u8; 32]>,
}

impl Drop for CentralAuthorityKey {
    fn drop(&mut self) {
        self.y0 = Scalar::zero();
        for seed in self.authority_seeds.values_mut() {
            seed.zeroize();
        }
        self.authority_seeds.clear();
    }
}

/// System-wide public key: `Y0 = e(g, g2)^y0`. Shared by every authority
/// and every encryptor; contains no secret material.
#[derive(Clone)]
pub struct SystemPublicKey {
    pub y0_pub: Gt,
}

/// Run once, by whoever stands up the organization's Central Authority.
pub fn central_setup(rng: &mut impl RngCore) -> (SystemPublicKey, CentralAuthorityKey) {
    let y0 = Scalar::random(&mut *rng);
    let g = G1Projective::generator();
    let g2 = G2Projective::generator();
    let y0_pub = bls12_381::pairing(&G1Affine::from(g), &G2Affine::from(g2 * y0));
    (
        SystemPublicKey { y0_pub },
        CentralAuthorityKey {
            y0,
            authority_seeds: HashMap::new(),
        },
    )
}

/// Issue the per-user Central Authority key component `DCA`. This is the
/// piece that "glues together" whatever the user reconstructs from each
/// attribute authority into the single system-wide value `Y0^s`. It does
/// not depend on the user's attributes at all — only on GID and the set of
/// *currently registered* authorities.
pub fn central_keygen(central: &CentralAuthorityKey, gid: &str) -> G2Projective {
    let sum: Scalar = central
        .authority_seeds
        .values()
        .map(|seed| prf_scalar(seed, gid))
        .fold(Scalar::zero(), |a, b| a + b);
    G2Projective::generator() * (central.y0 - sum)
}

// ---------------------------------------------------------------------
// Attribute Authorities
// ---------------------------------------------------------------------

/// An attribute authority's secret state. Note how little it is: unlike the
/// old single-authority `MasterSecretKey`, an authority never sees `y0` and
/// never sees another authority's seed — it is fully self-contained and can
/// be run by a mutually-distrusting department.
#[derive(Clone)]
pub struct AuthorityMasterKey {
    pub id: String,
    pub seed: [u8; 32],
}

impl Drop for AuthorityMasterKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Public registration for an authority: its id and the attributes it is
/// willing to vouch for. Purely a whitelist — carries no secret material,
/// same role `PublicKey::attr_pubs` played before.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorityPublicKey {
    pub id: String,
    pub universe: HashSet<String>,
}

/// Create a new attribute authority. The returned `seed` MUST also be
/// registered with the Central Authority (`CentralAuthorityKey::authority_seeds`)
/// out of band — this models the authority "registering" with the Central
/// Authority once, at authority-creation time, per the paper's Setup phase.
pub fn create_authority(
    id: &str,
    attributes: &[String],
    rng: &mut impl RngCore,
) -> (AuthorityPublicKey, AuthorityMasterKey) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut universe: HashSet<String> = attributes.iter().cloned().collect();
    universe.insert(dummy_attr(id));
    (
        AuthorityPublicKey {
            id: id.to_string(),
            universe,
        },
        AuthorityMasterKey {
            id: id.to_string(),
            seed,
        },
    )
}

/// Issue a user's key components for one authority. This is exactly BSW07
/// `keygen`, except the "shared random `r`" that ties a user's attributes
/// together is no longer *pure* randomness — it is `y_{k,GID} =
/// PRF(seed_k, GID)`, deterministic per (authority, user) and independent
/// across authorities/users. That single substitution is what makes
/// per-authority key material recombine correctly at decrypt time while
/// remaining useless to anyone who doesn't hold every required authority's
/// key for the *same* GID.
pub fn attribute_keygen(
    amsk: &AuthorityMasterKey,
    apk: &AuthorityPublicKey,
    gid: &str,
    attributes: &[String],
    rng: &mut impl RngCore,
) -> Result<HashMap<String, (G2Projective, G2Projective)>> {
    let y_k_u = prf_scalar(&amsk.seed, gid);
    let g2 = G2Projective::generator();

    let mut components = HashMap::new();
    let mut all_attrs: Vec<String> = attributes.to_vec();
    all_attrs.push(dummy_attr(&amsk.id));

    for attr in &all_attrs {
        if !apk.universe.contains(attr) {
            return Err(SecureDropError::UnknownAttribute(attr.clone()));
        }
        let r_i = Scalar::random(&mut *rng);
        let h_attr = hash_to_g2(attr);
        let d_i = (g2 * y_k_u) + (h_attr * r_i);
        let d_i_prime = g2 * r_i;
        components.insert(attr.clone(), (d_i, d_i_prime));
    }
    Ok(components)
}

// ---------------------------------------------------------------------
// User secret key (aggregate of Central Authority + attribute authorities)
// ---------------------------------------------------------------------

#[derive(Clone)]
pub struct MAUserSecretKey {
    pub gid: String,
    pub dca: G2Projective,
    /// authority id -> attribute id -> (d_i, d_i')
    pub per_authority: HashMap<String, HashMap<String, (G2Projective, G2Projective)>>,
}

impl Drop for MAUserSecretKey {
    fn drop(&mut self) {
        self.gid.clear();
        self.dca = G2Projective::identity();
        self.per_authority.clear();
    }
}

// ---------------------------------------------------------------------
// Ciphertext
// ---------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MACiphertext {
    pub policy: String,
    #[serde(with = "g1_serde")]
    pub e_root: G1Projective,
    /// authority id -> (that authority's access subtree, its leaf components)
    pub per_authority: HashMap<String, (AccessNode, HashMap<String, LeafCt>)>,
    pub wrapped_dek: [u8; 32],
    pub dek_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafCt {
    #[serde(with = "g1_serde")]
    pub c_y: G1Projective,
    #[serde(with = "g1_serde")]
    pub c_y_prime: G1Projective,
}

mod g1_serde {
    use bls12_381::{G1Affine, G1Projective};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(p: &G1Projective, s: S) -> Result<S::Ok, S::Error> {
        G1Affine::from(*p).to_compressed().to_vec().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<G1Projective, D::Error> {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        let mut arr = [0u8; 48];
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom("bad G1 length"));
        }
        arr.copy_from_slice(&bytes);
        let aff = G1Affine::from_compressed(&arr)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("invalid G1 point"))?;
        Ok(G1Projective::from(aff))
    }
}

// share_secret, re-derived here to validate against a per-authority universe
// instead of the old single global PublicKey.attr_pubs.
fn share_secret_ma(
    node: &AccessNode,
    secret: Scalar,
    universe: &HashSet<String>,
    out: &mut HashMap<String, LeafCt>,
    rng: &mut impl RngCore,
) -> Result<()> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            if !universe.contains(&attr_id) {
                return Err(SecureDropError::UnknownAttribute(attr_id));
            }
            let g = G1Projective::generator();
            let c_y = g * secret;
            let c_y_prime = hash_to_g1(&attr_id) * secret;
            out.insert(attr_id, LeafCt { c_y, c_y_prime });
            Ok(())
        }
        AccessNode::Threshold {
            threshold,
            children,
        } => {
            let t = *threshold;
            let mut coeffs = vec![secret];
            for _ in 1..t {
                coeffs.push(Scalar::random(&mut *rng));
            }
            for (i, child) in children.iter().enumerate() {
                let x = Scalar::from((i + 1) as u64);
                let mut share = Scalar::zero();
                let mut x_pow = Scalar::one();
                for c in &coeffs {
                    share += *c * x_pow;
                    x_pow *= x;
                }
                share_secret_ma(child, share, universe, out, rng)?;
            }
            Ok(())
        }
    }
}

fn reconstruct_authority_value(
    node: &AccessNode,
    leaves_ct: &HashMap<String, LeafCt>,
    leaves_key: &HashMap<String, (G2Projective, G2Projective)>,
    user_attrs: &HashSet<String>,
) -> Result<Gt> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            if !user_attrs.contains(&attr_id) {
                return Err(SecureDropError::AccessDenied);
            }
            let (d_i, d_i_prime) = leaves_key
                .get(&attr_id)
                .ok_or(SecureDropError::AccessDenied)?;
            let leaf = leaves_ct
                .get(&attr_id)
                .ok_or(SecureDropError::DecryptionFailed)?;
            let e1 = bls12_381::pairing(&G1Affine::from(leaf.c_y), &G2Affine::from(*d_i));
            let e2 = bls12_381::pairing(&G1Affine::from(leaf.c_y_prime), &G2Affine::from(*d_i_prime));
            Ok(e1 - e2)
        }
        AccessNode::Threshold {
            threshold,
            children,
        } => {
            let mut satisfied = Vec::new();
            for (i, child) in children.iter().enumerate() {
                if let Ok(val) =
                    reconstruct_authority_value(child, leaves_ct, leaves_key, user_attrs)
                {
                    satisfied.push((i + 1, val));
                    if satisfied.len() >= *threshold {
                        break;
                    }
                }
            }
            if satisfied.len() < *threshold {
                return Err(SecureDropError::AccessDenied);
            }
            let mut result = Gt::identity();
            for (i, (x_i, val_i)) in satisfied.iter().enumerate() {
                let mut lambda = Scalar::one();
                for (j, (x_j, _)) in satisfied.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let num = Scalar::from(*x_j as u64);
                    let den = Scalar::from(*x_j as u64) - Scalar::from(*x_i as u64);
                    lambda *= num * den.invert().unwrap();
                }
                result += *val_i * lambda;
            }
            Ok(result)
        }
    }
}

/// Encrypt: builds a policy over possibly several authorities' attributes.
/// `authorities` must contain the public key for every authority currently
/// registered in the system (not just the ones mentioned in the policy) —
/// unmentioned authorities are satisfied automatically via their dummy
/// attribute, per the "Leaving out authorities" extension.
pub fn encrypt_keying_material(
    system_pk: &SystemPublicKey,
    authorities: &HashMap<String, AuthorityPublicKey>,
    policy_str: &str,
    rng: &mut impl RngCore,
) -> Result<(MACiphertext, [u8; 32])> {
    let tree = parse_policy(policy_str)?;
    let mut per_auth_trees = partition_by_authority(&tree)?;

    for (auth_id, apk) in authorities {
        per_auth_trees
            .entry(auth_id.clone())
            .or_insert_with(|| AccessNode::leaf(crate::crypto::policy::Attribute::new(
                dummy_attr(auth_id),
                None,
            )));
        let _ = apk; // universe checked inside share_secret_ma
    }

    for auth_id in per_auth_trees.keys() {
        if !authorities.contains_key(auth_id) {
            return Err(SecureDropError::UnknownAuthority(auth_id.clone()));
        }
    }

    let s = Scalar::random(&mut *rng);
    let g = G1Projective::generator();
    let e_root = g * s;

    let mut per_authority = HashMap::new();
    for (auth_id, subtree) in &per_auth_trees {
        let apk = authorities.get(auth_id).expect("checked above");
        let mut leaves = HashMap::new();
        share_secret_ma(subtree, s, &apk.universe, &mut leaves, rng)?;
        per_authority.insert(auth_id.clone(), (subtree.clone(), leaves));
    }

    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);
    let dek_hash = sha256_32(&dek);

    let r = system_pk.y0_pub * s;
    let mut wrap_key = wrapping_key_from_gt(&r)?;
    let mut wrapped_dek = [0u8; 32];
    for i in 0..32 {
        wrapped_dek[i] = dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    Ok((
        MACiphertext {
            policy: policy_str.to_string(),
            e_root,
            per_authority,
            wrapped_dek,
            dek_hash,
        },
        dek,
    ))
}

/// Decrypt: every authority subtree present in the ciphertext must be
/// satisfied by the user's key material for that authority (this includes
/// the automatically-injected dummy leaves for authorities the policy
/// didn't otherwise mention — every user has those by construction).
pub fn decrypt_keying_material(user: &MAUserSecretKey, ct: &MACiphertext) -> Result<[u8; 32]> {
    let mut total = Gt::identity();

    for (auth_id, (subtree, leaves_ct)) in &ct.per_authority {
        let leaves_key = user
            .per_authority
            .get(auth_id)
            .ok_or(SecureDropError::AccessDenied)?;
        let user_attrs: HashSet<String> = leaves_key.keys().cloned().collect();
        if !subtree.satisfied_by(&user_attrs) {
            return Err(SecureDropError::AccessDenied);
        }
        let val = reconstruct_authority_value(subtree, leaves_ct, leaves_key, &user_attrs)?;
        total += val;
    }

    let ca_term = bls12_381::pairing(&G1Affine::from(ct.e_root), &G2Affine::from(user.dca));
    total += ca_term;

    let mut wrap_key = wrapping_key_from_gt(&total)?;
    let mut dek = [0u8; 32];
    for i in 0..32 {
        dek[i] = ct.wrapped_dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    let got_hash = sha256_32(&dek);
    if got_hash != ct.dek_hash {
        dek.zeroize();
        return Err(SecureDropError::DecryptionFailed);
    }
    Ok(dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    /// Sets up 3 independent authorities (clearance, department, role) plus
    /// a Central Authority, mirroring the existing README example.
    fn build_system() -> (
        SystemPublicKey,
        CentralAuthorityKey,
        HashMap<String, AuthorityPublicKey>,
        HashMap<String, AuthorityMasterKey>,
    ) {
        let mut rng = thread_rng();
        let (spk, mut central) = central_setup(&mut rng);

        let clearance_attrs: Vec<String> = (1..=10).map(|n| format!("clearance>={}", n)).collect();
        let dept_attrs: Vec<String> = ["intelligence", "operations", "engineering"]
            .iter()
            .map(|d| format!("department={}", d))
            .collect();
        let role_attrs: Vec<String> = ["analyst", "admin", "operator"]
            .iter()
            .map(|r| format!("role={}", r))
            .collect();

        let mut apks = HashMap::new();
        let mut amsks = HashMap::new();
        for (id, attrs) in [
            ("clearance", clearance_attrs),
            ("department", dept_attrs),
            ("role", role_attrs),
        ] {
            let (apk, amsk) = create_authority(id, &attrs, &mut rng);
            central.authority_seeds.insert(id.to_string(), amsk.seed);
            apks.insert(id.to_string(), apk);
            amsks.insert(id.to_string(), amsk);
        }
        (spk, central, apks, amsks)
    }

    fn issue_user(
        gid: &str,
        clearance: u32,
        department: &str,
        role: Option<&str>,
        central: &CentralAuthorityKey,
        apks: &HashMap<String, AuthorityPublicKey>,
        amsks: &HashMap<String, AuthorityMasterKey>,
        rng: &mut impl RngCore,
    ) -> MAUserSecretKey {
        let clearance_attrs: Vec<String> =
            (1..=clearance).map(|n| format!("clearance>={}", n)).collect();
        let dept_attrs = vec![format!("department={}", department)];
        let role_attrs: Vec<String> = role.map(|r| vec![format!("role={}", r)]).unwrap_or_default();

        let mut per_authority = HashMap::new();
        for (id, attrs) in [
            ("clearance", clearance_attrs),
            ("department", dept_attrs),
            ("role", role_attrs),
        ] {
            let amsk = &amsks[id];
            let apk = &apks[id];
            let comps = attribute_keygen(amsk, apk, gid, &attrs, rng).unwrap();
            per_authority.insert(id.to_string(), comps);
        }
        let dca = central_keygen(central, gid);
        MAUserSecretKey {
            gid: gid.to_string(),
            dca,
            per_authority,
        }
    }

    #[test]
    fn cross_authority_and_roundtrip() {
        let mut rng = thread_rng();
        let (spk, central, apks, amsks) = build_system();

        let alice = issue_user(
            "alice", 4, "intelligence", Some("analyst"), &central, &apks, &amsks, &mut rng,
        );

        let policy = "clearance>=4 AND department=intelligence";
        let (ct, dek) =
            encrypt_keying_material(&spk, &apks, policy, &mut rng).unwrap();

        let recovered = decrypt_keying_material(&alice, &ct).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn insufficient_clearance_denied() {
        let mut rng = thread_rng();
        let (spk, central, apks, amsks) = build_system();

        let bob = issue_user(
            "bob", 2, "operations", Some("operator"), &central, &apks, &amsks, &mut rng,
        );

        let policy = "clearance>=4 AND department=intelligence";
        let (ct, _dek) = encrypt_keying_material(&spk, &apks, policy, &mut rng).unwrap();

        let err = decrypt_keying_material(&bob, &ct).unwrap_err();
        assert!(matches!(err, SecureDropError::AccessDenied));
    }

    #[test]
    fn or_within_single_authority_works() {
        let mut rng = thread_rng();
        let (spk, central, apks, amsks) = build_system();

        let charlie = issue_user(
            "charlie", 1, "operations", Some("admin"), &central, &apks, &amsks, &mut rng,
        );

        // Both OR branches (role=admin, role=operator) belong to the same
        // "role" authority, so this is allowed even though cross-authority
        // OR (tested below) is rejected.
        let policy = "(role=admin OR role=operator) AND department=operations";
        let (ct, dek) = encrypt_keying_material(&spk, &apks, policy, &mut rng).unwrap();
        let recovered = decrypt_keying_material(&charlie, &ct).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn cross_authority_or_is_rejected_at_encrypt_time() {
        let mut rng = thread_rng();
        let (spk, _central, apks, _amsks) = build_system();

        // clearance and role are different authorities: OR across them is
        // not supported by Chase's construction and must fail loudly
        // instead of silently doing the wrong thing.
        let policy = "clearance>=5 OR role=admin";
        let err = encrypt_keying_material(&spk, &apks, policy, &mut rng).unwrap_err();
        assert!(matches!(err, SecureDropError::MixedAuthorityPolicy(_)));
    }

    #[test]
    fn two_users_cannot_collude_across_authorities() {
        // Alice has clearance>=4 but is in `operations`, not `intelligence`.
        // Dave is in `intelligence` but only has clearance 1.
        // Neither satisfies "clearance>=4 AND department=intelligence"
        // alone. This test checks that Alice's `clearance` authority key
        // component cannot be swapped onto Dave's `department` component to
        // forge a satisfying key for either GID — decrypt only ever uses a
        // single user's own `per_authority` map + their own `dca`, so
        // "borrowing" Alice's clearance>=4 component into Dave's key
        // structurally fails: Dave's `dca` was derived from PRF(seed,"dave"),
        // not PRF(seed,"alice"), so the terms don't cancel.
        let mut rng = thread_rng();
        let (spk, central, apks, amsks) = build_system();

        let alice = issue_user(
            "alice", 4, "operations", None, &central, &apks, &amsks, &mut rng,
        );
        let mut dave = issue_user(
            "dave", 1, "intelligence", None, &central, &apks, &amsks, &mut rng,
        );

        // Attempt the naive collusion: graft Alice's clearance component
        // into Dave's key.
        let alice_clearance = alice.per_authority.get("clearance").unwrap().clone();
        dave.per_authority
            .insert("clearance".to_string(), alice_clearance);

        let policy = "clearance>=4 AND department=intelligence";
        let (ct, dek) = encrypt_keying_material(&spk, &apks, policy, &mut rng).unwrap();

        let result = decrypt_keying_material(&dave, &ct);
        match result {
            Err(_) => {} // expected: denied or garbage
            Ok(recovered) => assert_ne!(dek, recovered, "collusion must not recover the real DEK"),
        }
    }
}
