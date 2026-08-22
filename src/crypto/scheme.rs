//! Small-universe CP-ABE (BSW07 adapted for Type-3 pairings on BLS12-381).

use crate::crypto::keys::{AbeCiphertext, MasterSecretKey, PublicKey, UserSecretKey};
use crate::crypto::policy::{parse_policy, AccessNode};
use crate::error::{Result, SecureDropError};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

/// Domain separation for Gt → IKM transcript
const GT_TRANSCRIPT_DST: &[u8] = b"SecureDrop-Gt-Transcript-v3";
/// HKDF salt (extract stage)
const HKDF_SALT: &[u8] = b"SecureDrop-Wrap-Salt-v3";
/// HKDF info / context (expand stage)
const HKDF_INFO: &[u8] = b"SecureDrop-CPABE-WrapKey-v3";

pub fn default_universe() -> Vec<String> {
    let mut attrs = Vec::new();
    for i in 1..=10 {
        attrs.push(format!("clearance>={}", i));
    }
    for d in &[
        "intelligence",
        "operations",
        "engineering",
        "finance",
        "hr",
        "legal",
        "executive",
    ] {
        attrs.push(format!("department={}", d));
    }
    for r in &["analyst", "operator", "admin", "auditor", "contractor"] {
        attrs.push(format!("role={}", r));
    }
    attrs
}

pub fn setup(universe: &[String], rng: &mut impl RngCore) -> (PublicKey, MasterSecretKey) {
    let alpha = Scalar::random(&mut *rng);
    let mut beta = Scalar::random(&mut *rng);
    if bool::from(beta.is_zero()) {
        beta = Scalar::one();
    }

    let g = G1Projective::generator();
    let g2 = G2Projective::generator();

    let h = g * beta;
    let beta_inv = beta.invert().unwrap();
    let f = g * beta_inv;
    let e_gg_alpha = bls12_381::pairing(&G1Affine::from(g), &G2Affine::from(g2 * alpha));

    let mut attr_pubs = HashMap::new();
    let mut epochs = HashMap::new();
    for attr in universe {
        let t_i = Scalar::random(&mut *rng);
        attr_pubs.insert(attr.clone(), g * t_i);
        epochs.insert(attr.clone(), 0u64);
    }

    let pk = PublicKey {
        g,
        h,
        f,
        e_gg_alpha,
        attr_pubs,
        epochs,
    };
    let msk = MasterSecretKey { alpha, beta };
    (pk, msk)
}

pub(crate) fn hash_to_g2(attr: &str) -> G2Projective {
    let mut hasher = Sha256::new();
    hasher.update(b"SecureDrop-H-attr-");
    hasher.update(attr.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&hash);
    let s = Scalar::from_bytes_wide(&bytes);
    G2Projective::generator() * s
}

pub(crate) fn hash_to_g1(attr: &str) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(b"SecureDrop-H-attr-");
    hasher.update(attr.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&hash);
    let s = Scalar::from_bytes_wide(&bytes);
    G1Projective::generator() * s
}

pub fn keygen(
    pk: &PublicKey,
    msk: &MasterSecretKey,
    user_id: &str,
    attributes: &[String],
    rng: &mut impl RngCore,
) -> Result<UserSecretKey> {
    let r = Scalar::random(&mut *rng);
    let g2 = G2Projective::generator();

    let beta_inv = msk.beta.invert().unwrap();
    let d = g2 * ((msk.alpha + r) * beta_inv);

    let mut components = HashMap::new();
    for attr in attributes {
        if !pk.attr_pubs.contains_key(attr) {
            return Err(SecureDropError::UnknownAttribute(attr.clone()));
        }
        let r_i = Scalar::random(&mut *rng);
        let h_attr = hash_to_g2(attr);
        let d_i = (g2 * r) + (h_attr * r_i);
        let d_i_prime = g2 * r_i;
        components.insert(attr.clone(), (d_i, d_i_prime));
    }

    Ok(UserSecretKey {
        user_id: user_id.to_string(),
        d,
        components,
        attributes: attributes.to_vec(),
    })
}

fn share_secret(
    node: &AccessNode,
    secret: Scalar,
    pk: &PublicKey,
    out: &mut HashMap<String, (G1Projective, G1Projective)>,
    rng: &mut impl RngCore,
) -> Result<()> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            if !pk.attr_pubs.contains_key(&attr_id) {
                return Err(SecureDropError::UnknownAttribute(attr_id));
            }
            let c_y = pk.g * secret;
            let h_attr_g1 = hash_to_g1(&attr_id);
            let c_y_prime = h_attr_g1 * secret;
            out.insert(attr_id, (c_y, c_y_prime));
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
                share_secret(child, share, pk, out, rng)?;
            }
            Ok(())
        }
    }
}

/// Build IKM bytes from a Gt element.
///
/// bls12_381 0.8 does not expose a stable public encoding for Gt.
/// We build a domain-separated transcript and hash it into fixed-length IKM.
/// This is for KDF use only (not for wire serialization of Gt).
fn gt_to_ikm(gt: &Gt) -> [u8; 64] {
    let repr = format!("{:?}", gt);
    let mut hasher = Sha256::new();
    hasher.update(GT_TRANSCRIPT_DST);
    hasher.update((repr.len() as u64).to_le_bytes());
    hasher.update(repr.as_bytes());
    let block1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(GT_TRANSCRIPT_DST);
    hasher2.update(b"block2");
    hasher2.update(&block1);
    hasher2.update(repr.as_bytes());
    let block2 = hasher2.finalize();

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&block1);
    ikm[32..].copy_from_slice(&block2);
    ikm
}

/// HKDF-Extract + HKDF-Expand → 32-byte wrapping key from Gt shared secret.
pub(crate) fn wrapping_key_from_gt(gt: &Gt) -> Result<[u8; 32]> {
    let ikm = gt_to_ikm(gt);
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| SecureDropError::Crypto(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

pub(crate) fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Encrypt: random DEK, wrap it with HKDF(e(g,g)^{alpha s}), return ABE CT + DEK.
pub fn encrypt_keying_material(
    pk: &PublicKey,
    policy_str: &str,
    rng: &mut impl RngCore,
) -> Result<(AbeCiphertext, [u8; 32])> {
    let tree = parse_policy(policy_str)?;
    let s = Scalar::random(&mut *rng);

    // Random DEK (never derived directly from Gt)
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);
    let dek_hash = sha256_32(&dek);

    // R = e(g,g)^{alpha s}
    let e_gg_alpha_s = pk.e_gg_alpha * s;
    let mut wrap_key = wrapping_key_from_gt(&e_gg_alpha_s)?;

    // wrapped_dek = DEK XOR wrap_key
    let mut wrapped_dek = [0u8; 32];
    for i in 0..32 {
        wrapped_dek[i] = dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    // C' = h^s = g^{beta s}  (BSW07)
    let c_prime = pk.h * s;
    let mut leaf_components = HashMap::new();
    share_secret(&tree, s, pk, &mut leaf_components, rng)?;

    let ct = AbeCiphertext {
        policy: policy_str.to_string(),
        c_prime,
        leaf_components,
        wrapped_dek,
        dek_hash,
    };
    Ok((ct, dek))
}

pub fn decrypt_keying_material(
    _pk: &PublicKey,
    sk: &UserSecretKey,
    ct: &AbeCiphertext,
) -> Result<[u8; 32]> {
    let tree = parse_policy(&ct.policy)?;
    let user_attrs: HashSet<String> = sk.attributes.iter().cloned().collect();
    if !tree.satisfied_by(&user_attrs) {
        return Err(SecureDropError::AccessDenied);
    }

    let result = decrypt_node(&tree, sk, ct, &user_attrs)?;

    let c_prime_aff = G1Affine::from(ct.c_prime);
    let d_aff = G2Affine::from(sk.d);
    let e_c_d = bls12_381::pairing(&c_prime_aff, &d_aff);

    // e(g,g)^{alpha s} = e(C', D) / e(g,g)^{r s}
    let e_gg_alpha_s = e_c_d - result;
    let mut wrap_key = wrapping_key_from_gt(&e_gg_alpha_s)?;

    let mut dek = [0u8; 32];
    for i in 0..32 {
        dek[i] = ct.wrapped_dek[i] ^ wrap_key[i];
    }
    wrap_key.zeroize();

    // Integrity check — wrong recovery ⇒ hash mismatch
    let got_hash = sha256_32(&dek);
    if got_hash != ct.dek_hash {
        dek.zeroize();
        return Err(SecureDropError::DecryptionFailed);
    }

    Ok(dek)
}

fn decrypt_node(
    node: &AccessNode,
    sk: &UserSecretKey,
    ct: &AbeCiphertext,
    user_attrs: &HashSet<String>,
) -> Result<Gt> {
    match node {
        AccessNode::Leaf(attr) => {
            let attr_id = attr.id();
            if !user_attrs.contains(&attr_id) {
                return Err(SecureDropError::AccessDenied);
            }
            let (d_i, d_i_prime) = sk
                .components
                .get(&attr_id)
                .ok_or(SecureDropError::AccessDenied)?;
            let (c_y, c_y_prime) = ct
                .leaf_components
                .get(&attr_id)
                .ok_or(SecureDropError::DecryptionFailed)?;

            let e1 = bls12_381::pairing(&G1Affine::from(*c_y), &G2Affine::from(*d_i));
            let e2 =
                bls12_381::pairing(&G1Affine::from(*c_y_prime), &G2Affine::from(*d_i_prime));
            Ok(e1 - e2)
        }
        AccessNode::Threshold {
            threshold,
            children,
        } => {
            let mut satisfied = Vec::new();
            for (i, child) in children.iter().enumerate() {
                if let Ok(val) = decrypt_node(child, sk, ct, user_attrs) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn basic_encrypt_decrypt() {
        let mut rng = thread_rng();
        let universe = default_universe();
        let (pk, msk) = setup(&universe, &mut rng);

        let attrs = vec![
            "clearance>=1".into(),
            "clearance>=2".into(),
            "clearance>=3".into(),
            "clearance>=4".into(),
            "department=intelligence".into(),
        ];
        let sk = keygen(&pk, &msk, "alice", &attrs, &mut rng).unwrap();

        let policy = "clearance>=4 AND department=intelligence";
        let (ct, dek) = encrypt_keying_material(&pk, policy, &mut rng).unwrap();

        let recovered = decrypt_keying_material(&pk, &sk, &ct).unwrap();
        assert_eq!(dek, recovered);
    }
}