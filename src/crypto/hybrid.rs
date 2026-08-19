//! Hybrid encryption: AES-256-GCM for the payload, CP-ABE for the DEK.

use crate::crypto::keys::{AbeCiphertext, PublicKey, UserSecretKey};
use crate::crypto::scheme::{decrypt_keying_material, encrypt_keying_material};
use crate::error::{Result, SecureDropError};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const NONCE_LEN: usize = 12;

/// Serializable leaf component.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredLeaf {
    pub attr: String,
    pub c_y: Vec<u8>,
    pub c_y_prime: Vec<u8>,
}

/// Serializable ABE ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredAbe {
    pub policy: String,
    pub c_prime: Vec<u8>,
    pub leaves: Vec<StoredLeaf>,
}

/// Complete package that is written to a .sdrop file.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurePackage {
    pub version: u32,
    pub created_at: i64,
    pub original_filename: String,
    pub policy: String,
    pub abe_ct: StoredAbe,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn g1_to_bytes(p: &bls12_381::G1Projective) -> Vec<u8> {
    bls12_381::G1Affine::from(*p).to_compressed().to_vec()
}
fn g1_from_bytes(b: &[u8]) -> Result<bls12_381::G1Projective> {
    let mut arr = [0u8; 48];
    if b.len() != 48 {
        return Err(SecureDropError::Serialization("bad G1 length".into()));
    }
    arr.copy_from_slice(b);
    let aff = bls12_381::G1Affine::from_compressed(&arr)
        .into_option()
        .ok_or_else(|| SecureDropError::Serialization("invalid G1".into()))?;
    Ok(bls12_381::G1Projective::from(aff))
}

impl SecurePackage {
    pub fn from_parts(
        abe: AbeCiphertext,
        nonce: [u8; NONCE_LEN],
        ciphertext: Vec<u8>,
        original_filename: String,
        policy: String,
    ) -> Self {
        let leaves = abe
            .leaf_components
            .iter()
            .map(|(attr, (c_y, c_y_prime))| StoredLeaf {
                attr: attr.clone(),
                c_y: g1_to_bytes(c_y),
                c_y_prime: g1_to_bytes(c_y_prime),
            })
            .collect();
        Self {
            version: 1,
            created_at: chrono::Utc::now().timestamp(),
            original_filename,
            policy,
            abe_ct: StoredAbe {
                policy: abe.policy,
                c_prime: g1_to_bytes(&abe.c_prime),
                leaves,
            },
            nonce,
            ciphertext,
        }
    }

    pub fn into_abe(&self) -> Result<AbeCiphertext> {
        let mut leaf_components = std::collections::HashMap::new();
        for leaf in &self.abe_ct.leaves {
            leaf_components.insert(
                leaf.attr.clone(),
                (g1_from_bytes(&leaf.c_y)?, g1_from_bytes(&leaf.c_y_prime)?),
            );
        }
        Ok(AbeCiphertext {
            policy: self.abe_ct.policy.clone(),
            c_prime: g1_from_bytes(&self.abe_ct.c_prime)?,
            leaf_components,
        })
    }
}

pub fn encrypt_file(
    pk: &PublicKey,
    policy: &str,
    plaintext: &[u8],
    original_filename: &str,
    rng: &mut impl RngCore,
) -> Result<SecurePackage> {
    let (abe_ct, mut dek) = encrypt_keying_material(pk, policy, rng)?;

    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| SecureDropError::Crypto(format!("AES key error: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = policy.as_bytes();
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| SecureDropError::Crypto(format!("AES-GCM encrypt failed: {}", e)))?;

    dek.zeroize();

    Ok(SecurePackage::from_parts(
        abe_ct,
        nonce_bytes,
        ciphertext,
        original_filename.to_string(),
        policy.to_string(),
    ))
}

pub fn decrypt_file(
    pk: &PublicKey,
    sk: &UserSecretKey,
    package: &SecurePackage,
) -> Result<Vec<u8>> {
    let abe_ct = package.into_abe()?;
    let mut dek = decrypt_keying_material(pk, sk, &abe_ct)?;

    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|e| SecureDropError::Crypto(format!("AES key error: {}", e)))?;

    let nonce = Nonce::from_slice(&package.nonce);
    let aad = package.policy.as_bytes();

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &package.ciphertext,
                aad,
            },
        )
        .map_err(|_| SecureDropError::DecryptionFailed)?;

    dek.zeroize();
    Ok(plaintext)
}