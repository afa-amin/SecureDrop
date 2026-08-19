//! Key material types for the CP-ABE scheme.

use bls12_381::{G1Projective, G2Projective, Gt, Scalar};
use std::collections::HashMap;

/// Master secret key. Must be kept offline / in HSM in real deployments.
#[derive(Clone)]
pub struct MasterSecretKey {
    pub alpha: Scalar,
    pub beta: Scalar,
}

impl Drop for MasterSecretKey {
    fn drop(&mut self) {
        // Best-effort overwrite of secret scalars
        self.alpha = Scalar::zero();
        self.beta = Scalar::zero();
    }
}

/// Public parameters.
#[derive(Clone)]
pub struct PublicKey {
    pub g: G1Projective,
    pub h: G1Projective,
    pub f: G1Projective,
    pub e_gg_alpha: Gt,
    pub attr_pubs: HashMap<String, G1Projective>,
    pub epochs: HashMap<String, u64>,
}

/// A user's secret key. Bound with a fresh random r for collusion resistance.
#[derive(Clone)]
pub struct UserSecretKey {
    pub user_id: String,
    pub d: G2Projective,
    pub components: HashMap<String, (G2Projective, G2Projective)>,
    pub attributes: Vec<String>,
}

impl Drop for UserSecretKey {
    fn drop(&mut self) {
        // Clear sensitive maps and identity; group elements are overwritten by drop of map
        self.components.clear();
        self.attributes.clear();
        self.user_id.clear();
        self.d = G2Projective::identity();
    }
}

/// Ciphertext components for the ABE keying material.
/// Recoverable value is e(g,g)^{alpha s}. The actual DEK is random and wrapped.
#[derive(Clone)]
pub struct AbeCiphertext {
    pub policy: String,
    pub c_prime: G1Projective, // h^s = g^{beta s}
    pub leaf_components: HashMap<String, (G1Projective, G1Projective)>,
    /// DEK XOR mask(kdf(e(g,g)^{alpha s})) — 32 bytes
    pub wrapped_dek: [u8; 32],
    /// SHA-256(DEK) for integrity check after unwrap
    pub dek_hash: [u8; 32],
}