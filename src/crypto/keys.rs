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
        self.components.clear();
        self.attributes.clear();
        self.user_id.clear();
    }
}

/// Ciphertext components for the ABE keying material.
/// The recoverable value is e(g,g)^{alpha s}; no message is embedded in Gt.
#[derive(Clone)]
pub struct AbeCiphertext {
    pub policy: String,
    pub c_prime: G1Projective, // g^s
    pub leaf_components: HashMap<String, (G1Projective, G1Projective)>,
}