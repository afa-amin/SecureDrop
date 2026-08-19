//! Error types for SecureDrop.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecureDropError {
    #[error("SecureDrop has not been initialized. Run `securedrop setup` first.")]
    NotInitialized,

    #[error("Master secret or public parameters are missing or corrupted")]
    MissingMasterMaterial,

    #[error("User `{0}` does not exist")]
    UserNotFound(String),

    #[error("User `{0}` already exists")]
    UserAlreadyExists(String),

    #[error("Package not found or unreadable: {0}")]
    PackageNotFound(String),

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Access denied: the user's attributes do not satisfy the policy")]
    AccessDenied,

    #[error("Decryption failed (wrong key, tampered package, or policy mismatch)")]
    DecryptionFailed,

    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Attribute `{0}` is not in the allowed universe")]
    UnknownAttribute(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SecureDropError>;

impl From<bincode::Error> for SecureDropError {
    fn from(e: bincode::Error) -> Self {
        SecureDropError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for SecureDropError {
    fn from(e: serde_json::Error) -> Self {
        SecureDropError::Serialization(e.to_string())
    }
}