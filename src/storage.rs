//! Local data directory management and package I/O.

use crate::crypto::{MasterSecretKey, PublicKey, SecurePackage, UserSecretKey};
use crate::error::{Result, SecureDropError};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const DEFAULT_DIR_NAME: &str = ".securedrop";
const MASTER_FILE: &str = "master.bin";
const USERS_DIR: &str = "users";
const META_FILE: &str = "meta.json";

#[derive(Serialize, Deserialize)]
struct StoredPublicKey {
    g: Vec<u8>,
    h: Vec<u8>,
    f: Vec<u8>,
    attr_pubs: HashMap<String, Vec<u8>>,
    epochs: HashMap<String, u64>,
}

#[derive(Serialize, Deserialize)]
struct StoredMasterSecret {
    alpha: Vec<u8>,
    beta: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Meta {
    pub created_at: i64,
    pub universe_size: usize,
    pub users: Vec<String>,
}

pub fn data_dir(custom: Option<&Path>) -> PathBuf {
    if let Some(p) = custom {
        return p.to_path_buf();
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_DIR_NAME)
}

pub fn is_initialized(dir: &Path) -> bool {
    dir.join(MASTER_FILE).exists() && dir.join(META_FILE).exists()
}

pub fn ensure_data_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::create_dir_all(dir.join(USERS_DIR))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
    Ok(())
}

/// Securely overwrite a file before deleting it (best-effort on SSD).
fn secure_delete(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(path)?.len();
    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path)?;
        let mut rng = rand::thread_rng();

        // Pass 1–2: zeros
        let zero_chunk = vec![0u8; 65536];
        for _ in 0..2 {
            file.seek(SeekFrom::Start(0))?;
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(zero_chunk.len() as u64) as usize;
                file.write_all(&zero_chunk[..n])?;
                remaining -= n as u64;
            }
            file.sync_all()?;
        }

        // Pass 3: random
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(65536) as usize;
            let mut buf = vec![0u8; n];
            rng.fill_bytes(&mut buf);
            file.write_all(&buf)?;
            remaining -= n as u64;
        }
        file.sync_all()?;
        // Final zeros
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(zero_chunk.len() as u64) as usize;
            file.write_all(&zero_chunk[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}

fn g1_to_bytes(p: &G1Projective) -> Vec<u8> {
    G1Affine::from(*p).to_compressed().to_vec()
}
fn g1_from_bytes(b: &[u8]) -> Result<G1Projective> {
    let mut arr = [0u8; 48];
    if b.len() != 48 {
        return Err(SecureDropError::Serialization("bad G1 length".into()));
    }
    arr.copy_from_slice(b);
    let aff = G1Affine::from_compressed(&arr)
        .into_option()
        .ok_or_else(|| SecureDropError::Serialization("invalid G1".into()))?;
    Ok(G1Projective::from(aff))
}

fn g2_to_bytes(p: &G2Projective) -> Vec<u8> {
    G2Affine::from(*p).to_compressed().to_vec()
}
fn g2_from_bytes(b: &[u8]) -> Result<G2Projective> {
    let mut arr = [0u8; 96];
    if b.len() != 96 {
        return Err(SecureDropError::Serialization("bad G2 length".into()));
    }
    arr.copy_from_slice(b);
    let aff = G2Affine::from_compressed(&arr)
        .into_option()
        .ok_or_else(|| SecureDropError::Serialization("invalid G2".into()))?;
    Ok(G2Projective::from(aff))
}

fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.to_bytes().to_vec()
}
fn scalar_from_bytes(b: &[u8]) -> Result<Scalar> {
    let mut arr = [0u8; 32];
    if b.len() != 32 {
        return Err(SecureDropError::Serialization("bad Scalar length".into()));
    }
    arr.copy_from_slice(b);
    Scalar::from_bytes(&arr)
        .into_option()
        .ok_or_else(|| SecureDropError::Serialization("invalid Scalar".into()))
}

pub fn save_master(dir: &Path, pk: &PublicKey, msk: &MasterSecretKey) -> Result<()> {
    ensure_data_dir(dir)?;

    let stored_pk = StoredPublicKey {
        g: g1_to_bytes(&pk.g),
        h: g1_to_bytes(&pk.h),
        f: g1_to_bytes(&pk.f),
        attr_pubs: pk
            .attr_pubs
            .iter()
            .map(|(k, v)| (k.clone(), g1_to_bytes(v)))
            .collect(),
        epochs: pk.epochs.clone(),
    };

    let stored_msk = StoredMasterSecret {
        alpha: scalar_to_bytes(&msk.alpha),
        beta: scalar_to_bytes(&msk.beta),
    };

    let bundle = (stored_pk, stored_msk);
    let data = bincode::serialize(&bundle)?;
    let path = dir.join(MASTER_FILE);
    let mut f = File::create(&path)?;
    f.write_all(&data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_master(dir: &Path) -> Result<(PublicKey, MasterSecretKey)> {
    let path = dir.join(MASTER_FILE);
    if !path.exists() {
        return Err(SecureDropError::NotInitialized);
    }
    let mut f = File::open(&path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    let (stored_pk, stored_msk): (StoredPublicKey, StoredMasterSecret) =
        bincode::deserialize(&data)?;

    let mut attr_pubs = HashMap::new();
    for (k, v) in stored_pk.attr_pubs {
        attr_pubs.insert(k, g1_from_bytes(&v)?);
    }

    let alpha = scalar_from_bytes(&stored_msk.alpha)?;
    let beta = scalar_from_bytes(&stored_msk.beta)?;

    let g = g1_from_bytes(&stored_pk.g)?;
    let g2 = G2Projective::generator();
    let e_gg_alpha = bls12_381::pairing(&G1Affine::from(g), &G2Affine::from(g2 * alpha));

    let pk = PublicKey {
        g,
        h: g1_from_bytes(&stored_pk.h)?,
        f: g1_from_bytes(&stored_pk.f)?,
        e_gg_alpha,
        attr_pubs,
        epochs: stored_pk.epochs,
    };
    let msk = MasterSecretKey { alpha, beta };
    Ok((pk, msk))
}

#[derive(Serialize, Deserialize)]
struct StoredUserKey {
    user_id: String,
    d: Vec<u8>,
    components: HashMap<String, (Vec<u8>, Vec<u8>)>,
    attributes: Vec<String>,
}

pub fn save_user_key(dir: &Path, sk: &UserSecretKey) -> Result<()> {
    ensure_data_dir(dir)?;
    let stored = StoredUserKey {
        user_id: sk.user_id.clone(),
        d: g2_to_bytes(&sk.d),
        components: sk
            .components
            .iter()
            .map(|(k, (a, b))| (k.clone(), (g2_to_bytes(a), g2_to_bytes(b))))
            .collect(),
        attributes: sk.attributes.clone(),
    };
    let data = bincode::serialize(&stored)?;
    let path = dir.join(USERS_DIR).join(format!("{}.key", sk.user_id));
    let mut f = File::create(&path)?;
    f.write_all(&data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn load_user_key(dir: &Path, user: &str) -> Result<UserSecretKey> {
    let path = dir.join(USERS_DIR).join(format!("{}.key", user));
    if !path.exists() {
        return Err(SecureDropError::UserNotFound(user.to_string()));
    }
    let mut f = File::open(&path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    let stored: StoredUserKey = bincode::deserialize(&data)?;

    let mut components = HashMap::new();
    for (k, (a, b)) in stored.components {
        components.insert(k, (g2_from_bytes(&a)?, g2_from_bytes(&b)?));
    }
    Ok(UserSecretKey {
        user_id: stored.user_id,
        d: g2_from_bytes(&stored.d)?,
        components,
        attributes: stored.attributes,
    })
}

pub fn list_users(dir: &Path) -> Result<Vec<String>> {
    let users_dir = dir.join(USERS_DIR);
    if !users_dir.exists() {
        return Ok(Vec::new());
    }
    let mut users = Vec::new();
    for entry in fs::read_dir(users_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(u) = name.strip_suffix(".key") {
            users.push(u.to_string());
        }
    }
    users.sort();
    Ok(users)
}

pub fn delete_user(dir: &Path, user: &str) -> Result<()> {
    let path = dir.join(USERS_DIR).join(format!("{}.key", user));
    if !path.exists() {
        return Err(SecureDropError::UserNotFound(user.to_string()));
    }
    // Secure overwrite then remove
    secure_delete(&path)?;
    Ok(())
}

pub fn save_meta(dir: &Path, meta: &Meta) -> Result<()> {
    let path = dir.join(META_FILE);
    let data = serde_json::to_vec_pretty(meta)?;
    fs::write(path, data)?;
    Ok(())
}

pub fn load_meta(dir: &Path) -> Result<Meta> {
    let path = dir.join(META_FILE);
    if !path.exists() {
        return Err(SecureDropError::NotInitialized);
    }
    let data = fs::read(path)?;
    Ok(serde_json::from_slice(&data)?)
}

pub fn write_package(path: &Path, package: &SecurePackage) -> Result<()> {
    let data = bincode::serialize(package)?;
    let mut f = File::create(path)?;
    f.write_all(b"SDRP")?;
    f.write_all(&data)?;
    Ok(())
}

pub fn read_package(path: &Path) -> Result<SecurePackage> {
    let mut f = File::open(path).map_err(|_| {
        SecureDropError::PackageNotFound(path.display().to_string())
    })?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic != b"SDRP" {
        return Err(SecureDropError::Other(
            "not a valid SecureDrop package (bad magic)".into(),
        ));
    }
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(bincode::deserialize(&data)?)
}