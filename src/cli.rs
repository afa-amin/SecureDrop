//! CLI definitions and command handlers.

use crate::crypto::{
    default_universe, expand_clearance, keygen, setup, Attribute,
};
use crate::crypto::hybrid::{decrypt_file, encrypt_file};
use crate::error::{Result, SecureDropError};
use crate::storage::{
    data_dir, delete_user, is_initialized, list_users, load_master, load_meta, load_user_key,
    read_package, save_master, save_meta, save_user_key, write_package, Meta,
};
use clap::{Parser, Subcommand};
use rand::thread_rng;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "securedrop",
    about = "SecureDrop — policy-based file encryption for organizations\n\n\
             Encrypt a file once under a human-readable policy. Only users whose\n\
             attributes satisfy the policy can decrypt it. The storage layer never\n\
             sees plaintext.\n\n\
             Policy examples:\n  \
               clearance>=4 AND department=intelligence\n  \
               (clearance>=3 OR role=admin) AND department=operations",
    version,
    long_about = None
)]
pub struct Cli {
    /// Override the default data directory (~/.securedrop)
    #[arg(long, global = true, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize SecureDrop (create master secret & public parameters)
    Setup {
        /// Force re-initialization (destroys existing keys!)
        #[arg(long)]
        force: bool,
    },

    /// Issue a private key to a user
    Issue {
        /// Username (unique identifier)
        #[arg(long)]
        user: String,

        /// Clearance level (1–10). The user receives clearance>=1 … clearance>=N
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=10))]
        clearance: u32,

        /// Department attribute (e.g. intelligence, operations)
        #[arg(long)]
        department: Option<String>,

        /// Role attribute (e.g. analyst, admin)
        #[arg(long)]
        role: Option<String>,
    },

    /// Encrypt a file under a policy
    Encrypt {
        /// Path to the file to encrypt
        #[arg(long)]
        file: PathBuf,

        /// Access policy, e.g. "clearance>=4 AND department=intelligence"
        #[arg(long)]
        policy: String,

        /// Output package path (default: <file>.sdrop)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Decrypt a package with a user key
    Decrypt {
        /// Path to the .sdrop package
        #[arg(long)]
        package: PathBuf,

        /// Username whose key should be used
        #[arg(long)]
        user: String,

        /// Output file path (default: original filename from package)
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// List all issued users
    ListUsers,

    /// Show status of the local installation
    Status,

    /// Revoke a user (deletes their key; old packages remain decryptable by them until re-encrypted)
    RevokeUser {
        /// Username to revoke
        user: String,
    },
}

pub fn run(cli: Cli) -> Result<()> {
    let dir = data_dir(cli.data_dir.as_deref());

    match cli.command {
        Commands::Setup { force } => cmd_setup(&dir, force),
        Commands::Issue {
            user,
            clearance,
            department,
            role,
        } => cmd_issue(&dir, &user, clearance, department.as_deref(), role.as_deref()),
        Commands::Encrypt { file, policy, out } => cmd_encrypt(&dir, &file, &policy, out.as_deref()),
        Commands::Decrypt {
            package,
            user,
            out,
        } => cmd_decrypt(&dir, &package, &user, out.as_deref()),
        Commands::ListUsers => cmd_list_users(&dir),
        Commands::Status => cmd_status(&dir),
        Commands::RevokeUser { user } => cmd_revoke_user(&dir, &user),
    }
}

fn require_init(dir: &Path) -> Result<()> {
    if !is_initialized(dir) {
        return Err(SecureDropError::NotInitialized);
    }
    Ok(())
}

fn cmd_setup(dir: &Path, force: bool) -> Result<()> {
    if is_initialized(dir) && !force {
        println!(
            "SecureDrop is already initialized at {}.\n\
             Use --force to re-initialize (this will destroy all existing keys).",
            dir.display()
        );
        return Ok(());
    }

    if force && dir.exists() {
        println!("Re-initializing — removing previous data…");
        std::fs::remove_dir_all(dir).ok();
    }

    println!("Generating master secret and public parameters…");
    let mut rng = thread_rng();
    let universe = default_universe();
    let (pk, msk) = setup(&universe, &mut rng);

    save_master(dir, &pk, &msk)?;
    let meta = Meta {
        created_at: chrono::Utc::now().timestamp(),
        universe_size: universe.len(),
        users: Vec::new(),
    };
    save_meta(dir, &meta)?;

    println!();
    println!("✓ SecureDrop initialized successfully.");
    println!("  Data directory : {}", dir.display());
    println!("  Attribute universe size : {}", universe.len());
    println!();
    println!("Next steps:");
    println!("  1. Issue a key   : securedrop issue --user alice --clearance 4 --department intelligence");
    println!("  2. Encrypt a file: securedrop encrypt --file secret.pdf --policy \"clearance>=4 AND department=intelligence\"");
    println!();
    println!("NOTE: The master secret is stored locally in plaintext for this demo.");
    println!("      For real deployments keep it in an HSM or at least an encrypted volume.");
    Ok(())
}

fn cmd_issue(
    dir: &Path,
    user: &str,
    clearance: u32,
    department: Option<&str>,
    role: Option<&str>,
) -> Result<()> {
    require_init(dir)?;

    let existing = list_users(dir)?;
    if existing.iter().any(|u| u == user) {
        return Err(SecureDropError::UserAlreadyExists(user.to_string()));
    }

    let (pk, msk) = load_master(dir)?;

    let mut attrs: Vec<String> = expand_clearance(clearance)
        .into_iter()
        .map(|a| a.id())
        .collect();

    if let Some(d) = department {
        attrs.push(Attribute::department(d).id());
    }
    if let Some(r) = role {
        attrs.push(Attribute::role(r).id());
    }

    let mut rng = thread_rng();
    let sk = keygen(&pk, &msk, user, &attrs, &mut rng)?;
    save_user_key(dir, &sk)?;

    let mut meta = load_meta(dir)?;
    meta.users.push(user.to_string());
    meta.users.sort();
    meta.users.dedup();
    save_meta(dir, &meta)?;

    println!("✓ Key issued for user \"{}\"", user);
    println!("  Attributes:");
    for a in &attrs {
        println!("    • {}", a);
    }
    println!();
    println!("  The private key is stored under {}/users/{}.key", dir.display(), user);
    println!("  Keep it confidential; anyone who obtains it can decrypt packages that match these attributes.");
    Ok(())
}

fn cmd_encrypt(dir: &Path, file: &Path, policy: &str, out: Option<&Path>) -> Result<()> {
    require_init(dir)?;

    if !file.exists() {
        return Err(SecureDropError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("file not found: {}", file.display()),
        )));
    }

    let _ = crate::crypto::parse_policy(policy)?;

    let (pk, _msk) = load_master(dir)?;
    let plaintext = std::fs::read(file)?;
    let filename = file
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut rng = thread_rng();
    let package = encrypt_file(&pk, policy, &plaintext, &filename, &mut rng)?;

    let out_path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(format!("{}.sdrop", file.display())));

    write_package(&out_path, &package)?;

    println!("✓ File encrypted successfully.");
    println!("  Policy     : {}", policy);
    println!("  Package    : {}", out_path.display());
    println!("  Original   : {}", filename);
    println!("  Size       : {} bytes → {} bytes (package)", plaintext.len(), std::fs::metadata(&out_path)?.len());
    println!();
    println!("Only holders of a private key whose attributes satisfy the policy can decrypt this package.");
    Ok(())
}

fn cmd_decrypt(dir: &Path, package_path: &Path, user: &str, out: Option<&Path>) -> Result<()> {
    require_init(dir)?;

    let (pk, _) = load_master(dir)?;
    let sk = load_user_key(dir, user)?;
    let package = read_package(package_path)?;

    println!("Decrypting with user \"{}\"…", user);
    println!("  Policy on package: {}", package.policy);

    let plaintext = decrypt_file(&pk, &sk, &package)?;

    let out_path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(&package.original_filename));

    std::fs::write(&out_path, &plaintext)?;

    println!("✓ Decryption successful.");
    println!("  Output file: {}", out_path.display());
    println!("  Size       : {} bytes", plaintext.len());
    Ok(())
}

fn cmd_list_users(dir: &Path) -> Result<()> {
    require_init(dir)?;
    let users = list_users(dir)?;
    if users.is_empty() {
        println!("No users have been issued keys yet.");
        println!("Use: securedrop issue --user <name> --clearance <n>");
        return Ok(());
    }
    println!("Issued users ({}):", users.len());
    for u in users {
        if let Ok(sk) = load_user_key(dir, &u) {
            println!("  • {}  [{}]", u, sk.attributes.join(", "));
        } else {
            println!("  • {}", u);
        }
    }
    Ok(())
}

fn cmd_status(dir: &Path) -> Result<()> {
    if !is_initialized(dir) {
        println!("SecureDrop is not initialized.");
        println!("Run: securedrop setup");
        return Ok(());
    }
    let meta = load_meta(dir)?;
    let users = list_users(dir)?;
    println!("SecureDrop status");
    println!("  Data directory : {}", dir.display());
    println!(
        "  Initialized    : {}",
        chrono::DateTime::from_timestamp(meta.created_at, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| meta.created_at.to_string())
    );
    println!("  Universe size  : {}", meta.universe_size);
    println!("  Users issued   : {}", users.len());
    Ok(())
}

fn cmd_revoke_user(dir: &Path, user: &str) -> Result<()> {
    require_init(dir)?;
    delete_user(dir, user)?;
    let mut meta = load_meta(dir)?;
    meta.users.retain(|u| u != user);
    save_meta(dir, &meta)?;
    println!("✓ User \"{}\" revoked (key deleted).", user);
    println!("  Note: packages already encrypted remain decryptable by anyone who still");
    println!("  possesses a copy of the old key. Re-encrypt sensitive data if needed.");
    Ok(())
}