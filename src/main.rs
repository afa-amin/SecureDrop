//! SecureDrop — policy-based file encryption CLI.
//!
//! A practical engineering implementation of a small-universe CP-ABE scheme
//! (Bethencourt-Sahai-Waters style) on BLS12-381, combined with AES-256-GCM
//! hybrid encryption.

mod cli;
pub mod crypto;
mod error;
mod storage;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli::run(cli) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}