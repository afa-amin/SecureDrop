
# SecureDrop

**Policy-based file encryption for organizations**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://chatgpt.com/c/LICENSE)  
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

SecureDrop is a minimal command-line tool for **attribute-based encryption of files** inside a single organization.

You encrypt a file once under a human-readable policy, for example:

```text
clearance>=4 AND department=intelligence

```

The resulting package can be stored anywhere — USB, NAS, S3, shared drive. Only users whose private keys satisfy the policy can decrypt it.

The storage layer never sees plaintext.

SecureDrop is designed for defense contractors, government, and regulated enterprises that need simple, policy-driven access control without a heavy key-management stack.

----------

## Features

-   **Policy-based access** — encrypt once; decrypt only with matching attributes
    
-   **Hybrid encryption** — AES-256-GCM for data, CP-ABE for the encryption key
    
-   **Simple policy language** — `clearance>=N`, `department=…`, `role=…`, `AND` / `OR`
    
-   **Collusion-resistant keys** — each user key is bound with a fresh random exponent
    
-   **Self-contained packages** — single `.sdrop` file, easy to copy or archive
    
-   **Local and offline operation** — no server or cloud dependency in v1
    
-   **Clear CLI** — guided messages, sensible defaults, hard to misuse
    

----------

## How It Works

SecureDrop follows a simple workflow:

1.  An administrator runs `setup`, which creates the master secret and public parameters.
    
2.  Users are issued private keys bound to their attributes.
    
3.  Anyone with the public parameters can encrypt a file under a policy.
    
4.  Only a user whose attributes satisfy the policy can decrypt the file.
    

### Cryptographic Architecture

SecureDrop uses:

-   **Ciphertext-Policy Attribute-Based Encryption (CP-ABE)**
    
-   **Bethencourt–Sahai–Waters (BSW07)** construction
    
-   **BLS12-381** pairing-friendly elliptic curve
    
-   **AES-256-GCM** for file encryption
    
-   **HKDF + SHA-256** for key derivation
    
-   Per-user random blinding for collusion resistance
    

The cryptographic core is an engineering implementation of a known CP-ABE construction. **SecureDrop is not a novel cryptosystem.**

----------

## Quick Start

### Build

```bash
git clone https://github.com/YOUR_USER/securedrop.git
cd securedrop
cargo build --release

```

The resulting binary will be:

```text
target/release/securedrop

```

On Windows:

```text
target/release/securedrop.exe

```

----------

## Typical Workflow

### 1. Initialize the Organization

Run setup once:

```bash
./target/release/securedrop setup

```

This creates the organization's master secret and public parameters.

----------

### 2. Issue User Keys

Create a key for Alice:

```bash
./target/release/securedrop issue \
  --user alice \
  --clearance 4 \
  --department intelligence

```

Create a key for Bob:

```bash
./target/release/securedrop issue \
  --user bob \
  --clearance 2 \
  --department operations

```

Alice receives attributes equivalent to:

```text
clearance>=1
clearance>=2
clearance>=3
clearance>=4
department=intelligence

```

Bob receives:

```text
clearance>=1
clearance>=2
department=operations

```

----------

### 3. Encrypt a File

Create a sample file:

```bash
echo "classified briefing" > secret.txt

```

Encrypt it using a policy:

```bash
./target/release/securedrop encrypt \
  --file secret.txt \
  --policy "clearance>=4 AND department=intelligence"

```

This produces:

```text
secret.txt.sdrop

```

----------

### 4. Decrypt as Alice

Alice satisfies the policy:

```text
clearance>=4 AND department=intelligence

```

Therefore decryption succeeds:

```bash
./target/release/securedrop decrypt \
  --package secret.txt.sdrop \
  --user alice \
  --out recovered.txt

```

----------

### 5. Attempt Decryption as Bob

Bob does not satisfy the policy:

```bash
./target/release/securedrop decrypt \
  --package secret.txt.sdrop \
  --user bob

```

Result:

```text
error: Access denied

```

----------

## Windows

From `target\release`:

```powershell
.\securedrop.exe setup

.\securedrop.exe issue `
  --user alice `
  --clearance 4 `
  --department intelligence

.\securedrop.exe encrypt `
  --file secret.txt `
  --policy "clearance>=4 AND department=intelligence"

.\securedrop.exe decrypt `
  --package secret.txt.sdrop `
  --user alice `
  --out recovered.txt

```

----------

# Policy Language

SecureDrop uses a small, human-readable policy language.

Construct

Meaning

Example

`clearance>=N`

Minimum clearance level from 1–10

`clearance>=4`

`department=name`

Exact department match

`department=intelligence`

`role=name`

Exact role match

`role=admin`

`AND`

Both conditions must match

`A AND B`

`OR`

Either condition can match

`A OR B`

`( ... )`

Grouping

`(A OR B) AND C`

----------

## Policy Examples

### Minimum Clearance

```text
clearance>=4

```

Any user with clearance level 4 or higher can decrypt.

----------

### Clearance + Department

```text
clearance>=4 AND department=intelligence

```

The user must:

-   Have clearance level 4 or higher
    
-   Belong to the `intelligence` department
    

----------

### Complex Policy

```text
(clearance>=3 OR role=admin) AND department=operations

```

The user must belong to the `operations` department and must satisfy at least one of:

-   Clearance level 3 or higher
    
-   `admin` role
    

----------

### Engineering Policy

```text
clearance>=5 AND department=engineering

```

Only users with sufficient clearance in the engineering department can decrypt.

----------

## Clearance Attributes

A user issued with:

```bash
--clearance 4

```

automatically receives:

```text
clearance>=1
clearance>=2
clearance>=3
clearance>=4

```

This makes policies such as:

```text
clearance>=2

```

naturally compatible with users who have higher clearance levels.

----------

# Commands

Command

Description

`securedrop setup [--force]`

Initialize master secret and public parameters

`securedrop issue --user <name> --clearance <1–10> [--department <d>] [--role <r>]`

Issue a private key

`securedrop encrypt --file <path> --policy "<policy>" [--out <package>]`

Encrypt a file

`securedrop decrypt --package <path> --user <name> [--out <file>]`

Decrypt a package

`securedrop list-users`

List issued users and their attributes

`securedrop status`

Show installation status

`securedrop revoke-user <name>`

Delete a user's key

### Global Options

```text
--data-dir <DIR>

```

Override the default SecureDrop data directory.

----------

# Package Format

A `.sdrop` file is a single self-contained encrypted package.

Conceptually, it contains:

```text
.sdrop
├── Version
├── Creation timestamp
├── Original filename
├── Policy string
├── CP-ABE ciphertext
│   └── Protects the data-encryption key
└── AES-256-GCM payload
    ├── Nonce
    └── Ciphertext

```

The policy is also bound as **AES-GCM Additional Authenticated Data (AAD)**.

This means tampering with the policy or authenticated package metadata can be detected during decryption.

Because the package is self-contained, it can be freely copied or archived:

-   USB
    
-   NAS
    
-   S3
    
-   Shared drives
    
-   Offline storage
    
-   Backup systems
    

The storage layer does not need access to the plaintext or user attributes.

----------

# Data Directory

By default, SecureDrop stores its local state under:

### Linux / macOS

```text
~/.securedrop/

```

### Windows

```text
C:\Users\<You>\.securedrop\

```

The directory contains:

```text
.securedrop/
├── master.bin
├── meta.json
└── users/
    ├── alice.key
    └── bob.key

```

### Files

File

Purpose

`master.bin`

Master secret and public parameters

`meta.json`

Installation metadata

`users/<name>.key`

User-specific private key

On Unix-like systems, sensitive files should be protected with restrictive permissions such as `0600`.

----------

## Custom Data Directory

Use:

```bash
securedrop --data-dir <DIR> <COMMAND>

```

This is useful for:

-   Testing
    
-   Development
    
-   Multiple isolated SecureDrop instances
    
-   Temporary environments
    
-   Lab deployments
    

Example:

```bash
securedrop --data-dir ./test-data setup

```

----------

# Security Model

## What SecureDrop Provides

### Ciphertext-Policy Attribute-Based Encryption

Files are encrypted against a policy rather than a specific user.

For example:

```text
clearance>=4 AND department=intelligence

```

The ciphertext does not need to know which individual users will eventually decrypt it.

----------

### Hybrid Encryption

SecureDrop uses a hybrid encryption design:

```text
                Random DEK
                   │
          ┌────────┴────────┐
          │                 │
          ▼                 ▼
      AES-256-GCM          CP-ABE
          │                 │
          ▼                 ▼
     Encrypt file       Encrypt DEK
          │                 │
          └────────┬────────┘
                   ▼
              .sdrop package

```

AES-256-GCM provides efficient encryption for the actual file contents, while CP-ABE protects the data-encryption key according to the policy.

----------

### Policy Authentication

The policy is bound to AES-GCM as authenticated associated data (AAD).

Therefore, unauthorized modification of the policy is detected during decryption.

----------

### Collusion Resistance

User private keys are bound using fresh random blinding.

This prevents users from simply combining their private key components to construct a valid key that neither user individually possesses.

----------

# Revocation

SecureDrop v1 uses **practical epoch-style revocation**.

Revoking a user:

```bash
securedrop revoke-user alice

```

removes Alice's local private key from the current installation.

This prevents future use of that key on the machine.

However, revocation is **not cryptographic invalidation of previously distributed keys**.

If someone already possesses:

-   Alice's old private key
    
-   A copy of an old `.sdrop` package
    

they may still be able to decrypt that package.

### Stronger Revocation

When stronger revocation is required:

1.  Revoke the user.
    
2.  Generate or move to a new security epoch.
    
3.  Re-issue valid user keys.
    
4.  Re-encrypt sensitive data under the new policy/epoch.
    

----------

# What SecureDrop Does Not Provide

SecureDrop v1 intentionally does **not** provide:

-   Multi-authority ABE
    
-   Multi-organization ABE
    
-   Cryptographic revocation that invalidates old ciphertexts offline
    
-   Network service
    
-   REST API
    
-   Web UI
    
-   Centralized key-management service
    
-   Formal security proof of this specific implementation
    

SecureDrop is intended as a **local, offline, policy-driven encryption tool**.

----------

# Threat Model

SecureDrop is designed to protect files against unauthorized access when the attacker can obtain the encrypted package.

For example:

```text
                  ┌─────────────────┐
                  │    Attacker     │
                  └────────┬────────┘
                           │
                           ▼
                    secret.sdrop
                           │
                           ▼
                  ┌─────────────────┐
                  │   Encrypted     │
                  │    Payload      │
                  └─────────────────┘
                           │
                    No valid ABE key
                           │
                           ▼
                      Access Denied

```

The attacker should not be able to recover the plaintext without a private key satisfying the encryption policy.

However, SecureDrop does **not** protect against a fully compromised endpoint where an authorized user's private key or plaintext is already accessible.

----------

# Production Security Considerations

The current prototype stores the master secret locally:

```text
~/.securedrop/master.bin

```

For production environments, this should be replaced or protected using stronger key-management infrastructure.

Recommended options include:

-   Hardware Security Modules (HSMs)
    
-   Secure enclaves where appropriate
    
-   Encrypted volumes
    
-   Enterprise key-management systems
    
-   Strict filesystem permissions
    
-   OS-level access controls
    
-   Secure backup procedures
    

> **Important:** Do not treat the current local master-secret storage as suitable for a high-assurance production deployment.

----------

# Cryptography

SecureDrop's cryptographic architecture is based on established primitives and constructions.

### CP-ABE

The core construction follows the ideas of:

**Bethencourt–Sahai–Waters (BSW07)**

The implementation is adapted to:

-   A small attribute universe
    
-   Type-3 pairings
    
-   BLS12-381
    

### Symmetric Encryption

File contents are encrypted using:

```text
AES-256-GCM

```

### Key Derivation

Key derivation uses:

```text
HKDF
SHA-256

```

### Key Hygiene

Sensitive key material should be handled using memory-zeroization mechanisms where appropriate.

SecureDrop uses the Rust `zeroize` ecosystem for this purpose.

----------

# Project Structure

```text
securedrop/
├── Cargo.toml
├── README.md
├── LICENSE
└── src/
    ├── main.rs
    │
    ├── cli.rs
    │   └── Clap definitions and command handlers
    │
    ├── error.rs
    │   └── Application error types
    │
    ├── storage.rs
    │   └── Data directory, package I/O, and key storage
    │
    └── crypto/
        ├── mod.rs
        │
        ├── policy.rs
        │   └── Policy parser and access tree
        │
        ├── keys.rs
        │   └── Key generation and user key handling
        │
        ├── scheme.rs
        │   └── CP-ABE / BSW07-style implementation
        │
        └── hybrid.rs
            └── AES-256-GCM and DEK wrapping

```

----------

# Dependencies

Main cryptographic and application dependencies include:

Dependency

Purpose

`bls12_381`

Pairing-friendly elliptic curve and cryptographic groups

`aes-gcm`

AES-256-GCM authenticated encryption

`hkdf`

Key derivation

`sha2`

SHA-256 hashing

`clap`

CLI argument parsing

`serde`

Serialization

`zeroize`

Sensitive-memory cleanup

----------

# Requirements

Building SecureDrop requires:

-   Rust **1.70+**
    
-   Rust edition **2021**
    
-   A working C toolchain for some cryptographic dependencies on certain platforms
    

Check your Rust installation:

```bash
rustc --version
cargo --version

```

----------

# Building from Source

Clone the repository:

```bash
git clone https://github.com/YOUR_USER/securedrop.git
cd securedrop

```

Build:

```bash
cargo build --release

```

Run the test suite:

```bash
cargo test

```

For development builds:

```bash
cargo build

```

----------

# Example End-to-End Scenario


## Example Organization

Suppose an organization has three employees with different clearance levels, departments, and roles:

| User     | Clearance | Department     | Role       |
|----------|-----------|----------------|------------|
| **Alice**| `4`       | `intelligence` | `analyst`  |
| **Bob**  | `2`       | `operations`   | `operator` |
| **Charlie**| `5`     | `engineering`  | `engineer` |

An administrator can issue their keys:

```bash
securedrop issue \
  --user alice \
  --clearance 4 \
  --department intelligence \
  --role analyst

securedrop issue \
  --user bob \
  --clearance 2 \
  --department operations \
  --role operator

securedrop issue \
  --user charlie \
  --clearance 5 \
  --department engineering \
  --role engineer

```

Now encrypt a sensitive intelligence briefing:

```bash
securedrop encrypt \
  --file intelligence-briefing.pdf \
  --policy "clearance>=4 AND department=intelligence"

```

The result:

```text
intelligence-briefing.pdf.sdrop

```

Alice can decrypt it because she satisfies:

```text
clearance>=4
AND
department=intelligence

```

Bob cannot because:

```text
clearance=2
department=operations

```

Charlie cannot because although his clearance is sufficient:

```text
clearance=5

```

his department is:

```text
engineering

```

rather than:

```text
intelligence

```

This demonstrates the core idea of SecureDrop:

> **Access is determined by policy satisfaction, not by the identity of the user who encrypted the file.**

----------

# Design Goals

SecureDrop intentionally focuses on a small set of goals:

### 1. Simple

Policies should be readable by humans:

```text
clearance>=4 AND department=intelligence

```

### 2. Offline

No central server is required for basic encryption and decryption.

### 3. Portable

A `.sdrop` package is self-contained and can be stored anywhere.

### 4. Policy-Driven

Encryption is based on organizational attributes rather than individual recipients.

### 5. Minimal

The project avoids unnecessary infrastructure in v1.

### 6. Cryptographically Grounded

The core construction is based on an established CP-ABE design rather than claiming a new cryptographic primitive.

----------

# Security Disclaimer

SecureDrop is a practical engineering implementation of a known CP-ABE construction.

It is intended for:

-   Controlled internal networks
    
-   Research
    
-   Prototyping
    
-   Laboratory environments
    
-   Pilot deployments
    

It has **not** received a formal security proof or independent cryptographic audit.

Before using SecureDrop in a high-assurance, defense, government, or other security-critical production environment, the implementation should undergo review by qualified cryptographers and security professionals.

> **Do not assume that implementing a published cryptographic construction automatically makes an implementation secure. Correctness, parameter choices, serialization, randomness, key handling, access-tree construction, error handling, and operational security all matter.**

----------

# License

SecureDrop is released under the **MIT License**.

See [`LICENSE`](https://chatgpt.com/c/LICENSE) for the full license text.

----------

# Acknowledgments

The cryptographic core follows the ideas of the:

**Bethencourt–Sahai–Waters (BSW07) Ciphertext-Policy Attribute-Based Encryption construction.**

The construction has been adapted to a small attribute universe and Type-3 pairings using BLS12-381.

SecureDrop is an **engineering artifact, not a novel cryptosystem**.

----------

# Summary

SecureDrop provides a lightweight way for organizations to encrypt files according to human-readable access policies.

Instead of encrypting a file specifically for Alice, the organization can encrypt it under a rule:

```text
clearance>=4 AND department=intelligence

```

The encrypted `.sdrop` package can then be stored or transferred without exposing the plaintext.

A user can decrypt the file only when their issued attributes satisfy the policy.

The core architecture combines:

```text
                    SecureDrop
                        │
          ┌─────────────┴─────────────┐
          │                           │
       CP-ABE                    AES-256-GCM
          │                           │
   Protect encryption key       Encrypt file data
          │                           │
          └─────────────┬─────────────┘
                        │
                        ▼
                   .sdrop package
                        │
                        ▼
               Policy-controlled
                    decryption

```

**SecureDrop = policy-based access control + attribute-based encryption + efficient symmetric file encryption, packaged as a simple offline CLI.**