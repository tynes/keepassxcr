# keepassxcr

A Rust reimplementation of the KeePassXC command-line interface.

- Reads and writes **KDBX 3.1** and **KDBX 4.x** databases
- CLI-compatible with `keepassxc-cli`
- Pure Rust cryptography (no C bindings)
- v0.1.0 — early development

## Build

Requires the **Rust 2024 edition** (rustc 1.85+).

```sh
cargo build --release
```

The binary is at `target/release/keepassxcr`.

## Usage

All commands that open a database accept credential flags:
`--password <PW>`, `--key-file <FILE>`, `--yubikey <SLOT>`, `--no-password`.

### Create a database

```sh
# KDBX 4 with AES-256 + Argon2id (defaults)
keepassxcr db-create passwords.kdbx

# KDBX 3.1 with Twofish + AES-KDF
keepassxcr db-create passwords.kdbx --format 3 --cipher twofish --kdf aes-kdf
```

### Add an entry

```sh
keepassxcr add passwords.kdbx Email/Gmail \
  --username user@gmail.com --url https://mail.google.com -g
```

### Show an entry

```sh
keepassxcr show passwords.kdbx Email/Gmail
keepassxcr show passwords.kdbx Email/Gmail --show-password
```

### List entries

```sh
keepassxcr ls passwords.kdbx
keepassxcr ls passwords.kdbx Email
```

### Search

```sh
keepassxcr search passwords.kdbx gmail
```

### Generate passwords

```sh
keepassxcr generate --length 32
keepassxcr diceware --words 8
```

### Interactive REPL

```sh
keepassxcr open passwords.kdbx
```

## Command reference

| Category | Command | Description |
|---|---|---|
| **Database** | `db-create` | Create a new database |
| | `db-edit` | Edit database credentials/settings |
| | `db-info` | Show database metadata |
| | `open` | Open database in interactive mode |
| | `merge` | Merge two databases |
| | `export` | Export database to XML |
| | `import` | Import XML into a new database |
| **Entries** | `add` | Add an entry |
| | `edit` | Edit an entry |
| | `show` | Show an entry |
| | `rm` | Remove an entry |
| | `mv` | Move an entry to a group |
| | `clip` | Copy a field to the clipboard |
| | `search` | Search entries by term |
| **Groups** | `ls` | List group contents |
| | `mkdir` | Create a group |
| | `rmdir` | Remove a group |
| **Attachments** | `attachment-import` | Import an attachment |
| | `attachment-export` | Export an attachment |
| | `attachment-rm` | Remove an attachment |
| **Utilities** | `generate` | Generate a random password |
| | `diceware` | Generate a diceware passphrase |
| | `estimate` | Estimate password strength |
| | `analyze` | Analyze passwords with offline HIBP data |

## Supported cryptography

| Component | Options |
|---|---|
| Ciphers | AES-128-CBC, AES-256-CBC, Twofish-CBC, ChaCha20 |
| KDFs | AES-KDF, Argon2d, Argon2id |
| Protected streams | Salsa20, ChaCha20 |
| Credentials | Password, key file, YubiKey challenge-response |
| Formats | KDBX 3.1, KDBX 4.0, KDBX 4.1 |

All cryptographic operations use pure Rust crates (`aes`, `twofish`, `chacha20`, `salsa20`, `argon2`). There are no C bindings.

## Project structure

```
src/
├── main.rs              Entry point
├── lib.rs               Public crate root
├── error.rs             Error types (AppError, AppResult)
├── cli/
│   ├── mod.rs           CLI definition (clap derive)
│   ├── commands.rs      Subcommand dispatch and handlers
│   └── interactive.rs   Interactive REPL (open command)
├── crypto/
│   ├── mod.rs           Crypto module root
│   ├── constants.rs     Cipher, KDF, and stream UUIDs
│   ├── cipher.rs        AES/Twofish/ChaCha20 encryption
│   ├── kdf.rs           Key derivation (AES-KDF, Argon2)
│   ├── hash.rs          SHA-256/SHA-512/HMAC utilities
│   ├── composite_key.rs Composite key assembly
│   ├── keyfile.rs       Key file parsing
│   └── protected_stream.rs  Salsa20/ChaCha20 inner streams
├── format/
│   ├── mod.rs           Format module root
│   ├── constants.rs     KDBX signatures and version numbers
│   ├── types.rs         KdbxVersion, Compression enums
│   ├── kdbx.rs          KDBX read/write logic
│   ├── block_stream.rs  KDBX3 hashed block stream
│   └── variant_map.rs   KDBX4 variant dictionary
├── model/
│   └── mod.rs           Database, Group, Entry data model
├── xml/
│   └── mod.rs           KeePass XML serialization/deserialization
└── util/
    ├── mod.rs           Utility module root
    └── byteio.rs        Binary read/write helpers
```

## Testing

### Rust unit tests

```sh
cargo test
```

### Python CLI compatibility tests

72 tests that run both `keepassxcr` and `keepassxc-cli` and compare output.

```sh
uv sync
uv run pytest
```

Both `keepassxcr` and `keepassxc-cli` must be on `PATH`. Build keepassxcr first with `cargo build`, then either install `keepassxc-cli` from your package manager or build it from the submodule.

## KeePassXC submodule

The `keepassxc/` directory is a Git submodule pointing to the original C++ KeePassXC source. It is used only as a reference implementation for testing and is **not** compiled into keepassxcr.

```sh
git submodule update --init
```

## Non-goals

- GUI
- Browser integration
- OS-specific integrations (Secret Service, Windows Credential Manager, macOS Keychain)
