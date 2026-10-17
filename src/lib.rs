//! Read and write KeePass (KDBX 3.1 and 4.x) databases, compatible with KeePassXC.
//!
//! This crate is the library behind the `keepassxcr` command-line tool. The
//! main entry points are [`format::read_kdbx`] and [`format::write_kdbx`],
//! which take a path and [`format::Credentials`] and give back a
//! [`format::KdbxFile`]: the file's header settings plus the decrypted
//! [`model::Database`] tree of groups and entries.
//!
//! Secrets are held in [`secrecy`] and [`zeroize`] types, re-exported here so
//! callers do not need to depend on matching versions themselves.
//!
//! # Example
//!
//! Create a database with one entry, save it, and read it back:
//!
//! ```
//! use keepassxcr::crypto::{CipherId, KdfConfig, ProtectedStreamAlgo};
//! use keepassxcr::format::{
//!     Compression, Credentials, KdbxFile, KdbxVersion, read_kdbx, write_kdbx,
//! };
//! use keepassxcr::model::{Database, Entry};
//! use keepassxcr::secrecy::{ExposeSecret, SecretString};
//!
//! # fn main() -> keepassxcr::error::AppResult<()> {
//! # let dir = std::env::temp_dir().join(format!("keepassxcr-doc-{}", std::process::id()));
//! # std::fs::create_dir_all(&dir)?;
//! # let path = dir.join("passwords.kdbx");
//! let credentials = Credentials {
//!     password: Some(SecretString::new("correct horse battery staple".into())),
//!     key_file: None,
//!     yubikey: None,
//!     agent: None,
//! };
//!
//! let mut database = Database::new("Passwords".into());
//! let mut entry = Entry::new("Gmail".into());
//! entry.set_username("user@gmail.com".into());
//! entry.set_password(SecretString::new("hunter2".into()));
//! database.root_mut().entries_mut().push(entry);
//!
//! // KDBX 4 with AES-256 and Argon2id, the same defaults as `keepassxcr db-create`.
//! // A fresh random KDF salt and master seed are drawn on every write.
//! let file = KdbxFile {
//!     version: KdbxVersion::V4_0,
//!     public_custom_data: None,
//!     cipher: CipherId::Aes256,
//!     compression: Compression::Gzip,
//!     kdf: KdfConfig::default_argon2id(),
//!     protected_stream: ProtectedStreamAlgo::ChaCha20,
//!     database,
//! };
//! write_kdbx(&path, &file, &credentials)?;
//!
//! let opened = read_kdbx(&path, &credentials)?;
//! let gmail = opened.database.entry_by_path(&[], "Gmail").expect("entry exists");
//! assert_eq!(gmail.username(), "user@gmail.com");
//! assert_eq!(gmail.password().expose_secret(), "hunter2");
//! # std::fs::remove_dir_all(&dir)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Stability
//!
//! The API follows the needs of the CLI and may change between 0.x releases.
//! The [`cli`] module is the command-line front end and is not meant to be
//! used as a library.

pub mod agent;
pub mod cli;
pub mod crypto;
pub mod error;
pub mod format;
pub mod model;
pub mod util;
pub mod xml;
pub mod yubikey;

pub use secrecy;
pub use zeroize;
