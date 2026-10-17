//! Read and write KeePass (KDBX 3.1 and 4.x) databases, compatible with KeePassXC.
//!
//! This crate is the library behind the `keepassxcr` command-line tool. The
//! main entry points are [`KdbxFile::open`] and [`KdbxFile::save`], which
//! take a path and [`Credentials`]. A [`KdbxFile`] holds the file's header
//! settings plus the decrypted [`Database`] tree of groups and entries.
//!
//! Secrets are held in [`secrecy`] and [`zeroize`] types, re-exported here so
//! callers do not need to depend on matching versions themselves.
//!
//! # Example
//!
//! Create a database with one entry, save it, and read it back:
//!
//! ```
//! use keepassxcr::secrecy::ExposeSecret;
//! use keepassxcr::{Credentials, Database, Entry, KdbxFile};
//!
//! # fn main() -> keepassxcr::AppResult<()> {
//! # let dir = std::env::temp_dir().join(format!("keepassxcr-doc-{}", std::process::id()));
//! # std::fs::create_dir_all(&dir)?;
//! # let path = dir.join("passwords.kdbx");
//! let credentials = Credentials::password("correct horse battery staple");
//!
//! let mut database = Database::new("Passwords".into());
//! let mut entry = Entry::new("Gmail".into());
//! entry.set_username("user@gmail.com".into());
//! entry.set_password("hunter2".to_string().into());
//! database.root_mut().entries_mut().push(entry);
//!
//! // KDBX 4 with AES-256 and Argon2id, the same defaults as `keepassxcr db-create`.
//! // A fresh random KDF salt and master seed are drawn on every save.
//! KdbxFile::new(database).save(&path, &credentials)?;
//!
//! let opened = KdbxFile::open(&path, &credentials)?;
//! let gmail = opened.database.entry_by_path(&[], "Gmail").expect("entry exists");
//! assert_eq!(gmail.username(), "user@gmail.com");
//! assert_eq!(gmail.password().expose_secret(), "hunter2");
//! # std::fs::remove_dir_all(&dir)?;
//! # Ok(())
//! # }
//! ```
//!
//! A key file or YubiKey goes through [`Credentials::builder`]. The file's
//! settings (cipher, KDF, compression) are public fields of [`KdbxFile`].
//!
//! # Features
//!
//! - `cli` (default): the `keepassxcr` binary. Library users can skip its
//!   dependencies (clap, the clipboard, the progress bar, ...) with
//!   `keepassxcr = { version = "0.3", default-features = false }`.
//!
//! # Stability
//!
//! The API may still change between 0.x releases. The public modules are
//! [`mod@format`], [`model`], [`crypto`], [`error`] and [`yubikey`]; anything
//! hidden from these docs serves the command-line tool and is not part of the
//! library API.

#[doc(hidden)]
pub mod agent;
#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cli;
pub mod crypto;
pub mod error;
pub mod format;
pub mod model;
#[doc(hidden)]
pub mod ssh;
pub(crate) mod util;
pub(crate) mod xml;
pub mod yubikey;

pub use error::{AppError, AppResult};
pub use format::{Credentials, KdbxFile, read_kdbx, write_kdbx};
pub use model::{Database, Entry, Group};

pub use secrecy;
pub use zeroize;
