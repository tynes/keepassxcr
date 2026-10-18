//! The `.fido2` file: a key file encrypted to one or more security keys.
//!
//! ```json
//! {
//!   "format": "keepassxcr-fido2-keyfile",
//!   "version": 1,
//!   "rp_id": "keepassxcr",
//!   "key_check": "<hex>",
//!   "keys": [
//!     { "label": "...", "credential_id": "<base64>", "salt": "<base64>",
//!       "pin": true, "nonce": "<base64>", "ciphertext": "<base64>" }
//!   ]
//! }
//! ```
//!
//! Each entry holds the same key file, encrypted with XChaCha20-Poly1305
//! under `HKDF-SHA256(salt, hmac-secret(salt))`. The credential id, salt,
//! PIN choice and relying party are bound as associated data, so editing
//! them makes the entry fail to decrypt instead of misbehaving.
//!
//! `key_check` is the first 4 bytes of the SHA-256 of the key file's key,
//! like the `Hash` attribute of KeePassXC's own `.keyx` files. It lets
//! `fido2 add-key --from` check that a plain copy is the right key file.

use std::fs;
use std::io::Write;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::KeyFile;
use crate::error::{AppError, AppResult};
use crate::fido2::{self, Enrolled, PinPrompt, RP_ID, SecretRequest, fido2_error};

const FORMAT: &str = "keepassxcr-fido2-keyfile";
const VERSION: u32 = 1;
const HKDF_INFO: &[u8] = b"keepassxcr fido2 key file v1";
/// Key files are small; this bounds what is read back.
const MAX_KEY_FILE: usize = 1 << 20;

/// A key file encrypted to security keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKeyFile {
    format: String,
    version: u32,
    rp_id: String,
    key_check: String,
    keys: Vec<Entry>,
}

/// One security key's copy of the key file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Free text naming the key, shown by `fido2 list`.
    pub label: String,
    credential_id: String,
    salt: String,
    /// Whether unlocking checks the key's PIN.
    pub pin: bool,
    nonce: String,
    ciphertext: String,
}

impl WrappedKeyFile {
    /// Parse `data` if it is a wrapped key file. Returns `None` for any
    /// other file, which is then an ordinary key file.
    pub fn parse(data: &[u8]) -> Option<AppResult<Self>> {
        let text = std::str::from_utf8(data).ok()?;
        if !text.trim_start().starts_with('{') || !text.contains(FORMAT) {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        if value.get("format").and_then(serde_json::Value::as_str) != Some(FORMAT) {
            return None;
        }
        Some(Self::from_json(value))
    }

    fn from_json(value: serde_json::Value) -> AppResult<Self> {
        let file: Self = serde_json::from_value(value)
            .map_err(|err| fido2_error(format!("malformed FIDO2 key file: {err}")))?;
        if file.version != VERSION {
            return Err(fido2_error(format!(
                "FIDO2 key file version {} is not supported; update keepassxcr",
                file.version
            )));
        }
        if file.keys.is_empty() {
            return Err(fido2_error(
                "the FIDO2 key file has no security keys enrolled",
            ));
        }
        Ok(file)
    }

    /// Read a wrapped key file.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or is not a wrapped key file.
    pub fn load(path: &Path) -> AppResult<Self> {
        let data = fs::read(path)?;
        Self::parse(&data).unwrap_or_else(|| {
            Err(AppError::InvalidInput(format!(
                "{} is not a FIDO2-protected key file",
                path.display()
            )))
        })
    }

    /// Write the file, replacing `path` atomically.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    pub fn save(&self, path: &Path) -> AppResult<()> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|err| fido2_error(format!("cannot encode the key file: {err}")))?;
        text.push('\n');
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let temp = dir.join(format!(".{name}.tmp{}", std::process::id()));
        let mut file = fs::File::create(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path).inspect_err(|_| {
            let _ = fs::remove_file(&temp);
        })?;
        Ok(())
    }

    /// Encrypt `key_file` to the plugged-in security key.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be enrolled.
    pub fn create(
        key_file: &[u8],
        label: &str,
        use_pin: bool,
        pin: PinPrompt<'_>,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Self> {
        let mut file = Self {
            format: FORMAT.to_string(),
            version: VERSION,
            rp_id: RP_ID.to_string(),
            key_check: key_check(&KeyFile::from_bytes(key_file)?),
            keys: Vec::new(),
        };
        file.add_key(key_file, label, use_pin, pin, on_touch)?;
        Ok(file)
    }

    /// Enrol another security key, which must be the only one plugged in
    /// that is not already enrolled.
    ///
    /// # Errors
    ///
    /// Fails when the key cannot be enrolled.
    pub fn add_key(
        &mut self,
        key_file: &[u8],
        label: &str,
        use_pin: bool,
        pin: PinPrompt<'_>,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<&Entry> {
        if key_file.len() > MAX_KEY_FILE {
            return Err(AppError::InvalidInput(
                "the key file is too large".to_string(),
            ));
        }
        if !self.holds(&KeyFile::from_bytes(key_file)?) {
            return Err(AppError::InvalidInput(
                "that is not the key file this file protects".to_string(),
            ));
        }
        let existing = self.credential_ids()?;
        let existing: Vec<&[u8]> = existing.iter().map(Vec::as_slice).collect();
        let Enrolled {
            credential_id,
            has_pin,
        } = fido2::enroll(&self.rp_id, label, &existing, &mut *pin, &mut *on_touch)?;
        let uv = use_pin && has_pin;
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        // Ask once more, now for the secret: this is the second touch.
        let request = SecretRequest {
            credential_id: &credential_id,
            salt: &salt,
            uv,
        };
        let (_, secret) =
            fido2::local_secret(&self.rp_id, std::slice::from_ref(&request), pin, on_touch)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = associated_data(&self.rp_id, &credential_id, &salt, uv);
        let ciphertext = cipher(&secret, &salt)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key_file,
                    aad: &aad,
                },
            )
            .map_err(|_| fido2_error("encrypting the key file failed"))?;
        self.keys.push(Entry {
            label: label.to_string(),
            credential_id: BASE64.encode(&credential_id),
            salt: BASE64.encode(salt),
            pin: uv,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        });
        Ok(self.keys.last().expect("just pushed"))
    }

    /// Decrypt the key file with any enrolled security key that is reachable.
    ///
    /// # Errors
    ///
    /// Fails when no enrolled key answers, or the file was tampered with.
    pub fn unwrap_key(
        &self,
        pin: PinPrompt<'_>,
        on_touch: &mut dyn FnMut(),
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        let ids = self.credential_ids()?;
        let salts = self
            .keys
            .iter()
            .map(|entry| decode_salt(&entry.salt))
            .collect::<AppResult<Vec<_>>>()?;
        let requests: Vec<SecretRequest<'_>> = self
            .keys
            .iter()
            .zip(&ids)
            .zip(&salts)
            .map(|((entry, id), salt)| SecretRequest {
                credential_id: id,
                salt,
                uv: entry.pin,
            })
            .collect();
        let (index, secret) = fido2::secret(&self.rp_id, &requests, pin, on_touch)?;
        let entry = &self.keys[index];
        let nonce = decode(&entry.nonce, "nonce")?;
        if nonce.len() != 24 {
            return Err(fido2_error("malformed FIDO2 key file: bad nonce"));
        }
        let ciphertext = decode(&entry.ciphertext, "ciphertext")?;
        let aad = associated_data(&self.rp_id, &ids[index], &salts[index], entry.pin);
        cipher(&secret, &salts[index])
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                fido2_error(format!(
                    "the key file entry for '{}' does not decrypt; the file was changed or is \
                     from another key",
                    entry.label
                ))
            })
            .and_then(|plain| {
                if self.holds(&KeyFile::from_bytes(&plain)?) {
                    Ok(plain)
                } else {
                    Err(fido2_error(format!(
                        "the key file entry for '{}' holds a different key file",
                        entry.label
                    )))
                }
            })
    }

    /// Whether `key_file` is the key file this file protects.
    pub fn holds(&self, key_file: &KeyFile) -> bool {
        key_check(key_file) == self.key_check
    }

    /// The enrolled keys.
    pub fn keys(&self) -> &[Entry] {
        &self.keys
    }

    /// Remove the entry at `index`. The last entry cannot be removed.
    ///
    /// # Errors
    ///
    /// Fails for an index out of range or the only entry.
    pub fn remove_key(&mut self, index: usize) -> AppResult<Entry> {
        if index >= self.keys.len() {
            return Err(AppError::InvalidInput(format!(
                "there is no security key number {}",
                index + 1
            )));
        }
        if self.keys.len() == 1 {
            return Err(AppError::InvalidInput(
                "cannot remove the only enrolled security key".to_string(),
            ));
        }
        Ok(self.keys.remove(index))
    }

    fn credential_ids(&self) -> AppResult<Vec<Vec<u8>>> {
        self.keys
            .iter()
            .map(|entry| decode(&entry.credential_id, "credential id"))
            .collect()
    }
}

fn key_check(key_file: &KeyFile) -> String {
    hex::encode(&crate::crypto::sha256(key_file.raw_key())[..4])
}

fn decode(text: &str, what: &str) -> AppResult<Vec<u8>> {
    BASE64
        .decode(text)
        .map_err(|_| fido2_error(format!("malformed FIDO2 key file: bad {what}")))
}

fn decode_salt(text: &str) -> AppResult<[u8; 32]> {
    decode(text, "salt")?
        .try_into()
        .map_err(|_| fido2_error("malformed FIDO2 key file: the salt is not 32 bytes"))
}

fn cipher(secret: &[u8; 32], salt: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(HKDF_INFO, &mut key[..])
        .expect("32 bytes is a valid HKDF output length");
    XChaCha20Poly1305::new(key[..].into())
}

fn associated_data(rp_id: &str, credential_id: &[u8], salt: &[u8; 32], pin: bool) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(FORMAT.as_bytes());
    aad.extend_from_slice(&VERSION.to_be_bytes());
    aad.extend_from_slice(&(rp_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(rp_id.as_bytes());
    aad.extend_from_slice(&(credential_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(credential_id);
    aad.extend_from_slice(salt);
    aad.push(u8::from(pin));
    aad
}
