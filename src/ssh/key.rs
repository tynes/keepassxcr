//! Read an entry's SSH private key the way KeePassXC does.

use std::fs;
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use ssh_encoding::Encode;
use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::model::Entry;
use crate::ssh::settings::{KeeAgentSettings, KeyLocation};

/// Largest key file read, as in KeePassXC.
const MAX_KEY_FILE: u64 = 1024 * 1024;

/// An entry's key, with the private half decrypted when asked for.
pub struct SshKey {
    /// Public key in SSH wire format, which ssh-agent uses to name keys.
    pub public_blob: Vec<u8>,
    /// `SHA256:...` fingerprint, as `ssh-add -l` prints it.
    pub fingerprint: String,
    /// Algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// Comment ssh-agent shows: the key's own, or `username@filename`.
    pub comment: String,
    /// Private key in ssh-agent's add-identity format, wiped on drop.
    private: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKey")
            .field("fingerprint", &self.fingerprint)
            .field("algorithm", &self.algorithm)
            .field("comment", &self.comment)
            .finish_non_exhaustive()
    }
}

impl SshKey {
    /// Private key in ssh-agent's format (algorithm name and key fields),
    /// present when loaded with `decrypt`.
    pub fn private(&self) -> Option<&[u8]> {
        self.private.as_deref().map(Vec::as_slice)
    }

    /// FIDO security key (`sk-...`), which needs ssh-agent's key provider.
    pub fn is_security_key(&self) -> bool {
        self.algorithm.starts_with("sk-")
    }
}

/// Load the key `settings` point at. With `decrypt`, an encrypted key is
/// opened with the entry's password, as KeePassXC does.
pub fn load(
    entry: &Entry,
    settings: &KeeAgentSettings,
    database: &Path,
    decrypt: bool,
) -> AppResult<SshKey> {
    let (file_name, data) = match settings.location()? {
        KeyLocation::Attachment(name) => {
            let attachment = entry
                .attachments()
                .iter()
                .find(|attachment| attachment.name() == name)
                .ok_or_else(|| invalid(format!("attachment '{name}' not found")))?;
            (name, Zeroizing::new(attachment.data().to_vec()))
        }
        KeyLocation::File(name) => {
            let path = resolve_key_path(&name, database);
            let file_name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let size = fs::metadata(&path)
                .map_err(|err| invalid(format!("cannot read {}: {err}", path.display())))?
                .len();
            if size > MAX_KEY_FILE {
                return Err(invalid(format!(
                    "{} is too large to be a private key",
                    path.display()
                )));
            }
            let data = fs::read(&path)
                .map_err(|err| invalid(format!("cannot read {}: {err}", path.display())))?;
            (file_name, Zeroizing::new(data))
        }
    };
    if data.is_empty() {
        return Err(invalid("private key is empty".to_string()));
    }
    let key = parse(&data)?;
    let key = if decrypt && key.is_encrypted() {
        key.decrypt(entry.password().expose_secret().as_bytes())
            .map_err(|_| {
                invalid(
                    "cannot decrypt the private key: the entry's password must be its passphrase"
                        .to_string(),
                )
            })?
    } else {
        key
    };

    let public = key.public_key();
    let public_blob = public
        .to_bytes()
        .map_err(|err| invalid(format!("bad public key: {err}")))?;
    let comment = if key.comment().is_empty() {
        format!("{}@{}", entry.username(), file_name)
    } else {
        key.comment().to_string()
    };
    let private = if decrypt {
        let key_data = key.key_data();
        let length = key_data
            .encoded_len()
            .map_err(|err| invalid(format!("bad private key: {err}")))?;
        // Sized up front so the buffer never reallocates and leaves copies.
        let mut buffer = Zeroizing::new(Vec::with_capacity(length));
        key_data
            .encode(&mut *buffer)
            .map_err(|err| invalid(format!("bad private key: {err}")))?;
        Some(buffer)
    } else {
        None
    };
    Ok(SshKey {
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algorithm: key.algorithm().as_str().to_string(),
        public_blob,
        comment,
        private,
    })
}

fn parse(data: &[u8]) -> AppResult<PrivateKey> {
    let text = String::from_utf8_lossy(data);
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return PrivateKey::from_openssh(text.trim().as_bytes())
            .map_err(|err| invalid(format!("cannot parse the private key: {err}")));
    }
    if text.contains("PRIVATE KEY-----") || text.starts_with("PuTTY-User-Key-File") {
        return Err(invalid(
            "only OpenSSH-format private keys are supported; convert this one with \
             'ssh-keygen -p -f <file>' (it rewrites the key in OpenSSH format)"
                .to_string(),
        ));
    }
    Err(invalid(
        "the attachment or file is not an SSH private key".to_string(),
    ))
}

/// Expand `~`, `$VAR` and `${VAR}`, then resolve a relative path against the
/// database's folder, like KeePassXC.
fn resolve_key_path(name: &str, database: &Path) -> PathBuf {
    let expanded = expand_env(name);
    let path = PathBuf::from(expanded);
    if path.is_relative() {
        let folder = database.parent().unwrap_or(Path::new("."));
        folder.join(path)
    } else {
        path
    }
}

fn expand_env(value: &str) -> String {
    let mut value = value.to_string();
    if let Some(rest) = value.strip_prefix('~')
        && (rest.is_empty() || rest.starts_with('/'))
        && let Some(home) = std::env::var_os("HOME")
    {
        value = format!("{}{rest}", home.to_string_lossy());
    }
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' {
            output.push(ch);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut name = String::new();
        while let Some(&next) = chars.peek() {
            let valid = if braced {
                next != '}'
            } else {
                next.is_ascii_alphanumeric() || next == '_'
            };
            if !valid {
                break;
            }
            name.push(next);
            chars.next();
        }
        let closed = !braced || chars.next_if_eq(&'}').is_some();
        if name.is_empty() || !closed {
            output.push('$');
            if braced {
                output.push('{');
            }
            output.push_str(&name);
            continue;
        }
        output.push_str(&std::env::var(&name).unwrap_or_default());
    }
    output
}

fn invalid(message: String) -> AppError {
    AppError::InvalidInput(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_variables() {
        // SAFETY: tests in this module do not read this variable concurrently.
        unsafe { std::env::set_var("KEEPASSXCR_TEST_KEYDIR", "/keys") };
        assert_eq!(expand_env("$KEEPASSXCR_TEST_KEYDIR/a"), "/keys/a");
        assert_eq!(expand_env("${KEEPASSXCR_TEST_KEYDIR}x"), "/keysx");
        assert_eq!(expand_env("cost$"), "cost$");
        assert_eq!(expand_env("${unclosed"), "${unclosed");
    }

    #[test]
    fn relative_paths_follow_the_database() {
        assert_eq!(
            resolve_key_path("keys/id", Path::new("/data/db.kdbx")),
            PathBuf::from("/data/keys/id")
        );
        assert_eq!(
            resolve_key_path("/abs/id", Path::new("/data/db.kdbx")),
            PathBuf::from("/abs/id")
        );
    }

    #[test]
    fn rejects_pem_keys_with_a_hint() {
        let err = parse(b"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
            .unwrap_err();
        assert!(err.to_string().contains("ssh-keygen -p"));
        assert!(parse(b"hello").is_err());
    }
}
