//! FIDO2 security keys (CTAP2 `hmac-secret`) protecting a KeePass key file.
//!
//! KeePassXC cannot unlock a database with a FIDO2-only key such as a
//! Yubico Security Key. Instead, keepassxcr keeps the database's ordinary
//! key file encrypted with a secret only the security key can produce (see
//! [`wrapped`]). The database itself stays a standard KeePassXC file.
//!
//! The protocol is spoken directly over USB HID: [`ctaphid`] frames the
//! messages, [`client`] sends the CTAP2 commands and [`pinuv`] protects the
//! PIN, salt and output in transit. A key plugged into another machine can
//! be used over a forwarded socket, like a YubiKey (see
//! [`crate::yubikey::forward`]).

use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::KeyFile;
use crate::error::{AppError, AppResult};

pub mod cbor;
pub mod client;
pub mod ctaphid;
#[cfg(any(test, feature = "software-fido2"))]
pub mod emulator;
mod hid;
pub mod pinuv;
pub mod wrapped;

pub use client::PinPrompt;
use client::{Authenticator, ERR_NO_CREDENTIALS};
use ctaphid::{PACKET_LEN, Transport};
pub use wrapped::WrappedKeyFile;

/// Relying party id keepassxcr's credentials are made for.
pub const RP_ID: &str = "keepassxcr";

/// Shown when the key waits for a touch.
pub const TOUCH_PROMPT: &str = "Touch your security key to continue.";

pub(crate) fn fido2_error(message: impl Into<String>) -> AppError {
    AppError::Fido2(message.into())
}

/// One credential a secret may come from.
#[derive(Debug, Clone)]
pub struct SecretRequest<'a> {
    pub credential_id: &'a [u8],
    pub salt: &'a [u8; 32],
    /// Verify the PIN, as when the credential was enrolled.
    pub uv: bool,
}

/// A credential just made on a key.
#[derive(Debug, Clone)]
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    /// Whether the key had a PIN set.
    pub has_pin: bool,
}

/// Load a key file, decrypting it with a security key when it is a
/// FIDO2-protected one.
///
/// # Errors
///
/// Fails when the file cannot be read or decrypted.
pub fn load_key_file(path: &Path, pin: PinPrompt<'_>) -> AppResult<KeyFile> {
    let data = Zeroizing::new(std::fs::read(path)?);
    match WrappedKeyFile::parse(&data) {
        Some(wrapped) => {
            let plain = wrapped?.unwrap_key(pin, &mut print_touch_prompt)?;
            KeyFile::from_bytes(&plain)
        }
        None => KeyFile::from_bytes(&data),
    }
}

/// Get the hmac-secret for whichever of `requests` a reachable key holds:
/// a key forwarded over a socket, else one plugged in here. Returns the
/// index of the request that answered.
///
/// # Errors
///
/// Fails when no key holds any of the credentials, or the key fails.
pub fn secret(
    rp_id: &str,
    requests: &[SecretRequest<'_>],
    pin: PinPrompt<'_>,
    on_touch: &mut dyn FnMut(),
) -> AppResult<(usize, Zeroizing<[u8; 32]>)> {
    #[cfg(unix)]
    if let Some(answer) = crate::yubikey::forward::fido2_secret(rp_id, requests)? {
        return Ok(answer);
    }
    local_secret(rp_id, requests, pin, on_touch)
}

/// [`secret`] from a key plugged into this machine.
///
/// # Errors
///
/// Fails when no key holds any of the credentials, or the key fails.
pub fn local_secret(
    rp_id: &str,
    requests: &[SecretRequest<'_>],
    pin: PinPrompt<'_>,
    on_touch: &mut dyn FnMut(),
) -> AppResult<(usize, Zeroizing<[u8; 32]>)> {
    let ids: Vec<&[u8]> = requests.iter().map(|r| r.credential_id).collect();
    let mut last_error = None;
    for transport in devices()? {
        let mut key = match Authenticator::open(transport) {
            Ok(key) => key,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        let found = match key.find_credential(rp_id, &ids) {
            Ok(found) => found,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        let Some(index) = found.and_then(|id| ids.iter().position(|i| *i == id.as_slice())) else {
            continue;
        };
        let request = &requests[index];
        let output = key.hmac_secret(
            rp_id,
            request.credential_id,
            request.salt,
            request.uv,
            pin,
            on_touch,
        )?;
        return Ok((index, output));
    }
    Err(last_error
        .unwrap_or_else(|| fido2_error("no plugged-in security key is enrolled in this key file")))
}

/// Make a new hmac-secret credential on the one plugged-in key that holds
/// none of `exclude`, so a key already enrolled is not enrolled twice.
///
/// # Errors
///
/// Fails when there is not exactly one such key, or it refuses.
pub fn enroll(
    rp_id: &str,
    label: &str,
    exclude: &[&[u8]],
    pin: PinPrompt<'_>,
    on_touch: &mut dyn FnMut(),
) -> AppResult<Enrolled> {
    let mut candidates = Vec::new();
    let mut enrolled_already = false;
    for transport in devices()? {
        let mut key = Authenticator::open(transport)?;
        if !exclude.is_empty() && key.find_credential(rp_id, exclude)?.is_some() {
            enrolled_already = true;
            continue;
        }
        candidates.push(key);
    }
    let mut key = match candidates.len() {
        1 => candidates.remove(0),
        0 if enrolled_already => {
            return Err(fido2_error(
                "the plugged-in security key is already enrolled; plug in the one to add",
            ));
        }
        0 => return Err(fido2_error(not_found_message())),
        _ => {
            return Err(fido2_error(
                "more than one security key is plugged in; plug in only the one to enroll",
            ));
        }
    };
    let has_pin = key.has_pin();
    let credential_id = key.make_credential(rp_id, label, pin, on_touch)?;
    Ok(Enrolled {
        credential_id,
        has_pin,
    })
}

/// Raw HID transports to every FIDO device: the software keys of test
/// builds when configured, otherwise USB.
fn devices() -> AppResult<Vec<Box<dyn Transport>>> {
    #[cfg(feature = "software-fido2")]
    if let Some(keys) = emulator::EmulatedAuthenticator::from_env()? {
        return Ok(keys
            .into_iter()
            .map(|key| Box::new(key) as Box<dyn Transport>)
            .collect());
    }
    let devices = hid::devices()?;
    if devices.is_empty() {
        return Err(fido2_error(not_found_message()));
    }
    Ok(devices)
}

fn not_found_message() -> &'static str {
    if cfg!(target_os = "linux") {
        "no security key found; plug it in and make sure you can open its hidraw device \
         (your distribution's FIDO udev rules, e.g. libfido2's)"
    } else {
        "no security key found; plug it in"
    }
}

impl Transport for Box<dyn Transport> {
    fn write_packet(&mut self, packet: &[u8; PACKET_LEN]) -> AppResult<()> {
        (**self).write_packet(packet)
    }

    fn read_packet(&mut self, timeout_ms: i32) -> AppResult<Option<[u8; PACKET_LEN]>> {
        (**self).read_packet(timeout_ms)
    }
}

/// Print the touch prompt on stderr.
pub fn print_touch_prompt() {
    eprintln!("{TOUCH_PROMPT}");
}

/// Map "no credentials" from a key to a clearer message.
pub fn is_not_enrolled(err: &AppError) -> bool {
    matches!(err, AppError::Fido2Status(ERR_NO_CREDENTIALS, _))
}

#[cfg(test)]
mod tests {
    use super::emulator::EmulatedAuthenticator;
    use super::*;
    use crate::error::AppError;

    fn no_pin() -> AppResult<Zeroizing<String>> {
        Err(fido2_error("no PIN expected"))
    }

    fn secret_of(
        key: &mut EmulatedAuthenticator,
        id: &[u8],
        salt: &[u8; 32],
        uv: bool,
        pin: &str,
    ) -> AppResult<[u8; 32]> {
        let mut auth = Authenticator::open(&mut *key)?;
        let mut touched = false;
        let secret = auth.hmac_secret(
            RP_ID,
            id,
            salt,
            uv,
            &mut || Ok(Zeroizing::new(pin.to_string())),
            &mut || touched = true,
        )?;
        assert!(touched, "no touch prompt");
        Ok(*secret)
    }

    #[test]
    fn hmac_secret_is_stable_and_depends_on_salt_and_uv() {
        for legacy in [false, true] {
            let mut key = EmulatedAuthenticator::new(&[5; 32], Some("1234"), legacy);
            let id = Authenticator::open(&mut key)
                .unwrap()
                .make_credential(
                    RP_ID,
                    "test",
                    &mut || Ok(Zeroizing::new("1234".to_string())),
                    &mut || {},
                )
                .unwrap();
            let salt = [9u8; 32];
            let a = secret_of(&mut key, &id, &salt, true, "1234").unwrap();
            let b = secret_of(&mut key, &id, &salt, true, "1234").unwrap();
            assert_eq!(a, b);
            assert_ne!(a, secret_of(&mut key, &id, &[8; 32], true, "1234").unwrap());
            assert_ne!(a, secret_of(&mut key, &id, &salt, false, "").unwrap());
            let err = secret_of(&mut key, &id, &salt, true, "0000").unwrap_err();
            assert!(err.to_string().contains("wrong security key PIN"), "{err}");
        }
    }

    #[test]
    fn output_is_what_the_emulator_documents() {
        // tests/test_fido2_python.py checks python-fido2 gets this value too.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mac = |key: &[u8], parts: &[&[u8]]| {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            parts.iter().for_each(|part| mac.update(part));
            mac.finalize().into_bytes().to_vec()
        };
        let secret = [3u8; 32];
        let mut key = EmulatedAuthenticator::new(&secret, Some("1234"), false);
        let id = Authenticator::open(&mut key)
            .unwrap()
            .make_credential(
                RP_ID,
                "test",
                &mut || Ok(Zeroizing::new("1234".to_string())),
                &mut || {},
            )
            .unwrap();
        let salt = [4u8; 32];
        for (uv, tag) in [(true, b"uv"), (false, b"nu")] {
            let got = secret_of(&mut key, &id, &salt, uv, "1234").unwrap();
            let cred_random = mac(&secret, &[tag, &id]);
            assert_eq!(got.to_vec(), mac(&cred_random, &[&salt]));
        }
    }

    #[test]
    fn a_key_without_a_pin_enrolls_with_a_touch() {
        let mut key = EmulatedAuthenticator::new(&[5; 32], None, false);
        let mut auth = Authenticator::open(&mut key).unwrap();
        assert!(!auth.has_pin());
        let id = auth
            .make_credential(RP_ID, "test", &mut no_pin, &mut || {})
            .unwrap();
        assert!(secret_of(&mut key, &id, &[1; 32], false, "").is_ok());
        assert!(secret_of(&mut key, &id, &[1; 32], true, "").is_err());
    }

    #[test]
    fn finds_only_its_own_credentials() {
        let mut one = EmulatedAuthenticator::new(&[1; 32], None, false);
        let mut two = EmulatedAuthenticator::new(&[2; 32], None, false);
        let id_one = Authenticator::open(&mut one)
            .unwrap()
            .make_credential(RP_ID, "one", &mut no_pin, &mut || {})
            .unwrap();
        let id_two = Authenticator::open(&mut two)
            .unwrap()
            .make_credential(RP_ID, "two", &mut no_pin, &mut || {})
            .unwrap();
        let ids: Vec<&[u8]> = vec![&id_one, &id_two];
        let mut auth = Authenticator::open(&mut two).unwrap();
        assert_eq!(
            auth.find_credential(RP_ID, &ids).unwrap(),
            Some(id_two.clone())
        );
        assert_eq!(auth.find_credential("other", &ids).unwrap(), None);
        let err = auth
            .hmac_secret(RP_ID, &id_one, &[0; 32], false, &mut no_pin, &mut || {})
            .unwrap_err();
        assert!(matches!(err, AppError::Fido2Status(0x2e, _)), "{err}");
    }
}
