//! FIDO2 security keys as a database key: Ledger's Security Key app, a
//! YubiKey 5, or any other authenticator with the `hmac-secret` extension.
//!
//! When a database is set up, the device registers a credential and
//! keepassxcr draws a random salt. Both are stored in the clear in the KDBX 4
//! `PublicCustomData` header (see [`Fido2Config`]). To unlock, the device
//! computes `hmac-secret(credential, salt)`, a fixed 32-byte secret, after
//! the user confirms on it. That secret takes the key-file slot of the
//! composite key, so the file stays an ordinary KDBX 4 database that
//! KeePassXC can read and save, although only keepassxcr can ask the device
//! for the secret.
//!
//! On a Ledger, the credential is derived from the device's seed: a Ledger
//! restored from the same 24 words answers with the same secret.
//!
//! The answer comes from, in order: a device forwarded over a socket (see
//! [`forward`]), the software device of test builds, or the FIDO2 devices
//! plugged in over USB. With several plugged in, each is asked and the one
//! the user confirms on wins.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

mod config;
mod ctap;
mod ctaphid;
#[cfg(any(test, feature = "software-fido2"))]
mod emulator;
#[cfg(unix)]
pub mod forward;
mod hid;

pub use config::Fido2Config;

use ctaphid::Device;

/// Bytes of the salt and of the secret the device derives from it.
pub const SALT_LEN: usize = 32;
/// The secret a device derives for a database, wiped when dropped.
pub type Secret = Zeroizing<[u8; SALT_LEN]>;
/// Relying party id keepassxcr registers credentials under.
pub const RP_ID: &str = "keepassxcr";

/// Shown when the device waits for the user.
const TOUCH_PROMPT: &str = "Please touch or confirm on your FIDO2 device to continue.";

/// Why one device did not answer.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The device does not hold the credential.
    NoCredentials,
    /// Another device answered first.
    Cancelled,
    /// Anything else.
    Error(AppError),
}

impl From<AppError> for Failure {
    fn from(err: AppError) -> Self {
        Self::Error(err)
    }
}

impl Failure {
    /// A CTAP2 status byte other than success.
    fn from_status(status: u8) -> Self {
        let message = match status {
            0x2e => return Self::NoCredentials,
            0x2d => return Self::Cancelled,
            0x27 => "the request was declined on the device".to_string(),
            0x2f => "timed out waiting for confirmation on the device".to_string(),
            0x36 => "the device requires its PIN, which keepassxcr cannot send yet".to_string(),
            0x2b | 0x2c | 0x11 | 0x12 | 0x14 => format!(
                "the device rejected the request (error {status:#04x}); it may not support \
                 hmac-secret"
            ),
            _ => format!("the device returned error {status:#04x}"),
        };
        fido2_error(message)
    }
}

/// A [`Failure`] with a message.
pub(crate) fn fido2_error(message: impl Into<String>) -> Failure {
    Failure::Error(AppError::Fido2(message.into()))
}

/// Register a FIDO2 device for a database: the device makes a credential,
/// keepassxcr draws a salt, and the device derives the database's secret.
/// The user confirms twice on the device.
///
/// # Errors
///
/// Fails when no device is reachable, the user declines, or the device lacks
/// hmac-secret.
pub fn enroll() -> AppResult<(Fido2Config, Secret)> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    #[cfg(unix)]
    let forwarded = forward::enroll(RP_ID, &salt)?;
    #[cfg(not(unix))]
    let forwarded = None;
    let (credential_id, secret) = match forwarded {
        Some(result) => result,
        None => local_enroll(RP_ID, &salt, &print_touch_prompt)?,
    };
    let config = Fido2Config {
        rp_id: RP_ID.to_string(),
        credential_id,
        salt,
    };
    Ok((config, secret))
}

/// Ask a FIDO2 device for the secret of the database set up with `config`.
///
/// # Errors
///
/// Fails when no device holding the credential is reachable, or the user declines.
pub fn secret(config: &Fido2Config) -> AppResult<Secret> {
    #[cfg(unix)]
    if let Some(secret) = forward::secret(config)? {
        return Ok(secret);
    }
    local_secret(
        &config.rp_id,
        &config.credential_id,
        &config.salt,
        &print_touch_prompt,
    )
}

/// Enroll a device on this machine: returns the credential id and secret.
fn local_enroll(
    rp_id: &str,
    salt: &[u8; SALT_LEN],
    on_touch: &(dyn Fn() + Sync),
) -> AppResult<(Vec<u8>, Secret)> {
    let (mut device, credential_id) = race(devices()?, |device, cancel| {
        ctap::make_credential(device, rp_id, cancel, on_touch)
    })?;
    // The same device, which now holds the credential.
    let secret = ctap::hmac_secret(
        &mut device,
        rp_id,
        &credential_id,
        salt,
        &AtomicBool::new(false),
        on_touch,
    )
    .map_err(|failure| into_error(failure, "the device lost the new credential"))?;
    Ok((credential_id, secret))
}

/// Ask the devices on this machine for a credential's secret.
fn local_secret(
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; SALT_LEN],
    on_touch: &(dyn Fn() + Sync),
) -> AppResult<Secret> {
    race(devices()?, |device, cancel| {
        ctap::hmac_secret(device, rp_id, credential_id, salt, cancel, on_touch)
    })
    .map(|(_, secret)| secret)
}

/// The FIDO2 devices to ask: the software device of test builds when
/// configured, otherwise those plugged in over USB.
fn devices() -> AppResult<Vec<Device>> {
    #[cfg(feature = "software-fido2")]
    if let Some(emulated) = emulator::Emulator::from_env()? {
        let device = Device::open(Box::new(emulated))
            .map_err(|failure| into_error(failure, "the software device failed"))?;
        return Ok(vec![device]);
    }
    hid::devices()
}

/// Run `op` on every device at once. The first to succeed wins and the
/// others are cancelled, so with several devices plugged in the user picks
/// one by confirming on it.
fn race<T: Send>(
    devices: Vec<Device>,
    op: impl Fn(&mut Device, &AtomicBool) -> Result<T, Failure> + Sync,
) -> AppResult<(Device, T)> {
    let done = AtomicBool::new(false);
    let results = thread::scope(|scope| {
        let handles: Vec<_> = devices
            .into_iter()
            .map(|mut device| {
                // Rust closures borrow by default; `move` takes these references by value.
                let (op, done) = (&op, &done);
                scope.spawn(move || {
                    let result = op(&mut device, done);
                    if result.is_ok() {
                        done.store(true, Ordering::Relaxed);
                    }
                    (device, result)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Vec<_>>()
    });

    let mut no_credentials = false;
    let mut error = None;
    for (device, result) in results {
        match result {
            Ok(value) => return Ok((device, value)),
            Err(Failure::NoCredentials) => no_credentials = true,
            Err(Failure::Cancelled) => {}
            Err(Failure::Error(err)) => {
                error.get_or_insert(err);
            }
        }
    }
    Err(error.unwrap_or_else(|| {
        AppError::Fido2(if no_credentials {
            "no FIDO2 device here holds this database's credential; plug in the device it was \
             set up with (or a Ledger restored from the same seed)"
                .to_string()
        } else {
            "the request was cancelled".to_string()
        })
    }))
}

/// The error for a [`Failure`] outside a race.
fn into_error(failure: Failure, no_credentials: &str) -> AppError {
    match failure {
        Failure::Error(err) => err,
        Failure::NoCredentials => AppError::Fido2(no_credentials.to_string()),
        Failure::Cancelled => AppError::Fido2("the request was cancelled".to_string()),
    }
}

fn print_touch_prompt() {
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{TOUCH_PROMPT}\n");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido2::emulator::Emulator;

    fn emulated(master: &[u8]) -> Device {
        Device::open(Box::new(Emulator::new(master.to_vec()))).expect("open emulator")
    }

    fn enroll_on(master: &[u8], salt: &[u8; SALT_LEN]) -> (Vec<u8>, Secret) {
        let mut device = emulated(master);
        let id = ctap::make_credential(&mut device, RP_ID, &AtomicBool::new(false), &|| {})
            .expect("make credential");
        let secret = ctap::hmac_secret(
            &mut device,
            RP_ID,
            &id,
            salt,
            &AtomicBool::new(false),
            &|| {},
        )
        .expect("hmac-secret");
        (id, secret)
    }

    #[test]
    fn same_credential_and_salt_give_the_same_secret() {
        let salt = [5u8; SALT_LEN];
        let (id, first) = enroll_on(b"seed", &salt);
        let again = race(vec![emulated(b"seed")], |device, cancel| {
            ctap::hmac_secret(device, RP_ID, &id, &salt, cancel, &|| {})
        })
        .unwrap_or_else(|err| panic!("{err}"))
        .1;
        assert_eq!(*first, *again);

        let other_salt = race(vec![emulated(b"seed")], |device, cancel| {
            ctap::hmac_secret(device, RP_ID, &id, &[6u8; SALT_LEN], cancel, &|| {})
        })
        .unwrap_or_else(|err| panic!("{err}"))
        .1;
        assert_ne!(*first, *other_salt);
    }

    #[test]
    fn device_asks_for_a_touch() {
        let touched = AtomicBool::new(false);
        let mut device = emulated(b"seed");
        ctap::make_credential(&mut device, RP_ID, &AtomicBool::new(false), &|| {
            touched.store(true, Ordering::Relaxed);
        })
        .expect("make credential");
        assert!(touched.load(Ordering::Relaxed));
    }

    #[test]
    fn the_device_holding_the_credential_wins_the_race() {
        let salt = [1u8; SALT_LEN];
        let (id, secret) = enroll_on(b"right", &salt);
        let devices = vec![emulated(b"wrong"), emulated(b"right"), emulated(b"other")];
        let (_, answer) = race(devices, |device, cancel| {
            ctap::hmac_secret(device, RP_ID, &id, &salt, cancel, &|| {})
        })
        .unwrap_or_else(|err| panic!("{err}"));
        assert_eq!(*answer, *secret);
    }

    #[test]
    fn a_device_without_the_credential_is_reported() {
        let (id, _) = enroll_on(b"right", &[1u8; SALT_LEN]);
        let err = race(vec![emulated(b"wrong")], |device, cancel| {
            ctap::hmac_secret(device, RP_ID, &id, &[1u8; SALT_LEN], cancel, &|| {})
        })
        .err()
        .map(|err| err.to_string())
        .unwrap_or_default();
        assert!(err.contains("holds this database's credential"), "{err}");
    }

    #[test]
    fn the_emulator_supports_hmac_secret() {
        assert!(matches!(
            ctap::supports_hmac_secret(&mut emulated(b"seed")),
            Ok(true)
        ));
    }
}
