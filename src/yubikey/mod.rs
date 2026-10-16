//! YubiKey HMAC-SHA1 challenge-response, compatible with KeePassXC.
//!
//! KeePassXC pads the 32-byte challenge to 64 bytes with PKCS#7 before sending
//! it, on USB and on PC/SC alike, and keepassxcr sends the very same bytes so
//! every slot configuration answers the same. The answer comes from, in order:
//! a key forwarded over a socket (see [`forward`]), the software key of test
//! builds, or a key plugged in over USB.

use std::fmt;
use std::io::{self, Write};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

#[cfg(any(test, feature = "software-yubikey"))]
mod emulator;
#[cfg(unix)]
pub mod forward;
mod hid;
mod otp;

/// Bytes sent to the key, after padding.
pub const CHALLENGE_LEN: usize = 64;
/// Bytes of an HMAC-SHA1 answer.
pub const RESPONSE_LEN: usize = 20;

/// An HMAC-SHA1 answer, wiped when dropped.
pub type Response = Zeroizing<[u8; RESPONSE_LEN]>;

/// Shown when the key waits for a touch, worded like keepassxc-cli.
const TOUCH_PROMPT: &str = "Please present or touch your YubiKey to continue.";

/// A YubiKey slot and, optionally, which key: `2` or `2:7370001`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct YubiKeySlot {
    /// Slot 1 or 2.
    pub slot: u8,
    /// Serial number of the key, when more than one may be plugged in.
    pub serial: Option<u32>,
}

impl FromStr for YubiKeySlot {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (slot, serial) = match value.split_once(':') {
            Some((slot, serial)) => (slot, Some(serial)),
            None => (value, None),
        };
        let slot = match slot {
            "1" => 1,
            "2" => 2,
            _ => return Err(format!("invalid YubiKey slot '{slot}' (use 1 or 2)")),
        };
        let serial = serial
            .map(|serial| {
                serial
                    .parse()
                    .map_err(|_| format!("invalid YubiKey serial '{serial}'"))
            })
            .transpose()?;
        Ok(Self { slot, serial })
    }
}

impl fmt::Display for YubiKeySlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.serial {
            Some(serial) => write!(f, "{}:{serial}", self.slot),
            None => write!(f, "{}", self.slot),
        }
    }
}

/// Pad a challenge to 64 bytes like KeePassXC: PKCS#7, so a 32-byte seed is
/// followed by 32 bytes of `0x20`.
///
/// # Errors
///
/// Fails for challenges longer than 64 bytes.
pub fn pad_challenge(challenge: &[u8]) -> AppResult<[u8; CHALLENGE_LEN]> {
    let pad = CHALLENGE_LEN
        .checked_sub(challenge.len())
        .ok_or_else(|| AppError::YubiKey("challenge is longer than 64 bytes".to_string()))?;
    let mut padded = [pad as u8; CHALLENGE_LEN];
    padded[..challenge.len()].copy_from_slice(challenge);
    Ok(padded)
}

/// Ask the YubiKey in `slot` for the HMAC-SHA1 of `challenge`, using a
/// forwarded key when one is reachable.
///
/// # Errors
///
/// Fails when no key answers or the challenge fails.
pub fn challenge(slot: YubiKeySlot, challenge: &[u8]) -> AppResult<Response> {
    let padded = pad_challenge(challenge)?;
    #[cfg(unix)]
    if let Some(response) = forward::challenge(slot, &padded)? {
        return Ok(response);
    }
    local_challenge(slot, &padded, &mut print_touch_prompt)
}

/// Challenge a key on this machine: the software key of test builds when
/// configured, otherwise USB.
fn local_challenge(
    slot: YubiKeySlot,
    padded: &[u8; CHALLENGE_LEN],
    on_touch: &mut dyn FnMut(),
) -> AppResult<Response> {
    #[cfg(feature = "software-yubikey")]
    if let Some(key) = emulator::EmulatedKey::from_env()? {
        return otp::Otp::without_delay(key).hmac_sha1(slot.slot, padded, on_touch);
    }
    hid::challenge(slot, padded, on_touch)
}

fn print_touch_prompt() {
    let mut stderr = io::stderr();
    let _ = writeln!(stderr, "{TOUCH_PROMPT}\n");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_slot_and_serial() {
        assert_eq!(
            "2".parse(),
            Ok(YubiKeySlot {
                slot: 2,
                serial: None
            })
        );
        assert_eq!(
            "1:7370001".parse(),
            Ok(YubiKeySlot {
                slot: 1,
                serial: Some(7_370_001)
            })
        );
        assert!("3".parse::<YubiKeySlot>().is_err());
        assert!("2:abc".parse::<YubiKeySlot>().is_err());
        assert_eq!(
            "1:7370001"
                .parse::<YubiKeySlot>()
                .map(|slot| slot.to_string()),
            Ok("1:7370001".to_string())
        );
    }

    #[test]
    fn pads_like_keepassxc() {
        let padded = pad_challenge(&[0xaa; 32]).expect("short");
        assert_eq!(&padded[..32], &[0xaa; 32]);
        assert_eq!(&padded[32..], &[0x20; 32]);
        assert_eq!(pad_challenge(&[1; 64]).expect("full"), [1; 64]);
        assert!(pad_challenge(&[1; 65]).is_err());
    }
}
