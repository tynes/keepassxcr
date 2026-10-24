//! Use a YubiKey plugged into another machine, over a forwarded Unix socket.
//!
//! `keepassxcr yubikey serve` runs where the key is plugged in and answers
//! challenges on a socket only its user can reach. `ssh -R` carries that
//! socket to a server, where keepassxcr sends its challenges through it
//! instead of looking for a key on USB. Only the padded challenge and the
//! 20-byte answer cross the connection; the touch prompt shows on both ends.
//!
//! Request: version (1), slot (1), serial big-endian (4, 0 = any key),
//! padded challenge (64). The reply framing is shared with `fido2 serve`
//! (see `util::forward`); `OK` is followed by the 20-byte answer.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::util::forward::{Forwarding, reply};
use crate::yubikey::otp::yubikey_error;
use crate::yubikey::{
    CHALLENGE_LEN, RESPONSE_LEN, Response, TOUCH_PROMPT, YubiKeySlot, local_challenge,
};

/// Environment variable naming the socket to send challenges to.
pub const SOCKET_ENV: &str = "KEEPASSXCR_YUBIKEY_SOCKET";

const FORWARDING: Forwarding = Forwarding {
    env: SOCKET_ENV,
    default_socket: ".keepassxcr-yubikey.sock",
    device: "YubiKey",
    command: "yubikey serve",
    touch_prompt: TOUCH_PROMPT,
    answer_timeout: Duration::from_secs(60),
    error: AppError::YubiKey,
};

const VERSION: u8 = 1;
const REQUEST_LEN: usize = 2 + 4 + CHALLENGE_LEN;

/// The socket `serve` listens on and clients look for by default:
/// `$KEEPASSXCR_YUBIKEY_SOCKET`, or `~/.keepassxcr-yubikey.sock`.
///
/// # Errors
///
/// Fails when neither the variable nor `HOME` is set.
pub fn socket_path() -> AppResult<PathBuf> {
    FORWARDING.socket_path()
}

/// Send a padded challenge through the forwarded socket, if one answers.
///
/// Returns `None` when there is no socket at the default path, so the caller
/// falls back to USB. A socket named in [`SOCKET_ENV`] must answer.
///
/// # Errors
///
/// Fails when the named socket is unreachable or the remote key fails.
pub(super) fn challenge(
    slot: YubiKeySlot,
    padded: &[u8; CHALLENGE_LEN],
) -> AppResult<Option<Response>> {
    let Some(stream) = FORWARDING.connect()? else {
        return Ok(None);
    };
    let mut message = [0u8; REQUEST_LEN];
    message[0] = VERSION;
    message[1] = slot.slot;
    message[2..6].copy_from_slice(&slot.serial.unwrap_or(0).to_be_bytes());
    message[6..].copy_from_slice(padded);
    FORWARDING
        .request(stream, &message, |stream| {
            let mut response = Zeroizing::new([0u8; RESPONSE_LEN]);
            stream.read_exact(&mut response[..])?;
            Ok(response)
        })
        .map(Some)
}

/// Answer challenges for the key plugged into this machine until killed.
///
/// # Errors
///
/// Fails when the socket cannot be created, or another `serve` already owns it.
pub fn serve(path: &Path) -> AppResult<()> {
    FORWARDING.serve(path, |stream, touch| {
        let mut message = [0u8; REQUEST_LEN];
        stream.read_exact(&mut message)?;
        let result = parse_request(&message)
            .and_then(|(slot, padded)| local_challenge(slot, &padded, &mut || touch()));
        match result {
            Ok(response) => reply(stream, Ok(&response[..])),
            Err(err) => reply(stream, Err(err)),
        }
    })
}

fn parse_request(message: &[u8; REQUEST_LEN]) -> AppResult<(YubiKeySlot, [u8; CHALLENGE_LEN])> {
    if message[0] != VERSION {
        return Err(yubikey_error(format!(
            "client speaks protocol version {}, this server {VERSION}; update keepassxcr on both ends",
            message[0]
        )));
    }
    if !matches!(message[1], 1 | 2) {
        return Err(yubikey_error(format!("invalid slot {}", message[1])));
    }
    let serial = u32::from_be_bytes([message[2], message[3], message[4], message[5]]);
    let slot = YubiKeySlot {
        slot: message[1],
        serial: (serial != 0).then_some(serial),
    };
    let mut padded = [0u8; CHALLENGE_LEN];
    padded.copy_from_slice(&message[6..]);
    Ok((slot, padded))
}
