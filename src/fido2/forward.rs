//! Use a FIDO2 device plugged into another machine, over a forwarded Unix socket.
//!
//! `keepassxcr fido2 serve` runs where the device is plugged in and answers
//! requests on a socket only its user can reach; `ssh -R` carries it to a
//! server, where keepassxcr sends its requests through it instead of USB.
//! The device still asks for confirmation on every request.
//!
//! Request: version (1), operation (1), relying party id length (1) and
//! bytes, salt (32), then for an assertion the credential id's big-endian
//! length (2) and bytes. The reply framing is shared with `yubikey serve`
//! (see `util::forward`); `OK` is followed by the 32-byte secret and, for an
//! enrollment, the new credential id's length (2) and bytes.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::fido2::{Fido2Config, SALT_LEN, Secret, TOUCH_PROMPT, local_enroll, local_secret};
use crate::util::forward::{Forwarding, reply};

/// Environment variable naming the socket to send requests to.
pub const SOCKET_ENV: &str = "KEEPASSXCR_FIDO2_SOCKET";

const FORWARDING: Forwarding = Forwarding {
    env: SOCKET_ENV,
    default_socket: ".keepassxcr-fido2.sock",
    device: "FIDO2 device",
    command: "fido2 serve",
    touch_prompt: TOUCH_PROMPT,
    // The device's own confirmation timeout, plus a margin.
    answer_timeout: Duration::from_secs(150),
    error: AppError::Fido2,
};

const VERSION: u8 = 1;
const OP_SECRET: u8 = 1;
const OP_ENROLL: u8 = 2;

/// The socket `serve` listens on and clients look for by default:
/// `$KEEPASSXCR_FIDO2_SOCKET`, or `~/.keepassxcr-fido2.sock`.
///
/// # Errors
///
/// Fails when neither the variable nor `HOME` is set.
pub fn socket_path() -> AppResult<PathBuf> {
    FORWARDING.socket_path()
}

/// Ask the forwarded device for a database's secret, if one is reachable.
///
/// # Errors
///
/// Fails when the named socket is unreachable or the remote device fails.
pub(super) fn secret(config: &Fido2Config) -> AppResult<Option<Secret>> {
    let Some(stream) = FORWARDING.connect()? else {
        return Ok(None);
    };
    let mut message = request(OP_SECRET, &config.rp_id, &config.salt)?;
    let len = u16::try_from(config.credential_id.len())
        .map_err(|_| AppError::Fido2("credential id is too long".to_string()))?;
    message.extend_from_slice(&len.to_be_bytes());
    message.extend_from_slice(&config.credential_id);
    FORWARDING.request(stream, &message, read_secret).map(Some)
}

/// Enroll the forwarded device, if one is reachable: the credential id and secret.
///
/// # Errors
///
/// Fails when the named socket is unreachable or the remote device fails.
pub(super) fn enroll(rp_id: &str, salt: &[u8; SALT_LEN]) -> AppResult<Option<(Vec<u8>, Secret)>> {
    let Some(stream) = FORWARDING.connect()? else {
        return Ok(None);
    };
    let message = request(OP_ENROLL, rp_id, salt)?;
    FORWARDING
        .request(stream, &message, |stream| {
            let secret = read_secret(stream)?;
            let credential_id = read_prefixed(stream)?;
            Ok((credential_id, secret))
        })
        .map(Some)
}

fn request(op: u8, rp_id: &str, salt: &[u8; SALT_LEN]) -> AppResult<Vec<u8>> {
    let rp_len = u8::try_from(rp_id.len())
        .map_err(|_| AppError::Fido2("relying party id is too long".to_string()))?;
    let mut message = vec![VERSION, op, rp_len];
    message.extend_from_slice(rp_id.as_bytes());
    message.extend_from_slice(salt);
    Ok(message)
}

fn read_secret(stream: &mut UnixStream) -> io::Result<Secret> {
    let mut secret = Zeroizing::new([0u8; SALT_LEN]);
    stream.read_exact(&mut secret[..])?;
    Ok(secret)
}

/// Bytes after a big-endian u16 length.
fn read_prefixed(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut bytes = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Answer requests for the FIDO2 devices plugged into this machine until killed.
///
/// # Errors
///
/// Fails when the socket cannot be created, or another `serve` already owns it.
pub fn serve(path: &Path) -> AppResult<()> {
    FORWARDING.serve(path, |stream, touch| {
        let mut head = [0u8; 3];
        stream.read_exact(&mut head)?;
        let [version, op, rp_len] = head;
        let mut rp_id = vec![0u8; usize::from(rp_len)];
        stream.read_exact(&mut rp_id)?;
        let mut salt = [0u8; SALT_LEN];
        stream.read_exact(&mut salt)?;
        let credential_id = match op {
            OP_SECRET => Some(read_prefixed(stream)?),
            _ => None,
        };

        let rp_id = String::from_utf8(rp_id)
            .map_err(|_| AppError::Fido2("relying party id is not UTF-8".to_string()));
        let answer = rp_id.and_then(|rp_id| match (version, op, credential_id) {
            (VERSION, OP_SECRET, Some(id)) => local_secret(&rp_id, &id, &salt, touch)
                .map(|secret| Zeroizing::new(secret.to_vec())),
            (VERSION, OP_ENROLL, _) => local_enroll(&rp_id, &salt, touch).map(|(id, secret)| {
                let mut answer = Zeroizing::new(secret.to_vec());
                // At most a few hundred bytes from the device; checked before sending.
                answer
                    .extend_from_slice(&(id.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
                answer.extend_from_slice(&id);
                answer
            }),
            (VERSION, op, _) => Err(AppError::Fido2(format!("unknown operation {op}"))),
            (version, ..) => Err(AppError::Fido2(format!(
                "client speaks protocol version {version}, this server {VERSION}; update \
                 keepassxcr on both ends"
            ))),
        });
        match answer {
            Ok(answer) => reply(stream, Ok(&answer)),
            Err(err) => reply(stream, Err(err)),
        }
    })
}
