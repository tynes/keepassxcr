//! Use a YubiKey plugged into another machine, over a forwarded Unix socket.
//!
//! `keepassxcr yubikey serve` runs where the key is plugged in and answers
//! challenges on a socket only its user can reach. `ssh -R` carries that
//! socket to a server, where keepassxcr sends its challenges through it
//! instead of looking for a key on USB. Only the padded challenge and the
//! 20-byte answer cross the connection; the touch prompt shows on both ends.
//!
//! The same socket carries FIDO2 hmac-secret requests for FIDO2-protected
//! key files (see [`crate::fido2`]); the PIN, when needed, is typed on the
//! machine running `serve`.
//!
//! YubiKey request: version 1 (1), slot (1), serial big-endian (4, 0 = any
//! key), padded challenge (64). Replies: any number of `TOUCH` bytes, then
//! `OK` followed by the 20-byte answer, or `ERROR` followed by a big-endian
//! u16 length and a UTF-8 message.
//!
//! FIDO2 request: version 2 (1), big-endian u32 length, then CBOR
//! `{1: rp_id, 2: [[credential_id, salt, uv], ...]}`. Replies: `TOUCH` and
//! `PIN` notices, then `OK` followed by the index of the credential that
//! answered (1) and the 32-byte secret, or `ERROR` as above.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::warn;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::fido2::cbor::Value;
use crate::fido2::{PinPrompt, SecretRequest};
use crate::util::unix::{current_uid, peer_uid};
use crate::yubikey::otp::yubikey_error;
use crate::yubikey::{
    CHALLENGE_LEN, RESPONSE_LEN, Response, TOUCH_PROMPT, YubiKeySlot, local_challenge,
};

/// Environment variable naming the socket to send challenges to.
pub const SOCKET_ENV: &str = "KEEPASSXCR_YUBIKEY_SOCKET";
/// Socket used when [`SOCKET_ENV`] is unset, relative to the home directory.
const DEFAULT_SOCKET: &str = ".keepassxcr-yubikey.sock";

const VERSION: u8 = 1;
const VERSION_FIDO2: u8 = 2;
const REQUEST_LEN: usize = 2 + 4 + CHALLENGE_LEN;
/// Largest FIDO2 request body accepted.
const MAX_FIDO2_REQUEST: u32 = 64 * 1024;
const MSG_OK: u8 = 0;
const MSG_ERROR: u8 = 1;
const MSG_TOUCH: u8 = 2;
const MSG_PIN: u8 = 3;

/// How long a client waits for an answer; covers the key's own touch timeout.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the server waits for a connected client's request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The socket `serve` listens on and clients look for by default:
/// `$KEEPASSXCR_YUBIKEY_SOCKET`, or `~/.keepassxcr-yubikey.sock`.
///
/// # Errors
///
/// Fails when neither the variable nor `HOME` is set.
pub fn socket_path() -> AppResult<PathBuf> {
    if let Some(path) = explicit_socket() {
        return Ok(PathBuf::from(path));
    }
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(|home| PathBuf::from(home).join(DEFAULT_SOCKET))
        .ok_or_else(|| {
            AppError::InvalidInput(format!("set {SOCKET_ENV} or HOME to choose a socket"))
        })
}

fn explicit_socket() -> Option<OsString> {
    env::var_os(SOCKET_ENV).filter(|path| !path.is_empty())
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
    match open_forwarded("YubiKey", yubikey_error)? {
        Some(stream) => request(stream, slot, padded).map(Some),
        None => Ok(None),
    }
}

/// Get a FIDO2 hmac-secret through the forwarded socket, if one answers.
///
/// Returns `None` when there is no socket at the default path, so the caller
/// falls back to USB. A socket named in [`SOCKET_ENV`] must answer.
///
/// # Errors
///
/// Fails when the named socket is unreachable or the remote key fails.
pub fn fido2_secret(
    rp_id: &str,
    requests: &[SecretRequest<'_>],
) -> AppResult<Option<(usize, Zeroizing<[u8; 32]>)>> {
    match open_forwarded("security key", AppError::Fido2)? {
        Some(stream) => fido2_request(stream, rp_id, requests).map(Some),
        None => Ok(None),
    }
}

/// Connect to the forwarded socket: `None` when the default one is absent.
fn open_forwarded(what: &str, error: fn(String) -> AppError) -> AppResult<Option<UnixStream>> {
    let explicit = explicit_socket().is_some();
    let Ok(path) = socket_path() else {
        return Ok(None);
    };
    let stream = match connect(&path) {
        Ok(stream) => stream,
        Err(err) if explicit => {
            return Err(error(format!(
                "cannot reach the forwarded {what} at {} ({err}); is 'keepassxcr yubikey serve' \
                 running and the socket forwarded?",
                path.display()
            )));
        }
        Err(err) => {
            if err.kind() != io::ErrorKind::NotFound {
                warn!("ignoring key socket {}: {err}", path.display());
            }
            return Ok(None);
        }
    };
    Ok(Some(stream))
}

/// Connect to a socket only if it is a socket owned by this user, so another
/// user cannot plant one and collect challenges.
fn connect(path: &Path) -> io::Result<UnixStream> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket() || meta.uid() != current_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a socket owned by you",
        ));
    }
    UnixStream::connect(path)
}

fn request(
    mut stream: UnixStream,
    slot: YubiKeySlot,
    padded: &[u8; CHALLENGE_LEN],
) -> AppResult<Response> {
    let forward_error = |err: io::Error| yubikey_error(format!("forwarded YubiKey: {err}"));
    stream
        .set_read_timeout(Some(ANSWER_TIMEOUT))
        .map_err(forward_error)?;
    let mut message = [0u8; REQUEST_LEN];
    message[0] = VERSION;
    message[1] = slot.slot;
    message[2..6].copy_from_slice(&slot.serial.unwrap_or(0).to_be_bytes());
    message[6..].copy_from_slice(padded);
    stream.write_all(&message).map_err(forward_error)?;

    let mut prompted = false;
    loop {
        let mut kind = [0u8; 1];
        stream.read_exact(&mut kind).map_err(forward_error)?;
        match kind[0] {
            MSG_TOUCH if !prompted => {
                prompted = true;
                eprintln!("{TOUCH_PROMPT} (on the machine running 'keepassxcr yubikey serve')\n");
            }
            MSG_TOUCH => {}
            MSG_OK => {
                let mut response = Zeroizing::new([0u8; RESPONSE_LEN]);
                stream
                    .read_exact(&mut response[..])
                    .map_err(forward_error)?;
                return Ok(response);
            }
            MSG_ERROR => {
                let text = read_error(&mut stream).map_err(forward_error)?;
                return Err(yubikey_error(format!("forwarded YubiKey: {text}")));
            }
            other => {
                return Err(yubikey_error(format!(
                    "forwarded YubiKey sent unknown message {other}"
                )));
            }
        }
    }
}

fn fido2_request(
    mut stream: UnixStream,
    rp_id: &str,
    requests: &[SecretRequest<'_>],
) -> AppResult<(usize, Zeroizing<[u8; 32]>)> {
    let forward_error =
        |err: io::Error| crate::fido2::fido2_error(format!("forwarded security key: {err}"));
    // The PIN is typed on the other end, so allow time for it.
    stream
        .set_read_timeout(Some(ANSWER_TIMEOUT * 2))
        .map_err(forward_error)?;
    let body = Value::int_map(vec![
        (1, Value::text(rp_id)),
        (
            2,
            Value::Array(
                requests
                    .iter()
                    .map(|r| {
                        Value::Array(vec![
                            Value::Bytes(r.credential_id.to_vec()),
                            Value::Bytes(r.salt.to_vec()),
                            Value::Bool(r.uv),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
    .encode();
    let mut message = vec![VERSION_FIDO2];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes());
    message.extend_from_slice(&body);
    stream.write_all(&message).map_err(forward_error)?;

    let (mut touched, mut pinned) = (false, false);
    loop {
        let mut kind = [0u8; 1];
        stream.read_exact(&mut kind).map_err(forward_error)?;
        match kind[0] {
            MSG_TOUCH if !touched => {
                touched = true;
                eprintln!(
                    "{} (on the machine running 'keepassxcr yubikey serve')",
                    crate::fido2::TOUCH_PROMPT
                );
            }
            MSG_PIN if !pinned => {
                pinned = true;
                eprintln!(
                    "Enter the security key's PIN on the machine running 'keepassxcr yubikey serve'."
                );
            }
            MSG_TOUCH | MSG_PIN => {}
            MSG_OK => {
                let mut answer = Zeroizing::new([0u8; 33]);
                stream.read_exact(&mut answer[..]).map_err(forward_error)?;
                let index = usize::from(answer[0]);
                if index >= requests.len() {
                    return Err(crate::fido2::fido2_error(
                        "forwarded security key answered for an unknown credential",
                    ));
                }
                let mut secret = Zeroizing::new([0u8; 32]);
                secret.copy_from_slice(&answer[1..]);
                return Ok((index, secret));
            }
            MSG_ERROR => {
                let text = read_error(&mut stream).map_err(forward_error)?;
                return Err(crate::fido2::fido2_error(format!(
                    "forwarded security key: {text}"
                )));
            }
            other => {
                return Err(crate::fido2::fido2_error(format!(
                    "forwarded security key sent unknown message {other}"
                )));
            }
        }
    }
}

fn read_error(stream: &mut UnixStream) -> io::Result<String> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut text = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut text)?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

/// Answer YubiKey challenges and FIDO2 requests for the keys plugged into
/// this machine until killed. `pin` asks for a security key's PIN here.
///
/// # Errors
///
/// Fails when the socket cannot be created, or another `serve` already owns it.
pub fn serve(path: &Path, pin: PinPrompt<'_>) -> AppResult<()> {
    let listener = bind(path)?;
    println!(
        "Answering YubiKey and security key requests on {}",
        path.display()
    );
    println!(
        "Forward it with: ssh -R <remote path>:{} <host>",
        path.display()
    );
    for stream in listener.incoming().flatten() {
        match answer(stream, &mut *pin) {
            // A client that connected and left, e.g. another `serve` probing.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(err) => warn!("YubiKey request failed: {err}"),
            Ok(()) => {}
        }
    }
    Ok(())
}

fn bind(path: &Path) -> AppResult<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(AppError::InvalidInput(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        if UnixStream::connect(path).is_ok() {
            return Err(AppError::InvalidInput(format!(
                "another 'keepassxcr yubikey serve' is already answering on {}",
                path.display()
            )));
        }
        // Left over from a server that was killed.
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn answer(mut stream: UnixStream, pin: PinPrompt<'_>) -> io::Result<()> {
    if peer_uid(&stream)? != current_uid() {
        return Ok(());
    }
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    let mut version = [0u8; 1];
    stream.read_exact(&mut version)?;
    if version[0] == VERSION_FIDO2 {
        return answer_fido2(stream, pin);
    }
    let mut message = [0u8; REQUEST_LEN];
    message[0] = version[0];
    stream.read_exact(&mut message[1..])?;
    let result = parse_request(&message).and_then(|(slot, padded)| {
        let mut notify = stream.try_clone()?;
        local_challenge(slot, &padded, &mut || {
            eprintln!("{TOUCH_PROMPT}");
            let _ = notify.write_all(&[MSG_TOUCH]);
        })
    });
    match result {
        Ok(response) => {
            let mut reply = Zeroizing::new([0u8; 1 + RESPONSE_LEN]);
            reply[0] = MSG_OK;
            reply[1..].copy_from_slice(&response[..]);
            stream.write_all(&reply[..])
        }
        Err(err) => send_error(&mut stream, err),
    }
}

fn send_error(stream: &mut UnixStream, err: AppError) -> io::Result<()> {
    let text = match err {
        AppError::YubiKey(message)
        | AppError::Fido2(message)
        | AppError::Fido2Status(_, message) => message,
        other => other.to_string(),
    };
    let text = &text.as_bytes()[..text.len().min(usize::from(u16::MAX))];
    let mut reply = vec![MSG_ERROR];
    reply.extend_from_slice(&(text.len() as u16).to_be_bytes());
    reply.extend_from_slice(text);
    stream.write_all(&reply)
}

fn answer_fido2(mut stream: UnixStream, pin: PinPrompt<'_>) -> io::Result<()> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len > MAX_FIDO2_REQUEST {
        return send_error(&mut stream, crate::fido2::fido2_error("request too large"));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body)?;
    let parsed = match parse_fido2_request(&body) {
        Ok(parsed) => parsed,
        Err(err) => return send_error(&mut stream, err),
    };
    let (rp_id, entries) = parsed;
    let requests: Vec<SecretRequest<'_>> = entries
        .iter()
        .map(|(id, salt, uv)| SecretRequest {
            credential_id: id,
            salt,
            uv: *uv,
        })
        .collect();
    let mut touch_notify = stream.try_clone()?;
    let mut pin_notify = stream.try_clone()?;
    let mut ask_pin = || {
        let _ = pin_notify.write_all(&[MSG_PIN]);
        pin()
    };
    let result = crate::fido2::local_secret(&rp_id, &requests, &mut ask_pin, &mut || {
        eprintln!("{}", crate::fido2::TOUCH_PROMPT);
        let _ = touch_notify.write_all(&[MSG_TOUCH]);
    });
    match result {
        Ok((index, secret)) => {
            let mut reply = Zeroizing::new([0u8; 34]);
            reply[0] = MSG_OK;
            reply[1] = index as u8;
            reply[2..].copy_from_slice(&secret[..]);
            stream.write_all(&reply[..])
        }
        Err(err) => send_error(&mut stream, err),
    }
}

type Fido2Entries = Vec<(Vec<u8>, [u8; 32], bool)>;

fn parse_fido2_request(body: &[u8]) -> AppResult<(String, Fido2Entries)> {
    let malformed = || crate::fido2::fido2_error("malformed forwarded request");
    let value = Value::decode(body)?;
    let rp_id = value
        .get_int(1)
        .and_then(Value::as_text)
        .ok_or_else(malformed)?
        .to_string();
    let items = value
        .get_int(2)
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    if items.is_empty() || items.len() > 255 {
        return Err(malformed());
    }
    let entries = items
        .iter()
        .map(|item| {
            let fields = item
                .as_array()
                .filter(|f| f.len() == 3)
                .ok_or_else(malformed)?;
            let id = fields[0].as_bytes().ok_or_else(malformed)?.to_vec();
            let salt: [u8; 32] = fields[1]
                .as_bytes()
                .and_then(|s| s.try_into().ok())
                .ok_or_else(malformed)?;
            let uv = fields[2].as_bool().ok_or_else(malformed)?;
            Ok((id, salt, uv))
        })
        .collect::<AppResult<_>>()?;
    Ok((rp_id, entries))
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
