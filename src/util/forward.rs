//! Unix-socket plumbing shared by `yubikey serve` and `fido2 serve`.
//!
//! A server runs where the device is plugged in and answers requests on a
//! socket only its user can reach; `ssh -R` carries that socket to another
//! machine. Each device type defines its own request; the replies share one
//! framing: any number of `TOUCH` bytes, then `OK` followed by the answer, or
//! `ERROR` followed by a big-endian u16 length and a UTF-8 message.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::util::unix::{current_uid, peer_uid};

const MSG_OK: u8 = 0;
const MSG_ERROR: u8 = 1;
const MSG_TOUCH: u8 = 2;

/// How long the server waits for a connected client's request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// One kind of forwarded device: where its socket lives and how it reports errors.
pub struct Forwarding {
    /// Environment variable naming the socket.
    pub env: &'static str,
    /// Socket used when `env` is unset, relative to the home directory.
    pub default_socket: &'static str,
    /// The device, as named in messages ("YubiKey").
    pub device: &'static str,
    /// The serving subcommand, as named in messages ("yubikey serve").
    pub command: &'static str,
    /// Shown when the device waits for a touch.
    pub touch_prompt: &'static str,
    /// How long a client waits for an answer; covers the device's own timeout.
    pub answer_timeout: Duration,
    /// Wraps a message in this device's error variant.
    pub error: fn(String) -> AppError,
}

impl Forwarding {
    /// The socket `serve` listens on and clients look for by default: the
    /// path in [`Self::env`], or [`Self::default_socket`] in the home directory.
    ///
    /// # Errors
    ///
    /// Fails when neither the variable nor `HOME` is set.
    pub fn socket_path(&self) -> AppResult<PathBuf> {
        if let Some(path) = self.explicit_socket() {
            return Ok(PathBuf::from(path));
        }
        env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .map(|home| PathBuf::from(home).join(self.default_socket))
            .ok_or_else(|| {
                AppError::InvalidInput(format!("set {} or HOME to choose a socket", self.env))
            })
    }

    fn explicit_socket(&self) -> Option<OsString> {
        env::var_os(self.env).filter(|path| !path.is_empty())
    }

    /// Connect to the forwarded device, if one is reachable.
    ///
    /// Returns `None` when there is no socket at the default path, so the
    /// caller falls back to USB. A socket named in [`Self::env`] must answer.
    ///
    /// # Errors
    ///
    /// Fails when the named socket is unreachable.
    pub fn connect(&self) -> AppResult<Option<UnixStream>> {
        let explicit = self.explicit_socket().is_some();
        let Ok(path) = self.socket_path() else {
            return Ok(None);
        };
        match connect(&path) {
            Ok(stream) => Ok(Some(stream)),
            Err(err) if explicit => Err((self.error)(format!(
                "cannot reach the forwarded {} at {} ({err}); is 'keepassxcr {}' running and \
                 the socket forwarded?",
                self.device,
                path.display(),
                self.command
            ))),
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    warn!("ignoring {} socket {}: {err}", self.device, path.display());
                }
                Ok(None)
            }
        }
    }

    /// Send `message` and wait for the answer, which `read_ok` reads after `OK`.
    ///
    /// # Errors
    ///
    /// Fails when the connection breaks or the remote device fails.
    pub fn request<T>(
        &self,
        mut stream: UnixStream,
        message: &[u8],
        read_ok: impl FnOnce(&mut UnixStream) -> io::Result<T>,
    ) -> AppResult<T> {
        let forward_error =
            |err: io::Error| (self.error)(format!("forwarded {}: {err}", self.device));
        stream
            .set_read_timeout(Some(self.answer_timeout))
            .map_err(forward_error)?;
        stream.write_all(message).map_err(forward_error)?;

        let mut prompted = false;
        loop {
            let mut kind = [0u8; 1];
            stream.read_exact(&mut kind).map_err(forward_error)?;
            match kind[0] {
                MSG_TOUCH if !prompted => {
                    prompted = true;
                    eprintln!(
                        "{} (on the machine running 'keepassxcr {}')\n",
                        self.touch_prompt, self.command
                    );
                }
                MSG_TOUCH => {}
                MSG_OK => return read_ok(&mut stream).map_err(forward_error),
                MSG_ERROR => {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).map_err(forward_error)?;
                    let mut text = vec![0u8; usize::from(u16::from_be_bytes(len))];
                    stream.read_exact(&mut text).map_err(forward_error)?;
                    return Err((self.error)(format!(
                        "forwarded {}: {}",
                        self.device,
                        String::from_utf8_lossy(&text)
                    )));
                }
                other => {
                    return Err((self.error)(format!(
                        "forwarded {} sent unknown message {other}",
                        self.device
                    )));
                }
            }
        }
    }

    /// Answer requests on `path` until killed. `handle` reads one request
    /// from the stream, answers it with [`reply`], and calls the touch
    /// callback it is given whenever the device waits for a touch.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot be created, or another server already owns it.
    pub fn serve(
        &self,
        path: &Path,
        mut handle: impl FnMut(&mut UnixStream, &(dyn Fn() + Sync)) -> io::Result<()>,
    ) -> AppResult<()> {
        let listener = self.bind(path)?;
        println!("Answering {} requests on {}", self.device, path.display());
        println!(
            "Forward it with: ssh -R <remote path>:{} <host>",
            path.display()
        );
        for mut stream in listener.incoming().flatten() {
            let result = (|| {
                if peer_uid(&stream)? != current_uid() {
                    return Ok(());
                }
                stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
                // A clone, so the touch callback can write while `handle` holds the stream.
                let notify = Mutex::new(stream.try_clone()?);
                let touch = || {
                    eprintln!("{}", self.touch_prompt);
                    if let Ok(mut notify) = notify.lock() {
                        let _ = notify.write_all(&[MSG_TOUCH]);
                    }
                };
                handle(&mut stream, &touch)
            })();
            match result {
                // A client that connected and left, e.g. another `serve` probing.
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {}
                Err(err) => warn!("{} request failed: {err}", self.device),
                Ok(()) => {}
            }
        }
        Ok(())
    }

    fn bind(&self, path: &Path) -> AppResult<UnixListener> {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if !meta.file_type().is_socket() {
                return Err(AppError::InvalidInput(format!(
                    "{} exists and is not a socket",
                    path.display()
                )));
            }
            if UnixStream::connect(path).is_ok() {
                return Err(AppError::InvalidInput(format!(
                    "another 'keepassxcr {}' is already answering on {}",
                    self.command,
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
}

/// Send the server's answer: `OK` and `answer`, or `ERROR` and the message.
///
/// # Errors
///
/// Fails when the client is gone.
pub fn reply(stream: &mut UnixStream, result: AppResult<&[u8]>) -> io::Result<()> {
    match result {
        Ok(answer) => {
            // One write, so a secret answer is not split over several buffers.
            let mut message = zeroize::Zeroizing::new(Vec::with_capacity(1 + answer.len()));
            message.push(MSG_OK);
            message.extend_from_slice(answer);
            stream.write_all(&message)
        }
        Err(err) => {
            let text = match err {
                AppError::YubiKey(message) | AppError::Fido2(message) => message,
                other => other.to_string(),
            };
            let text = &text.as_bytes()[..text.len().min(usize::from(u16::MAX))];
            let mut message = vec![MSG_ERROR];
            message.extend_from_slice(&(text.len() as u16).to_be_bytes());
            message.extend_from_slice(text);
            stream.write_all(&message)
        }
    }
}

/// Connect to a socket only if it is a socket owned by this user, so another
/// user cannot plant one and collect requests.
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
