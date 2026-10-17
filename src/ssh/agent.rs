//! Client side of the ssh-agent protocol (draft-miller-ssh-agent): add,
//! remove and list identities on the agent at `SSH_AUTH_SOCK`.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
#[cfg(feature = "cli")]
use crate::ssh::key::SshKey;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
#[cfg(feature = "cli")]
const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
#[cfg(feature = "cli")]
const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
#[cfg(feature = "cli")]
const SSH_AGENT_CONSTRAIN_LIFETIME: u8 = 1;
#[cfg(feature = "cli")]
const SSH_AGENT_CONSTRAIN_CONFIRM: u8 = 2;
#[cfg(feature = "cli")]
const SSH_AGENT_CONSTRAIN_EXTENSION: u8 = 255;

/// Largest reply accepted, as in OpenSSH.
const MAX_REPLY: u32 = 256 * 1024;
/// How long to wait for the agent. A confirm prompt is answered later, at
/// signing time, so adding never waits on a person.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Constraints on an added key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Constraints {
    /// ssh-agent forgets the key after this many seconds.
    pub lifetime_secs: Option<u32>,
    /// ssh-agent asks (through ssh-askpass) before each use.
    pub confirm: bool,
}

/// A connection target: one ssh-agent socket.
#[derive(Debug, Clone)]
pub struct SshAgent {
    socket: PathBuf,
}

impl SshAgent {
    /// The agent at `SSH_AUTH_SOCK`.
    pub fn from_env() -> AppResult<Self> {
        match std::env::var_os("SSH_AUTH_SOCK").filter(|value| !value.is_empty()) {
            Some(socket) => Ok(Self::at(PathBuf::from(socket))),
            None => Err(AppError::InvalidInput(
                "no ssh-agent: SSH_AUTH_SOCK is not set (start one with 'eval \"$(ssh-agent)\"')"
                    .to_string(),
            )),
        }
    }

    /// The agent at `socket`.
    pub fn at(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// Socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Add `key`, which must have been loaded with its private half.
    #[cfg(feature = "cli")]
    pub fn add(&self, key: &SshKey, constraints: Constraints) -> AppResult<()> {
        let private = key
            .private()
            .ok_or_else(|| AppError::InvalidInput("the private key was not decrypted".into()))?;
        let constrained =
            constraints.lifetime_secs.is_some() || constraints.confirm || key.is_security_key();
        let mut message = Zeroizing::new(Vec::with_capacity(private.len() + 256));
        message.push(if constrained {
            SSH_AGENTC_ADD_ID_CONSTRAINED
        } else {
            SSH_AGENTC_ADD_IDENTITY
        });
        message.extend_from_slice(private);
        put_string(&mut message, key.comment.as_bytes());
        if let Some(lifetime) = constraints.lifetime_secs {
            message.push(SSH_AGENT_CONSTRAIN_LIFETIME);
            message.extend_from_slice(&lifetime.to_be_bytes());
        }
        if constraints.confirm {
            message.push(SSH_AGENT_CONSTRAIN_CONFIRM);
        }
        if key.is_security_key() {
            // OpenSSH's built-in FIDO support, as KeePassXC asks for by default.
            message.push(SSH_AGENT_CONSTRAIN_EXTENSION);
            put_string(&mut message, b"sk-provider@openssh.com");
            put_string(&mut message, b"internal");
        }
        let reply = self.request(&message)?;
        match reply.first() {
            Some(&SSH_AGENT_SUCCESS) => Ok(()),
            _ => {
                let mut reasons = Vec::new();
                if constraints.lifetime_secs.is_some() {
                    reasons.push("the agent may not support a lifetime limit");
                }
                if constraints.confirm {
                    reasons.push("the agent may not support confirmation (it needs ssh-askpass)");
                }
                if key.is_security_key() {
                    reasons.push("the agent may not support security keys");
                }
                let reasons = if reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", reasons.join("; "))
                };
                Err(AppError::InvalidInput(format!(
                    "ssh-agent refused the key{reasons}"
                )))
            }
        }
    }

    /// Remove the key with this public blob. Returns false when the agent did
    /// not have it.
    pub fn remove(&self, public_blob: &[u8]) -> AppResult<bool> {
        let mut message = vec![SSH_AGENTC_REMOVE_IDENTITY];
        put_string(&mut message, public_blob);
        let reply = self.request(&message)?;
        Ok(reply.first() == Some(&SSH_AGENT_SUCCESS))
    }

    /// Public blobs of the keys the agent holds.
    pub fn identities(&self) -> AppResult<Vec<Vec<u8>>> {
        let reply = self.request(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let malformed = || AppError::Format("malformed ssh-agent identities reply".to_string());
        let mut rest = match reply.split_first() {
            Some((&SSH_AGENT_IDENTITIES_ANSWER, rest)) => rest,
            Some((&SSH_AGENT_FAILURE, _)) => {
                return Err(AppError::InvalidInput(
                    "ssh-agent refused to list keys".to_string(),
                ));
            }
            _ => return Err(malformed()),
        };
        let count = take_u32(&mut rest).ok_or_else(malformed)?;
        let mut blobs = Vec::new();
        for _ in 0..count {
            let blob = take_string(&mut rest).ok_or_else(malformed)?;
            take_string(&mut rest).ok_or_else(malformed)?; // comment
            blobs.push(blob.to_vec());
        }
        Ok(blobs)
    }

    #[cfg(not(unix))]
    fn request(&self, _message: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        Err(AppError::InvalidInput(
            "ssh-agent support is only available on Unix".to_string(),
        ))
    }

    #[cfg(unix)]
    fn request(&self, message: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        let unreachable = |err: std::io::Error| {
            AppError::InvalidInput(format!(
                "cannot reach ssh-agent at {}: {err}",
                self.socket.display()
            ))
        };
        let mut stream = UnixStream::connect(&self.socket).map_err(unreachable)?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(unreachable)?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(unreachable)?;
        let length = u32::try_from(message.len())
            .map_err(|_| AppError::InvalidInput("ssh-agent request too large".to_string()))?;
        let mut framed = Zeroizing::new(Vec::with_capacity(message.len() + 4));
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(message);
        stream.write_all(&framed).map_err(unreachable)?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).map_err(unreachable)?;
        let length = u32::from_be_bytes(header);
        if length == 0 || length > MAX_REPLY {
            return Err(AppError::Format(format!(
                "ssh-agent sent a reply of {length} bytes"
            )));
        }
        let mut reply = Zeroizing::new(vec![0u8; length as usize]);
        stream.read_exact(&mut reply).map_err(unreachable)?;
        Ok(reply)
    }
}

fn put_string(buffer: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.extend_from_slice(value);
}

fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (head, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*head))
}

fn take_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = take_u32(rest)? as usize;
    if rest.len() < length {
        return None;
    }
    let (value, tail) = rest.split_at(length);
    *rest = tail;
    Some(value)
}
