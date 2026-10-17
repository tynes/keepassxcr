//! Command side: find, start, query and stop agents.

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use tracing::warn;
use zeroize::Zeroizing;

use crate::agent::wire::{self, Location, Request, Response, Startup};
use crate::agent::{AgentKey, AgentStatus, DbState};
use crate::crypto::KdfConfig;
use crate::error::{AppError, AppResult};
use crate::yubikey::YubiKeySlot;

/// How long a command waits for the agent. Covers a slow KDF on a busy agent.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Credentials from a running agent for `database`.
///
/// Returns `None` when no agent was ever started or it was locked explicitly,
/// so the caller prompts as usual. Returns [`AppError::Locked`] when the agent
/// timed out, so scripts fail instead of stopping at a password prompt.
pub fn credentials_for(database: &Path) -> AppResult<Option<AgentKey>> {
    let location = match Location::for_database(database) {
        Ok(location) => location,
        Err(AppError::InvalidInput(message)) => {
            warn!("ignoring unlock agent: {message}");
            return Ok(None);
        }
        // A missing database is reported by the read that follows.
        Err(_) => return Ok(None),
    };
    match location_state(&location) {
        DbState::Unlocked(status) => Ok(Some(AgentKey {
            socket: location.socket,
            database: location.database,
            yubikey: status.yubikey,
        })),
        DbState::Expired(marker) => Err(marker.to_error(database)),
        DbState::Locked => Ok(None),
    }
}

/// Unlock state of one database.
pub fn state(database: &Path) -> AppResult<DbState> {
    Ok(location_state(&Location::for_database(database)?))
}

/// Unlock state of every database with a running or expired agent.
pub fn status_all() -> AppResult<Vec<DbState>> {
    let mut states = Vec::new();
    for stem in wire::all_locations()? {
        let socket = stem.with_extension("sock");
        let marker = stem.with_extension("expired");
        if let Some(status) = query_status(&socket, None) {
            states.push(DbState::Unlocked(status));
        } else if let Some(marker) = fs::read(&marker)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
        {
            states.push(DbState::Expired(marker));
        }
    }
    Ok(states)
}

/// Start an agent holding `key` (the joined password and key-file
/// components) and the YubiKey slot for `database`.
///
/// An agent that is already running is left as it is.
pub fn unlock(
    database: &Path,
    key: &[u8],
    yubikey: Option<YubiKeySlot>,
    idle: Duration,
    max: Duration,
) -> AppResult<AgentStatus> {
    let location = Location::for_database(database)?;
    if let DbState::Unlocked(status) = location_state(&location) {
        return Ok(status);
    }

    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("__agent")
        .arg(&location.database)
        .arg("--idle-secs")
        .arg(idle.as_secs().to_string())
        .arg("--max-secs")
        .arg(max.as_secs().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe and touches no parent state. A new
    // session detaches the agent from the terminal, so Ctrl-C and closing the
    // terminal do not reach it.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;

    let mut stdin = child.stdin.take().expect("stdin is piped");
    let startup = Startup {
        key: Zeroizing::new(hex::encode(key)),
        yubikey,
    };
    let mut key_line = Zeroizing::new(serde_json::to_string(&startup).map_err(io::Error::from)?);
    drop(Zeroizing::new(startup.key));
    key_line.push('\n');
    stdin.write_all(key_line.as_bytes())?;
    drop(stdin);

    let mut reply = String::new();
    BufReader::new(child.stdout.take().expect("stdout is piped")).read_line(&mut reply)?;
    let reply = reply.trim_end();
    if reply != "ready" {
        let _ = child.wait();
        let reason = reply
            .strip_prefix("error: ")
            .unwrap_or("it exited unexpectedly");
        return Err(AppError::InvalidInput(format!(
            "agent failed to start: {reason}"
        )));
    }

    let status = query_status(&location.socket, Some(&location.database))
        .ok_or_else(|| AppError::InvalidInput("agent started but does not answer".to_string()))?;
    Ok(status)
}

/// Stop the agent for `database`, or every agent when `None`.
///
/// Also clears expiry markers, so commands go back to prompting. Returns the
/// databases whose agents were running.
pub fn lock(database: Option<&Path>) -> AppResult<Vec<PathBuf>> {
    let stems = match database {
        Some(database) => vec![Location::for_database(database)?.socket.with_extension("")],
        None => wire::all_locations()?,
    };
    let mut locked = Vec::new();
    for stem in stems {
        let socket = stem.with_extension("sock");
        if let Ok(response) = query(&socket, &Request::Lock) {
            locked.extend(response.database);
        }
        let _ = fs::remove_file(stem.with_extension("expired"));
    }
    Ok(locked)
}

/// Ask the agent to run `kdf` over its composite key.
pub(super) fn transform(
    key: &AgentKey,
    kdf: &KdfConfig,
    challenge_response: Option<&[u8; 32]>,
) -> AppResult<Zeroizing<Vec<u8>>> {
    let response = ask(
        key,
        &Request::Transform {
            kdf: kdf.clone(),
            challenge_response: challenge_response
                .map(|response| Zeroizing::new(hex::encode(response))),
        },
    )?;
    let transformed = response
        .transformed
        .ok_or_else(|| AppError::Crypto("agent sent no key".to_string()))?;
    hex::decode(transformed.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| AppError::Crypto("agent sent a malformed key".to_string()))
}

/// The YubiKey result the agent remembers for `challenge`.
pub(super) fn recall(key: &AgentKey, challenge: &[u8]) -> AppResult<Option<[u8; 32]>> {
    let response = ask(
        key,
        &Request::Recall {
            challenge: hex::encode(challenge),
        },
    )?;
    let Some(encoded) = response.challenge_response else {
        return Ok(None);
    };
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(encoded.as_bytes(), &mut decoded)
        .map_err(|_| AppError::Crypto("agent sent a malformed YubiKey result".to_string()))?;
    Ok(Some(decoded))
}

/// Have the agent remember a YubiKey result for `challenge`.
pub(super) fn remember(key: &AgentKey, challenge: &[u8], response: &[u8; 32]) -> AppResult<()> {
    ask(
        key,
        &Request::Remember {
            challenge: hex::encode(challenge),
            challenge_response: Zeroizing::new(hex::encode(response)),
        },
    )?;
    Ok(())
}

/// Have the agent remove an SSH key from the ssh-agent at `socket` when it locks.
pub(super) fn track_ssh_key(key: &AgentKey, socket: &Path, public_blob: &[u8]) -> AppResult<()> {
    ask(
        key,
        &Request::TrackSshKey {
            socket: socket.to_path_buf(),
            public_key: hex::encode(public_blob),
        },
    )?;
    Ok(())
}

/// Send `request` to the agent behind `key` and check who answered.
fn ask(key: &AgentKey, request: &Request) -> AppResult<Response> {
    let response = query(&key.socket, request).map_err(|err| {
        AppError::Locked(format!(
            "locked: the unlock agent for {} stopped ({err}); run 'keepassxcr unlock {}'",
            key.database.display(),
            key.database.display(),
        ))
    })?;
    if let Some(error) = response.error {
        return Err(AppError::Crypto(format!("agent: {error}")));
    }
    if response.database.as_deref() != Some(key.database.as_path()) {
        return Err(AppError::Crypto(
            "agent answered for another database".to_string(),
        ));
    }
    Ok(response)
}

fn location_state(location: &Location) -> DbState {
    if let Some(status) = query_status(&location.socket, Some(&location.database)) {
        return DbState::Unlocked(status);
    }
    match location.read_marker() {
        Some(marker) => DbState::Expired(marker),
        None => DbState::Locked,
    }
}

/// Status of the agent at `socket`, if one answers for `database`.
fn query_status(socket: &Path, database: Option<&Path>) -> Option<AgentStatus> {
    let response = query(socket, &Request::Status).ok()?;
    let answered = response.database?;
    if database.is_some_and(|expected| expected != answered) {
        return None;
    }
    Some(AgentStatus {
        database: answered,
        idle_left: Duration::from_secs(response.idle_left_secs.unwrap_or(0)),
        max_left: Duration::from_secs(response.max_left_secs.unwrap_or(0)),
        yubikey: response.yubikey,
    })
}

fn query(socket: &Path, request: &Request) -> io::Result<Response> {
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(err) => {
            // The agent died without cleaning up; drop its socket.
            if err.kind() == io::ErrorKind::ConnectionRefused {
                let _ = fs::remove_file(socket);
            }
            return Err(err);
        }
    };
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    wire::write_message(&mut stream, request)?;
    wire::read_message(&stream)
}
