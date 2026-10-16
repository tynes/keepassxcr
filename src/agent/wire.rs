//! Socket locations and the line-delimited JSON protocol between commands and the agent.

use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::agent::ExpiredMarker;
use crate::crypto::{KdfConfig, sha256};
use crate::error::{AppError, AppResult};

/// Largest request or response line accepted.
const MAX_LINE: u64 = 64 * 1024;
/// Longest runtime directory that leaves room for `/<16 hex>.expired` in a socket path.
const MAX_DIR_LEN: usize = 104 - 26;

/// A request from a command to the agent.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(super) enum Request {
    /// Report the database and time left. Does not reset the idle timer.
    Status,
    /// Wipe the key and exit.
    Lock,
    /// Run the KDF over the composite key. Resets the idle timer.
    Transform { kdf: KdfConfig },
}

/// The agent's reply. Fields are filled according to the request.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_left_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_left_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformed: Option<String>,
}

/// Where one database's agent socket and expiry marker live.
#[derive(Debug, Clone)]
pub(super) struct Location {
    pub database: PathBuf,
    pub socket: PathBuf,
    pub marker: PathBuf,
}

impl Location {
    /// Resolve the location for a database path.
    pub fn for_database(database: &Path) -> AppResult<Self> {
        let database = fs::canonicalize(database)?;
        let digest = sha256(database.as_os_str().as_bytes());
        let name = hex::encode(&digest[..8]);
        let dir = runtime_dir()?;
        // Unix socket paths are limited to about 100 bytes (104 on macOS).
        if dir.as_os_str().len() > MAX_DIR_LEN {
            return Err(AppError::InvalidInput(format!(
                "{} is too long for a Unix socket path; point XDG_RUNTIME_DIR at a shorter directory",
                dir.display()
            )));
        }
        Ok(Self {
            socket: dir.join(format!("{name}.sock")),
            marker: dir.join(format!("{name}.expired")),
            database,
        })
    }

    /// Read the expiry marker, if any.
    pub fn read_marker(&self) -> Option<ExpiredMarker> {
        let data = fs::read(&self.marker).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Remove the expiry marker, ignoring a missing file.
    pub fn clear_marker(&self) {
        let _ = fs::remove_file(&self.marker);
    }
}

/// Per-user directory for agent sockets, created with mode 0700.
///
/// Uses `$XDG_RUNTIME_DIR/keepassxcr`, or `keepassxcr-<uid>` in the temp
/// directory. Refuses a directory that is a symlink, belongs to someone else
/// or is readable by others, since another user could then plant a socket.
pub(super) fn runtime_dir() -> AppResult<PathBuf> {
    let uid = current_uid();
    let dir = match env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        Some(base) => PathBuf::from(base).join("keepassxcr"),
        None => env::temp_dir().join(format!("keepassxcr-{uid}")),
    };
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let meta = fs::symlink_metadata(&dir)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(AppError::InvalidInput(format!(
            "refusing to use {}: it must be a directory owned by you with mode 0700",
            dir.display()
        )));
    }
    Ok(dir)
}

/// Every agent location in the runtime directory, found by socket or marker.
pub(super) fn all_locations() -> AppResult<Vec<PathBuf>> {
    let dir = runtime_dir()?;
    let mut stems: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("sock" | "expired")
            )
        })
        .map(|path| path.with_extension(""))
        .collect();
    stems.sort();
    stems.dedup();
    Ok(stems)
}

/// Write one JSON line.
pub(super) fn write_message<T: Serialize>(stream: &mut UnixStream, message: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    stream.write_all(&line)
}

/// Read one JSON line, bounded by [`MAX_LINE`].
pub(super) fn read_message<T: for<'de> Deserialize<'de>>(stream: &UnixStream) -> io::Result<T> {
    let mut line = String::new();
    BufReader::new(stream.take(MAX_LINE)).read_line(&mut line)?;
    if line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "agent closed the connection",
        ));
    }
    serde_json::from_str(&line).map_err(io::Error::from)
}

pub(super) fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}
