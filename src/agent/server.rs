//! Agent side: hold the composite key, answer requests, expire.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::agent::wire::{self, Location, Request, Response, Startup};
use crate::agent::{ExpiredMarker, unix_now};
use crate::crypto::sha256;
use crate::error::{AppError, AppResult};
use crate::util::unix::{current_uid, peer_uid};
use crate::yubikey::YubiKeySlot;

/// Transformed keys (and YubiKey results) kept per agent. Each save adds one,
/// reads reuse them.
const CACHE_LIMIT: usize = 16;
/// How long a connected client may take to send its request.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

struct State {
    /// Password and key-file components, joined but not yet hashed.
    key: Zeroizing<Vec<u8>>,
    /// Transformed keys by hash of the KDF parameters and YubiKey result, so
    /// repeated reads of an unchanged file skip the KDF.
    cache: HashMap<[u8; 32], Zeroizing<Vec<u8>>>,
    /// YubiKey results by challenge, so reads of an unchanged file need no touch.
    responses: HashMap<Vec<u8>, Zeroizing<[u8; 32]>>,
}

struct Agent {
    location: Location,
    started: Instant,
    idle: Duration,
    max: Duration,
    /// Inode of the socket this agent bound, to notice being replaced.
    socket_inode: u64,
    /// Milliseconds after `started` of the last request. Kept outside `state`
    /// so the expiry watcher never waits for a request in progress.
    last_used_ms: AtomicU64,
    /// Requests still running their KDF. The idle timeout waits for them; the
    /// maximum lifetime does not.
    busy: AtomicUsize,
    yubikey: Option<YubiKeySlot>,
    state: Mutex<State>,
}

/// Run the agent for `database`. Reads its key and YubiKey slot from stdin,
/// prints `ready` (or `error: ...`) on stdout, then serves until it expires.
pub fn serve(database: &Path, idle: Duration, max: Duration) -> AppResult<()> {
    harden_process();
    let mut stdout = io::stdout();
    let (agent, listener) = match start(database, idle, max) {
        Ok(started) => started,
        Err(err) => {
            let _ = writeln!(stdout, "error: {err}");
            return Err(err);
        }
    };
    writeln!(stdout, "ready")?;
    stdout.flush()?;

    let agent = Arc::new(agent);
    let watcher = Arc::clone(&agent);
    thread::spawn(move || watcher.watch_expiry());

    for stream in listener.incoming().flatten() {
        agent.handle(stream);
    }
    Ok(())
}

fn start(database: &Path, idle: Duration, max: Duration) -> AppResult<(Agent, UnixListener)> {
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    let malformed = || AppError::InvalidInput("malformed key on stdin".to_string());
    let startup: Startup = serde_json::from_str(&line).map_err(|_| malformed())?;
    let key = Zeroizing::new(hex::decode(startup.key.as_bytes()).map_err(|_| malformed())?);
    lock_memory(&key);

    let location = Location::for_database(database)?;
    let _ = fs::remove_file(&location.socket);
    let listener = UnixListener::bind(&location.socket)?;
    fs::set_permissions(&location.socket, fs::Permissions::from_mode(0o600))?;
    let socket_inode = fs::symlink_metadata(&location.socket)?.ino();
    location.clear_marker();

    let now = Instant::now();
    let agent = Agent {
        location,
        started: now,
        idle,
        max,
        socket_inode,
        last_used_ms: AtomicU64::new(0),
        busy: AtomicUsize::new(0),
        yubikey: startup.yubikey,
        state: Mutex::new(State {
            key,
            cache: HashMap::new(),
            responses: HashMap::new(),
        }),
    };
    Ok((agent, listener))
}

/// Marks a request as running its KDF; on drop, restarts the idle timeout
/// from when the request finished.
struct Busy<'a>(&'a Agent);

impl<'a> Busy<'a> {
    fn start(agent: &'a Agent) -> Self {
        agent.busy.fetch_add(1, Ordering::SeqCst);
        Busy(agent)
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.touch();
        self.0.busy.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Agent {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn handle(&self, mut stream: UnixStream) {
        if peer_uid(&stream).ok() != Some(current_uid()) {
            return;
        }
        if stream.set_read_timeout(Some(CLIENT_TIMEOUT)).is_err() {
            return;
        }
        let response = match wire::read_message::<Request>(&stream) {
            Ok(Request::Status) => self.status(),
            Ok(Request::Lock) => {
                let _ = wire::write_message(&mut stream, &self.status());
                self.shutdown(None);
            }
            Ok(Request::Transform {
                kdf,
                challenge_response,
            }) => self.transform(&kdf, challenge_response.as_ref().map(|hex| hex.as_str())),
            Ok(Request::Recall { challenge }) => self.recall(&challenge),
            Ok(Request::Remember {
                challenge,
                challenge_response,
            }) => self.remember(&challenge, &challenge_response),
            Err(err) => Response {
                error: Some(format!("bad request: {err}")),
                ..Response::default()
            },
        };
        let _ = wire::write_message(&mut stream, &response);
    }

    fn status(&self) -> Response {
        let (idle_left, max_left) = self.time_left();
        Response {
            database: Some(self.location.database.clone()),
            idle_left_secs: Some(idle_left.as_secs()),
            max_left_secs: Some(max_left.as_secs()),
            yubikey: self.yubikey,
            ..Response::default()
        }
    }

    fn transform(
        &self,
        kdf: &crate::crypto::KdfConfig,
        challenge_response: Option<&str>,
    ) -> Response {
        self.touch();
        let challenge_response = match challenge_response.map(decode_result).transpose() {
            Ok(decoded) => decoded,
            Err(err) => return error_response(err),
        };
        let id = match serde_json::to_vec(kdf) {
            Ok(encoded) => {
                let mut encoded = Zeroizing::new(encoded);
                if let Some(response) = &challenge_response {
                    encoded.extend_from_slice(&response[..]);
                }
                sha256(&encoded)
            }
            Err(err) => return error_response(err.to_string()),
        };
        let cached = self.state().cache.get(&id).cloned();
        let transformed = match cached {
            Some(transformed) => transformed,
            None => {
                // Run the KDF without holding the lock: it can take as long as
                // the file's settings say, and expiry must not wait for it.
                let _busy = Busy::start(self);
                let mut raw = Zeroizing::new(self.state().key.to_vec());
                if let Some(response) = &challenge_response {
                    raw.extend_from_slice(&response[..]);
                }
                lock_memory(&raw);
                let transformed = match kdf.transform(&sha256(&raw)) {
                    Ok(transformed) => transformed,
                    Err(err) => return error_response(err.to_string()),
                };
                lock_memory(&transformed);
                let mut state = self.state();
                if state.cache.len() >= CACHE_LIMIT {
                    state.cache.clear();
                }
                state.cache.insert(id, transformed.clone());
                transformed
            }
        };
        Response {
            database: Some(self.location.database.clone()),
            transformed: Some(Zeroizing::new(hex::encode(&transformed[..]))),
            ..Response::default()
        }
    }

    /// Record a request now, restarting the idle timeout.
    fn touch(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_used_ms.store(elapsed, Ordering::Relaxed);
    }

    fn recall(&self, challenge: &str) -> Response {
        self.touch();
        let Ok(challenge) = hex::decode(challenge) else {
            return error_response("malformed challenge".to_string());
        };
        let challenge_response = self
            .state()
            .responses
            .get(&challenge)
            .map(|response| Zeroizing::new(hex::encode(&response[..])));
        Response {
            database: Some(self.location.database.clone()),
            challenge_response,
            ..Response::default()
        }
    }

    fn remember(&self, challenge: &str, challenge_response: &str) -> Response {
        let (Ok(challenge), Ok(response)) =
            (hex::decode(challenge), decode_result(challenge_response))
        else {
            return error_response("malformed YubiKey result".to_string());
        };
        lock_memory(&response[..]);
        let mut state = self.state();
        if state.responses.len() >= CACHE_LIMIT {
            state.responses.clear();
        }
        state.responses.insert(challenge, response);
        Response {
            database: Some(self.location.database.clone()),
            ..Response::default()
        }
    }

    fn time_left(&self) -> (Duration, Duration) {
        let now = Instant::now();
        let last_used =
            self.started + Duration::from_millis(self.last_used_ms.load(Ordering::Relaxed));
        let idle_left = (last_used + self.idle).saturating_duration_since(now);
        let max_left = (self.started + self.max).saturating_duration_since(now);
        (idle_left.min(max_left), max_left)
    }

    fn watch_expiry(&self) {
        loop {
            thread::sleep(Duration::from_secs(1));
            if !self.owns_socket() {
                // Another agent took over this database's socket.
                self.shutdown(None);
            }
            let (idle_left, max_left) = self.time_left();
            if max_left.is_zero() {
                self.shutdown(Some("maximum lifetime reached"));
            }
            if idle_left.is_zero() && self.busy.load(Ordering::SeqCst) == 0 {
                self.shutdown(Some("idle timeout"));
            }
        }
    }

    fn owns_socket(&self) -> bool {
        fs::symlink_metadata(&self.location.socket)
            .is_ok_and(|meta| meta.ino() == self.socket_inode)
    }

    /// Wipe the key, remove the socket and exit. With a reason, leave an
    /// expiry marker so commands fail instead of prompting.
    ///
    /// Never waits for a request in progress: if one holds the state, the key
    /// is wiped by the process exiting instead.
    fn shutdown(&self, reason: Option<&str>) -> ! {
        if let Ok(mut state) = self.state.try_lock() {
            state.key.iter_mut().for_each(|byte| *byte = 0);
            state.cache.clear();
            state.responses.clear();
        }
        if self.owns_socket() {
            let _ = fs::remove_file(&self.location.socket);
            if let Some(reason) = reason {
                write_marker(&self.location.marker, &self.location.database, reason);
            }
        }
        std::process::exit(0);
    }
}

/// Decode a hex SHA-256 YubiKey result.
fn decode_result(encoded: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut decoded = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded, &mut decoded[..])
        .map_err(|_| "malformed YubiKey result".to_string())?;
    Ok(decoded)
}

fn error_response(message: String) -> Response {
    Response {
        error: Some(message),
        ..Response::default()
    }
}

fn write_marker(path: &Path, database: &Path, reason: &str) {
    let marker = ExpiredMarker {
        database: PathBuf::from(database),
        expired_at: unix_now(),
        reason: reason.to_string(),
    };
    if let Ok(data) = serde_json::to_vec(&marker) {
        let _ = fs::write(path, data);
    }
}

/// Keep the key out of core dumps and, on Linux, away from ptrace and
/// `/proc/<pid>/mem` by processes running as the same user.
pub fn harden_process() {
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on this process with valid arguments.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Best-effort: keep secret pages out of swap.
fn lock_memory(bytes: &[u8]) {
    if !bytes.is_empty() {
        // SAFETY: the range is a live allocation owned by the caller.
        unsafe {
            libc::mlock(bytes.as_ptr().cast(), bytes.len());
        }
    }
}
