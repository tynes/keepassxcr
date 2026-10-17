//! Background agent that keeps a database unlocked between commands.
//!
//! `keepassxcr unlock` starts one agent per database. The agent holds the
//! composite key (password and key file hashed together, before the KDF) and
//! answers KDF requests over a Unix socket only the same user can reach, so
//! the key never leaves the agent and each command decrypts the file itself.
//! The agent never writes to a terminal: when it expires it leaves a marker
//! file, and commands that find the marker fail instead of prompting.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::KdfConfig;
use crate::error::{AppError, AppResult};

#[cfg(unix)]
mod client;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod wire;

#[cfg(unix)]
pub use client::{credentials_for, lock, state, status_all, unlock};
#[cfg(unix)]
pub use server::{harden_process, serve};

/// Handle to a running agent, used by [`crate::format::Credentials`].
#[derive(Debug, Clone)]
pub struct AgentKey {
    socket: PathBuf,
    database: PathBuf,
}

impl AgentKey {
    /// Ask the agent to run `kdf` over its composite key.
    pub fn transform(&self, kdf: &KdfConfig) -> AppResult<Vec<u8>> {
        #[cfg(unix)]
        return client::transform(self, kdf);
        #[cfg(not(unix))]
        {
            let _ = kdf;
            Err(unsupported())
        }
    }
}

/// A running agent's view of its database.
#[derive(Debug, Clone)]
pub struct AgentStatus {
    /// Canonical database path.
    pub database: PathBuf,
    /// Time until the idle timeout, reset by each use.
    pub idle_left: Duration,
    /// Time until the agent's hard maximum lifetime.
    pub max_left: Duration,
}

/// Why and when an agent stopped by itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiredMarker {
    /// Canonical database path.
    pub database: PathBuf,
    /// Unix time in seconds.
    pub expired_at: u64,
    /// Human-readable reason, e.g. "idle timeout".
    pub reason: String,
}

/// Unlock state of one database.
#[derive(Debug, Clone)]
pub enum DbState {
    /// An agent is running and will serve commands.
    Unlocked(AgentStatus),
    /// The agent timed out; commands fail until `unlock` runs again.
    Expired(ExpiredMarker),
    /// No agent, never unlocked or explicitly locked; commands prompt as usual.
    Locked,
}

impl ExpiredMarker {
    /// Seconds since the agent expired.
    pub fn age(&self) -> Duration {
        Duration::from_secs(unix_now().saturating_sub(self.expired_at))
    }

    /// Error returned by commands that find this marker.
    pub fn to_error(&self, database: &Path) -> AppError {
        AppError::Locked(format!(
            "locked: {} expired {} ago ({}); run 'keepassxcr unlock {}' or pass --no-agent",
            database.display(),
            format_duration(self.age()),
            self.reason,
            database.display(),
        ))
    }
}

/// Parse durations like `90`, `30s`, `15m`, `8h` or `1d`.
pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
        Some(index) => value.split_at(index),
        None => (value, "s"),
    };
    let amount: u64 = digits
        .parse()
        .map_err(|_| format!("invalid duration '{value}'"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => {
            return Err(format!(
                "invalid duration unit in '{value}' (use s, m, h or d)"
            ));
        }
    };
    if amount == 0 {
        return Err("duration must be greater than zero".to_string());
    }
    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration '{value}' is too large"))
}

/// Format a duration compactly, e.g. `1h05m`, `14m`, `42s`.
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let (hours, minutes) = (secs / 3600, secs % 3600 / 60);
    match (hours, minutes) {
        (0, 0) => format!("{secs}s"),
        (0, _) => format!("{minutes}m"),
        _ => format!("{hours}h{minutes:02}m"),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(not(unix))]
fn unsupported() -> AppError {
    AppError::InvalidInput("the unlock agent is only supported on Unix".to_string())
}

/// Stand-ins for platforms without Unix sockets: commands always prompt.
#[cfg(not(unix))]
mod unsupported_platform {
    use super::*;

    pub fn credentials_for(_database: &Path) -> AppResult<Option<AgentKey>> {
        Ok(None)
    }

    pub fn state(_database: &Path) -> AppResult<DbState> {
        Ok(DbState::Locked)
    }

    pub fn status_all() -> AppResult<Vec<DbState>> {
        Ok(Vec::new())
    }

    pub fn unlock(
        _database: &Path,
        _raw_key: &[u8],
        _idle: Duration,
        _max: Duration,
    ) -> AppResult<AgentStatus> {
        Err(unsupported())
    }

    pub fn lock(_database: Option<&Path>) -> AppResult<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    pub fn serve(_database: &Path, _idle: Duration, _max: Duration) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn harden_process() {}
}
#[cfg(not(unix))]
pub use unsupported_platform::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(28_800)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("5w").is_err());
        assert!(parse_duration("m").is_err());
    }

    #[test]
    fn formats_durations() {
        assert_eq!(format_duration(Duration::from_secs(42)), "42s");
        assert_eq!(format_duration(Duration::from_secs(14 * 60 + 5)), "14m");
        assert_eq!(format_duration(Duration::from_secs(3900)), "1h05m");
    }
}
