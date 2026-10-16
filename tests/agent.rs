//! End-to-end tests for `unlock`, `lock`, `status` and the background agent.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use predicates::str::contains;

const PASSWORD: &str = "agent-test-password";
const EXIT_LOCKED: i32 = 3;

/// A database and a private runtime directory, so tests never share agents.
struct Fixture {
    dir: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        // Kept short: Unix socket paths are limited to about 100 bytes.
        let dir = std::env::temp_dir().join(format!("kxa-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self {
            db: dir.join("db.kdbx"),
            dir,
        };
        fixture
            .cmd(&["db-create", "--kdf", "aes-kdf", "--password", PASSWORD])
            .assert()
            .success();
        fixture
            .cmd(&["add", "--username", "alice", "--password", PASSWORD])
            .arg("Api")
            .assert()
            .success();
        fixture
    }

    /// `keepassxcr <args[0]> <db> <args[1..]>` with this fixture's runtime dir
    /// and no stdin, as in a script.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("keepassxcr").unwrap();
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("RUST_BACKTRACE", "0")
            .arg(args[0])
            .arg(&self.db)
            .args(&args[1..])
            .write_stdin("");
        cmd
    }

    fn unlock(&self, idle: &str) {
        self.cmd(&["unlock", "--idle", idle])
            .write_stdin(format!("{PASSWORD}\n"))
            .assert()
            .success()
            .stdout(contains("Unlocked"));
    }

    fn runtime_files(&self) -> Vec<String> {
        let dir = self.dir.join("run/keepassxcr");
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = Command::cargo_bin("keepassxcr")
            .unwrap()
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .arg("lock")
            .ok();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn has_extension(names: &[String], extension: &str) -> bool {
    names.iter().any(|name| {
        Path::new(name)
            .extension()
            .is_some_and(|ext| ext == extension)
    })
}

#[test]
fn unlocked_database_serves_reads_and_writes_without_a_password() {
    let fixture = Fixture::new("rw");
    fixture.unlock("15m");

    fixture
        .cmd(&["status"])
        .assert()
        .success()
        .stdout(contains("unlocked"));
    fixture
        .cmd(&["show", "Api"])
        .assert()
        .success()
        .stdout(contains("Username: alice"));
    fixture
        .cmd(&["add", "--username", "bob"])
        .arg("Second")
        .assert()
        .success();
    // The save drew a new KDF seed; the agent handles that too.
    fixture
        .cmd(&["ls"])
        .assert()
        .success()
        .stdout(contains("[E] Second"));

    let files = fixture.runtime_files();
    assert!(has_extension(&files, "sock"), "{files:?}");
}

#[test]
fn expired_agent_fails_fast_instead_of_prompting() {
    let fixture = Fixture::new("exp");
    fixture.unlock("1s");
    thread::sleep(Duration::from_secs(3));

    fixture
        .cmd(&["status"])
        .assert()
        .code(1)
        .stdout(contains("expired"))
        .stdout(contains("idle timeout"));
    // A password on stdin would be read by a prompt; the command must not read it.
    fixture
        .cmd(&["show", "Api"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .code(EXIT_LOCKED)
        .stderr(contains("keepassxcr unlock"));
    fixture
        .cmd(&["show", "Api", "--no-agent"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();

    let files = fixture.runtime_files();
    assert!(!has_extension(&files, "sock"), "{files:?}");
}

#[test]
fn explicit_lock_returns_to_normal_prompting() {
    let fixture = Fixture::new("lock");
    fixture.unlock("15m");

    fixture
        .cmd(&["lock"])
        .assert()
        .success()
        .stdout(contains("Locked"));
    fixture
        .cmd(&["status"])
        .assert()
        .code(1)
        .stdout(contains("locked"));
    fixture
        .cmd(&["show", "Api"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    assert!(fixture.runtime_files().is_empty());
}

#[test]
fn wrong_password_does_not_start_an_agent() {
    let fixture = Fixture::new("bad");
    fixture
        .cmd(&["unlock"])
        .write_stdin("not-the-password\n")
        .assert()
        .failure();
    fixture.cmd(&["status"]).assert().code(1);
    assert!(!has_extension(&fixture.runtime_files(), "sock"));
}

#[test]
fn changing_credentials_locks_the_agent() {
    let fixture = Fixture::new("edit");
    fixture.unlock("15m");
    fixture
        .cmd(&[
            "db-edit",
            "--password",
            PASSWORD,
            "--new-password",
            "changed",
        ])
        .assert()
        .success()
        .stdout(contains("Locked the unlock agent"));
    fixture.cmd(&["status"]).assert().code(1);
}
