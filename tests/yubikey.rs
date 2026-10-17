//! End-to-end YubiKey challenge-response tests against the emulated key.
//!
//! Needs `--features software-yubikey`, which lets the binary use
//! `KEEPASSXCR_SOFTWARE_YUBIKEY` instead of USB. Compatibility with KeePassXC
//! itself is checked by `tests/test_yubikey_compat.py`.
#![cfg(all(unix, feature = "software-yubikey"))]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

const PASSWORD: &str = "yubikey-test-password";
const SECRET: &str = "0102030405060708090a0b0c0d0e0f1011121314";
const OTHER_SECRET: &str = "1111111111111111111111111111111111111111";
const TOUCH_PROMPT: &str = "Please present or touch your YubiKey to continue.";

/// A private directory with a database path, runtime dir and home.
struct Fixture {
    dir: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        // Kept short: Unix socket paths are limited to about 100 bytes.
        let dir = std::env::temp_dir().join(format!("kxy-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            db: dir.join("db.kdbx"),
            dir,
        }
    }

    /// keepassxcr with this fixture's runtime dir and home, and no YubiKey.
    fn bare(&self) -> Command {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("HOME", &self.dir)
            .env("RUST_BACKTRACE", "0")
            .env_remove("KEEPASSXCR_SOFTWARE_YUBIKEY")
            .env_remove("KEEPASSXCR_YUBIKEY_SOCKET")
            .write_stdin("");
        cmd
    }

    /// `keepassxcr <command> <db> <args>` with the emulated key (`spec`) plugged in.
    fn with_key(&self, spec: &str, command: &str, args: &[&str]) -> Command {
        let mut cmd = self.bare();
        cmd.env("KEEPASSXCR_SOFTWARE_YUBIKEY", spec)
            .arg(command)
            .arg(&self.db)
            .args(args);
        cmd
    }

    /// `keepassxcr <command> <db> <args>` with no key plugged in.
    fn without_key(&self, command: &str, args: &[&str]) -> Command {
        let mut cmd = self.bare();
        cmd.arg(command).arg(&self.db).args(args);
        cmd
    }

    fn create(&self, extra: &[&str]) {
        let mut args = vec!["--kdf", "aes-kdf", "--password", PASSWORD, "-y", "2"];
        args.extend_from_slice(extra);
        self.with_key(SECRET, "db-create", &args).assert().success();
        self.with_key(
            SECRET,
            "add",
            &[
                "Api",
                "--username",
                "alice",
                "--password",
                PASSWORD,
                "-y",
                "2",
            ],
        )
        .assert()
        .success();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.bare().arg("lock").ok();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn opens_a_database_made_with_a_real_yubikey() {
    // Third-party known answer: keepass-rs's fixture for this secret.
    let fixture = Fixture::new("fixture");
    let db = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/keepass-rs/test_db_with_challenge_response_key.kdbx");
    fixture
        .bare()
        .env("KEEPASSXCR_SOFTWARE_YUBIKEY", SECRET)
        .arg("ls")
        .arg(db)
        .args(["--password", "demopass", "-y", "2"])
        .assert()
        .success()
        .stdout(contains("entry1"))
        .stdout(contains("entry2"));
}

#[test]
fn round_trips_kdbx4_and_kdbx3() {
    for (name, format) in [("v4", "4"), ("v3", "3")] {
        let fixture = Fixture::new(name);
        fixture.create(&["--format", format]);
        fixture
            .with_key(SECRET, "show", &["Api", "--password", PASSWORD, "-y", "2"])
            .assert()
            .success()
            .stdout(contains("alice"));
    }
}

#[test]
fn a_yubikey_alone_is_enough() {
    // In KDBX 3.1 the KDF then runs over an empty key, as in KeePassXC.
    for (name, format) in [("only4", "4"), ("only3", "3")] {
        let fixture = Fixture::new(name);
        fixture
            .with_key(
                SECRET,
                "db-create",
                &[
                    "--format",
                    format,
                    "--kdf",
                    "aes-kdf",
                    "--no-password",
                    "-y",
                    "2",
                ],
            )
            .assert()
            .success();
        fixture
            .with_key(SECRET, "ls", &["--no-password", "-y", "2"])
            .assert()
            .success();
    }
}

#[test]
fn fixed_length_slots_round_trip() {
    let fixture = Fixture::new("fixed");
    let fixed = format!("{SECRET}:fixed");
    fixture
        .with_key(
            &fixed,
            "db-create",
            &["--kdf", "aes-kdf", "--no-password", "-y", "2"],
        )
        .assert()
        .success();
    fixture
        .with_key(&fixed, "ls", &["--no-password", "-y", "2"])
        .assert()
        .success();
    // A variable-length slot with the same secret answers differently.
    fixture
        .with_key(SECRET, "ls", &["--no-password", "-y", "2"])
        .assert()
        .failure();
}

#[test]
fn needs_the_right_key() {
    let fixture = Fixture::new("wrong");
    fixture.create(&[]);
    fixture
        .with_key(OTHER_SECRET, "ls", &["--password", PASSWORD, "-y", "2"])
        .assert()
        .failure();
    fixture
        .with_key(SECRET, "ls", &["--password", PASSWORD])
        .assert()
        .failure();
    fixture
        .without_key("ls", &["--password", PASSWORD, "-y", "2"])
        .assert()
        .failure()
        .stderr(contains("no YubiKey found"));
}

#[test]
fn prompts_for_a_touch() {
    let fixture = Fixture::new("touch");
    fixture.create(&[]);
    fixture
        .with_key(
            &format!("{SECRET}:touch"),
            "ls",
            &["--password", PASSWORD, "-y", "2"],
        )
        .assert()
        .success()
        .stderr(contains(TOUCH_PROMPT));
}

#[test]
fn db_edit_adds_and_removes_the_yubikey() {
    let fixture = Fixture::new("edit");
    fixture
        .with_key(
            SECRET,
            "db-create",
            &["--kdf", "aes-kdf", "--password", PASSWORD],
        )
        .assert()
        .success();
    fixture
        .with_key(
            SECRET,
            "db-edit",
            &["--password", PASSWORD, "--new-yubikey", "2"],
        )
        .assert()
        .success();
    fixture
        .with_key(SECRET, "ls", &["--password", PASSWORD])
        .assert()
        .failure();
    fixture
        .with_key(
            SECRET,
            "db-edit",
            &["--password", PASSWORD, "-y", "2", "--unset-yubikey"],
        )
        .assert()
        .success();
    fixture
        .without_key("ls", &["--password", PASSWORD])
        .assert()
        .success();
}

#[test]
fn agent_reads_without_the_key_until_the_file_changes() {
    let fixture = Fixture::new("agent");
    fixture.create(&[]);
    fixture
        .with_key(SECRET, "unlock", &["--password", PASSWORD, "-y", "2"])
        .assert()
        .success()
        .stdout(contains("YubiKey slot 2"));

    // The agent remembers the answer for the current seed.
    fixture
        .without_key("show", &["Api"])
        .assert()
        .success()
        .stdout(contains("alice"));
    // A save draws a new seed, so it needs the key.
    fixture
        .without_key("add", &["Mail", "--username", "bob"])
        .assert()
        .failure()
        .stderr(contains("no YubiKey found"));
    fixture
        .with_key(SECRET, "add", &["Mail", "--username", "bob"])
        .assert()
        .success();
    // The answer for the new seed was remembered by that save.
    fixture
        .without_key("show", &["Mail"])
        .assert()
        .success()
        .stdout(contains("bob"));
}

#[test]
fn agent_remembers_the_master_seed_answer_for_kdbx3() {
    let fixture = Fixture::new("agent3");
    fixture.create(&["--format", "3"]);
    fixture
        .with_key(SECRET, "unlock", &["--password", PASSWORD, "-y", "2"])
        .assert()
        .success();
    fixture
        .without_key("show", &["Api"])
        .assert()
        .success()
        .stdout(contains("alice"));
}

#[test]
fn unlock_with_the_wrong_key_leaves_nothing_running() {
    let fixture = Fixture::new("agentwrong");
    fixture.create(&[]);
    fixture
        .with_key(OTHER_SECRET, "unlock", &["--password", PASSWORD, "-y", "2"])
        .assert()
        .failure();
    fixture.without_key("status", &[]).assert().code(1);
}

/// `keepassxcr yubikey serve` with the emulated key, until dropped.
struct Server(Child);

impl Server {
    fn start(fixture: &Fixture, socket: &Path) -> Self {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("keepassxcr"))
            .env("HOME", &fixture.dir)
            .env("RUST_BACKTRACE", "0")
            .env("KEEPASSXCR_SOFTWARE_YUBIKEY", format!("{SECRET}:touch"))
            .args(["yubikey", "serve", "--socket"])
            .arg(socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Wait for it to listen.
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(line.contains("Answering"), "{line}");
        Self(child)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn uses_a_key_forwarded_over_a_socket() {
    let fixture = Fixture::new("fwd");
    fixture.create(&[]);
    let socket = fixture.dir.join("yk.sock");
    let _server = Server::start(&fixture, &socket);

    fixture
        .without_key("show", &["Api", "--password", PASSWORD, "-y", "2"])
        .env("KEEPASSXCR_YUBIKEY_SOCKET", &socket)
        .assert()
        .success()
        .stdout(contains("alice"))
        .stderr(contains(
            "on the machine running 'keepassxcr yubikey serve'",
        ));
}

#[test]
fn uses_the_default_socket_when_present() {
    let fixture = Fixture::new("fwddef");
    fixture.create(&[]);
    let _server = Server::start(&fixture, &fixture.dir.join(".keepassxcr-yubikey.sock"));

    fixture
        .without_key("show", &["Api", "--password", PASSWORD, "-y", "2"])
        .assert()
        .success()
        .stdout(contains("alice"));
}

#[test]
fn a_named_socket_that_does_not_answer_is_an_error() {
    let fixture = Fixture::new("fwdgone");
    fixture.create(&[]);
    fixture
        .with_key(SECRET, "ls", &["--password", PASSWORD, "-y", "2"])
        .env(
            "KEEPASSXCR_YUBIKEY_SOCKET",
            fixture.dir.join("missing.sock"),
        )
        .assert()
        .failure()
        .stderr(contains("cannot reach the forwarded YubiKey"));
}
