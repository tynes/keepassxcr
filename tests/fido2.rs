//! End-to-end FIDO2 (hmac-secret) tests against the emulated device.
//!
//! Needs `--features software-fido2`, which lets the binary use
//! `KEEPASSXCR_SOFTWARE_FIDO2` instead of USB. That KeePassXC accepts and
//! keeps such databases is checked by `tests/test_cli_compat.py`.
#![cfg(all(unix, feature = "software-fido2"))]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

const PASSWORD: &str = "fido2-test-password";
const SEED: &str = "000102030405060708090a0b0c0d0e0f";
const OTHER_SEED: &str = "ffffffffffffffffffffffffffffffff";
const TOUCH_PROMPT: &str = "Please touch or confirm on your FIDO2 device to continue.";

/// A private directory with a database path, runtime dir and home.
struct Fixture {
    dir: PathBuf,
    db: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        // Kept short: Unix socket paths are limited to about 100 bytes.
        // /tmp, not temp_dir(): macOS temp_dir() is too long for the agent socket path.
        let dir = Path::new("/tmp").join(format!("kxf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            db: dir.join("db.kdbx"),
            dir,
        }
    }

    /// keepassxcr with this fixture's runtime dir and home, and no device.
    fn bare(&self) -> Command {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("HOME", &self.dir)
            .env("RUST_BACKTRACE", "0")
            .env_remove("KEEPASSXCR_SOFTWARE_FIDO2")
            .env_remove("KEEPASSXCR_FIDO2_SOCKET")
            .write_stdin("");
        cmd
    }

    /// `keepassxcr <command> <db> <args>` with the emulated device (`seed`) plugged in.
    fn with_device(&self, seed: &str, command: &str, args: &[&str]) -> Command {
        let mut cmd = self.bare();
        cmd.env("KEEPASSXCR_SOFTWARE_FIDO2", seed)
            .arg(command)
            .arg(&self.db)
            .args(args);
        cmd
    }

    /// `keepassxcr <command> <db> <args>` with no device plugged in.
    fn without_device(&self, command: &str, args: &[&str]) -> Command {
        let mut cmd = self.bare();
        cmd.arg(command).arg(&self.db).args(args);
        cmd
    }

    fn create(&self) {
        self.with_device(
            SEED,
            "db-create",
            &["--kdf", "aes-kdf", "--password", PASSWORD, "--fido2"],
        )
        .assert()
        .success()
        .stderr(contains(TOUCH_PROMPT));
        self.with_device(
            SEED,
            "add",
            &[
                "Api",
                "--username",
                "alice",
                "--password",
                PASSWORD,
                "--fido2",
            ],
        )
        .assert()
        .success();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.bare().arg("lock").arg(&self.db).assert();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn creates_and_opens_with_the_device() {
    let fixture = Fixture::new("open");
    fixture.create();
    fixture
        .with_device(SEED, "show", &["Api", "--password", PASSWORD, "--fido2"])
        .assert()
        .success()
        .stdout(contains("alice"))
        .stderr(contains(TOUCH_PROMPT));
    fixture
        .with_device(SEED, "db-info", &["--password", PASSWORD, "--fido2"])
        .assert()
        .success()
        .stdout(contains("FIDO2: credential "));
}

#[test]
fn needs_the_device() {
    let fixture = Fixture::new("need");
    fixture.create();
    fixture
        .without_device("ls", &["--password", PASSWORD])
        .assert()
        .failure()
        .stderr(contains("pass --fido2"));
}

#[test]
fn another_device_does_not_open_it() {
    let fixture = Fixture::new("other");
    fixture.create();
    fixture
        .with_device(OTHER_SEED, "ls", &["--password", PASSWORD, "--fido2"])
        .assert()
        .failure()
        .stderr(contains("holds this database's credential"));
}

#[test]
fn rejects_a_key_file_with_the_device() {
    let fixture = Fixture::new("kf");
    fixture
        .with_device(SEED, "ls", &["--fido2", "--key-file", "/dev/null"])
        .assert()
        .failure()
        .stderr(contains("cannot be used with"));
}

#[test]
fn needs_kdbx4() {
    let fixture = Fixture::new("v3");
    fixture
        .with_device(
            SEED,
            "db-create",
            &[
                "--format",
                "3",
                "--kdf",
                "aes-kdf",
                "--password",
                PASSWORD,
                "--fido2",
            ],
        )
        .assert()
        .failure()
        .stderr(contains("KDBX 4"));
}

#[test]
fn a_database_without_fido2_says_so() {
    let fixture = Fixture::new("none");
    fixture
        .with_device(
            SEED,
            "db-create",
            &["--kdf", "aes-kdf", "--password", PASSWORD],
        )
        .assert()
        .success();
    fixture
        .with_device(SEED, "ls", &["--password", PASSWORD, "--fido2"])
        .assert()
        .failure()
        .stderr(contains("not set up for a FIDO2 device"));
}

#[test]
fn db_edit_removes_and_adds_the_device() {
    let fixture = Fixture::new("edit");
    fixture.create();

    fixture
        .with_device(
            SEED,
            "db-edit",
            &["--password", PASSWORD, "--fido2", "--unset-fido2"],
        )
        .assert()
        .success();
    fixture
        .without_device("ls", &["--password", PASSWORD])
        .assert()
        .success()
        .stdout(contains("Api"))
        .stderr(contains("pass --fido2").not());

    fixture
        .with_device(
            OTHER_SEED,
            "db-edit",
            &["--password", PASSWORD, "--new-fido2"],
        )
        .assert()
        .success();
    fixture
        .without_device("ls", &["--password", PASSWORD])
        .assert()
        .failure();
    fixture
        .with_device(OTHER_SEED, "ls", &["--password", PASSWORD, "--fido2"])
        .assert()
        .success()
        .stdout(contains("Api"));
}

#[test]
fn the_agent_needs_no_device() {
    let fixture = Fixture::new("agent");
    fixture.create();
    fixture
        .with_device(
            SEED,
            "unlock",
            &["--password", PASSWORD, "--fido2", "--idle", "1m"],
        )
        .assert()
        .success();
    fixture
        .without_device("show", &["Api"])
        .assert()
        .success()
        .stdout(contains("alice"));
}

/// `keepassxcr fido2 serve` with the emulated device, until dropped.
struct Server(Child);

impl Server {
    fn start(fixture: &Fixture, socket: &Path) -> Self {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("keepassxcr"))
            .env("HOME", &fixture.dir)
            .env("RUST_BACKTRACE", "0")
            .env("KEEPASSXCR_SOFTWARE_FIDO2", SEED)
            .args(["fido2", "serve", "--socket"])
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
fn creates_and_opens_through_a_forwarded_device() {
    let fixture = Fixture::new("fwd");
    let socket = fixture.dir.join("f.sock");
    let _server = Server::start(&fixture, &socket);

    fixture
        .without_device(
            "db-create",
            &["--kdf", "aes-kdf", "--password", PASSWORD, "--fido2"],
        )
        .env("KEEPASSXCR_FIDO2_SOCKET", &socket)
        .assert()
        .success()
        .stderr(contains("on the machine running 'keepassxcr fido2 serve'"));
    fixture
        .without_device("ls", &["--password", PASSWORD, "--fido2"])
        .env("KEEPASSXCR_FIDO2_SOCKET", &socket)
        .assert()
        .success();
    // The same device, plugged in here, opens it too.
    fixture
        .with_device(SEED, "ls", &["--password", PASSWORD, "--fido2"])
        .assert()
        .success();
}

#[test]
fn uses_the_default_socket_when_present() {
    let fixture = Fixture::new("fwddef");
    fixture.create();
    let _server = Server::start(&fixture, &fixture.dir.join(".keepassxcr-fido2.sock"));
    fixture
        .without_device("show", &["Api", "--password", PASSWORD, "--fido2"])
        .assert()
        .success()
        .stdout(contains("alice"));
}

#[test]
fn a_named_socket_that_does_not_answer_is_an_error() {
    let fixture = Fixture::new("fwdgone");
    fixture.create();
    fixture
        .with_device(SEED, "ls", &["--password", PASSWORD, "--fido2"])
        .env("KEEPASSXCR_FIDO2_SOCKET", fixture.dir.join("missing.sock"))
        .assert()
        .failure()
        .stderr(contains("cannot reach the forwarded FIDO2 device"));
}
