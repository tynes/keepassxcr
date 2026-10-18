//! End-to-end tests of FIDO2-protected key files against emulated security keys.
//!
//! Needs `--features software-fido2`, which lets the binary use
//! `KEEPASSXCR_SOFTWARE_FIDO2` instead of USB. That the database opens in
//! KeePassXC with the plain key file is checked by `tests/test_cli_compat.py`.
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
const KEY_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const KEY_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const PIN: &str = "1234";
const TOUCH: &str = "Touch your security key to continue.";

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        // Kept short: Unix socket paths are limited to about 100 bytes.
        let dir = std::env::temp_dir().join(format!("kxf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn wrapped(&self) -> PathBuf {
        self.path("db.keyx.fido2")
    }

    fn db(&self) -> PathBuf {
        self.path("db.kdbx")
    }

    /// keepassxcr with `keys` plugged in (comma-separated emulator specs) and
    /// `pin` typed, or none when empty.
    fn cmd(&self, keys: &str, pin: Option<&str>) -> Command {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("HOME", &self.dir)
            .env("RUST_BACKTRACE", "0")
            .env("KEEPASSXCR_SOFTWARE_FIDO2", keys)
            .env_remove("KEEPASSXCR_YUBIKEY_SOCKET")
            .env_remove("KEEPASSXCR_FIDO2_PIN")
            .write_stdin("");
        if let Some(pin) = pin {
            cmd.env("KEEPASSXCR_FIDO2_PIN", pin);
        }
        cmd
    }

    fn key_a(&self) -> String {
        format!("{KEY_A}:pin={PIN}")
    }

    fn key_b(&self) -> String {
        format!("{KEY_B}:pin={PIN}")
    }

    /// Enroll key A with a new key file and make a database with it.
    fn setup(&self) {
        self.cmd(&self.key_a(), Some(PIN))
            .args(["fido2", "enroll"])
            .arg(self.wrapped())
            .arg("--backup")
            .arg(self.path("db.keyx"))
            .args(["--label", "key A"])
            .assert()
            .success()
            .stdout(contains("Enrolled key A: unlocks with its PIN and a touch"))
            .stderr(contains(TOUCH));
        self.cmd(&self.key_a(), Some(PIN))
            .arg("db-create")
            .arg(self.db())
            .args(["--kdf", "aes-kdf", "--password", PASSWORD, "--key-file"])
            .arg(self.wrapped())
            .assert()
            .success();
        self.cmd(&self.key_a(), Some(PIN))
            .arg("add")
            .arg(self.db())
            .args([
                "Mail",
                "--username",
                "alice",
                "--password",
                PASSWORD,
                "--key-file",
            ])
            .arg(self.wrapped())
            .assert()
            .success();
    }

    fn show(&self, keys: &str, pin: Option<&str>, key_file: &Path) -> assert_cmd::assert::Assert {
        self.cmd(keys, pin)
            .arg("show")
            .arg(self.db())
            .args(["Mail", "--password", PASSWORD, "--key-file"])
            .arg(key_file)
            .assert()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.cmd("", None).arg("lock").ok();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn the_wrapped_key_file_and_its_backup_both_open_the_database() {
    let fixture = Fixture::new("basic");
    fixture.setup();
    fixture
        .show(&fixture.key_a(), Some(PIN), &fixture.wrapped())
        .success()
        .stdout(contains("alice"))
        .stderr(contains(TOUCH));
    // The plain backup is an ordinary KeePassXC key file: no security key needed.
    fixture
        .show("", None, &fixture.path("db.keyx"))
        .success()
        .stdout(contains("alice"));
    let backup = fs::read_to_string(fixture.path("db.keyx")).unwrap();
    assert!(backup.contains("<Version>2.0</Version>"), "{backup}");
    let mode = fs::metadata(fixture.path("db.keyx"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "backup is readable by others");
    // The wrapped file has no plain key material.
    let wrapped = fs::read_to_string(fixture.wrapped()).unwrap();
    assert!(wrapped.contains("\"format\": \"keepassxcr-fido2-keyfile\""));
    let hex_key: String = backup
        .lines()
        .filter(|line| line.trim().len() == 35)
        .collect();
    assert!(!hex_key.is_empty() && !wrapped.contains(hex_key.trim()));
}

#[test]
fn needs_the_enrolled_key_and_its_pin() {
    let fixture = Fixture::new("wrong");
    fixture.setup();
    fixture
        .show(&fixture.key_b(), Some(PIN), &fixture.wrapped())
        .failure()
        .stderr(contains("no plugged-in security key is enrolled"));
    fixture
        .show(&fixture.key_a(), Some("9999"), &fixture.wrapped())
        .failure()
        .stderr(contains("wrong security key PIN (7 tries left)"));
    fixture
        .show(&fixture.key_a(), None, &fixture.wrapped())
        .failure()
        .stderr(contains("KEEPASSXCR_FIDO2_PIN"));
}

#[test]
fn a_spare_key_can_be_added_and_the_first_removed() {
    let fixture = Fixture::new("spare");
    fixture.setup();
    // Both plugged in: A unlocks, B (the one not enrolled) is added.
    fixture
        .cmd(
            &format!("{},{}", fixture.key_a(), fixture.key_b()),
            Some(PIN),
        )
        .args(["fido2", "add-key"])
        .arg(fixture.wrapped())
        .args(["--label", "key B"])
        .assert()
        .success()
        .stdout(contains("Enrolled key B"));
    fixture
        .show(&fixture.key_b(), Some(PIN), &fixture.wrapped())
        .success()
        .stdout(contains("alice"));
    fixture
        .cmd("", None)
        .args(["fido2", "list"])
        .arg(fixture.wrapped())
        .assert()
        .success()
        .stdout(contains(
            "1. key A (PIN and touch)\n2. key B (PIN and touch)",
        ));
    // Adding again with only enrolled keys plugged in is refused.
    fixture
        .cmd(&fixture.key_b(), Some(PIN))
        .args(["fido2", "add-key"])
        .arg(fixture.wrapped())
        .assert()
        .failure()
        .stderr(contains("already enrolled"));
    fixture
        .cmd("", None)
        .args(["fido2", "remove-key"])
        .arg(fixture.wrapped())
        .arg("1")
        .assert()
        .success()
        .stdout(contains("Removed key A"));
    fixture
        .show(&fixture.key_a(), Some(PIN), &fixture.wrapped())
        .failure();
    fixture
        .show(&fixture.key_b(), Some(PIN), &fixture.wrapped())
        .success();
    fixture
        .cmd("", None)
        .args(["fido2", "remove-key"])
        .arg(fixture.wrapped())
        .arg("1")
        .assert()
        .failure()
        .stderr(contains("only enrolled security key"));
}

#[test]
fn a_spare_key_can_be_added_from_the_backup() {
    let fixture = Fixture::new("frombackup");
    fixture.setup();
    fixture
        .cmd(&fixture.key_b(), Some(PIN))
        .args(["fido2", "add-key"])
        .arg(fixture.wrapped())
        .arg("--from")
        .arg(fixture.path("db.keyx"))
        .assert()
        .success();
    fixture
        .show(&fixture.key_b(), Some(PIN), &fixture.wrapped())
        .success();
    // Another key file is refused.
    fs::write(fixture.path("other.key"), [7u8; 32]).unwrap();
    fixture
        .cmd(&format!("{KEY_A}:pin=5678"), Some("5678"))
        .args(["fido2", "add-key"])
        .arg(fixture.wrapped())
        .arg("--from")
        .arg(fixture.path("other.key"))
        .assert()
        .failure()
        .stderr(contains("is not the key file protected by"));
}

#[test]
fn export_gives_back_the_plain_key_file() {
    let fixture = Fixture::new("export");
    fixture.setup();
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .args(["fido2", "export"])
        .arg(fixture.wrapped())
        .arg("--output")
        .arg(fixture.path("exported.keyx"))
        .assert()
        .success();
    assert_eq!(
        fs::read(fixture.path("exported.keyx")).unwrap(),
        fs::read(fixture.path("db.keyx")).unwrap()
    );
    // Never overwrites.
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .args(["fido2", "export"])
        .arg(fixture.wrapped())
        .arg("--output")
        .arg(fixture.path("db.keyx"))
        .assert()
        .failure()
        .stderr(contains("already exists"));
}

#[test]
fn an_existing_key_file_can_be_protected() {
    let fixture = Fixture::new("from");
    fs::write(fixture.path("plain.key"), [9u8; 32]).unwrap();
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .args(["fido2", "enroll"])
        .arg(fixture.wrapped())
        .arg("--from")
        .arg(fixture.path("plain.key"))
        .assert()
        .success();
    fixture
        .cmd("", None)
        .arg("db-create")
        .arg(fixture.db())
        .args(["--kdf", "aes-kdf", "--password", PASSWORD, "--key-file"])
        .arg(fixture.path("plain.key"))
        .assert()
        .success();
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .arg("ls")
        .arg(fixture.db())
        .args(["--password", PASSWORD, "--key-file"])
        .arg(fixture.wrapped())
        .assert()
        .success();
}

#[test]
fn touch_only_when_asked() {
    let fixture = Fixture::new("nopin");
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .args(["fido2", "enroll", "--no-pin"])
        .arg(fixture.wrapped())
        .arg("--backup")
        .arg(fixture.path("db.keyx"))
        .assert()
        .success()
        .stdout(contains("unlocks with a touch"))
        .stderr(contains("anyone holding the security key"));
    fixture
        .cmd(&fixture.key_a(), None)
        .arg("db-create")
        .arg(fixture.db())
        .args(["--kdf", "aes-kdf", "--no-password", "--key-file"])
        .arg(fixture.wrapped())
        .assert()
        .success();
    // A key without a PIN at all enrolls with a touch too.
    let other = fixture.path("other.fido2");
    fixture
        .cmd(KEY_B, None)
        .args(["fido2", "enroll"])
        .arg(&other)
        .arg("--backup")
        .arg(fixture.path("other.keyx"))
        .assert()
        .success()
        .stdout(contains("unlocks with a touch"));
}

#[test]
fn a_changed_file_does_not_decrypt() {
    let fixture = Fixture::new("tamper");
    fixture.setup();
    let text = fs::read_to_string(fixture.wrapped()).unwrap();
    fs::write(
        fixture.wrapped(),
        text.replace("\"pin\": true", "\"pin\": false"),
    )
    .unwrap();
    fixture
        .show(&fixture.key_a(), Some(PIN), &fixture.wrapped())
        .failure()
        .stderr(contains("does not decrypt"));
}

#[test]
fn the_agent_needs_one_touch_at_unlock() {
    let fixture = Fixture::new("agent");
    fixture.setup();
    fixture
        .cmd(&fixture.key_a(), Some(PIN))
        .arg("unlock")
        .arg(fixture.db())
        .args(["--password", PASSWORD, "--key-file"])
        .arg(fixture.wrapped())
        .assert()
        .success();
    // No security key and no PIN, saves included.
    fixture
        .cmd("", None)
        .arg("add")
        .arg(fixture.db())
        .args(["Bank", "--username", "bob"])
        .assert()
        .success()
        .stderr(contains(TOUCH).not());
    fixture
        .cmd("", None)
        .arg("show")
        .arg(fixture.db())
        .arg("Bank")
        .assert()
        .success()
        .stdout(contains("bob"));
}

/// `keepassxcr yubikey serve` with emulated key A, until dropped.
struct Server(Child);

impl Server {
    fn start(fixture: &Fixture, socket: &Path) -> Self {
        let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin!("keepassxcr"))
            .env("HOME", &fixture.dir)
            .env("RUST_BACKTRACE", "0")
            .env("KEEPASSXCR_SOFTWARE_FIDO2", fixture.key_a())
            .env("KEEPASSXCR_FIDO2_PIN", PIN)
            .args(["yubikey", "serve", "--socket"])
            .arg(socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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
fn uses_a_security_key_forwarded_over_a_socket() {
    let fixture = Fixture::new("fwd");
    fixture.setup();
    let socket = fixture.path("yk.sock");
    let _server = Server::start(&fixture, &socket);
    // No key and no PIN on this side: the PIN is typed where the key is.
    fixture
        .cmd("", None)
        .env("KEEPASSXCR_YUBIKEY_SOCKET", &socket)
        .arg("show")
        .arg(fixture.db())
        .args(["Mail", "--password", PASSWORD, "--key-file"])
        .arg(fixture.wrapped())
        .assert()
        .success()
        .stdout(contains("alice"))
        .stderr(contains(
            "on the machine running 'keepassxcr yubikey serve'",
        ));
}
