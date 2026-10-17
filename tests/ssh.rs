//! End-to-end tests for `ssh-key-import`, `ssh-add` and `unlock --ssh-add`
//! against a real OpenSSH ssh-agent. Skipped when OpenSSH is not installed.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Stdio};
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

const PASSWORD: &str = "ssh-test-password";
const PASSPHRASE: &str = "key-passphrase";

fn openssh_available() -> bool {
    ["ssh-agent", "ssh-keygen", "ssh-add"].iter().all(|tool| {
        StdCommand::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .stdout(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

/// A database, a private ssh-agent and a private unlock-agent directory.
struct Fixture {
    dir: PathBuf,
    db: PathBuf,
    agent: Child,
}

impl Fixture {
    /// `None` when OpenSSH is missing, so the test is skipped.
    fn new(name: &str) -> Option<Self> {
        if !openssh_available() {
            eprintln!("skipping: OpenSSH is not installed");
            return None;
        }
        // Kept short: Unix socket paths are limited to about 100 bytes.
        let dir = std::env::temp_dir().join(format!("kxs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("run")).unwrap();
        fs::set_permissions(dir.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        let agent = StdCommand::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(dir.join("agent.sock"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if dir.join("agent.sock").exists() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let fixture = Self {
            db: dir.join("db.kdbx"),
            dir,
            agent,
        };
        fixture
            .cmd(&["db-create", "--kdf", "aes-kdf", "--password", PASSWORD])
            .assert()
            .success();
        Some(fixture)
    }

    /// `keepassxcr <args[0]> <db> <args[1..]>` with this fixture's agents.
    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("SSH_AUTH_SOCK", self.dir.join("agent.sock"))
            .env("RUST_BACKTRACE", "0")
            .arg(args[0])
            .arg(&self.db)
            .args(&args[1..])
            .write_stdin("");
        cmd
    }

    /// Generate a key file and an entry whose password is `passphrase`.
    fn key_entry(&self, title: &str, kind: &str, passphrase: &str) -> PathBuf {
        let key = self.dir.join(title.to_lowercase());
        let status = StdCommand::new("ssh-keygen")
            .args(["-q", "-t", kind, "-N", passphrase, "-C", title, "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(status.success());
        self.cmd(&["add", "--password", PASSWORD, title, "-p"])
            .write_stdin(format!("{passphrase}\n"))
            .assert()
            .success();
        key
    }

    fn import(&self, title: &str, key: &Path, extra: &[&str]) {
        self.cmd(&["ssh-key-import", "--password", PASSWORD, title])
            .arg(key)
            .args(extra)
            .assert()
            .success()
            .stdout(contains("Stored"));
    }

    /// `ssh-add -l` of the private agent.
    fn loaded(&self) -> String {
        let output = StdCommand::new("ssh-add")
            .arg("-l")
            .env("SSH_AUTH_SOCK", self.dir.join("agent.sock"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn fingerprint(key: &Path) -> String {
        let output = StdCommand::new("ssh-keygen")
            .arg("-lf")
            .arg(key.with_extension("pub"))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.split_whitespace().nth(1).unwrap().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = cargo_bin_cmd!("keepassxcr")
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .arg("lock")
            .ok();
        let _ = self.agent.kill();
        let _ = self.agent.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn adds_lists_and_removes_keys() {
    let Some(fx) = Fixture::new("add") else {
        return;
    };
    let ed25519 = fx.key_entry("Ed", "ed25519", PASSPHRASE);
    let ecdsa = fx.key_entry("Ec", "ecdsa", "");
    let rsa = fx.key_entry("Rsa", "rsa", "rsa-pass");
    fx.import("Ed", &ed25519, &[]);
    fx.import("Ec", &ecdsa, &[]);
    fx.import("Rsa", &rsa, &["--lifetime", "1h"]);

    fx.cmd(&["ssh-add", "--password", PASSWORD, "-l"])
        .assert()
        .success()
        .stdout(contains("Ed\tSHA256:"))
        .stdout(contains("not loaded"));

    fx.cmd(&["ssh-add", "--password", PASSWORD, "Ed", "Ec", "Rsa"])
        .assert()
        .success()
        .stdout(contains("expires in 1h00m"));
    let loaded = fx.loaded();
    for key in [&ed25519, &ecdsa, &rsa] {
        assert!(loaded.contains(&Fixture::fingerprint(key)), "{loaded}");
    }
    // The key's own comment is what ssh-agent shows.
    assert!(loaded.contains(" Ed (ED25519)"), "{loaded}");

    fx.cmd(&["ssh-add", "--password", PASSWORD, "-d", "Ed"])
        .assert()
        .success()
        .stdout(contains("Removed Ed"));
    assert!(!fx.loaded().contains(&Fixture::fingerprint(&ed25519)));

    fx.cmd(&["ssh-add", "--password", PASSWORD, "-d", "--all"])
        .assert()
        .success();
    assert!(!fx.loaded().contains("SHA256:"));
}

#[test]
fn import_requires_the_passphrase_as_entry_password() {
    let Some(fx) = Fixture::new("pass") else {
        return;
    };
    let key = fx.key_entry("Ed", "ed25519", PASSPHRASE);
    fx.cmd(&["edit", "--password", PASSWORD, "Ed", "-p"])
        .write_stdin("something else\n")
        .assert()
        .success();
    fx.cmd(&["ssh-key-import", "--password", PASSWORD, "Ed"])
        .arg(&key)
        .assert()
        .failure()
        .stderr(contains("passphrase"));
    fx.cmd(&["ssh-add", "--password", PASSWORD, "Ed"])
        .assert()
        .failure()
        .stderr(contains("no SSH key settings"));
}

#[test]
fn unlock_adds_keys_and_lock_removes_them() {
    let Some(fx) = Fixture::new("unlock") else {
        return;
    };
    let removed = fx.key_entry("Removed", "ed25519", PASSPHRASE);
    let kept = fx.key_entry("Kept", "ed25519", "");
    let manual = fx.key_entry("Manual", "ed25519", "");
    fx.import("Removed", &removed, &[]);
    fx.import("Kept", &kept, &["--keep-on-lock"]);
    fx.import("Manual", &manual, &["--no-add-on-unlock"]);

    fx.cmd(&["unlock", "--ssh-add", "--max", "2h"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success()
        .stdout(contains("Added SSH key Removed"))
        .stdout(contains("removed on lock, expires in 1h59m"));
    let loaded = fx.loaded();
    assert!(loaded.contains(&Fixture::fingerprint(&removed)), "{loaded}");
    assert!(loaded.contains(&Fixture::fingerprint(&kept)), "{loaded}");
    assert!(!loaded.contains(&Fixture::fingerprint(&manual)), "{loaded}");

    // Added while unlocked, so it goes on lock too.
    fx.cmd(&["ssh-add", "Manual"]).assert().success();

    fx.cmd(&["lock"]).assert().success();
    let loaded = fx.loaded();
    assert!(
        !loaded.contains(&Fixture::fingerprint(&removed)),
        "{loaded}"
    );
    assert!(!loaded.contains(&Fixture::fingerprint(&manual)), "{loaded}");
    assert!(loaded.contains(&Fixture::fingerprint(&kept)), "{loaded}");
}

#[test]
fn expiry_removes_keys() {
    let Some(fx) = Fixture::new("expiry") else {
        return;
    };
    let key = fx.key_entry("Ed", "ed25519", "");
    fx.import("Ed", &key, &[]);
    fx.cmd(&["unlock", "--ssh-add", "--idle", "1s"])
        .write_stdin(format!("{PASSWORD}\n"))
        .assert()
        .success();
    assert!(fx.loaded().contains(&Fixture::fingerprint(&key)));
    thread::sleep(Duration::from_secs(4));
    assert!(!fx.loaded().contains(&Fixture::fingerprint(&key)));
}

/// Settings exactly as KeePassXC 2.7 writes them (UTF-16LE with a BOM), with
/// the key in a differently named attachment.
#[test]
fn uses_settings_written_by_keepassxc() {
    let Some(fx) = Fixture::new("kpxc") else {
        return;
    };
    let key = fx.key_entry("Server", "ed25519", PASSPHRASE);
    let text = [
        r#"<?xml version="1.0" encoding="UTF-16"?>"#,
        r#"<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#,
        "  <AllowUseOfSshKey>true</AllowUseOfSshKey>",
        "  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>",
        "  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>",
        "  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>",
        "  <UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding>",
        "  <LifetimeConstraintDuration>120</LifetimeConstraintDuration>",
        "  <Location>",
        "    <SelectedType>attachment</SelectedType>",
        "    <AttachmentName>server-key</AttachmentName>",
        "    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>",
        "    <FileName/>",
        "  </Location>",
        "</EntrySettings>",
        "",
    ]
    .join("\n");
    let mut settings = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        settings.extend_from_slice(&unit.to_le_bytes());
    }
    let settings_path = fx.dir.join("KeeAgent.settings");
    fs::write(&settings_path, settings).unwrap();
    for (name, path) in [
        ("server-key", key.as_path()),
        ("KeeAgent.settings", &settings_path),
    ] {
        fx.cmd(&["attachment-import", "--password", PASSWORD, "Server", name])
            .arg(path)
            .assert()
            .success();
    }

    fx.cmd(&["ssh-add", "--password", PASSWORD, "--all"])
        .assert()
        .success()
        .stdout(contains("Added Server"))
        .stdout(contains("expires in 2m"));
    assert!(fx.loaded().contains(&Fixture::fingerprint(&key)));
}
