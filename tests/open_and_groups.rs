//! `add` into a missing group names the group, and `open` survives errors.

use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::str::contains;

const PASSWORD: &str = "open-test-password";

#[test]
fn missing_group_errors_and_open_keeps_going() {
    let dir = std::env::temp_dir().join(format!("kxo-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let db = dir.join("db.kdbx");
    let run = || {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", &dir).env("RUST_BACKTRACE", "0");
        cmd
    };

    run()
        .args(["db-create", "--kdf", "aes-kdf", "--password", PASSWORD])
        .arg(&db)
        .assert()
        .success();

    // The parent group does not exist yet.
    run()
        .arg("add")
        .arg(&db)
        .args(["Email/Gmail", "--username", "a@example.com"])
        .args(["--password", PASSWORD])
        .assert()
        .failure()
        .stderr(contains("group not found: Email"))
        .stderr(contains("keepassxcr mkdir"));

    // After mkdir, the same add works.
    run()
        .arg("mkdir")
        .arg(&db)
        .args(["Email", "--password", PASSWORD])
        .assert()
        .success();
    run()
        .arg("add")
        .arg(&db)
        .args(["Email/Gmail", "--username", "a@example.com"])
        .args(["--password", PASSWORD])
        .assert()
        .success();

    // A failing command in `open` prints its error and the prompt keeps going.
    run()
        .arg("open")
        .arg(&db)
        .args(["--password", PASSWORD])
        .write_stdin("ls Nope\nshow Missing\nls Email\n")
        .assert()
        .success()
        .stderr(contains("group not found: Nope"))
        .stderr(contains("entry not found"))
        .stdout(contains("[E] Gmail"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn database_names_without_an_extension_use_kdbx() {
    let dir = std::env::temp_dir().join(format!("kxe-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let run = || {
        let mut cmd = cargo_bin_cmd!("keepassxcr");
        cmd.env("XDG_RUNTIME_DIR", &dir).env("RUST_BACKTRACE", "0");
        cmd
    };

    run()
        .args(["db-create", "--kdf", "aes-kdf", "--password", PASSWORD])
        .arg(dir.join("vault"))
        .assert()
        .success()
        .stdout(contains("vault.kdbx"));
    assert!(dir.join("vault.kdbx").is_file());
    assert!(!dir.join("vault").exists());

    // Reads and writes by the same short name reach the same file.
    run()
        .arg("mkdir")
        .arg(dir.join("vault"))
        .args(["Email", "--password", PASSWORD])
        .assert()
        .success();
    run()
        .arg("ls")
        .arg(dir.join("vault.kdbx"))
        .args(["--password", PASSWORD])
        .assert()
        .success()
        .stdout(contains("[G] Email"));

    let _ = fs::remove_dir_all(&dir);
}
