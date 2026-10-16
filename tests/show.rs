//! `show -a` prints raw attribute values, like keepassxc-cli.

use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;

const PASSWORD: &str = "show-test-password";

#[test]
fn show_attributes_prints_only_the_values() {
    let dir = std::env::temp_dir().join(format!("kxs-{}", std::process::id()));
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
    run()
        .arg("add")
        .arg(&db)
        .args([
            "Api",
            "--username",
            "alice",
            "--notes",
            "Password: decoy",
            "-p",
        ])
        .args(["--password", PASSWORD])
        .write_stdin("s3cret\n")
        .assert()
        .success();

    run()
        .arg("show")
        .arg(&db)
        .args(["Api", "-q", "-a", "Password", "--attributes", "username"])
        .args(["--password", PASSWORD])
        .assert()
        .success()
        .stdout("s3cret\nalice\n");
    run()
        .arg("show")
        .arg(&db)
        .args(["Api", "-a", "Nope", "--password", PASSWORD])
        .assert()
        .failure();

    let _ = fs::remove_dir_all(&dir);
}
