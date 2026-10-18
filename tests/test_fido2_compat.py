"""FIDO2-protected key files keep databases compatible with KeePassXC.

keepassxcr opens the database with the key file it decrypts with an emulated
security key; keepassxc-cli opens the same database with the plain key file.
Both directions are checked: a key file keepassxcr generates, and one
keepassxc-cli generates and keepassxcr then protects.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from test_cli_compat import PROJECT_ROOT, original_binary, run_cli  # noqa: F401

PASSWORD = "fido2-compat-password"
KEY = "0303030303030303030303030303030303030303030303030303030303030303:pin=1234"
ENV = {
    "KEEPASSXCR_SOFTWARE_FIDO2": KEY,
    "KEEPASSXCR_FIDO2_PIN": "1234",
    "QT_QPA_PLATFORM": "offscreen",
    "RUST_BACKTRACE": "0",
}


@pytest.fixture(scope="session")
def rust_fido2_binary() -> Path:
    """keepassxcr with emulated security keys, built apart from the release binary."""
    target = PROJECT_ROOT / "target" / "software-fido2"
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "software-fido2",
            "--target-dir",
            str(target),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        timeout=600,
    )
    return target / "release" / "keepassxcr"


def rust(binary: Path, *args: str):
    return run_cli(binary, list(args), env=ENV)


def upstream(binary: Path, command: str, db: Path, key_file: Path, *rest: str):
    return run_cli(
        binary,
        [command, "-k", str(key_file), str(db), *rest],
        stdin_text=PASSWORD + "\n",
        env=ENV,
    )


def test_keepassxc_opens_a_database_made_with_a_protected_key_file(
    tmp_path, rust_fido2_binary, original_binary  # noqa: F811
):
    wrapped, backup, db = tmp_path / "db.keyx.fido2", tmp_path / "db.keyx", tmp_path / "db.kdbx"
    assert rust(rust_fido2_binary, "fido2", "enroll", str(wrapped), "--backup", str(backup)).exit_code == 0
    created = rust(
        rust_fido2_binary, "db-create", str(db), "--password", PASSWORD, "--key-file", str(wrapped)
    )
    assert created.exit_code == 0, created.stderr
    added = rust(
        rust_fido2_binary, "add", str(db), "Mail", "--username", "alice",
        "--password", PASSWORD, "--key-file", str(wrapped),
    )
    assert added.exit_code == 0, added.stderr

    shown = upstream(original_binary, "show", db, backup, "Mail")
    assert shown.exit_code == 0, shown.stderr
    assert "alice" in shown.stdout
    saved = upstream(original_binary, "add", db, backup, "-u", "bob", "Bank")
    assert saved.exit_code == 0, saved.stderr

    shown = rust(
        rust_fido2_binary, "show", str(db), "Bank", "--password", PASSWORD, "--key-file", str(wrapped)
    )
    assert shown.exit_code == 0, shown.stderr
    assert "bob" in shown.stdout


def test_a_keepassxc_key_file_can_be_protected(tmp_path, rust_fido2_binary, original_binary):  # noqa: F811
    plain, wrapped, db = tmp_path / "kpxc.keyx", tmp_path / "kpxc.keyx.fido2", tmp_path / "db.kdbx"
    created = run_cli(
        original_binary,
        ["db-create", "-p", "--set-key-file", str(plain), str(db)],
        stdin_text=f"{PASSWORD}\n{PASSWORD}\n",
        env=ENV,
    )
    assert created.exit_code == 0, created.stderr
    assert plain.is_file()
    assert rust(rust_fido2_binary, "fido2", "enroll", str(wrapped), "--from", str(plain)).exit_code == 0
    listed = rust(
        rust_fido2_binary, "ls", str(db), "--password", PASSWORD, "--key-file", str(wrapped)
    )
    assert listed.exit_code == 0, listed.stderr
