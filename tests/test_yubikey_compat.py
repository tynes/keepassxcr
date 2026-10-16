"""Differential YubiKey tests: keepassxcr against upstream KeePassXC.

Both CLIs use a software YubiKey with the same secret: keepassxcr through its
`software-yubikey` test feature, keepassxc-cli built from upstream source with
only the device call replaced (see build-software-yubikey-keepassxc.sh). A
database written by either must open in the other, for KDBX 4 and 3.1, for
variable-length and fixed 64-byte slots, with and without a password.

Run with `just compat-yubikey`, or point KEEPASSXC_CLI_SOFTWARE_YUBIKEY at a
keepassxc-cli built by that script. Skipped otherwise.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from test_cli_compat import PROJECT_ROOT, CliResult, run_cli

UPSTREAM = os.environ.get("KEEPASSXC_CLI_SOFTWARE_YUBIKEY")
pytestmark = pytest.mark.skipif(
    not UPSTREAM,
    reason="KEEPASSXC_CLI_SOFTWARE_YUBIKEY is not set (run `just compat-yubikey`)",
)

PASSWORD = "yubikey-compat-password"
SECRET = "0102030405060708090a0b0c0d0e0f1011121314"
OTHER_SECRET = "1111111111111111111111111111111111111111"
FIXTURE = PROJECT_ROOT / "tests" / "data" / "keepass-rs" / "test_db_with_challenge_response_key.kdbx"


@pytest.fixture(scope="session")
def rust_yubikey_binary() -> Path:
    """keepassxcr with the software YubiKey, built apart from the release binary."""
    target = PROJECT_ROOT / "target" / "software-yubikey"
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "software-yubikey",
            "--target-dir",
            str(target),
        ],
        cwd=PROJECT_ROOT,
        check=True,
        timeout=600,
    )
    return target / "release" / "keepassxcr"


@pytest.fixture(scope="session")
def upstream_binary() -> Path:
    path = Path(UPSTREAM or "")
    assert path.is_file(), f"KEEPASSXC_CLI_SOFTWARE_YUBIKEY={UPSTREAM} does not exist"
    return path


def key_env(secret: str, mode: str) -> dict[str, str]:
    """The same software key for both CLIs."""
    rust_spec = f"{secret}:fixed" if mode == "fixed" else secret
    return {
        "KEEPASSXCR_SOFTWARE_YUBIKEY": rust_spec,
        "KPXC_TEST_YUBIKEY_SECRET": secret,
        "KPXC_TEST_YUBIKEY_MODE": mode,
        "QT_QPA_PLATFORM": "offscreen",
        "RUST_BACKTRACE": "0",
    }


def upstream(
    binary: Path,
    command: str,
    db: Path,
    *,
    options: tuple[str, ...] = (),
    entry: str | None = None,
    with_password: bool,
    env: dict[str, str],
) -> CliResult:
    """`keepassxc-cli <command> [--no-password] -y 2 [options] <db> [entry]`."""
    auth = [] if with_password else ["--no-password"]
    return run_cli(
        binary,
        [command, *auth, "-y", "2", *options, str(db), *([entry] if entry else [])],
        stdin_text=PASSWORD + "\n" if with_password else None,
        env=env,
    )


def rust(
    binary: Path,
    command: str,
    db: Path,
    *extra: str,
    with_password: bool,
    env: dict[str, str],
) -> CliResult:
    """`keepassxcr <command> <db> [args] <auth> -y 2`."""
    auth = ["--password", PASSWORD] if with_password else ["--no-password"]
    return run_cli(binary, [command, str(db), *extra, *auth, "-y", "2"], env=env)


CASES = [
    pytest.param(fmt, mode, with_password, id=f"kdbx{fmt}-{mode}-{label}")
    for fmt in ("4", "3")
    for mode in ("variable", "fixed")
    for with_password, label in ((True, "password"), (False, "yubikey-only"))
]


@pytest.mark.parametrize(("fmt", "mode", "with_password"), CASES)
def test_databases_open_in_both_directions(
    tmp_path, rust_yubikey_binary, upstream_binary, fmt, mode, with_password
):
    env = key_env(SECRET, mode)
    db = tmp_path / "yk.kdbx"
    kdf = ["--kdf", "aes-kdf"] if fmt == "3" else []
    assert rust(
        rust_yubikey_binary,
        "db-create",
        db,
        "--format",
        fmt,
        *kdf,
        with_password=with_password,
        env=env,
    ).exit_code == 0
    assert rust(
        rust_yubikey_binary,
        "add",
        db,
        "Mail",
        "--username",
        "alice",
        with_password=with_password,
        env=env,
    ).exit_code == 0

    # Upstream reads keepassxcr's file, then saves it with a new seed.
    shown = upstream(
        upstream_binary, "show", db, entry="Mail", with_password=with_password, env=env
    )
    assert shown.exit_code == 0, shown.stderr
    assert "alice" in shown.stdout
    added = upstream(
        upstream_binary,
        "add",
        db,
        options=("-u", "bob"),
        entry="Bank",
        with_password=with_password,
        env=env,
    )
    assert added.exit_code == 0, added.stderr

    # keepassxcr reads upstream's file and saves again; upstream reads that.
    shown = rust(rust_yubikey_binary, "show", db, "Bank", with_password=with_password, env=env)
    assert shown.exit_code == 0, shown.stderr
    assert "bob" in shown.stdout
    assert rust(
        rust_yubikey_binary,
        "add",
        db,
        "Shop",
        "--username",
        "carol",
        with_password=with_password,
        env=env,
    ).exit_code == 0
    listed = upstream(upstream_binary, "ls", db, with_password=with_password, env=env)
    assert listed.exit_code == 0, listed.stderr
    assert {"Mail", "Bank", "Shop"} <= set(listed.stdout.split())


@pytest.mark.parametrize("fmt", ["4", "3"])
def test_a_different_secret_opens_neither(tmp_path, rust_yubikey_binary, upstream_binary, fmt):
    db = tmp_path / "yk.kdbx"
    kdf = ["--kdf", "aes-kdf"] if fmt == "3" else []
    env = key_env(SECRET, "variable")
    assert rust(
        rust_yubikey_binary, "db-create", db, "--format", fmt, *kdf, with_password=True, env=env
    ).exit_code == 0
    wrong = key_env(OTHER_SECRET, "variable")
    assert upstream(upstream_binary, "ls", db, with_password=True, env=wrong).exit_code != 0
    assert rust(rust_yubikey_binary, "ls", db, with_password=True, env=wrong).exit_code != 0


def test_third_party_fixture_opens_in_both(rust_yubikey_binary, upstream_binary):
    """keepass-rs's YubiKey fixture (password demopass): checks the harness itself."""
    env = key_env(SECRET, "variable")
    upstream_result = run_cli(
        upstream_binary, ["ls", "-y", "2", str(FIXTURE)], stdin_text="demopass\n", env=env
    )
    rust_result = run_cli(
        rust_yubikey_binary,
        ["ls", str(FIXTURE), "--password", "demopass", "-y", "2"],
        env=env,
    )
    for result in (upstream_result, rust_result):
        assert result.exit_code == 0, result.stderr
        assert "entry1" in result.stdout
