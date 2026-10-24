"""KeePassXC compatibility of FIDO2 (hmac-secret) databases.

keepassxcr puts the FIDO2 device's secret in the key-file slot of the
composite key and keeps the device's settings in the KDBX 4 PublicCustomData
header. These tests check both halves against the real keepassxc-cli: given
the same secret as a key file, KeePassXC opens the database, and when it
saves a change it keeps the settings, so keepassxcr still opens the file with
the device.

keepassxcr runs with its `software-fido2` emulated device, whose secret this
file recomputes from the header to hand KeePassXC as a key file.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import subprocess
from pathlib import Path

import pytest

from test_cli_compat import PROJECT_ROOT, run_cli
from test_cli_compat import original_binary  # noqa: F401  (pytest fixture)

PASSWORD = "fido2-compat-password"
SEED = "000102030405060708090a0b0c0d0e0f"
PUBLIC_CUSTOM_DATA = 12
END_OF_HEADER = 0


@pytest.fixture(scope="session")
def rust_fido2_binary() -> Path:
    """keepassxcr with the software FIDO2 device, built apart from the release binary."""
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


def public_custom_data(db_path: Path) -> dict[str, bytes | str | int]:
    """The KDBX 4 PublicCustomData variant map of a database."""
    data = db_path.read_bytes()
    offset = 12  # Two signatures and the version.
    while True:
        field_id = data[offset]
        (length,) = struct.unpack_from("<I", data, offset + 1)
        value = data[offset + 5 : offset + 5 + length]
        offset += 5 + length
        if field_id == PUBLIC_CUSTOM_DATA:
            return parse_variant_map(value)
        if field_id == END_OF_HEADER:
            return {}


def parse_variant_map(data: bytes) -> dict[str, bytes | str | int]:
    """Parse a KDBX variant map: byte arrays, strings and unsigned ints."""
    entries: dict[str, bytes | str | int] = {}
    offset = 2  # Version.
    while data[offset] != 0:
        kind = data[offset]
        (name_len,) = struct.unpack_from("<I", data, offset + 1)
        name = data[offset + 5 : offset + 5 + name_len].decode()
        offset += 5 + name_len
        (value_len,) = struct.unpack_from("<I", data, offset)
        value = data[offset + 4 : offset + 4 + value_len]
        offset += 4 + value_len
        if kind == 0x18:
            entries[name] = value.decode()
        elif kind in (0x04, 0x05):
            entries[name] = int.from_bytes(value, "little")
        else:
            entries[name] = value
    return entries


def emulated_secret(db_path: Path) -> bytes:
    """The secret the emulated device derives for this database (see src/fido2/emulator.rs)."""
    settings = public_custom_data(db_path)
    credential_id = settings["KPXCR_FIDO2_CREDENTIAL_ID"]
    salt = settings["KPXCR_FIDO2_SALT"]
    assert isinstance(credential_id, bytes) and isinstance(salt, bytes)
    master = bytes.fromhex(SEED)
    cred_random = hmac.new(master, b"cred" + credential_id, hashlib.sha256).digest()
    return hmac.new(cred_random, salt, hashlib.sha256).digest()


def rust(binary: Path, args: list[str]):
    return run_cli(binary, args, env={"KEEPASSXCR_SOFTWARE_FIDO2": SEED})


def test_keepassxc_opens_and_keeps_a_fido2_database(
    rust_fido2_binary: Path, original_binary: Path, tmp_path: Path  # noqa: F811
) -> None:
    db = tmp_path / "fido2.kdbx"
    auth = ["--password", PASSWORD, "--fido2"]
    r = rust(rust_fido2_binary, ["db-create", str(db), "--kdf", "aes-kdf", *auth])
    assert r.exit_code == 0, r.stderr
    r = rust(rust_fido2_binary, ["add", str(db), "FromKeepassxcr", *auth])
    assert r.exit_code == 0, r.stderr

    settings = public_custom_data(db)
    assert settings["KPXCR_FIDO2_VERSION"] == 1
    assert settings["KPXCR_FIDO2_RP_ID"] == "keepassxcr"

    # KeePassXC reads a 32-byte key file as the raw key.
    key_file = tmp_path / "secret.key"
    key_file.write_bytes(emulated_secret(db))

    r = run_cli(
        original_binary,
        ["ls", "--key-file", str(key_file), str(db)],
        stdin_text=PASSWORD + "\n",
    )
    assert r.exit_code == 0, r.stderr
    assert "FromKeepassxcr" in r.stdout

    # A save by KeePassXC.
    r = run_cli(
        original_binary,
        ["mkdir", "--key-file", str(key_file), str(db), "FromKeepassxc"],
        stdin_text=PASSWORD + "\n",
    )
    assert r.exit_code == 0, r.stderr

    assert public_custom_data(db).items() >= settings.items()
    r = rust(rust_fido2_binary, ["ls", str(db), *auth])
    assert r.exit_code == 0, r.stderr
    assert "FromKeepassxcr" in r.stdout
    assert "FromKeepassxc/" in r.stdout


def test_wrong_key_file_is_rejected_by_keepassxc(
    rust_fido2_binary: Path, original_binary: Path, tmp_path: Path  # noqa: F811
) -> None:
    db = tmp_path / "fido2.kdbx"
    r = rust(
        rust_fido2_binary,
        ["db-create", str(db), "--kdf", "aes-kdf", "--password", PASSWORD, "--fido2"],
    )
    assert r.exit_code == 0, r.stderr
    key_file = tmp_path / "wrong.key"
    key_file.write_bytes(bytes(32))
    r = run_cli(
        original_binary,
        ["ls", "--key-file", str(key_file), str(db)],
        stdin_text=PASSWORD + "\n",
    )
    assert r.exit_code != 0
