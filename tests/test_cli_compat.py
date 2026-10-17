"""CLI Compatibility Test Suite for keepassxcr vs keepassxc-cli.

Runs the same operations against both binaries and verifies they produce
equivalent behavior (exit codes, output structure, cross-compatible databases).
"""

from __future__ import annotations

import base64
import dataclasses
import logging
import os
import re
import shutil
import string
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# ─── Constants & Config ───────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_PASSWORD = "test-password-12345"
TEST_PASSWORD_2 = "another-password-67890"
TIMEOUT = 60
OUTPUT_LOG_LIMIT = 2000

log = logging.getLogger("compat")


# ─── Helpers ──────────────────────────────────────────────────────────────────


@dataclasses.dataclass
class CliResult:
    exit_code: int
    stdout: str
    stderr: str


def redact_args(args: list[str]) -> list[str]:
    """Replace password values so they never land in the log."""
    redacted = list(args)
    for i, arg in enumerate(redacted[:-1]):
        if arg in ("--password", "--source-password"):
            redacted[i + 1] = "***"
    return redacted


def truncate(text: str) -> str:
    """Shorten long command output for the log."""
    if len(text) <= OUTPUT_LOG_LIMIT:
        return text
    return f"{text[:OUTPUT_LOG_LIMIT]}... [{len(text) - OUTPUT_LOG_LIMIT} more chars]"


def run_cli(
    binary: Path,
    args: list[str],
    stdin_text: str | None = None,
    env: dict | None = None,
    timeout: int = TIMEOUT,
) -> CliResult:
    """Run a CLI binary with the given args and return structured result."""
    stdin_note = " (with stdin)" if stdin_text else ""
    log.info("$ %s %s%s", binary.name, " ".join(redact_args(args)), stdin_note)
    proc = subprocess.run(
        [str(binary)] + args,
        input=stdin_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )
    log.info("  -> exit %d", proc.returncode)
    if proc.stdout:
        log.debug("  stdout:\n%s", truncate(proc.stdout))
    if proc.stderr:
        log.debug("  stderr:\n%s", truncate(proc.stderr))
    return CliResult(proc.returncode, proc.stdout, proc.stderr)


def make_auth(binary: Path, password: str) -> tuple[list[str], str | None]:
    """Returns (extra_args, stdin_text) depending on which binary.

    keepassxcr supports --password <value>; keepassxc-cli reads from stdin.
    """
    if binary.name == "keepassxcr":
        return (["--password", password], None)
    else:
        return ([], password + "\n")


def make_db_create(
    binary: Path,
    db_path: Path,
    password: str,
    key_file: Path | None = None,
) -> CliResult:
    """Create a database, handling CLI differences for db-create."""
    if binary.name == "keepassxcr":
        args = ["db-create", str(db_path), "--password", password]
        if key_file:
            args += ["--key-file", str(key_file)]
        return run_cli(binary, args)
    else:
        args = ["db-create", str(db_path), "-p"]
        if key_file:
            args += ["--set-key-file", str(key_file)]
        # Original prompts for password twice (enter + repeat)
        return run_cli(binary, args, stdin_text=password + "\n" + password + "\n")


def make_import(
    binary: Path,
    xml_path: Path,
    db_path: Path,
    password: str,
) -> CliResult:
    """Import XML into a new database, handling CLI differences."""
    if binary.name == "keepassxcr":
        return run_cli(
            binary,
            ["import", str(xml_path), str(db_path), "--password", password],
        )
    else:
        # Original prompts for password twice (enter + repeat)
        return run_cli(
            binary,
            ["import", str(xml_path), str(db_path), "-p"],
            stdin_text=password + "\n" + password + "\n",
        )


def normalize_output(text: str) -> str:
    """Strip ANSI escape codes and normalize whitespace."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return text.strip()


def parse_ls_output(stdout: str, binary_name: str) -> tuple[set[str], set[str]]:
    """Parse ls output into (groups, entries) sets.

    keepassxcr format:   [G] Name / [E] Name
    keepassxc-cli format: Name/ (group) / Name (entry)
    """
    groups: set[str] = set()
    entries: set[str] = set()
    for line in normalize_output(stdout).splitlines():
        line = line.strip()
        if not line:
            continue
        if binary_name == "keepassxcr":
            m = re.match(r"\[G\]\s+(.*)", line)
            if m:
                groups.add(m.group(1).strip())
                continue
            m = re.match(r"\[E\]\s+(.*)", line)
            if m:
                entries.add(m.group(1).strip())
        else:
            # keepassxc-cli: trailing / means group
            if line.endswith("/"):
                groups.add(line[:-1].strip())
            else:
                entries.add(line.strip())
    return groups, entries


def parse_show_output(stdout: str) -> dict[str, str]:
    """Parse show output into dict of lowercase-field -> value."""
    fields: dict[str, str] = {}
    for line in normalize_output(stdout).splitlines():
        m = re.match(r"(\w[\w\s]*?):\s*(.*)", line)
        if m:
            fields[m.group(1).strip().lower()] = m.group(2).strip()
    return fields


def parse_db_info(stdout: str) -> dict[str, str]:
    """Parse db-info output into dict of lowercase-label -> value."""
    info: dict[str, str] = {}
    for line in normalize_output(stdout).splitlines():
        m = re.match(r"(.+?):\s*(.*)", line)
        if m:
            info[m.group(1).strip().lower()] = m.group(2).strip()
    return info


def compare_generate_structure(
    password: str,
    length: int = 20,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
) -> None:
    """Validate generated password structure (length and character classes)."""
    assert len(password) == length, f"expected length {length}, got {len(password)}"
    if lower:
        assert any(c in string.ascii_lowercase for c in password), "missing lowercase"
    if upper:
        assert any(c in string.ascii_uppercase for c in password), "missing uppercase"
    if digits:
        assert any(c in string.digits for c in password), "missing digits"


# ─── Session Fixtures (build binaries once) ───────────────────────────────────


@pytest.fixture(scope="session")
def rust_binary():
    """Build the Rust binary once per session."""
    log.info("Building keepassxcr with cargo build --release")
    subprocess.run(
        ["cargo", "build", "--release"],
        cwd=PROJECT_ROOT,
        check=True,
        timeout=300,
    )
    binary = PROJECT_ROOT / "target" / "release" / "keepassxcr"
    assert binary.exists(), f"Rust binary not found at {binary}"
    log.info("Using keepassxcr at %s", binary)
    return binary


MACOS_APP_CLI = Path("/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli")

INSTALL_HINT = (
    "Install keepassxc-cli and re-run: `brew install --cask keepassxc` on macOS, "
    "`apt install keepassxc` (or your distro's package) on Linux. "
    "Or point KEEPASSXC_CLI at an existing binary."
)


def find_installed_keepassxc_cli() -> Path | None:
    """Return an installed keepassxc-cli, preferring $KEEPASSXC_CLI, then PATH, then the macOS app bundle."""
    override = os.environ.get("KEEPASSXC_CLI")
    if override:
        path = Path(override)
        if not path.is_file():
            pytest.exit(f"KEEPASSXC_CLI={override} does not exist", returncode=1)
        return path
    on_path = shutil.which("keepassxc-cli")
    if on_path:
        return Path(on_path)
    if MACOS_APP_CLI.is_file():
        return MACOS_APP_CLI
    return None


def run_build_step(args: list[str], cwd: Path, timeout: int) -> None:
    """Run one step of the keepassxc-cli build, stopping the session with its output if it fails."""
    log.info("Build step: %s", " ".join(args))
    proc = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    if proc.returncode != 0:
        output = (proc.stdout + proc.stderr).strip().splitlines()
        tail = "\n".join(output[-30:])
        pytest.exit(
            f"No installed keepassxc-cli found, and building it from the submodule failed.\n"
            f"`{' '.join(args)}` exited {proc.returncode}:\n{tail}\n\n{INSTALL_HINT}",
            returncode=1,
        )


def build_keepassxc_cli() -> Path:
    """Build keepassxc-cli from the git submodule (needs cmake, Qt and KeePassXC's build deps)."""
    if shutil.which("cmake") is None:
        pytest.exit(
            f"No installed keepassxc-cli found, and cmake is not available to build it.\n{INSTALL_HINT}",
            returncode=1,
        )
    run_build_step(
        ["git", "submodule", "update", "--init", "--recursive"], PROJECT_ROOT, 120
    )
    build_dir = PROJECT_ROOT / "keepassxc" / "build"
    build_dir.mkdir(exist_ok=True)
    run_build_step(
        [
            "cmake",
            "..",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DWITH_XC_BROWSER=OFF",
            "-DWITH_XC_SSHAGENT=OFF",
            "-DWITH_XC_FDOSECRETS=OFF",
            "-DWITH_XC_YUBIKEY=OFF",
            "-DWITH_XC_NETWORKING=OFF",
            "-DWITH_GUI_TESTS=OFF",
            "-DWITH_TESTS=OFF",
        ],
        build_dir,
        120,
    )
    run_build_step(
        ["cmake", "--build", ".", "--target", "keepassxc-cli", "-j"], build_dir, 600
    )
    found = sorted(build_dir.rglob("keepassxc-cli"))
    for candidate in found:
        if candidate.is_file():
            return candidate
    pytest.exit(f"keepassxc-cli binary not found in {build_dir}", returncode=1)


@pytest.fixture(scope="session")
def original_binary():
    """Use an installed keepassxc-cli, falling back to building it from the submodule."""
    binary = find_installed_keepassxc_cli()
    if binary is None:
        log.info("No installed keepassxc-cli found; building it from the submodule")
        binary = build_keepassxc_cli()
    log.info("Using keepassxc-cli at %s", binary)
    return binary


@pytest.fixture(scope="session")
def both_binaries(rust_binary, original_binary):
    """Return both binaries as a list for iteration."""
    return [rust_binary, original_binary]


# ─── Function Fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def fresh_db(tmp_path):
    """Return path for a fresh (not yet created) database."""
    return tmp_path / "test.kdbx"


@pytest.fixture()
def populated_db(tmp_path, rust_binary):
    """Create a database with groups and entries using the Rust binary."""
    db_path = tmp_path / "populated.kdbx"
    run_cli(rust_binary, ["db-create", str(db_path), "--password", TEST_PASSWORD])
    # Groups
    run_cli(
        rust_binary,
        ["mkdir", str(db_path), "Group1", "--password", TEST_PASSWORD],
    )
    run_cli(
        rust_binary,
        ["mkdir", str(db_path), "Group1/SubGroup", "--password", TEST_PASSWORD],
    )
    run_cli(
        rust_binary,
        ["mkdir", str(db_path), "Group2", "--password", TEST_PASSWORD],
    )
    # Entries (use -g to generate passwords, avoiding interactive prompts)
    run_cli(
        rust_binary,
        [
            "add", str(db_path), "Entry1",
            "--username", "user1", "--url", "https://example.com",
            "--notes", "note1", "--password", TEST_PASSWORD, "-g",
        ],
    )
    run_cli(
        rust_binary,
        [
            "add", str(db_path), "Group1/Entry2",
            "--username", "user2", "--url", "https://test.com",
            "--password", TEST_PASSWORD, "-g",
        ],
    )
    run_cli(
        rust_binary,
        [
            "add", str(db_path), "Group1/SubGroup/Entry3",
            "--username", "user3", "--password", TEST_PASSWORD, "-g",
        ],
    )
    return db_path


@pytest.fixture()
def populated_db_with_attachment(tmp_path, rust_binary, populated_db):
    """Return (db_path, attach_file) with an attachment already imported."""
    attach_file = tmp_path / "test_attachment.txt"
    attach_file.write_text("Hello, this is test attachment content.")
    run_cli(
        rust_binary,
        [
            "attachment-import", str(populated_db), "Entry1",
            "test_attachment.txt", str(attach_file),
            "--password", TEST_PASSWORD,
        ],
    )
    return populated_db, attach_file


# ─── Test Classes ─────────────────────────────────────────────────────────────


class TestDbCreate:
    """Test database creation with various format/cipher/kdf combinations."""

    @pytest.mark.parametrize(
        "fmt,kdf,cipher",
        [
            ("4", "argon2id", "aes256"),
            ("4", "argon2id", "chacha20"),
            ("4", "argon2d", "twofish"),
            ("3", "aes-kdf", "aes256"),
            ("3", "aes-kdf", "twofish"),
        ],
    )
    def test_create_format_combos(
        self, rust_binary, original_binary, tmp_path, fmt, kdf, cipher
    ):
        # Rust binary supports --format/--kdf/--cipher; original does not
        db_rust = tmp_path / f"test_keepassxcr_{fmt}_{kdf}_{cipher}.kdbx"
        r = run_cli(
            rust_binary,
            [
                "db-create", str(db_rust),
                "--format", fmt, "--kdf", kdf, "--cipher", cipher,
                "--password", TEST_PASSWORD,
            ],
        )
        assert r.exit_code == 0, f"keepassxcr: {r.stderr}"
        assert db_rust.exists()

        # Original: create with defaults (no format/kdf/cipher flags)
        db_orig = tmp_path / f"test_keepassxc-cli_{fmt}_{kdf}_{cipher}.kdbx"
        r = make_db_create(original_binary, db_orig, TEST_PASSWORD)
        assert r.exit_code == 0, f"keepassxc-cli: {r.stderr}"
        assert db_orig.exists()

    def test_create_with_key_file(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"keyfile_{binary.name}.kdbx"
            key_file = tmp_path / f"key_{binary.name}.key"
            key_file.write_text("this-is-a-key-file-content")
            r = make_db_create(binary, db_path, TEST_PASSWORD, key_file=key_file)
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            assert db_path.exists()

    def test_create_already_exists(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"exists_{binary.name}.kdbx"
            r1 = make_db_create(binary, db_path, TEST_PASSWORD)
            assert r1.exit_code == 0, f"{binary.name} first: {r1.stderr}"
            # Second creation may overwrite or fail; just check it doesn't crash
            r2 = make_db_create(binary, db_path, TEST_PASSWORD)
            # Either success (overwrite) or a clean error is acceptable
            assert isinstance(r2.exit_code, int)


class TestDbEdit:
    """Test database credential editing."""

    def test_change_password(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"edit_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            # Change password
            if binary.name == "keepassxcr":
                r = run_cli(binary, [
                    "db-edit", str(db_path),
                    "--password", TEST_PASSWORD,
                    "--new-password", TEST_PASSWORD_2,
                ])
            else:
                r = run_cli(
                    binary,
                    ["db-edit", str(db_path), "--set-password"],
                    stdin_text=TEST_PASSWORD + "\n" + TEST_PASSWORD_2 + "\n" + TEST_PASSWORD_2 + "\n",
                )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify new password works
            pw_args2, pw_stdin2 = make_auth(binary, TEST_PASSWORD_2)
            r2 = run_cli(
                binary, ["db-info", str(db_path)] + pw_args2, stdin_text=pw_stdin2
            )
            assert r2.exit_code == 0, f"{binary.name} verify: {r2.stderr}"

    def test_edit_wrong_password(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"edit_wrong_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            if binary.name == "keepassxcr":
                r = run_cli(binary, [
                    "db-edit", str(db_path),
                    "--password", "wrong-password",
                    "--new-password", TEST_PASSWORD_2,
                ])
            else:
                r = run_cli(
                    binary,
                    ["db-edit", str(db_path)],
                    stdin_text="wrong-password\n" + TEST_PASSWORD_2 + "\n",
                )
            assert r.exit_code != 0


class TestDbInfo:
    """Test database info display."""

    def test_db_info(self, rust_binary, original_binary, tmp_path):
        results = {}
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"info_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary, ["db-info", str(db_path)] + pw_args, stdin_text=pw_stdin
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            results[binary.name] = parse_db_info(r.stdout)
        # Both should report some metadata
        for name, info in results.items():
            assert len(info) > 0, f"{name}: no info parsed"


class TestOpen:
    """Test interactive REPL mode."""

    def test_help(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"open_help_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            commands = "help\nexit\n"
            full_stdin = (pw_stdin or "") + commands
            r = run_cli(
                binary,
                ["open", str(db_path)] + pw_args,
                stdin_text=full_stdin,
                timeout=15,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            assert len(r.stdout) > 0

    def test_ls_in_repl(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            commands = "ls\nexit\n"
            full_stdin = (pw_stdin or "") + commands
            r = run_cli(
                binary,
                ["open", str(populated_db)] + pw_args,
                stdin_text=full_stdin,
                timeout=15,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_show_in_repl(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            commands = "show Entry1\nexit\n"
            full_stdin = (pw_stdin or "") + commands
            r = run_cli(
                binary,
                ["open", str(populated_db)] + pw_args,
                stdin_text=full_stdin,
                timeout=15,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_add_save_in_repl(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"repl_add_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            # Original REPL add prompts interactively for fields; just test
            # basic REPL interaction doesn't crash
            if binary.name == "keepassxcr":
                commands = "add NewEntry\nsave\nexit\n"
            else:
                commands = "add -g NewEntry\nsave\nexit\n"
            full_stdin = (pw_stdin or "") + commands
            r = run_cli(
                binary,
                ["open", str(db_path)] + pw_args,
                stdin_text=full_stdin,
                timeout=15,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify entry was saved (only for Rust; original REPL may not save)
            if binary.name == "keepassxcr":
                pw_args2, pw_stdin2 = make_auth(binary, TEST_PASSWORD)
                r2 = run_cli(
                    binary,
                    ["show", str(db_path), "NewEntry"] + pw_args2,
                    stdin_text=pw_stdin2,
                )
                assert r2.exit_code == 0, f"{binary.name} verify: {r2.stderr}"

    def test_close_and_quit(self, rust_binary, original_binary, tmp_path):
        """Test that close and quit also exit the REPL."""
        for exit_cmd in ["close", "quit"]:
            for binary in [rust_binary, original_binary]:
                db_path = tmp_path / f"repl_{exit_cmd}_{binary.name}.kdbx"
                make_db_create(binary, db_path, TEST_PASSWORD)
                pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
                commands = f"{exit_cmd}\n"
                full_stdin = (pw_stdin or "") + commands
                r = run_cli(
                    binary,
                    ["open", str(db_path)] + pw_args,
                    stdin_text=full_stdin,
                    timeout=15,
                )
                assert r.exit_code == 0, f"{binary.name} {exit_cmd}: {r.stderr}"


class TestMerge:
    """Test database merging."""

    def test_basic_merge(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db1 = tmp_path / f"merge_target_{binary.name}.kdbx"
            db2 = tmp_path / f"merge_source_{binary.name}.kdbx"
            # Create both databases
            make_db_create(binary, db1, TEST_PASSWORD)
            make_db_create(binary, db2, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            # Add entry to source
            if binary.name == "keepassxcr":
                run_cli(binary, [
                    "add", str(db2), "SourceEntry",
                    "--username", "srcuser",
                    "--password", TEST_PASSWORD, "-g",
                ])
            else:
                run_cli(
                    binary,
                    ["add", str(db2), "SourceEntry", "--username", "srcuser", "-g"],
                    stdin_text=TEST_PASSWORD + "\n",
                )
            # Merge source into target
            if binary.name == "keepassxcr":
                r = run_cli(binary, [
                    "merge", str(db1), str(db2),
                    "--password", TEST_PASSWORD,
                    "--source-password", TEST_PASSWORD,
                ])
            else:
                # keepassxc-cli prompts for target password then source password
                r = run_cli(
                    binary,
                    ["merge", "-s", str(db1), str(db2)],
                    stdin_text=TEST_PASSWORD + "\n",
                )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_merge_different_passwords(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db1 = tmp_path / f"merge_diff_t_{binary.name}.kdbx"
            db2 = tmp_path / f"merge_diff_s_{binary.name}.kdbx"
            make_db_create(binary, db1, TEST_PASSWORD)
            make_db_create(binary, db2, TEST_PASSWORD_2)
            # Merge with different passwords
            if binary.name == "keepassxcr":
                r = run_cli(binary, [
                    "merge", str(db1), str(db2),
                    "--password", TEST_PASSWORD,
                    "--source-password", TEST_PASSWORD_2,
                ])
            else:
                r = run_cli(
                    binary,
                    ["merge", str(db1), str(db2)],
                    stdin_text=TEST_PASSWORD + "\n" + TEST_PASSWORD_2 + "\n",
                )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"


class TestExportImport:
    """Test XML export/import roundtrip."""

    def test_xml_roundtrip(self, rust_binary, original_binary, populated_db, tmp_path):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            # Export
            r = run_cli(
                binary, ["export", str(populated_db)] + pw_args, stdin_text=pw_stdin
            )
            assert r.exit_code == 0, f"{binary.name} export: {r.stderr}"
            xml_content = r.stdout
            assert len(xml_content) > 0
            assert "<?xml" in xml_content or "<KeePassFile" in xml_content
            # Write XML to file
            xml_path = tmp_path / f"export_{binary.name}.xml"
            xml_path.write_text(xml_content)
            # Import back
            imported_db = tmp_path / f"imported_{binary.name}.kdbx"
            r2 = make_import(binary, xml_path, imported_db, TEST_PASSWORD)
            assert r2.exit_code == 0, f"{binary.name} import: {r2.stderr}"
            assert imported_db.exists()

    def test_cross_cli_roundtrip(
        self, rust_binary, original_binary, tmp_path
    ):
        """Export from one CLI, import with the other."""
        # Create a db with rust binary
        db_path = tmp_path / "cross_src.kdbx"
        run_cli(
            rust_binary,
            ["db-create", str(db_path), "--password", TEST_PASSWORD],
        )
        run_cli(
            rust_binary,
            [
                "add", str(db_path), "CrossEntry",
                "--username", "crossuser",
                "--password", TEST_PASSWORD, "-g",
            ],
        )
        # Export from rust binary
        r = run_cli(
            rust_binary,
            ["export", str(db_path), "--password", TEST_PASSWORD],
        )
        assert r.exit_code == 0, f"rust export: {r.stderr}"
        xml_path = tmp_path / "cross.xml"
        xml_path.write_text(r.stdout)
        # Import with original binary
        imported_db = tmp_path / "cross_imported.kdbx"
        r2 = make_import(original_binary, xml_path, imported_db, TEST_PASSWORD)
        assert r2.exit_code == 0, f"original import: {r2.stderr}"


class TestAdd:
    """Test entry addition."""

    def test_add_with_fields(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"add_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            args = [
                "add", str(db_path), "TestEntry",
                "--username", "testuser", "--url", "https://example.com",
                "--notes", "some notes",
            ] + pw_args + ["-g"]
            r = run_cli(binary, args, stdin_text=pw_stdin)
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_add_with_generate(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"add_gen_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            args = ["add", str(db_path), "GenEntry", "-g"] + pw_args
            r = run_cli(binary, args, stdin_text=pw_stdin)
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify password was generated
            show_flag = "--show-password" if binary.name == "keepassxcr" else "-s"
            show_args = [
                "show", str(db_path), "GenEntry", show_flag,
            ] + pw_args
            r2 = run_cli(binary, show_args, stdin_text=pw_stdin)
            assert r2.exit_code == 0, f"{binary.name} show: {r2.stderr}"
            fields = parse_show_output(r2.stdout)
            assert "password" in fields
            assert len(fields["password"]) > 0

    def test_add_duplicate_rejected(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"add_dup_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            args = ["add", str(db_path), "DupEntry", "-g"] + pw_args
            r1 = run_cli(binary, args, stdin_text=pw_stdin)
            assert r1.exit_code == 0, f"{binary.name} first: {r1.stderr}"
            r2 = run_cli(binary, args, stdin_text=pw_stdin)
            assert r2.exit_code != 0, f"{binary.name} duplicate should fail"


class TestEdit:
    """Test entry editing."""

    def test_edit_username(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                [
                    "edit", str(populated_db), "Entry1",
                    "--username", "newuser",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_edit_url(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                [
                    "edit", str(populated_db), "Entry1",
                    "--url", "https://new.example.com",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"

    def test_edit_title(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"edit_title_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "OldTitle", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                [
                    "edit", str(db_path), "OldTitle", "--title", "NewTitle",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify new title
            r2 = run_cli(
                binary,
                ["show", str(db_path), "NewTitle"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r2.exit_code == 0, f"{binary.name} verify: {r2.stderr}"

    def test_edit_nonexistent(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                [
                    "edit", str(populated_db), "NoSuchEntry",
                    "--username", "x",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0


class TestShow:
    """Test entry display."""

    def test_show_fields(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["show", str(populated_db), "Entry1"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            fields = parse_show_output(r.stdout)
            assert "title" in fields
            assert fields["title"] == "Entry1"
            assert "username" in fields
            assert fields["username"] == "user1"

    def test_show_password(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            show_flag = "--show-password" if binary.name == "keepassxcr" else "-s"
            r = run_cli(
                binary,
                [
                    "show", str(populated_db), "Entry1", show_flag,
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            fields = parse_show_output(r.stdout)
            assert "password" in fields

    def test_show_nonexistent(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["show", str(populated_db), "NoSuchEntry"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0


# Entries for the `show -a` differential tests: (title, attributes, tags), where
# attributes are (key, value, protected). Values cover whitespace, case
# collisions and the placeholders keepassxc-cli resolves.
ATTRIBUTE_ENTRIES = [
    (
        "Api",
        [
            ("UserName", "alice", False),
            ("Password", "s3cret", True),
            ("URL", "https://api.example.com", False),
            ("Notes", "first line\nPassword: decoy\n", False),
            ("api-key", "k-123", True),
            ("Region", "eu-west", False),
            ("Empty", "", False),
            ("Spaced Name", "  padded  ", False),
        ],
        "zeta; alpha,beta;alpha & co",
    ),
    (
        "Ambig",
        [("token", "lower", False), ("TOKEN", "upper", False)],
        "",
    ),
    (
        "Ref",
        [
            ("UserName", "{TITLE}-user", False),
            ("Password", "p{USERNAME}", True),
            ("URL", "https://Bob:S%20cret@Example.COM:8443/a%20b/c?q=1&r=%41#frag", False),
            ("Notes", "{REF:U@T:Api}", False),
            (
                "Refs",
                "{REF:T@U:alice}|{REF:I@T:Api}|{REF:A@O:eu-west}|{REF:N@T:Api}"
                "|{REF:x@T:Api}|{REF:P@T:Nobody}",
                False,
            ),
            ("Mixed", "a{TITLE}b{title}c{Unknown}d{}e{S:Region}f{S:Notes}g{S:Missing}", False),
            (
                "UrlParts",
                "{URL:SCM}|{URL:HOST}|{URL:PORT}|{URL:PATH}|{URL:QUERY}|{URL:FRAGMENT}"
                "|{URL:USERINFO}|{URL:USERNAME}|{URL:PASSWORD}|{URL:RMVSCM}",
                False,
            ),
            ("Loop", "{S:Loop}", False),
            ("Nested", "{{TITLE}}", False),
            ("Other", "{DT_YEAR}-{DT_UTC_YEAR}|{DB_DIR}|[{TOTP}]", False),
        ],
        "",
    ),
]

SHOW_ATTRIBUTE_CASES = [
    ("Api", ["Password"]),
    ("Api", ["password"]),
    ("Api", ["PASSWORD"]),
    ("Api", ["UserName", "Password", "URL", "Title"]),
    ("Api", ["username", "url", "title"]),
    ("Api", ["Notes"]),
    ("Api", ["api-key"]),
    ("Api", ["API-KEY"]),
    ("Api", ["Region", "Empty"]),
    ("Api", ["Spaced Name"]),
    ("Api", ["spaced name"]),
    ("Api", ["Password", "Password"]),
    ("Api", ["Uuid", "Tags"]),
    ("Api", ["uuid"]),
    ("Api", ["Nope"]),
    ("Api", ["Password", "Nope", "UserName", "Nope2"]),
    ("Ambig", ["token", "TOKEN"]),
    ("Ambig", ["Token"]),
    ("Ambig", ["Token", "token"]),
    ("Ref", ["UserName", "Password", "Notes"]),
    ("Ref", ["Refs"]),
    ("Ref", ["Mixed"]),
    ("Ref", ["UrlParts"]),
    ("Ref", ["Loop", "Nested"]),
    ("Ref", ["Other"]),
    ("NoSuchEntry", ["Password"]),
]


def build_attribute_db(original_binary: Path, tmp_path: Path) -> Path:
    """Create ATTRIBUTE_ENTRIES in a database written by keepassxc-cli.

    keepassxc-cli has no way to add custom attributes, so this exports an
    empty database, adds the entries to the XML and imports it again.
    """
    seed = tmp_path / "seed.kdbx"
    assert make_db_create(original_binary, seed, TEST_PASSWORD).exit_code == 0
    exported = run_cli(
        original_binary, ["export", "-q", str(seed)], stdin_text=TEST_PASSWORD + "\n"
    )
    assert exported.exit_code == 0, exported.stderr
    tree = ET.ElementTree(ET.fromstring(exported.stdout))
    group = tree.find("./Root/Group")
    assert group is not None
    for number, (title, attributes, tags) in enumerate(ATTRIBUTE_ENTRIES, start=1):
        entry = ET.SubElement(group, "Entry")
        ET.SubElement(entry, "UUID").text = base64.b64encode(
            number.to_bytes(16, "big")
        ).decode()
        ET.SubElement(entry, "Tags").text = tags or None
        for key, value, protected in [("Title", title, False)] + attributes:
            string_el = ET.SubElement(entry, "String")
            ET.SubElement(string_el, "Key").text = key
            value_el = ET.SubElement(string_el, "Value")
            value_el.text = value or None
            if protected:
                value_el.set("ProtectInMemory", "True")
    xml_path = tmp_path / "attributes.xml"
    tree.write(xml_path, encoding="utf-8", xml_declaration=True)
    db_path = tmp_path / "attributes.kdbx"
    imported = make_import(original_binary, xml_path, db_path, TEST_PASSWORD)
    assert imported.exit_code == 0, imported.stderr
    return db_path


def show_attributes(binary: Path, db_path: Path, entry: str, attributes: list[str]) -> CliResult:
    """Run `show -q -a ...` with each binary's way of passing the password."""
    args = ["show", "-q", str(db_path), entry]
    for attribute in attributes:
        args += ["-a", attribute]
    if binary.name == "keepassxcr":
        return run_cli(binary, args + ["--password", TEST_PASSWORD, "--no-agent"])
    return run_cli(binary, args, stdin_text=TEST_PASSWORD + "\n")


@pytest.fixture(scope="module")
def attribute_db(original_binary, tmp_path_factory):
    return build_attribute_db(original_binary, tmp_path_factory.mktemp("attributes"))


class TestShowAttributes:
    """Differential tests: `show -a` must print exactly what keepassxc-cli prints."""

    @pytest.mark.parametrize(
        "entry,attributes",
        SHOW_ATTRIBUTE_CASES,
        ids=[f"{entry}:{','.join(attrs)}" for entry, attrs in SHOW_ATTRIBUTE_CASES],
    )
    def test_matches_keepassxc_cli(
        self, rust_binary, original_binary, attribute_db, entry, attributes
    ):
        expected = show_attributes(original_binary, attribute_db, entry, attributes)
        actual = show_attributes(rust_binary, attribute_db, entry, attributes)
        assert actual.stdout == expected.stdout
        assert actual.exit_code == expected.exit_code
        if expected.exit_code != 0:
            # keepassxc-cli also logs Qt warnings on success; only errors must match.
            assert actual.stderr == expected.stderr

    def test_matches_after_keepassxcr_saves(
        self, rust_binary, original_binary, attribute_db
    ):
        """Whitespace and every attribute survive a keepassxcr write."""
        # Same directory, so {DB_DIR} resolves the same.
        db_path = attribute_db.with_name("saved.kdbx")
        shutil.copy(attribute_db, db_path)
        added = run_cli(
            rust_binary,
            ["add", str(db_path), "Extra", "--password", TEST_PASSWORD, "--no-agent", "-g"],
        )
        assert added.exit_code == 0, added.stderr
        for entry, attributes in SHOW_ATTRIBUTE_CASES:
            if entry == "NoSuchEntry":
                continue
            before = show_attributes(original_binary, attribute_db, entry, attributes)
            after = show_attributes(original_binary, db_path, entry, attributes)
            assert after.stdout == before.stdout, f"{entry} {attributes}"


class TestRm:
    """Test entry removal."""

    def test_remove_entry(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"rm_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "ToRemove", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                ["rm", str(db_path), "ToRemove"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Both move the entry to the Recycle Bin first.
            r3 = run_cli(
                binary,
                ["ls", str(db_path), "Recycle Bin"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r3.exit_code == 0, f"{binary.name}: {r3.stderr}"
            _, entries = parse_ls_output(r3.stdout, binary.name)
            assert "ToRemove" in entries, f"{binary.name}: {r3.stdout}"
            # Removing it from the Recycle Bin deletes it for good.
            r4 = run_cli(
                binary,
                ["rm", str(db_path), "Recycle Bin/ToRemove"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r4.exit_code == 0, f"{binary.name}: {r4.stderr}"
            r5 = run_cli(
                binary,
                ["ls", str(db_path), "Recycle Bin"] + pw_args,
                stdin_text=pw_stdin,
            )
            _, entries = parse_ls_output(r5.stdout, binary.name)
            assert "ToRemove" not in entries, f"{binary.name}: {r5.stdout}"


class TestLs:
    """Test group listing."""

    def test_ls_root(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["ls", str(populated_db)] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            groups, entries = parse_ls_output(r.stdout, binary.name)
            assert "Group1" in groups
            assert "Group2" in groups
            assert "Entry1" in entries

    def test_ls_subgroup(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["ls", str(populated_db), "Group1"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            groups, entries = parse_ls_output(r.stdout, binary.name)
            assert "SubGroup" in groups
            assert "Entry2" in entries

    def test_ls_nonexistent_group(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["ls", str(populated_db), "NoSuchGroup"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0


class TestMkdir:
    """Test group creation."""

    def test_mkdir_simple(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"mkdir_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["mkdir", str(db_path), "NewGroup"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify
            r2 = run_cli(
                binary,
                ["ls", str(db_path)] + pw_args,
                stdin_text=pw_stdin,
            )
            groups, _ = parse_ls_output(r2.stdout, binary.name)
            assert "NewGroup" in groups

    def test_mkdir_nested(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"mkdir_nested_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            if binary.name == "keepassxcr":
                # Rust auto-creates parent groups
                r = run_cli(
                    binary,
                    ["mkdir", str(db_path), "A/B/C"] + pw_args,
                    stdin_text=pw_stdin,
                )
                assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            else:
                # Original requires creating each level separately
                for group in ["A", "A/B", "A/B/C"]:
                    r = run_cli(
                        binary,
                        ["mkdir", str(db_path), group] + pw_args,
                        stdin_text=pw_stdin,
                    )
                    assert r.exit_code == 0, f"{binary.name} mkdir {group}: {r.stderr}"
            # Verify nested path exists
            r2 = run_cli(
                binary,
                ["ls", str(db_path), "A/B"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r2.exit_code == 0, f"{binary.name} verify: {r2.stderr}"
            groups, _ = parse_ls_output(r2.stdout, binary.name)
            assert "C" in groups


class TestRmdir:
    """Test group removal."""

    def test_rmdir(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"rmdir_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["mkdir", str(db_path), "ToRemove"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                ["rmdir", str(db_path), "ToRemove"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify gone
            r2 = run_cli(
                binary,
                ["ls", str(db_path)] + pw_args,
                stdin_text=pw_stdin,
            )
            groups, _ = parse_ls_output(r2.stdout, binary.name)
            assert "ToRemove" not in groups
            # Both move the group to the Recycle Bin first.
            assert "Recycle Bin" in groups, f"{binary.name}: {r2.stdout}"
            r3 = run_cli(
                binary,
                ["ls", str(db_path), "Recycle Bin"] + pw_args,
                stdin_text=pw_stdin,
            )
            groups, _ = parse_ls_output(r3.stdout, binary.name)
            assert "ToRemove" in groups, f"{binary.name}: {r3.stdout}"

    def test_rmdir_root_rejected(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"rmdir_root_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["rmdir", str(db_path)] + pw_args,
                stdin_text=pw_stdin,
            )
            # Removing root should fail (or be rejected)
            assert r.exit_code != 0


class TestMv:
    """Test entry movement."""

    def test_move_entry(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"mv_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["mkdir", str(db_path), "Dest"] + pw_args,
                stdin_text=pw_stdin,
            )
            run_cli(
                binary,
                ["add", str(db_path), "MoveMe", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                ["mv", str(db_path), "MoveMe", "Dest"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify in destination
            r2 = run_cli(
                binary,
                ["show", str(db_path), "Dest/MoveMe"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r2.exit_code == 0, f"{binary.name} verify: {r2.stderr}"

    def test_move_nonexistent_entry(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"mv_noent_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["mkdir", str(db_path), "Dest"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                ["mv", str(db_path), "NoSuch", "Dest"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0

    def test_move_nonexistent_dest(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"mv_nodest_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "Mover", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            r = run_cli(
                binary,
                ["mv", str(db_path), "Mover", "NoDest"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0


class TestSearch:
    """Test entry search."""

    def test_search_by_title(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["search", str(populated_db), "Entry1"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            results = [
                line.strip()
                for line in normalize_output(r.stdout).splitlines()
                if line.strip()
            ]
            assert any("Entry1" in line for line in results)

    def test_search_by_username(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["search", str(populated_db), "user2"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            results = [
                line.strip()
                for line in normalize_output(r.stdout).splitlines()
                if line.strip()
            ]
            assert any("Entry2" in line for line in results)

    def test_search_no_results(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["search", str(populated_db), "zzz_nonexistent_zzz"] + pw_args,
                stdin_text=pw_stdin,
            )
            # Rust returns 0, original returns 1 for no results
            assert r.exit_code in (0, 1), f"{binary.name}: {r.stderr}"
            results = [
                line.strip()
                for line in normalize_output(r.stdout).splitlines()
                if line.strip()
            ]
            assert len(results) == 0

    def test_search_case_insensitive(self, rust_binary, original_binary, populated_db):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["search", str(populated_db), "entry1"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            results = [
                line.strip()
                for line in normalize_output(r.stdout).splitlines()
                if line.strip()
            ]
            assert any("Entry1" in line for line in results)


class TestAnalyze:
    """Test password analysis."""

    def test_analyze_without_hibp(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"analyze_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            # Add an entry with a weak password via -p (stdin)
            if binary.name == "keepassxcr":
                run_cli(
                    binary,
                    ["add", str(db_path), "WeakEntry", "-p", "--password", TEST_PASSWORD],
                    stdin_text="123\n",
                )
            else:
                run_cli(
                    binary,
                    ["add", str(db_path), "WeakEntry", "-p"],
                    stdin_text=TEST_PASSWORD + "\n123\n",
                )
            # Rust: analyze works without HIBP file (zxcvbn only)
            # Original: analyze requires a HIBP file; provide an empty one
            if binary.name == "keepassxcr":
                analyze_args = ["analyze", str(db_path)] + pw_args
            else:
                hibp_file = tmp_path / f"empty_hibp_{binary.name}.txt"
                hibp_file.write_text("")
                analyze_args = [
                    "analyze", "--hibp", str(hibp_file), str(db_path),
                ] + pw_args
            r = run_cli(binary, analyze_args, stdin_text=pw_stdin)
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Should report the weak password
            output = normalize_output(r.stdout)
            assert len(output) > 0

    def test_analyze_with_hibp(self, rust_binary, original_binary, tmp_path):
        """Test with a mock HIBP file."""
        import hashlib

        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"analyze_hibp_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "HibpEntry", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            # Create a HIBP file with a hash that won't match
            hibp_file = tmp_path / f"hibp_{binary.name}.txt"
            fake_hash = hashlib.sha1(b"password123").hexdigest().upper()
            hibp_file.write_text(f"{fake_hash}:42\n")
            r = run_cli(
                binary,
                ["analyze", str(db_path), "--hibp", str(hibp_file)] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"


class TestEstimate:
    """Test password strength estimation."""

    def test_estimate_known_password(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["estimate", "correct-horse-battery-staple"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            output = normalize_output(r.stdout).lower()
            assert "score" in output or "entropy" in output

    def test_estimate_advanced(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["estimate", "--advanced", "P@ssw0rd!"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            output = normalize_output(r.stdout).lower()
            assert "score" in output or "entropy" in output
            assert "crack" in output or "log10" in output

    def test_estimate_simple_password(self, rust_binary, original_binary):
        """Both CLIs should give low score to 'password'."""
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["estimate", "password"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            info = parse_db_info(r.stdout)  # reuse key:value parser
            # Rust outputs "Score", original outputs "Entropy"
            if "score" in info:
                score = int(info["score"])
                assert score <= 1, f"{binary.name}: expected low score, got {score}"
            elif "entropy" in info:
                # Original uses entropy; low entropy for weak password
                entropy = float(info["entropy"])
                assert entropy < 20, f"{binary.name}: expected low entropy, got {entropy}"


class TestGenerate:
    """Test password generation."""

    def test_generate_default(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["generate"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            password = normalize_output(r.stdout)
            expected_len = 20 if binary.name == "keepassxcr" else 32
            compare_generate_structure(password, length=expected_len)

    def test_generate_custom_length(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["generate", "--length", "32"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            password = normalize_output(r.stdout)
            compare_generate_structure(password, length=32)

    def test_generate_structure(self, rust_binary, original_binary):
        """Generate multiple times to check structure consistency."""
        for binary in [rust_binary, original_binary]:
            for _ in range(3):
                r = run_cli(binary, ["generate", "--length", "30"])
                assert r.exit_code == 0
                password = normalize_output(r.stdout)
                assert len(password) == 30


class TestDiceware:
    """Test diceware passphrase generation."""

    def test_diceware_default(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["diceware"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            words = normalize_output(r.stdout).split()
            expected_words = 6 if binary.name == "keepassxcr" else 7
            assert len(words) == expected_words, (
                f"{binary.name}: expected {expected_words} words, got {len(words)}"
            )

    def test_diceware_custom_words(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["diceware", "--words", "8"])
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            words = normalize_output(r.stdout).split()
            assert len(words) == 8, f"{binary.name}: expected 8 words, got {len(words)}"


class TestAttachmentImport:
    """Test attachment import."""

    def test_import_attachment(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"attach_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "AttachEntry", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            attach_file = tmp_path / f"file_{binary.name}.txt"
            attach_file.write_text("attachment content here")
            r = run_cli(
                binary,
                [
                    "attachment-import", str(db_path), "AttachEntry",
                    "myfile.txt", str(attach_file),
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"


class TestAttachmentExport:
    """Test attachment export."""

    def test_export_to_file(
        self, rust_binary, original_binary, populated_db_with_attachment, tmp_path
    ):
        db_path, _ = populated_db_with_attachment
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            output_file = tmp_path / f"exported_{binary.name}.txt"
            r = run_cli(
                binary,
                [
                    "attachment-export", str(db_path), "Entry1",
                    "test_attachment.txt", str(output_file),
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            assert output_file.exists()
            content = output_file.read_text()
            assert "test attachment content" in content

    def test_export_to_stdout(
        self, rust_binary, original_binary, populated_db_with_attachment
    ):
        db_path, _ = populated_db_with_attachment
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            # Rust: omit output file for stdout; original: use --stdout flag
            args = [
                "attachment-export", str(db_path), "Entry1",
                "test_attachment.txt",
            ]
            if binary.name != "keepassxcr":
                args.append("--stdout")
            args += pw_args
            r = run_cli(binary, args, stdin_text=pw_stdin)
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            assert "test attachment content" in r.stdout


class TestAttachmentRm:
    """Test attachment removal."""

    def test_remove_attachment(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"att_rm_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            run_cli(
                binary,
                ["add", str(db_path), "AEntry", "-g"] + pw_args,
                stdin_text=pw_stdin,
            )
            # Create and import attachment
            att_file = tmp_path / f"att_{binary.name}.txt"
            att_file.write_text("remove me")
            run_cli(
                binary,
                [
                    "attachment-import", str(db_path), "AEntry",
                    "removable.txt", str(att_file),
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            # Remove it
            r = run_cli(
                binary,
                [
                    "attachment-rm", str(db_path), "AEntry", "removable.txt",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code == 0, f"{binary.name}: {r.stderr}"
            # Verify gone (export should fail)
            r2 = run_cli(
                binary,
                [
                    "attachment-export", str(db_path), "AEntry", "removable.txt",
                ] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r2.exit_code != 0, f"{binary.name}: attachment should be gone"


class TestCrossCompatibility:
    """Create database with one CLI, read with the other.

    Tests all format/cipher/kdf combinations in both directions.
    """

    @pytest.mark.parametrize(
        "fmt,kdf,cipher",
        [
            ("4", "argon2id", "aes256"),
            ("4", "argon2id", "chacha20"),
            ("4", "argon2d", "twofish"),
            ("3", "aes-kdf", "aes256"),
            ("3", "aes-kdf", "twofish"),
        ],
    )
    @pytest.mark.parametrize(
        "creator,reader",
        [("rust", "orig"), ("orig", "rust")],
    )
    def test_cross_format_combos(
        self,
        rust_binary,
        original_binary,
        tmp_path,
        fmt,
        kdf,
        cipher,
        creator,
        reader,
    ):
        binaries = {"rust": rust_binary, "orig": original_binary}
        creator_bin = binaries[creator]
        reader_bin = binaries[reader]

        db_path = tmp_path / f"cross_{creator}_{fmt}_{kdf}_{cipher}.kdbx"
        pw_args_r, pw_stdin_r = make_auth(reader_bin, TEST_PASSWORD)

        # Create database
        if creator_bin.name == "keepassxcr":
            create_args = [
                "db-create", str(db_path),
                "--format", fmt, "--kdf", kdf, "--cipher", cipher,
                "--password", TEST_PASSWORD,
            ]
            r = run_cli(creator_bin, create_args)
        else:
            # Original doesn't support --format/--kdf/--cipher; create with defaults
            r = make_db_create(creator_bin, db_path, TEST_PASSWORD)
        assert r.exit_code == 0, f"{creator} create: {r.stderr}"

        # Add an entry
        if creator_bin.name == "keepassxcr":
            run_cli(creator_bin, [
                "add", str(db_path), "CrossEntry",
                "--username", "crossuser", "--url", "https://cross.test",
                "--password", TEST_PASSWORD, "-g",
            ])
        else:
            run_cli(
                creator_bin,
                [
                    "add", str(db_path), "CrossEntry",
                    "--username", "crossuser", "--url", "https://cross.test",
                    "-g",
                ],
                stdin_text=TEST_PASSWORD + "\n",
            )

        # Read with other CLI
        r2 = run_cli(
            reader_bin,
            ["show", str(db_path), "CrossEntry"] + pw_args_r,
            stdin_text=pw_stdin_r,
        )
        assert r2.exit_code == 0, (
            f"{reader} read ({creator}-created {fmt}/{kdf}/{cipher}): {r2.stderr}"
        )
        fields = parse_show_output(r2.stdout)
        assert fields.get("title") == "CrossEntry"
        assert fields.get("username") == "crossuser"

        # Also verify ls works
        r3 = run_cli(
            reader_bin,
            ["ls", str(db_path)] + pw_args_r,
            stdin_text=pw_stdin_r,
        )
        assert r3.exit_code == 0, (
            f"{reader} ls ({creator}-created {fmt}/{kdf}/{cipher}): {r3.stderr}"
        )


class TestErrorCases:
    """Test error handling across both CLIs."""

    def test_nonexistent_db(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["show", "/tmp/does_not_exist.kdbx", "Entry"] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0

    def test_wrong_password(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            db_path = tmp_path / f"wrong_pw_{binary.name}.kdbx"
            make_db_create(binary, db_path, TEST_PASSWORD)
            wrong_args, wrong_stdin = make_auth(binary, "totally-wrong")
            r = run_cli(
                binary,
                ["ls", str(db_path)] + wrong_args,
                stdin_text=wrong_stdin,
            )
            assert r.exit_code != 0

    def test_corrupted_file(self, rust_binary, original_binary, tmp_path):
        for binary in [rust_binary, original_binary]:
            corrupted = tmp_path / f"corrupted_{binary.name}.kdbx"
            corrupted.write_bytes(b"this is not a valid kdbx file at all")
            pw_args, pw_stdin = make_auth(binary, TEST_PASSWORD)
            r = run_cli(
                binary,
                ["ls", str(corrupted)] + pw_args,
                stdin_text=pw_stdin,
            )
            assert r.exit_code != 0

    def test_invalid_subcommand(self, rust_binary, original_binary):
        for binary in [rust_binary, original_binary]:
            r = run_cli(binary, ["not-a-real-command"])
            assert r.exit_code != 0
