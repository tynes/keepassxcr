# List available recipes
default:
    @just --list

# Build a debug binary
build:
    cargo build

# Build the release binary (target/release/keepassxcr)
release:
    cargo build --release

# Run the Rust unit and integration tests (YubiKey and FIDO2 tests use emulated keys)
[positional-arguments]
test *args:
    cargo test --features software-yubikey,software-fido2 "$@"

# Run the Python compatibility suite against keepassxc-cli (add --log-cli-level=DEBUG to see command output)
[positional-arguments]
compat *args:
    uv run --project tests pytest tests "$@"

# Build upstream keepassxc-cli with a software YubiKey and run the YubiKey differential tests
[positional-arguments]
compat-yubikey *args:
    KEEPASSXC_CLI_SOFTWARE_YUBIKEY="$(tests/build-software-yubikey-keepassxc.sh)" uv run --project tests pytest tests/test_yubikey_compat.py "$@"

# Run both test suites
test-all: test compat
