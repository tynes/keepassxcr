# List available recipes
default:
    @just --list

# Build a debug binary
build:
    cargo build

# Build the release binary (target/release/keepassxcr)
release:
    cargo build --release

# Run the Rust unit and integration tests
test *args:
    cargo test {{args}}

# Run the Python compatibility suite against keepassxc-cli (builds it from the submodule; needs cmake and Qt)
compat *args:
    uv run --project tests pytest tests {{args}}

# Run both test suites
test-all: test compat
