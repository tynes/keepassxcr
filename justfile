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
[positional-arguments]
test *args:
    cargo test "$@"

# Run the Python compatibility suite against keepassxc-cli (add --log-cli-level=DEBUG to see command output)
[positional-arguments]
compat *args:
    uv run --project tests pytest tests "$@"

# Run both test suites
test-all: test compat
