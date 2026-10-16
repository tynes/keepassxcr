# keepassxcr

A Rust reimplementation of the KeePassXC command-line interface.

- Reads and writes **KDBX 3.1** and **KDBX 4.x** databases
- CLI-compatible with `keepassxc-cli`
- Pure Rust cryptography (no C bindings)
- v0.1.0 — early development

## Build

Requires the **Rust 2024 edition** (rustc 1.85+).

```sh
cargo build --release
```

The binary is at `target/release/keepassxcr`.

## Usage

All commands that open a database accept credential flags:
`--password <PW>`, `--key-file <FILE>`, `--no-password`.

Without `--password`, the password is prompted for, or read from stdin when stdin is not a
terminal (`echo "$PW" | keepassxcr ls db.kdbx`). Prefer that over `--password`, which is visible
to other users in the process list. `db-create` and `import` ask for the password twice.
`--yubikey` is accepted for compatibility but not supported yet.

### Create a database

```sh
# KDBX 4 with AES-256 + Argon2id (defaults)
keepassxcr db-create passwords.kdbx

# KDBX 3.1 with Twofish + AES-KDF
keepassxcr db-create passwords.kdbx --format 3 --cipher twofish --kdf aes-kdf
```

### Add an entry

```sh
keepassxcr add passwords.kdbx Email/Gmail \
  --username user@gmail.com --url https://mail.google.com -g
```

### Show an entry

```sh
keepassxcr show passwords.kdbx Email/Gmail
keepassxcr show passwords.kdbx Email/Gmail --show-password
keepassxcr show -a Password passwords.kdbx Email/Gmail   # just the value, for scripts
```

### List entries

```sh
keepassxcr ls passwords.kdbx
keepassxcr ls passwords.kdbx Email
```

### Search

```sh
keepassxcr search passwords.kdbx gmail
```

### Generate passwords

```sh
keepassxcr generate --length 32
keepassxcr diceware --words 8
```

### Interactive REPL

```sh
keepassxcr open passwords.kdbx
```

### Unlock once, use many times

```sh
keepassxcr unlock passwords.kdbx            # asks for the password once
keepassxcr show passwords.kdbx Email/Gmail  # no prompt while unlocked
keepassxcr status                           # exit 0 if anything is unlocked
keepassxcr lock                             # lock every database now
```

`unlock` starts a background agent for that database. It holds the composite key (before the
KDF) and runs the KDF for other keepassxcr commands over a Unix socket in `$XDG_RUNTIME_DIR`
(or the temp directory) that only your user can reach; the password never leaves it. It locks
after 15 minutes without use or 8 hours in total, adjustable with `--idle` and `--max`
(`90s`, `15m`, `8h`, `1d`). Any program running as your user can use it while unlocked, as with
ssh-agent.

The agent never writes to your terminal. When it times out, commands for that database fail
with exit code 3 and say to run `unlock` again, instead of stopping a script at a password
prompt. `keepassxcr status [DB]` prints the time left and exits 0 when unlocked and 1
otherwise, so it fits in a shell prompt or at the top of a script. After an explicit `lock`,
commands prompt as usual again. `--password`, `--no-password` or `--no-agent` skip the agent
for one command; `db-edit` always does, and locks the agent once the credentials change.

## Command reference

| Category | Command | Description |
|---|---|---|
| **Database** | `db-create` | Create a new database |
| | `db-edit` | Edit database credentials/settings |
| | `db-info` | Show database metadata |
| | `open` | Open database in interactive mode |
| | `merge` | Merge two databases by UUID, keeping the newer version of each entry |
| | `export` | Export database to XML |
| | `import` | Import XML into a new database |
| **Entries** | `add` | Add an entry |
| | `edit` | Edit an entry |
| | `show` | Show an entry |
| | `rm` | Remove an entry |
| | `mv` | Move an entry to a group |
| | `clip` | Copy a field to the clipboard |
| | `search` | Search entries by term |
| **Groups** | `ls` | List group contents |
| | `mkdir` | Create a group |
| | `rmdir` | Remove a group |
| **Attachments** | `attachment-import` | Import an attachment |
| | `attachment-export` | Export an attachment |
| | `attachment-rm` | Remove an attachment |
| **Utilities** | `generate` | Generate a random password |
| | `diceware` | Generate a diceware passphrase |
| | `estimate` | Estimate password strength |
| | `analyze` | Analyze passwords with offline HIBP data |
| **Unlock agent** | `unlock` | Keep a database unlocked in a background agent |
| | `lock` | Stop the agent for a database, or all of them |
| | `status` | Show whether a database is unlocked and for how long |

## Supported cryptography

| Component | Options |
|---|---|
| Ciphers | AES-128-CBC, AES-256-CBC, Twofish-CBC, ChaCha20 |
| KDFs | AES-KDF, Argon2d, Argon2id |
| Protected streams | Salsa20, ChaCha20 |
| Credentials | Password, key file (raw, hex, hashed, XML v1.0 and v2.0) |
| Formats | KDBX 3.1, KDBX 4.0, KDBX 4.1 |

All cryptographic operations use pure Rust crates (`aes`, `twofish`, `chacha20`, `salsa20`, `argon2`). There are no C bindings.

## Project structure

```
src/
├── main.rs              Entry point
├── lib.rs               Public crate root
├── error.rs             Error types (AppError, AppResult)
├── agent/
│   ├── mod.rs           Unlock agent types and duration parsing
│   ├── client.rs        Start, query and stop agents
│   ├── server.rs        The agent process
│   └── wire.rs          Socket locations and JSON protocol
├── cli/
│   ├── mod.rs           CLI definition (clap derive)
│   ├── commands.rs      Subcommand dispatch and handlers
│   └── interactive.rs   Interactive REPL (open command)
├── crypto/
│   ├── mod.rs           Crypto module root
│   ├── constants.rs     Cipher, KDF, and stream UUIDs
│   ├── cipher.rs        AES/Twofish/ChaCha20 encryption
│   ├── kdf.rs           Key derivation (AES-KDF, Argon2)
│   ├── hash.rs          SHA-256/SHA-512/HMAC utilities
│   ├── composite_key.rs Composite key assembly
│   ├── keyfile.rs       Key file parsing
│   └── protected_stream.rs  Salsa20/ChaCha20 inner streams
├── format/
│   ├── mod.rs           Format module root
│   ├── constants.rs     KDBX signatures and version numbers
│   ├── types.rs         KdbxVersion, Compression enums
│   ├── kdbx.rs          KDBX read/write logic
│   ├── block_stream.rs  KDBX3 hashed block stream
│   └── variant_map.rs   KDBX4 variant dictionary
├── model/
│   └── mod.rs           Database, Group, Entry data model
├── xml/
│   └── mod.rs           KeePass XML serialization/deserialization
└── util/
    ├── mod.rs           Utility module root
    └── byteio.rs        Binary read/write helpers
```

## Testing

With [just](https://github.com/casey/just) installed, `just build` builds, `just test` runs the Rust tests, `just compat` runs the compatibility suite, and `just test-all` runs both. Run `just` to list every recipe.

### Rust unit tests

```sh
cargo test
```

### Python CLI compatibility tests

72 tests that run both `keepassxcr` and `keepassxc-cli` and compare output.

```sh
uv sync
uv run pytest
```

The suite builds keepassxcr itself. It uses an installed `keepassxc-cli` from `$KEEPASSXC_CLI`, `PATH`, or `/Applications/KeePassXC.app` (`brew install --cask keepassxc` on macOS, `apt install keepassxc` on Debian/Ubuntu). Only when none is found does it build `keepassxc-cli` from the submodule, which needs cmake, Qt, Botan and KeePassXC's other build dependencies.

The suite logs every command it runs and its exit code as it goes. Add `--log-cli-level=DEBUG` (e.g. `just compat --log-cli-level=DEBUG -k merge`) to also see each command's stdout and stderr; a failing test always prints its full log.

## KeePassXC submodule

The `keepassxc/` directory is a Git submodule pointing to the original C++ KeePassXC source. It is used only as a reference implementation for testing and is **not** compiled into keepassxcr.

```sh
git submodule update --init
```

## Non-goals

- GUI
- Browser integration
- OS-specific integrations (Secret Service, Windows Credential Manager, macOS Keychain)
