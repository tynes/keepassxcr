# keepassxcr

[![crates.io](https://img.shields.io/crates/v/keepassxcr.svg)](https://crates.io/crates/keepassxcr)
[![docs.rs](https://docs.rs/keepassxcr/badge.svg)](https://docs.rs/keepassxcr)

A Rust reimplementation of the KeePassXC command-line interface, and a library for reading and
writing KeePass databases.

- Reads and writes **KDBX 3.1** and **KDBX 4.x** databases
- CLI-compatible with `keepassxc-cli`
- Pure Rust cryptography (no C bindings)
- v0.2.0 — early development; keep a backup of any database you use it on

## Install

Requires Rust 1.88 or newer.

```sh
cargo install keepassxcr --locked
```

This puts `keepassxcr` in `~/.cargo/bin`. `--locked` builds with the exact dependency versions
the release was tested with.

On Linux the build needs no system libraries (YubiKey access goes straight to `/dev/hidraw*`).
On macOS it compiles hidapi's small C backend for IOKit, so the Xcode command line tools must be
installed (`xcode-select --install`).

### From source

```sh
git clone https://github.com/tynes/keepassxcr
cd keepassxcr
cargo build --release      # binary at target/release/keepassxcr
cargo install --path .     # or install it into ~/.cargo/bin
```

## Using it as a library

```sh
cargo add keepassxcr --no-default-features
```

`--no-default-features` turns off the `cli` feature, which only the `keepassxcr` binary needs, so
your build skips clap, the clipboard and the other CLI dependencies.

`KdbxFile::open` and `save` read and write a database with `Credentials` (a password, key file
and/or YubiKey slot), and `keepassxcr::model` holds the groups and entries:

```rust
use keepassxcr::secrecy::ExposeSecret;
use keepassxcr::{Credentials, KdbxFile};

let credentials = Credentials::password("correct horse battery staple");
let file = KdbxFile::open("passwords.kdbx", &credentials)?;
if let Some(entry) = file.database.entry_by_path(&["Email"], "Gmail") {
    println!("{}: {}", entry.username(), entry.password().expose_secret());
}
```

For a key file or YubiKey, use `Credentials::builder()`. The
[crate documentation](https://docs.rs/keepassxcr) has a full example that creates and saves a
database. The library API may still change between 0.x releases.

## Usage

All commands that open a database accept credential flags:
`--password <PW>`, `--key-file <FILE>`, `--no-password`, `-y, --yubikey <SLOT[:SERIAL]>`.

Without `--password`, the password is prompted for, or read from stdin when stdin is not a
terminal (`echo "$PW" | keepassxcr ls db.kdbx`). Prefer that over `--password`, which is visible
to other users in the process list, so `--help` no longer lists it. `db-create` and `import` ask for the password twice.

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

`show -a` prints exactly what `keepassxc-cli show -a` prints: names match
case-insensitively, placeholders such as `{USERNAME}`, `{S:attr}` and
`{REF:P@T:Other}` are resolved, and unknown or ambiguous names are reported on
stderr after the other values are printed. `{TOTP}` resolves to nothing, since
keepassxcr does not generate TOTP codes.

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

### YubiKey

keepassxcr supports YubiKey HMAC-SHA1 challenge-response the same way KeePassXC does, so the
same database opens in KeePassXC with the same key. It talks to the key's OTP interface over USB
(IOKit on macOS, hidraw on Linux).

```sh
ykman otp chalresp --touch --generate 2        # only if slot 2 is empty: this overwrites it
keepassxcr db-create --yubikey 2 passwords.kdbx
keepassxcr show -y 2 passwords.kdbx Email/Gmail
keepassxcr show -y 2:7370001 passwords.kdbx Email/Gmail   # pick a key by serial
keepassxcr db-edit passwords.kdbx --new-yubikey 2         # add a YubiKey to a database
keepassxcr db-edit -y 2 passwords.kdbx --unset-yubikey    # remove it
```

The key prints `Please present or touch your YubiKey to continue.` when it waits for a touch.
Every save draws a new seed and so asks the key again, as in KeePassXC. With `unlock --yubikey 2`
the agent remembers the key's answer for the file's current seed, so reads need no touch until
the file is saved; the save itself needs the key.

On macOS, if the key is not found, allow your terminal under System Settings > Privacy &
Security > Input Monitoring (the OTP interface is a keyboard to macOS). On Linux you need read
and write access to its hidraw device, which Yubico's udev rule gives.

#### Using a YubiKey on another machine

Forward the challenge, not the USB device. On the machine with the key:

```sh
keepassxcr yubikey serve     # listens on ~/.keepassxcr-yubikey.sock
```

Then connect with the socket forwarded (paths must be absolute):

```sh
ssh -R /home/me/.keepassxcr-yubikey.sock:/Users/me/.keepassxcr-yubikey.sock server
```

or in `~/.ssh/config`:

```
Host server
    RemoteForward /home/me/.keepassxcr-yubikey.sock /Users/me/.keepassxcr-yubikey.sock
```

On the server keepassxcr uses `~/.keepassxcr-yubikey.sock` when it exists (or the socket named
in `KEEPASSXCR_YUBIKEY_SOCKET`) instead of USB, and the touch prompt shows on both machines. A
leftover socket from an earlier connection makes `ssh -R` fail to bind; add
`StreamLocalBindUnlink yes` to the server's `sshd_config`, or delete the stale socket. While
connected, anyone with root on the server can send challenges to your key, as with ssh-agent
forwarding; a slot set up with `--touch` still needs your finger for each one.

### SSH keys

keepassxcr loads SSH keys stored in entries into your ssh-agent, using the same settings as
KeePassXC's SSH agent integration (a `KeeAgent.settings` attachment), so an entry set up in the
KeePassXC app works here and the reverse. The private key is an attachment on the entry, or a
file the settings point at, and the entry's password is the key's passphrase. keepassxc-cli has
no equivalent; in KeePassXC this only happens in the app.

```sh
keepassxcr add -p passwords.kdbx SSH/GitHub                 # password = the key's passphrase
keepassxcr ssh-key-import passwords.kdbx SSH/GitHub ~/.ssh/id_ed25519
keepassxcr ssh-add passwords.kdbx SSH/GitHub                # load one key
keepassxcr ssh-add passwords.kdbx --all                     # what KeePassXC loads on unlock
keepassxcr ssh-add -l passwords.kdbx                        # entries with keys, loaded or not
keepassxcr ssh-add -d passwords.kdbx --all                  # remove them again
keepassxcr unlock --ssh-add passwords.kdbx                  # unlock and load in one step
```

`ssh-key-import` checks that the entry's password opens the key, then stores it with settings
that add it on unlock and remove it on lock; `--no-add-on-unlock`, `--keep-on-lock`,
`--lifetime 1h` and `--confirm` change them. `ssh-add -t 30m` and `-c` override an entry's
lifetime and confirmation for one call.

While the database is unlocked with `unlock`, every key `ssh-add` loads gets an ssh-agent
lifetime no longer than the unlock session has left, and keys set to "remove on lock" are
removed by `lock` and when the session times out. Without an unlock session a key stays in
ssh-agent until you remove it or its own lifetime runs out. Keys go to the agent in
`SSH_AUTH_SOCK`; once loaded, ssh-agent holds the decrypted key, and agent forwarding
(`ssh -A`) works as usual. Only OpenSSH-format private keys are read (the default since OpenSSH
7.8); convert an older PEM key with `ssh-keygen -p -f <file>`.

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
| | `rm` | Remove an entry (moved to the recycle bin first, like KeePassXC) |
| | `mv` | Move an entry to a group |
| | `clip` | Copy a field to the clipboard; cleared after 10 seconds unless a timeout is given (0 keeps it) |
| | `search` | Search entries by term |
| **Groups** | `ls` | List group contents |
| | `mkdir` | Create a group |
| | `rmdir` | Remove a group (moved to the recycle bin first, like KeePassXC) |
| **Attachments** | `attachment-import` | Import an attachment |
| | `attachment-export` | Export an attachment; a new output file is readable by its owner only and an existing one is never replaced |
| | `attachment-rm` | Remove an attachment |
| **Utilities** | `generate` | Generate a random password |
| | `diceware` | Generate a diceware passphrase |
| | `estimate` | Estimate password strength |
| | `analyze` | Analyze passwords with offline HIBP data |
| **SSH keys** | `ssh-add` | Load SSH keys from entries into ssh-agent (`-l` list, `-d` remove, `--all`) |
| | `ssh-key-import` | Store an SSH private key in an entry, set up like KeePassXC's SSH agent tab |
| **YubiKey** | `yubikey serve` | Answer YubiKey challenges forwarded from another machine |
| **Unlock agent** | `unlock` | Keep a database unlocked in a background agent (`--ssh-add` also loads SSH keys) |
| | `lock` | Stop the agent for a database, or all of them |
| | `status` | Show whether a database is unlocked and for how long |

## Supported cryptography

| Component | Options |
|---|---|
| Ciphers | AES-128-CBC, AES-256-CBC, Twofish-CBC, ChaCha20 |
| KDFs | AES-KDF, Argon2d, Argon2id |
| Protected streams | Salsa20, ChaCha20 |
| Credentials | Password, key file (raw, hex, hashed, XML v1.0 and v2.0), YubiKey HMAC-SHA1 challenge-response |
| Formats | KDBX 3.1, KDBX 4.0, KDBX 4.1 |

All cryptographic operations use pure Rust crates (`aes`, `twofish`, `chacha20`, `salsa20`, `argon2`). There are no C bindings for cryptography; on macOS, USB access to a YubiKey goes through `hidapi`'s IOKit backend.

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
│   ├── ssh.rs           ssh-add, ssh-key-import, unlock --ssh-add
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
├── ssh/
│   ├── mod.rs           Entries with SSH keys
│   ├── settings.rs      KeeAgent.settings (KeePassXC's SSH agent settings)
│   ├── key.rs           Read and decrypt an entry's OpenSSH private key
│   └── agent.rs         ssh-agent protocol client (add, remove, list)
├── yubikey/
│   ├── mod.rs           Slot parsing, KeePassXC-style padding, picking a backend
│   ├── otp.rs           YubiKey OTP HID protocol (frames, CRC, touch polling)
│   ├── hid.rs           USB access through hidapi
│   ├── forward.rs       `yubikey serve` and forwarded-socket client
│   └── emulator.rs      Software YubiKey for tests (`software-yubikey` feature)
└── util/
    ├── mod.rs           Utility module root
    ├── byteio.rs        Binary read/write helpers
    └── unix.rs          User ids of processes and socket peers
```

## Testing

With [just](https://github.com/casey/just) installed, `just build` builds, `just test` runs the Rust tests, `just compat` runs the compatibility suite, and `just test-all` runs both. Run `just` to list every recipe.

### Rust unit tests

```sh
cargo test --features software-yubikey
```

The `software-yubikey` feature replaces the USB YubiKey with an emulated one
(`KEEPASSXCR_SOFTWARE_YUBIKEY=<hex secret>[:fixed][:touch]`) so the YubiKey tests in
`tests/yubikey.rs` run without hardware. It is for tests only; never build a binary you use with it.

`tests/ssh.rs` starts its own `ssh-agent` and uses `ssh-keygen` and `ssh-add`; it is skipped when
OpenSSH is not installed.

### Python CLI compatibility tests

72 tests that run both `keepassxcr` and `keepassxc-cli` and compare output.

```sh
uv sync
uv run pytest
```

The suite builds keepassxcr itself. It uses an installed `keepassxc-cli` from `$KEEPASSXC_CLI`, `PATH`, or `/Applications/KeePassXC.app` (`brew install --cask keepassxc` on macOS, `apt install keepassxc` on Debian/Ubuntu). Only when none is found does it build `keepassxc-cli` from the submodule, which needs cmake, Qt, Botan and KeePassXC's other build dependencies.

The suite logs every command it runs and its exit code as it goes. Add `--log-cli-level=DEBUG` (e.g. `just compat --log-cli-level=DEBUG -k merge`) to also see each command's stdout and stderr; a failing test always prints its full log.

### YubiKey differential tests

```sh
just compat-yubikey
```

Builds upstream KeePassXC 2.7.12's `keepassxc-cli` with only its YubiKey device call replaced by
the same software key (`tests/keepassxc-software-yubikey.patch`, built by
`tests/build-software-yubikey-keepassxc.sh`; needs KeePassXC's build dependencies with YubiKey
support), then checks that databases written by either CLI open in the other for KDBX 4 and 3.1,
both slot modes, with and without a password.

## KeePassXC submodule

The `keepassxc/` directory is a Git submodule pointing to the original C++ KeePassXC source. It is used only as a reference implementation for testing and is **not** compiled into keepassxcr.

```sh
git submodule update --init
```

## Releasing

Releases are published by `.github/workflows/release.yml` when a `v*` tag is pushed:

1. Move the `Unreleased` notes in `CHANGELOG.md` under the new version, and bump `version` in
   `Cargo.toml` to match. Merge that to `main`.
2. Tag the merge commit and push the tag:
   ```sh
   git tag -a v0.1.0 -m "keepassxcr 0.1.0"
   git push origin v0.1.0
   ```
3. The workflow checks that the tag matches `Cargo.toml`, runs the tests, publishes to crates.io
   with the `CARGO_REGISTRY_TOKEN` repository secret, and creates the GitHub release from that
   version's `CHANGELOG.md` section.

To publish by hand instead: `cargo publish --dry-run`, then `cargo login` and `cargo publish`.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

`assets/diceware.txt` is the [EFF large wordlist](https://www.eff.org/dice) as shipped by
KeePassXC, used under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).

## Non-goals

- GUI
- Browser integration
- OS-specific integrations (Secret Service, Windows Credential Manager, macOS Keychain)
