# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (0.x releases may change the library API).

## [Unreleased]

### Changed

- A missing group now names the first group that doesn't exist and the
  `mkdir` command that creates it, instead of a bare "group not found".
- `open` no longer exits when a command fails: it prints the error and shows
  the prompt again. `exit`, Ctrl+D or Ctrl+C end the session.
- The unlock prompt reads `Enter password to unlock <file>:`, like
  keepassxc-cli, instead of `Password:`, which looked like an entry's
  Password field in front of `show -a` output.

### Fixed

- `open` exits on Ctrl+D (end of input) instead of printing the prompt
  forever.

## [0.3.0] - 2026-10-17

Loads SSH keys stored in a database into ssh-agent, compatible with
KeePassXC's SSH agent integration. keepassxc-cli has no equivalent.

### Added

- `ssh-add DB ENTRY...` loads an entry's SSH key into the agent at
  `SSH_AUTH_SOCK`. `--all` loads what KeePassXC loads on unlock, `-l` lists
  entries with keys and whether they are loaded, `-d` removes keys, and
  `-t` / `-c` set a lifetime or ask before each use.
- `ssh-key-import DB ENTRY KEYFILE` stores an OpenSSH private key in an entry
  with KeePassXC-compatible `KeeAgent.settings`, after checking that the
  entry's password opens it.
- `unlock --ssh-add` loads the keys when the database is unlocked. While
  unlocked, ssh-agent never keeps a key longer than the session has left, and
  keys set to "remove on lock" are removed by `lock` and when the session
  times out.
- Ed25519, ECDSA, RSA and FIDO (`sk-`) keys in OpenSSH format. Older PEM keys
  are refused with a hint to convert them with `ssh-keygen -p`.

## [0.2.0] - 2026-10-17

Makes the crate easier to use as a library. The CLI behaves as before.

### Added

- `Credentials::password(..)` and `Credentials::builder()`, so callers no
  longer fill in every field of `Credentials` by hand.
- `KdbxFile::new(database)` with the `db-create` defaults (KDBX 4, AES-256,
  Argon2id, ChaCha20, gzip), plus `KdbxFile::open` and `KdbxFile::save`.
- `Credentials`, `KdbxFile`, `Database`, `Entry`, `Group`, `AppError` and
  `AppResult` re-exported at the crate root.
- `KdfConfig::transform_with_progress` and `crypto::set_kdf_progress_hook`
  for following a long AES-KDF run.
- CI runs `cargo clippy -D warnings` and builds the library without the CLI.

### Changed

- The CLI is behind a default `cli` feature. Library users can depend on
  `keepassxcr` with `default-features = false` to skip clap, rpassword,
  arboard, indicatif, zxcvbn, anyhow and tracing-subscriber.
- The library no longer draws a progress bar on stderr during AES-KDF; the
  CLI draws it through the progress hook.
- `AppError` is `#[non_exhaustive]`.
- The `util` and `xml` modules are now private, and `agent` and `cli` are
  hidden from the docs. They were internal to the CLI.

## [0.1.0] - 2026-10-17

First release on crates.io.

### Added

- `keepassxcr` command-line tool, compatible with `keepassxc-cli`: database
  (`db-create`, `db-edit`, `db-info`, `open`, `merge`, `export`, `import`),
  entry (`add`, `edit`, `show`, `rm`, `mv`, `clip`, `search`), group (`ls`,
  `mkdir`, `rmdir`), attachment and utility (`generate`, `diceware`,
  `estimate`, `analyze`) commands. `diceware` draws from the EFF large
  wordlist, as KeePassXC does.
- Reading and writing KDBX 3.1, 4.0 and 4.1 with AES, Twofish and ChaCha20,
  AES-KDF and Argon2d/Argon2id, keeping history, times, tags, custom data and
  the recycle bin intact.
- Credentials: password, key files (raw, hex, hashed, XML v1.0 and v2.0) and
  YubiKey HMAC-SHA1 challenge-response compatible with KeePassXC, including
  forwarding a YubiKey over SSH with `yubikey serve`.
- `unlock`, `lock` and `status`: a background agent that keeps a database
  unlocked for a limited time.
- The `keepassxcr` library crate, exposing the KDBX reader and writer and the
  database model.

[Unreleased]: https://github.com/tynes/keepassxcr/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tynes/keepassxcr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tynes/keepassxcr/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tynes/keepassxcr/releases/tag/v0.1.0
