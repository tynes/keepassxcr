# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (0.x releases may change the library API).

## [Unreleased]

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

[Unreleased]: https://github.com/tynes/keepassxcr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tynes/keepassxcr/releases/tag/v0.1.0
