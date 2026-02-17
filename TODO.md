# Task

Please reimplement KeePassXC from scratch as a CLI only application written in rust. It should use external libraries for cryptography and focus
on simplicity. The original implementation has been downloaded into this repo, please use it as a guide.

# CLI Architecture Overview (Clean Reimplementation)

This document provides a CLI-only architecture overview for a clean reimplementation aligned with KeePassXC’s current file format and cryptographic capabilities.

## Scope and Goals
- Deliver a CLI-first password manager compatible with KeePassXC’s database format and cryptographic settings.
- Preserve compatibility with KDBX 3.1 and 4.x databases, while keeping the design modular enough to extend.

## Database File Format
### KDBX Versions and Signatures
- The KDBX file format is identified by two signatures and explicit versioning metadata in the header, with versions ranging from 2.x through 4.1 in the current implementation constants (including 3.1 and 4.1).【F:src/format/KeePass2.h†L31-L47】
- Reimplementation should target KDBX 3.1 and 4.x (3.1 for legacy compatibility and 4.x for modern KDF options). KDBX 4 supports features that require newer KDFs such as Argon2, whereas KDBX 3.1 is limited to AES-KDF.【F:docs/topics/DatabaseOperations.adoc†L411-L418】

### Header and Inner Header Structure (High-Level)
- The format distinguishes a main header (cipher, compression, KDF parameters, etc.) and inner header metadata; these header field IDs are enumerated in the format constants and should be modeled as strongly typed identifiers in the reimplementation to avoid parsing errors and ensure forward compatibility.【F:src/format/KeePass2.h†L67-L114】

## Cryptography and Encryption Support
### Database Encryption Ciphers
The reimplementation should support the same database encryption ciphers as KeePassXC:
- AES-128, AES-256, Twofish, and ChaCha20 are registered as supported cipher IDs in the format constants.【F:src/format/KeePass2.h†L49-L55】
- The product documentation also calls out Twofish and ChaCha20 as supported encryption choices beyond the default AES encryption line, confirming that these are user-facing options.【F:docs/topics/Welcome.adoc†L41-L47】

### Key Derivation Functions (KDFs)
The KDF layer transforms the composite master key and is critical for resisting brute-force attacks:
- AES-KDF is supported for KDBX 3.1 and KDBX 4, and is iteration-based (linear time cost).【F:docs/topics/DatabaseOperations.adoc†L411-L418】
- Argon2 (Argon2d and Argon2id) is recommended for KDBX 4 and provides memory-hard protection; Argon2id is recommended to mitigate timing-based attacks.【F:docs/topics/DatabaseOperations.adoc†L413-L418】
- KDBX 3.1 only supports AES-KDF, so Argon2 requires KDBX 4 compatibility mode.【F:docs/topics/DatabaseOperations.adoc†L411-L418】

### Protected Field Stream Ciphers
- The format defines multiple inner/protected stream algorithms (ArcFour variant, Salsa20, ChaCha20). A CLI reimplementation should preserve these options for protected entry fields (e.g., passwords).【F:src/format/KeePass2.h†L116-L123】

## Credential Sources and Composite Key
- KeePassXC databases are protected by a composite key derived from one or more credentials: a password, a key file, and optional hardware keys like YubiKey or OnlyKey. The UI documentation explicitly supports YubiKey/OnlyKey challenge-response in database credentials, which should map to CLI credential flows as well.【F:docs/topics/DatabaseOperations.adoc†L376-L385】

## CLI Architecture (Subsystems)
### 1) CLI Front-End
- **Argument parsing & command dispatch**: map `keepassxc-cli <command> [options]` to command handlers, mirroring the supported CLI commands list in the man page.【F:docs/man/keepassxc-cli.1.adoc†L24-L132】
- **Interactive mode**: support a shell-like session for multiple operations (`open`, `close`, `exit`/`quit`).【F:docs/man/keepassxc-cli.1.adoc†L85-L109】

### 2) Core Database Engine
- **KDBX reader/writer** that validates signatures/versions and implements header/inner-header parsing according to KDBX conventions (using the header field IDs as a reference).【F:src/format/KeePass2.h†L31-L114】
- **Entry/group model**: maintain hierarchical groups with entries, with support for attachments, custom fields, history, and TOTP (implied by CLI features such as attachment commands, show/clip with TOTP, and reports).【F:docs/man/keepassxc-cli.1.adoc†L43-L132】

### 3) Crypto and Key Management Layer
- **Cipher selection**: choose AES, Twofish, or ChaCha20 based on database metadata and CLI options for creation and editing.【F:src/format/KeePass2.h†L49-L55】
- **KDF selection**: default to Argon2id for KDBX 4, with AES-KDF used for KDBX 3.1 or explicit compatibility choices.【F:docs/topics/DatabaseOperations.adoc†L411-L418】
- **Protected streams**: implement Salsa20/ChaCha20 protected field streams for in-memory protected values.【F:src/format/KeePass2.h†L116-L123】

### 4) Credential Providers
- **Password prompt**: interactive password entry (optionally suppressed with `--no-password`).【F:docs/man/keepassxc-cli.1.adoc†L132-L150】
- **Key file**: load/generate a key file specified via `--key-file` for database creation and unlocking.【F:docs/man/keepassxc-cli.1.adoc†L132-L145】
- **YubiKey challenge-response**: allow slot selection via `--yubikey` and incorporate the response into the composite key for both creation and unlocking flows.【F:docs/man/keepassxc-cli.1.adoc†L146-L150】

## CLI Command Set (Behaviors)
Below is the canonical command set the CLI should implement. This list mirrors the current CLI man page and should be preserved for compatibility.

### Database Commands
- `db-create <database>`: create a new database with password, key file, and/or YubiKey challenge-response credentials; do not create if all credentials are empty.【F:docs/man/keepassxc-cli.1.adoc†L70-L75】
- `db-edit <database>`: modify database credentials/settings, with optional key file creation if it does not exist.【F:docs/man/keepassxc-cli.1.adoc†L76-L80】
- `db-info <database>`: show database information (metadata summary).【F:docs/man/keepassxc-cli.1.adoc†L81-L82】
- `open <database>` / `close`: enter/exit interactive mode for a database session.【F:docs/man/keepassxc-cli.1.adoc†L85-L109】
- `merge <database1> <database2>`: merge two databases, optionally reusing credentials or specifying separate credentials for the second database.【F:docs/man/keepassxc-cli.1.adoc†L92-L104】
- `export <database>` / `import <xml> <database>`: export to stdout (default XML) and import from XML into a newly created database (KDBX 4).【F:docs/man/keepassxc-cli.1.adoc†L112-L121】

### Entry and Group Operations
- `add <database> <entry>`: add entry with optional password generation/prompting.【F:docs/man/keepassxc-cli.1.adoc†L41-L49】
- `edit <database> <entry>`: edit entry fields with optional password generation/prompting.【F:docs/man/keepassxc-cli.1.adoc†L122-L126】
- `show <database> <entry>`: display entry fields (title, username, password, URL, notes) and optionally TOTP.【F:docs/man/keepassxc-cli.1.adoc†L127-L132】
- `rm <database> <entry>`: remove entry (move to recycle bin if present).【F:docs/man/keepassxc-cli.1.adoc†L109-L111】
- `ls <database> [group]`: list group contents (defaults to root group).【F:docs/man/keepassxc-cli.1.adoc†L88-L91】
- `mkdir <database> <group>` / `rmdir <database> <group>`: create or remove groups (trash bin behavior applies).【F:docs/man/keepassxc-cli.1.adoc†L100-L113】
- `mv <database> <entry> <group>`: move entry to a group.【F:docs/man/keepassxc-cli.1.adoc†L102-L105】
- `search <database> <term>`: search entries by term.【F:docs/man/keepassxc-cli.1.adoc†L121-L122】

### Attachments and Clipboard
- `attachment-import` / `attachment-export` / `attachment-rm`: manage entry attachments, with optional stdout export support.【F:docs/man/keepassxc-cli.1.adoc†L49-L61】
- `clip <database> <entry> [timeout]`: copy an entry attribute or TOTP to clipboard, with auto-clear timeout and group disambiguation behavior.【F:docs/man/keepassxc-cli.1.adoc†L62-L69】

### Reporting and Utilities
- `analyze <database>`: analyze passwords for weaknesses using offline HIBP SHA-1 hash lookup (or okon-cli).【F:docs/man/keepassxc-cli.1.adoc†L49-L58】
- `estimate [password]`: estimate password entropy (with optional advanced mode).【F:docs/man/keepassxc-cli.1.adoc†L127-L156】
- `generate`: generate a random password using configurable options (also usable via `add`/`edit`).【F:docs/man/keepassxc-cli.1.adoc†L112-L120】
- `diceware`: generate a diceware passphrase.【F:docs/man/keepassxc-cli.1.adoc†L82-L84】

### Session and Help
- `help [command]`: show command list or detailed command help.【F:docs/man/keepassxc-cli.1.adoc†L116-L118】
- `exit` / `quit`: terminate interactive mode (synonyms).【F:docs/man/keepassxc-cli.1.adoc†L89-L109】

## YubiKey Support for Database Creation
- The CLI must allow YubiKey challenge-response slots as part of database creation credentials (`db-create`) using the `--yubikey` option, aligning with the global CLI credential flags and the documented YubiKey support in KeePassXC database credentials.【F:docs/man/keepassxc-cli.1.adoc†L146-L150】【F:docs/topics/DatabaseOperations.adoc†L376-L385】

## Non-Goals (For a CLI-Only Reimplementation)
- GUI features and settings are out of scope; only CLI operations and data format compatibility are required.
- Browser integration and OS-specific integrations are excluded from the clean reimplementation scope.

