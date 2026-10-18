use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};

use crate::error::{AppError, AppResult};
use crate::yubikey::YubiKeySlot;

mod commands;
mod interactive;
mod progress;
mod ssh;

/// Run the keepassxcr CLI.
pub fn run() -> anyhow::Result<()> {
    // Decrypted data must never end up in a core dump, even if parsing a
    // hostile file crashes the process.
    crate::agent::harden_process();
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    progress::install();
    commands::dispatch(cli).context("command failed")
}

/// Top-level CLI definition.
#[derive(Debug, Parser)]
#[command(
    name = "keepassxcr",
    version,
    about = "KeePassXC-compatible CLI password manager"
)]
pub struct Cli {
    /// Increase logging verbosity.
    #[arg(long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands supported by the CLI.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new database.
    DbCreate(DbCreateArgs),
    /// Edit database credentials/settings.
    DbEdit(DbEditArgs),
    /// Show database metadata.
    DbInfo(DbOpenArgs),
    /// Open a database in interactive mode.
    Open(DbOpenArgs),
    /// Merge two databases.
    Merge(MergeArgs),
    /// Export a database to XML.
    Export(DbExportArgs),
    /// Import XML into a new database.
    Import(DbImportArgs),
    /// Add an entry.
    Add(EntryAddArgs),
    /// Edit an entry.
    Edit(EntryEditArgs),
    /// Show an entry.
    Show(EntryShowArgs),
    /// Remove an entry.
    Rm(EntryPathArgs),
    /// List group contents.
    Ls(GroupPathArgs),
    /// Create a group.
    Mkdir(GroupCreateArgs),
    /// Remove a group.
    Rmdir(GroupPathArgs),
    /// Move an entry to a group.
    Mv(EntryMoveArgs),
    /// Search entries by term.
    Search(SearchArgs),
    /// Import an attachment.
    AttachmentImport(AttachmentImportArgs),
    /// Export an attachment.
    AttachmentExport(AttachmentExportArgs),
    /// Remove an attachment.
    AttachmentRm(AttachmentRemoveArgs),
    /// Copy a field to the clipboard.
    Clip(ClipArgs),
    /// Load SSH keys stored in entries into ssh-agent (KeePassXC's SSH agent settings).
    SshAdd(SshAddArgs),
    /// Store an SSH private key in an entry, set up for ssh-add and KeePassXC.
    SshKeyImport(SshKeyImportArgs),
    /// Analyze passwords with offline HIBP data.
    Analyze(AnalyzeArgs),
    /// Estimate password strength.
    Estimate(EstimateArgs),
    /// Generate a random password.
    Generate(GenerateArgs),
    /// Generate a diceware passphrase.
    Diceware(DicewareArgs),
    /// Keep a database unlocked in a background agent.
    Unlock(UnlockArgs),
    /// Stop the unlock agent for a database, or all of them.
    Lock(LockArgs),
    /// Show whether a database is unlocked and for how long.
    Status(LockArgs),
    /// Use a YubiKey or security key plugged into another machine.
    #[command(subcommand)]
    Yubikey(YubiKeyCommand),
    /// Protect a key file with FIDO2 security keys (e.g. a Yubico Security Key).
    #[command(subcommand)]
    Fido2(Fido2Command),
    /// Run the unlock agent (started by `unlock`).
    #[command(name = "__agent", hide = true)]
    Agent(AgentArgs),
}

/// Common database credential arguments.
#[derive(Debug, Args, Clone)]
pub struct CredentialArgs {
    /// Database password (unsafe; prefer prompt or stdin).
    ///
    /// Hidden from help: other local users can read it in the process list.
    #[arg(long, hide = true)]
    pub password: Option<String>,
    /// Disable password prompt.
    #[arg(long)]
    pub no_password: bool,
    /// Key file path.
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
    /// YubiKey challenge-response slot and optional serial (e.g. 2 or 2:7370001).
    #[arg(short = 'y', long, value_name = "SLOT[:SERIAL]")]
    pub yubikey: Option<YubiKeySlot>,
    /// Ignore the unlock agent and ask for credentials.
    #[arg(long)]
    pub no_agent: bool,
}

/// Open a database with credentials.
#[derive(Debug, Args, Clone)]
pub struct DbOpenArgs {
    /// Path to the database file.
    pub database: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Unlock arguments.
#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Path to the database file.
    pub database: PathBuf,

    /// Lock after this long without use (e.g. 90s, 15m, 1h).
    #[arg(long, value_name = "DURATION", default_value = "15m", value_parser = crate::agent::parse_duration)]
    pub idle: Duration,

    /// Lock after this long no matter what (e.g. 8h, 1d).
    #[arg(long, value_name = "DURATION", default_value = "8h", value_parser = crate::agent::parse_duration)]
    pub max: Duration,

    /// Also load the SSH keys KeePassXC loads on unlock into ssh-agent
    /// (entries set to "add key to agent when database is opened").
    #[arg(long)]
    pub ssh_add: bool,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// YubiKey subcommands.
#[derive(Debug, Subcommand)]
pub enum YubiKeyCommand {
    /// Answer YubiKey and security key requests from a socket, e.g. forwarded
    /// with `ssh -R`.
    ///
    /// Run this where the key is plugged in. On the other machine keepassxcr
    /// uses $KEEPASSXCR_YUBIKEY_SOCKET, or ~/.keepassxcr-yubikey.sock when it
    /// exists, instead of USB. A security key's PIN is asked for here.
    Serve(YubiKeyServeArgs),
}

/// FIDO2 key file subcommands.
///
/// A FIDO2-protected key file (`.fido2`) holds an ordinary KeePass key file
/// encrypted so that only an enrolled security key can open it. Pass it to
/// `--key-file` like any key file; the database stays a standard KeePassXC
/// file that KeePassXC opens with the plain key file.
#[derive(Debug, Subcommand)]
pub enum Fido2Command {
    /// Create a FIDO2-protected key file with the plugged-in security key.
    ///
    /// Without --from, a new random key file is made and its plain copy is
    /// written to --backup: keep that copy offline, it is what KeePassXC opens
    /// the database with and the way back in if the security key is lost.
    Enroll(Fido2EnrollArgs),
    /// Enrol another security key, e.g. a spare, in a FIDO2-protected key file.
    AddKey(Fido2AddKeyArgs),
    /// List the security keys enrolled in a FIDO2-protected key file.
    List(Fido2FileArgs),
    /// Remove an enrolled security key (by its number in `list`).
    RemoveKey(Fido2RemoveKeyArgs),
    /// Decrypt a FIDO2-protected key file back to the plain key file.
    Export(Fido2ExportArgs),
}

/// `fido2 enroll` arguments.
#[derive(Debug, Args)]
pub struct Fido2EnrollArgs {
    /// The FIDO2-protected key file to create (e.g. personal.keyx.fido2).
    pub file: PathBuf,
    /// Protect this existing key file instead of making a new one.
    #[arg(long, value_name = "KEY_FILE", conflicts_with = "backup")]
    pub from: Option<PathBuf>,
    /// Where to write the plain copy of the new key file.
    #[arg(long, value_name = "PATH", required_unless_present = "from")]
    pub backup: Option<PathBuf>,
    #[command(flatten)]
    pub key: Fido2KeyArgs,
}

/// How a security key is enrolled.
#[derive(Debug, Args)]
pub struct Fido2KeyArgs {
    /// Name for this security key, shown by `fido2 list`.
    #[arg(long, default_value = "security key")]
    pub label: String,
    /// Unlock with a touch only, even when the key has a PIN.
    #[arg(long)]
    pub no_pin: bool,
}

/// `fido2 add-key` arguments.
#[derive(Debug, Args)]
pub struct Fido2AddKeyArgs {
    /// The FIDO2-protected key file.
    pub file: PathBuf,
    /// Read the key file from this plain copy instead of unlocking with an
    /// enrolled security key.
    #[arg(long, value_name = "KEY_FILE")]
    pub from: Option<PathBuf>,
    #[command(flatten)]
    pub key: Fido2KeyArgs,
}

/// A FIDO2-protected key file.
#[derive(Debug, Args)]
pub struct Fido2FileArgs {
    /// The FIDO2-protected key file.
    pub file: PathBuf,
}

/// `fido2 remove-key` arguments.
#[derive(Debug, Args)]
pub struct Fido2RemoveKeyArgs {
    /// The FIDO2-protected key file.
    pub file: PathBuf,
    /// Number of the key to remove, as `fido2 list` shows it.
    pub number: usize,
}

/// `fido2 export` arguments.
#[derive(Debug, Args)]
pub struct Fido2ExportArgs {
    /// The FIDO2-protected key file.
    pub file: PathBuf,
    /// Write the plain key file here (refuses to overwrite).
    #[arg(long, short, value_name = "PATH")]
    pub output: PathBuf,
}

/// `yubikey serve` arguments.
#[derive(Debug, Args)]
pub struct YubiKeyServeArgs {
    /// Socket to listen on [default: $KEEPASSXCR_YUBIKEY_SOCKET, else ~/.keepassxcr-yubikey.sock].
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

/// Lock and status arguments.
#[derive(Debug, Args)]
pub struct LockArgs {
    /// Path to the database file. Omit for every unlocked database.
    pub database: Option<PathBuf>,
}

/// Hidden agent arguments.
#[derive(Debug, Args)]
pub struct AgentArgs {
    /// Canonical database path.
    pub database: PathBuf,
    /// Idle timeout in seconds.
    #[arg(long)]
    pub idle_secs: u64,
    /// Maximum lifetime in seconds.
    #[arg(long)]
    pub max_secs: u64,
}

/// Create database arguments.
#[derive(Debug, Args)]
pub struct DbCreateArgs {
    /// Path to the database file.
    pub database: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,

    /// Database format version (3.1 or 4).
    #[arg(long, value_name = "VERSION", default_value = "4")]
    pub format: u32,

    /// Cipher name (aes256, twofish, chacha20).
    #[arg(long, value_name = "CIPHER", default_value = "aes256")]
    pub cipher: String,

    /// KDF name (argon2id, argon2d, aes-kdf).
    #[arg(long, value_name = "KDF", default_value = "argon2id")]
    pub kdf: String,
}

/// Edit database arguments.
#[derive(Debug, Args)]
pub struct DbEditArgs {
    /// Path to the database file.
    pub database: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,

    /// New password (unsafe; prefer prompt or stdin).
    ///
    /// Hidden from help: other local users can read it in the process list.
    #[arg(long, hide = true)]
    pub new_password: Option<String>,
    /// Disable prompt for new password.
    #[arg(long)]
    pub new_no_password: bool,
    /// New key file.
    #[arg(long, value_name = "FILE")]
    pub new_key_file: Option<PathBuf>,
    /// New YubiKey challenge-response slot and optional serial (e.g. 2 or 2:7370001).
    #[arg(long, value_name = "SLOT[:SERIAL]", conflicts_with = "unset_yubikey")]
    pub new_yubikey: Option<YubiKeySlot>,
    /// Stop requiring a YubiKey.
    #[arg(long)]
    pub unset_yubikey: bool,
}

/// Merge two databases.
#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Target database path.
    pub database: PathBuf,
    /// Source database path to merge.
    pub source: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,

    /// Source database password (unsafe; prefer prompt or stdin).
    ///
    /// Hidden from help: other local users can read it in the process list.
    #[arg(long, hide = true)]
    pub source_password: Option<String>,
    /// Source key file.
    #[arg(long, value_name = "FILE")]
    pub source_key_file: Option<PathBuf>,
    /// YubiKey slot and optional serial for the source database.
    #[arg(long = "yubikey-from", value_name = "SLOT[:SERIAL]")]
    pub source_yubikey: Option<YubiKeySlot>,
}

/// Export database arguments.
#[derive(Debug, Args)]
pub struct DbExportArgs {
    /// Path to the database file.
    pub database: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Import database arguments.
#[derive(Debug, Args)]
pub struct DbImportArgs {
    /// Input XML file.
    pub xml: PathBuf,
    /// Path to the database file.
    pub database: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Entry path arguments.
#[derive(Debug, Args)]
pub struct EntryPathArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Add entry arguments.
#[derive(Debug, Args)]
pub struct EntryAddArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,

    /// Username to set.
    #[arg(long)]
    pub username: Option<String>,
    /// URL to set.
    #[arg(long)]
    pub url: Option<String>,
    /// Notes to set.
    #[arg(long)]
    pub notes: Option<String>,

    /// Prompt for the entry password.
    #[arg(short = 'p', long = "password-prompt", conflicts_with = "generate")]
    pub password_prompt: bool,

    /// Generate a random password.
    #[arg(short = 'g', long)]
    pub generate: bool,

    #[command(flatten)]
    pub password_options: PasswordOptionsArgs,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Edit entry arguments.
#[derive(Debug, Args)]
pub struct EntryEditArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,

    /// New title.
    #[arg(long)]
    pub title: Option<String>,
    /// New username.
    #[arg(long)]
    pub username: Option<String>,
    /// New URL.
    #[arg(long)]
    pub url: Option<String>,
    /// New notes.
    #[arg(long)]
    pub notes: Option<String>,

    /// Prompt for the entry password.
    #[arg(short = 'p', long = "password-prompt", conflicts_with = "generate")]
    pub password_prompt: bool,

    /// Generate a random password.
    #[arg(short = 'g', long)]
    pub generate: bool,

    #[command(flatten)]
    pub password_options: PasswordOptionsArgs,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Show entry arguments.
#[derive(Debug, Args)]
pub struct EntryShowArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,

    /// Show password field.
    #[arg(long)]
    pub show_password: bool,
    /// Show TOTP if available.
    #[arg(long)]
    pub totp: bool,
    /// Print only these attributes' values, one per line (Title, UserName,
    /// Password, URL, Notes or a custom attribute). Repeatable.
    #[arg(short = 'a', long = "attributes", value_name = "ATTR")]
    pub attributes: Vec<String>,
    /// Accepted for keepassxc-cli compatibility; keepassxcr prints no extra output.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Group path arguments.
#[derive(Debug, Args)]
pub struct GroupPathArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Group path (Group/Subgroup). Defaults to root.
    pub group: Option<String>,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Group creation arguments.
#[derive(Debug, Args)]
pub struct GroupCreateArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Group path to create.
    pub group: String,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Move entry arguments.
#[derive(Debug, Args)]
pub struct EntryMoveArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,
    /// Destination group path.
    pub group: String,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Search arguments.
#[derive(Debug, Args)]
pub struct SearchArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Search term.
    pub term: String,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Attachment import arguments.
#[derive(Debug, Args)]
pub struct AttachmentImportArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,
    /// Attachment name.
    pub name: String,
    /// Attachment file path.
    pub file: PathBuf,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Attachment export arguments.
#[derive(Debug, Args)]
pub struct AttachmentExportArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,
    /// Attachment name.
    pub name: String,
    /// Output file (use '-' for stdout).
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Attachment remove arguments.
#[derive(Debug, Args)]
pub struct AttachmentRemoveArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,
    /// Attachment name.
    pub name: String,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// `ssh-add` arguments.
#[derive(Debug, Args)]
pub struct SshAddArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entries holding SSH keys (Group/Entry).
    #[arg(required_unless_present_any = ["all", "list"])]
    pub entries: Vec<String>,

    /// Every key KeePassXC loads on unlock; with --remove, every SSH key entry.
    #[arg(short = 'a', long, conflicts_with = "entries")]
    pub all: bool,
    /// Remove the keys from ssh-agent instead.
    #[arg(short = 'd', long, conflicts_with = "list")]
    pub remove: bool,
    /// List entries with SSH keys and whether ssh-agent has them.
    #[arg(short = 'l', long, conflicts_with_all = ["entries", "all"])]
    pub list: bool,
    /// Have ssh-agent forget the keys after this long (e.g. 30m, 8h), instead
    /// of the entry's setting. Never longer than an unlocked database's time left.
    #[arg(short = 't', long, value_name = "DURATION", value_parser = crate::agent::parse_duration)]
    pub lifetime: Option<Duration>,
    /// Have ssh-agent ask before each use (needs ssh-askpass).
    #[arg(short = 'c', long)]
    pub confirm: bool,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// `ssh-key-import` arguments.
#[derive(Debug, Args)]
pub struct SshKeyImportArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry to store the key in (Group/Entry); its password must be the key's
    /// passphrase, or empty for an unencrypted key.
    pub entry: String,
    /// OpenSSH private key file.
    pub key: PathBuf,

    /// Attachment name [default: the key file's name].
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
    /// Don't load the key when the database is unlocked with `unlock --ssh-add`.
    #[arg(long)]
    pub no_add_on_unlock: bool,
    /// Keep the key in ssh-agent when the database locks.
    #[arg(long)]
    pub keep_on_lock: bool,
    /// Have ssh-agent forget the key after this long (e.g. 1h).
    #[arg(short = 't', long, value_name = "DURATION", value_parser = crate::agent::parse_duration)]
    pub lifetime: Option<Duration>,
    /// Have ssh-agent ask before each use (needs ssh-askpass).
    #[arg(short = 'c', long)]
    pub confirm: bool,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Clip arguments.
#[derive(Debug, Args)]
pub struct ClipArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Entry path (Group/Entry).
    pub entry: String,
    /// Field to copy (title, username, password, url, notes, totp).
    pub field: String,
    /// Seconds before the clipboard is cleared (default 10, 0 to keep it).
    pub timeout: Option<u64>,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Analyze arguments.
#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    /// Path to the database file.
    pub database: PathBuf,
    /// Path to HIBP SHA-1 hash list.
    #[arg(long, value_name = "FILE")]
    pub hibp: Option<PathBuf>,

    #[command(flatten)]
    pub credentials: CredentialArgs,
}

/// Estimate arguments.
#[derive(Debug, Args)]
pub struct EstimateArgs {
    /// Password to estimate (omit to prompt).
    pub password: Option<String>,
    /// Enable advanced output.
    #[arg(long)]
    pub advanced: bool,
}

/// Password generation arguments.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[command(flatten)]
    pub options: PasswordOptionsArgs,
}

/// Diceware arguments.
#[derive(Debug, Args)]
pub struct DicewareArgs {
    /// Number of words.
    #[arg(long, default_value = "6")]
    pub words: usize,
}

/// Password generation options shared by generate/add/edit commands.
#[derive(Debug, Args, Clone)]
pub struct PasswordOptionsArgs {
    /// Length of the password.
    #[arg(long, default_value = "20")]
    pub length: usize,
    /// Include lowercase letters.
    #[arg(long, default_value_t = true)]
    pub lower: bool,
    /// Include uppercase letters.
    #[arg(long, default_value_t = true)]
    pub upper: bool,
    /// Include digits.
    #[arg(long, default_value_t = true)]
    pub digits: bool,
    /// Include symbols.
    #[arg(long, default_value_t = true)]
    pub symbols: bool,
}

impl CredentialArgs {
    /// Validate credential inputs.
    pub fn validate(&self) -> AppResult<()> {
        if self.no_password && self.password.is_some() {
            return Err(AppError::InvalidInput(
                "--no-password conflicts with --password".to_string(),
            ));
        }
        Ok(())
    }
}

fn init_tracing(verbose: bool) {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .try_init();
}
