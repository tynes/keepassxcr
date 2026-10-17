use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};

use crate::error::{AppError, AppResult};

mod commands;
mod interactive;

/// Run the keepassxcr CLI.
pub fn run() -> anyhow::Result<()> {
    // Decrypted data must never end up in a core dump, even if parsing a
    // hostile file crashes the process.
    crate::agent::harden_process();
    let cli = Cli::parse();
    init_tracing(cli.verbose);
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
    /// YubiKey challenge-response slot (1 or 2).
    #[arg(long, value_name = "SLOT")]
    pub yubikey: Option<u8>,
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

    #[command(flatten)]
    pub credentials: CredentialArgs,
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
    /// New YubiKey challenge-response slot (1 or 2).
    #[arg(long, value_name = "SLOT")]
    pub new_yubikey: Option<u8>,
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
        if let Some(slot) = self.yubikey {
            if slot != 1 && slot != 2 {
                return Err(AppError::InvalidInput(
                    "--yubikey must be 1 or 2".to_string(),
                ));
            }
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
