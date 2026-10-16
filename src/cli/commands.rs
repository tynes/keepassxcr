use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::Context as _;
use rand::Rng;
use rand::seq::SliceRandom;
use secrecy::{ExposeSecret, SecretString};
use sha1::Digest as _;
use tracing::{error, warn};

use crate::cli::{
    AnalyzeArgs, AttachmentExportArgs, AttachmentImportArgs, AttachmentRemoveArgs, ClipArgs,
    Command, DbCreateArgs, DbEditArgs, DbExportArgs, DbImportArgs, DbOpenArgs, DicewareArgs,
    EntryAddArgs, EntryEditArgs, EntryMoveArgs, EntryPathArgs, EntryShowArgs, EstimateArgs,
    GenerateArgs, GroupCreateArgs, GroupPathArgs, MergeArgs, PasswordOptionsArgs, SearchArgs,
};
use crate::crypto::{CipherId, KdfConfig, KdfType, KeyFile, ProtectedStreamAlgo};
use crate::error::{AppError, AppResult};
use crate::format::{Compression, Credentials, KdbxFile, KdbxVersion, read_kdbx, write_kdbx};
use crate::model::{Attachment, Database, Entry, Group};
use crate::xml::{BinaryPool, write_database};

/// Dispatch CLI commands.
pub fn dispatch(cli: crate::cli::Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::DbCreate(args) => db_create(args).context("db-create failed"),
        Command::DbEdit(args) => db_edit(args).context("db-edit failed"),
        Command::DbInfo(args) => db_info(args).context("db-info failed"),
        Command::Open(args) => {
            crate::cli::interactive::open_interactive(args).context("open failed")
        }
        Command::Merge(args) => merge(args).context("merge failed"),
        Command::Export(args) => export_db(args).context("export failed"),
        Command::Import(args) => import_db(args).context("import failed"),
        Command::Add(args) => add_entry(args).context("add failed"),
        Command::Edit(args) => edit_entry(args).context("edit failed"),
        Command::Show(args) => show_entry(args).context("show failed"),
        Command::Rm(args) => remove_entry(args).context("rm failed"),
        Command::Ls(args) => list_group(args).context("ls failed"),
        Command::Mkdir(args) => create_group(args).context("mkdir failed"),
        Command::Rmdir(args) => remove_group(args).context("rmdir failed"),
        Command::Mv(args) => move_entry(args).context("mv failed"),
        Command::Search(args) => search(args).context("search failed"),
        Command::AttachmentImport(args) => {
            attachment_import(args).context("attachment-import failed")
        }
        Command::AttachmentExport(args) => {
            attachment_export(args).context("attachment-export failed")
        }
        Command::AttachmentRm(args) => attachment_remove(args).context("attachment-rm failed"),
        Command::Clip(args) => clip(args).context("clip failed"),
        Command::Analyze(args) => analyze(args).context("analyze failed"),
        Command::Estimate(args) => estimate(args).context("estimate failed"),
        Command::Generate(args) => generate(args).context("generate failed"),
        Command::Diceware(args) => diceware(args).context("diceware failed"),
    }
}

fn db_create(args: DbCreateArgs) -> anyhow::Result<()> {
    let credentials = build_new_database_credentials(&args.credentials)?;
    if credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "db-create requires at least one credential".to_string(),
        )));
    }

    let version = parse_version(args.format)?;
    let cipher = parse_cipher(&args.cipher)?;
    let kdf = parse_kdf(&args.kdf, version)?;

    let name = database_name_from_path(&args.database);
    let mut database = Database::new(name.clone());
    database.meta_mut().set_name(name);

    let protected_stream = if version.is_kdbx4() {
        ProtectedStreamAlgo::ChaCha20
    } else {
        ProtectedStreamAlgo::Salsa20
    };

    let file = KdbxFile {
        version,
        cipher,
        compression: Compression::Gzip,
        kdf,
        protected_stream,
        database,
    };

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Database created at {}", args.database.display());
    Ok(())
}

fn db_edit(args: DbEditArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.credentials)?;
    let file = read_kdbx(&args.database, &credentials)?;

    let new_credentials = build_new_credentials(&args, &credentials)?;
    if new_credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "db-edit requires new credentials".to_string(),
        )));
    }

    write_kdbx(&args.database, &file, &new_credentials)?;
    println!("Database credentials updated.");
    Ok(())
}

fn db_info(args: DbOpenArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.credentials)?;
    let file = read_kdbx(&args.database, &credentials)?;
    let (groups, entries) = count_groups_entries(file.database.root());

    println!("Name: {}", file.database.meta().name());
    println!("Description: {}", file.database.meta().description());
    println!("Version: {:?}", file.version);
    println!("Cipher: {:?}", file.cipher);
    println!("KDF: {:?}", file.kdf);
    println!("Compression: {:?}", file.compression);
    println!("Groups: {groups}");
    println!("Entries: {entries}");
    Ok(())
}

fn merge(args: MergeArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.credentials)?;
    let mut target = read_kdbx(&args.database, &credentials)?;

    let source_password = match args.source_password {
        Some(password) => {
            warn_password_argument();
            Some(SecretString::new(password))
        }
        None if args.source_key_file.is_none() => {
            let password = read_secret("Password for source database: ")?;
            (!password.is_empty()).then(|| SecretString::new(password))
        }
        None => None,
    };
    let source_credentials = Credentials {
        password: source_password,
        key_file: args
            .source_key_file
            .as_ref()
            .map(|path| KeyFile::load(path))
            .transpose()?,
    };
    let source = read_kdbx(&args.source, &source_credentials)?;

    let stats = merge_databases(&mut target.database, &source.database);
    write_kdbx(&args.database, &target, &credentials)?;
    println!(
        "Merged {} into {}: {} added, {} updated.",
        args.source.display(),
        args.database.display(),
        stats.added,
        stats.updated
    );
    Ok(())
}

/// Counts reported by [`merge_databases`].
#[derive(Debug, Default, PartialEq, Eq)]
struct MergeStats {
    added: usize,
    updated: usize,
}

/// Merge `source` into `target` by UUID, keeping the newer version of each entry.
///
/// This follows KeePassXC's default "keep newer" mode: entries and groups are
/// matched by UUID wherever they are in the tree, new ones are added under
/// their (matched or newly created) parent group, and when both sides have an
/// entry the one with the later modification time wins. The losing version is
/// kept in the entry history, so nothing is lost. The source root group maps
/// onto the target root group. Deletions recorded in the source are not
/// applied.
fn merge_databases(target: &mut Database, source: &Database) -> MergeStats {
    let mut stats = MergeStats::default();
    let root_uuid = target.root().uuid();
    merge_group_contents(target.root_mut(), source.root(), root_uuid, &mut stats);
    stats
}

fn merge_group_contents(
    target_root: &mut Group,
    source: &Group,
    target_group: uuid::Uuid,
    stats: &mut MergeStats,
) {
    for entry in source.entries() {
        if let Some(existing) = target_root.entry_by_uuid_mut(entry.uuid()) {
            if merge_entry(existing, entry) {
                stats.updated += 1;
            }
        } else if let Some(group) = target_root.group_by_uuid_mut(target_group) {
            group.entries_mut().push(entry.clone());
            stats.added += 1;
        }
    }
    for child in source.groups() {
        if target_root.group_by_uuid(child.uuid()).is_none()
            && let Some(parent) = target_root.group_by_uuid_mut(target_group)
        {
            parent.groups_mut().push(child.shell());
        }
        merge_group_contents(target_root, child, child.uuid(), stats);
    }
}

/// Merge one entry; returns true if the target's current version changed.
fn merge_entry(target: &mut Entry, source: &Entry) -> bool {
    let target_time = target.last_modification_secs();
    let source_time = source.last_modification_secs();
    if source_time == target_time {
        return false;
    }

    let mut history: Vec<Entry> = target
        .history()
        .iter()
        .chain(source.history())
        .cloned()
        .collect();
    let source_is_newer = source_time > target_time;
    let (mut winner, loser) = if source_is_newer {
        (source.clone(), target.clone())
    } else {
        (target.clone(), source.clone())
    };
    let mut loser = loser;
    loser.history_mut().clear();
    history.push(loser);

    // Oldest first, without duplicate versions.
    history.sort_by_key(|item| item.last_modification_secs());
    history.dedup_by_key(|item| item.last_modification_secs());
    history.retain(|item| item.last_modification_secs() != winner.last_modification_secs());
    *winner.history_mut() = history;
    *target = winner;
    source_is_newer
}

fn export_db(args: DbExportArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.credentials)?;
    let file = read_kdbx(&args.database, &credentials)?;
    let mut database = file.database.clone();
    strip_attachments(database.root_mut());
    let output = write_database(
        &database,
        &[0u8; 32],
        ProtectedStreamAlgo::Salsa20,
        false,
        BinaryPool::InnerHeader,
    )?;
    let mut stdout = io::stdout();
    stdout.write_all(&output.xml)?;
    Ok(())
}

fn import_db(args: DbImportArgs) -> anyhow::Result<()> {
    let xml_bytes = fs::read(&args.xml)?;
    let database =
        crate::xml::read_database(&xml_bytes, &[], &[0u8; 32], ProtectedStreamAlgo::Salsa20)?;

    let credentials = build_new_database_credentials(&args.credentials)?;
    if credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "import requires credentials for new database".to_string(),
        )));
    }

    let file = KdbxFile {
        version: KdbxVersion::V4,
        cipher: CipherId::Aes256,
        compression: Compression::Gzip,
        kdf: KdfConfig::default_argon2id(),
        protected_stream: ProtectedStreamAlgo::ChaCha20,
        database,
    };

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Imported XML into {}", args.database.display());
    Ok(())
}

fn add_entry(args: EntryAddArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let group = file
        .database
        .group_by_path_mut(&group_path)
        .ok_or_else(|| AppError::InvalidInput("group not found".to_string()))?;

    if group.find_entry(title).is_some() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "entry already exists".to_string(),
        )));
    }

    let mut entry = Entry::new(title.to_string());
    if let Some(username) = args.username {
        entry.set_username(username);
    }
    if let Some(url) = args.url {
        entry.set_url(url);
    }
    if let Some(notes) = args.notes {
        entry.set_notes(notes);
    }

    let password = if args.password_prompt {
        let value = read_secret("Entry password: ")?;
        if value.is_empty() { None } else { Some(value) }
    } else if args.generate {
        Some(generate_password(password_options_from_args(
            &args.password_options,
        ))?)
    } else {
        None
    };
    if let Some(pass) = password {
        entry.set_password(SecretString::new(pass));
    }

    group.entries_mut().push(entry);
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry added.");
    Ok(())
}

fn edit_entry(args: EntryEditArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path_mut(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    // Keep the previous version in the entry history, like KeePassXC does.
    entry.begin_update();
    if let Some(value) = args.title {
        entry.set_title(value);
    }
    if let Some(value) = args.username {
        entry.set_username(value);
    }
    if let Some(value) = args.url {
        entry.set_url(value);
    }
    if let Some(value) = args.notes {
        entry.set_notes(value);
    }

    let password = if args.password_prompt {
        let value = read_secret("Entry password: ")?;
        if value.is_empty() { None } else { Some(value) }
    } else if args.generate {
        Some(generate_password(password_options_from_args(
            &args.password_options,
        ))?)
    } else {
        None
    };
    if let Some(pass) = password {
        entry.set_password(SecretString::new(pass));
    }

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry updated.");
    Ok(())
}

fn show_entry(args: EntryShowArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    println!("Title: {}", entry.title());
    println!("Username: {}", entry.username());
    if args.show_password {
        println!("Password: {}", entry.password().expose_secret());
    }
    println!("URL: {}", entry.url());
    println!("Notes: {}", entry.notes());

    Ok(())
}

fn remove_entry(args: EntryPathArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let removed = remove_entry_from_group(file.database.root_mut(), &group_path, title);
    if !removed {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "entry not found".to_string(),
        )));
    }
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry removed.");
    Ok(())
}

fn list_group(args: GroupPathArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let path = split_group_path(args.group.as_deref())?;
    let group = file
        .database
        .group_by_path(&path)
        .ok_or_else(|| AppError::InvalidInput("group not found".to_string()))?;

    for child in group.groups() {
        println!("[G] {}", child.name());
    }
    for entry in group.entries() {
        println!("[E] {}", entry.title());
    }
    Ok(())
}

fn create_group(args: GroupCreateArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let path = split_group_path(Some(&args.group))?;
    ensure_group_path(file.database.root_mut(), &path);
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Group created.");
    Ok(())
}

fn remove_group(args: GroupPathArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let path = split_group_path(args.group.as_deref())?;
    if path.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "cannot remove root group".to_string(),
        )));
    }
    let removed = remove_group_by_path(file.database.root_mut(), &path);
    if !removed {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "group not found".to_string(),
        )));
    }
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Group removed.");
    Ok(())
}

fn move_entry(args: EntryMoveArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (source_path, title) = split_entry_path(&args.entry)?;
    let dest_path = split_group_path(Some(&args.group))?;
    let entry = take_entry(file.database.root_mut(), &source_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;
    let dest_group = file
        .database
        .group_by_path_mut(&dest_path)
        .ok_or_else(|| AppError::InvalidInput("destination group not found".to_string()))?;
    dest_group.entries_mut().push(entry);
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry moved.");
    Ok(())
}

fn search(args: SearchArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let mut results = Vec::new();
    collect_search_results(file.database.root(), "", &args.term, &mut results);
    for path in results {
        println!("{path}");
    }
    Ok(())
}

fn attachment_import(args: AttachmentImportArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path_mut(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    let data = fs::read(&args.file)?;
    entry.begin_update();
    entry
        .attachments_mut()
        .push(Attachment::new(args.name, data));

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Attachment imported.");
    Ok(())
}

fn attachment_export(args: AttachmentExportArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;
    let attachment = entry
        .attachments()
        .iter()
        .find(|att| att.name() == args.name)
        .ok_or_else(|| AppError::InvalidInput("attachment not found".to_string()))?;

    if let Some(output) = args.output {
        fs::write(output, attachment.data())?;
    } else {
        io::stdout().write_all(attachment.data())?;
    }
    Ok(())
}

fn attachment_remove(args: AttachmentRemoveArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path_mut(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    if !entry
        .attachments()
        .iter()
        .any(|attachment| attachment.name() == args.name)
    {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "attachment not found".to_string(),
        )));
    }
    entry.begin_update();
    entry
        .attachments_mut()
        .retain(|attachment| attachment.name() != args.name);

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Attachment removed.");
    Ok(())
}

fn clip(args: ClipArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let entry = file
        .database
        .entry_by_path(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    let value = match args.field.as_str() {
        "title" => entry.title().to_string(),
        "username" => entry.username().to_string(),
        "password" => entry.password().expose_secret().to_string(),
        "url" => entry.url().to_string(),
        "notes" => entry.notes().to_string(),
        _ => {
            return Err(anyhow::anyhow!(AppError::InvalidInput(
                "unknown field".to_string(),
            )));
        }
    };

    let mut clipboard = arboard::Clipboard::new()
        .map_err(|err| AppError::Clipboard(format!("clipboard error: {err}")))?;
    clipboard
        .set_text(value.clone())
        .map_err(|err| AppError::Clipboard(format!("clipboard error: {err}")))?;

    if let Some(timeout) = args.timeout {
        thread::sleep(Duration::from_secs(timeout));
        if let Err(err) = clipboard.set_text("") {
            error!("Failed to clear clipboard: {err}");
        }
    }

    println!("Copied {} to clipboard.", args.field);
    Ok(())
}

fn analyze(args: AnalyzeArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let entries = collect_passwords(file.database.root(), "");

    let mut weak = Vec::new();
    for (path, password) in &entries {
        if password.is_empty() {
            weak.push((path.clone(), "empty password".to_string()));
            continue;
        }
        if let Ok(result) = zxcvbn::zxcvbn(password, &[]) {
            if result.score() < 3 {
                weak.push((path.clone(), format!("weak score {}", result.score())));
            }
        }
    }

    if let Some(hibp_path) = args.hibp {
        let hibp_hits = hibp_check(&entries, &hibp_path)?;
        for (path, count) in hibp_hits {
            weak.push((path, format!("pwned {count} times")));
        }
    }

    if weak.is_empty() {
        println!("No weak passwords detected.");
    } else {
        for (path, reason) in weak {
            println!("{path}: {reason}");
        }
    }

    Ok(())
}

fn estimate(args: EstimateArgs) -> anyhow::Result<()> {
    let password = if let Some(pass) = args.password {
        pass
    } else {
        rpassword::prompt_password("Password: ")?
    };

    let result = zxcvbn::zxcvbn(&password, &[])
        .map_err(|_| AppError::InvalidInput("unable to estimate".to_string()))?;
    println!("Score: {}", result.score());
    println!("Guesses: {}", result.guesses());
    if args.advanced {
        println!(
            "Crack time (online): {}",
            result.crack_times().online_throttling_100_per_hour()
        );
        println!(
            "Crack time (offline): {}",
            result.crack_times().offline_fast_hashing_1e10_per_second()
        );
    }
    Ok(())
}

fn generate(args: GenerateArgs) -> anyhow::Result<()> {
    let password = generate_password(password_options_from_args(&args.options))?;
    println!("{password}");
    Ok(())
}

fn diceware(args: DicewareArgs) -> anyhow::Result<()> {
    let words = diceware_words();
    let mut rng = rand::thread_rng();
    let mut output = Vec::with_capacity(args.words);
    for _ in 0..args.words {
        let word = words
            .choose(&mut rng)
            .ok_or_else(|| AppError::InvalidInput("wordlist empty".to_string()))?;
        output.push(word.to_string());
    }
    println!("{}", output.join(" "));
    Ok(())
}

/// Build credentials from CLI arguments.
pub(crate) fn build_credentials(args: &crate::cli::CredentialArgs) -> AppResult<Credentials> {
    build_credentials_with(args, false)
}

/// Build credentials for a new database, asking twice for a prompted password.
fn build_new_database_credentials(args: &crate::cli::CredentialArgs) -> AppResult<Credentials> {
    build_credentials_with(args, true)
}

fn build_credentials_with(
    args: &crate::cli::CredentialArgs,
    confirm: bool,
) -> AppResult<Credentials> {
    args.validate()?;
    reject_yubikey(args.yubikey)?;
    let password = if let Some(pass) = &args.password {
        warn_password_argument();
        Some(SecretString::new(pass.clone()))
    } else if args.no_password {
        None
    } else {
        let prompt = read_secret("Password: ")?;
        if confirm && !prompt.is_empty() {
            let repeat = read_secret("Repeat password: ")?;
            if repeat != prompt {
                return Err(AppError::InvalidInput("passwords do not match".to_string()));
            }
        }
        if prompt.is_empty() {
            None
        } else {
            Some(SecretString::new(prompt))
        }
    };

    let key_file = args
        .key_file
        .as_ref()
        .map(|path| KeyFile::load(path))
        .transpose()?;

    Ok(Credentials { password, key_file })
}

/// Read a secret from the terminal without echo, or a line from stdin when
/// stdin is not a terminal (so passwords can be piped in, like keepassxc-cli).
fn read_secret(prompt: &str) -> io::Result<String> {
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt);
    }
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Warn that passwords given as arguments are visible to other local users.
fn warn_password_argument() {
    if io::stderr().is_terminal() {
        warn!(
            "passwords given on the command line are visible in the process list and shell \
             history; pipe the password on stdin or use the prompt instead"
        );
    }
}

/// YubiKey challenge-response is not implemented compatibly with KeePassXC yet.
///
/// The challenge has to be sent to the key on every open and save, so a fixed
/// response cannot work. Fail clearly instead of writing a database KeePassXC
/// cannot open.
fn reject_yubikey(slot: Option<u8>) -> AppResult<()> {
    if slot.is_some() {
        return Err(AppError::InvalidInput(
            "YubiKey challenge-response is not supported yet".to_string(),
        ));
    }
    Ok(())
}

fn build_new_credentials(args: &DbEditArgs, current: &Credentials) -> AppResult<Credentials> {
    reject_yubikey(args.new_yubikey)?;
    let password = if let Some(pass) = &args.new_password {
        warn_password_argument();
        Some(SecretString::new(pass.clone()))
    } else if args.new_no_password {
        None
    } else {
        current.password.clone()
    };

    let key_file = if let Some(path) = &args.new_key_file {
        Some(KeyFile::load(path)?)
    } else {
        current.key_file.clone()
    };

    Ok(Credentials { password, key_file })
}

fn parse_version(value: u32) -> AppResult<KdbxVersion> {
    match value {
        3 => Ok(KdbxVersion::V3_1),
        4 => Ok(KdbxVersion::V4),
        _ => Err(AppError::InvalidInput("unsupported version".to_string())),
    }
}

fn parse_cipher(value: &str) -> AppResult<CipherId> {
    match value.to_lowercase().as_str() {
        "aes256" | "aes-256" | "aes" => Ok(CipherId::Aes256),
        "aes128" | "aes-128" => Ok(CipherId::Aes128),
        "twofish" => Ok(CipherId::Twofish),
        "chacha20" => Ok(CipherId::ChaCha20),
        _ => Err(AppError::InvalidInput("unsupported cipher".to_string())),
    }
}

fn parse_kdf(value: &str, version: KdbxVersion) -> AppResult<KdfConfig> {
    match value.to_lowercase().as_str() {
        "argon2id" => {
            if !version.is_kdbx4() {
                return Err(AppError::InvalidInput("Argon2 requires KDBX4".to_string()));
            }
            Ok(KdfConfig::default_argon2id())
        }
        "argon2d" => {
            if !version.is_kdbx4() {
                return Err(AppError::InvalidInput("Argon2 requires KDBX4".to_string()));
            }
            let mut config = KdfConfig::default_argon2id();
            if let KdfConfig::Argon2 { kind, .. } = &mut config {
                *kind = KdfType::Argon2d;
            }
            Ok(config)
        }
        "aes-kdf" | "aes" => Ok(KdfConfig::default_aes(!version.is_kdbx4())),
        _ => Err(AppError::InvalidInput("unsupported KDF".to_string())),
    }
}

fn database_name_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("Database")
        .to_string()
}

fn load_database(
    path: &Path,
    args: &crate::cli::CredentialArgs,
) -> AppResult<(KdbxFile, Credentials)> {
    let credentials = build_credentials(args)?;
    let file = read_kdbx(path, &credentials)?;
    Ok((file, credentials))
}

/// Split an entry path into group segments and entry title.
pub(crate) fn split_entry_path(path: &str) -> AppResult<(Vec<&str>, &str)> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return Err(AppError::InvalidInput("entry path is empty".to_string()));
    }
    let (groups, entry) = parts.split_at(parts.len() - 1);
    Ok((groups.to_vec(), entry[0]))
}

/// Split a group path into segments.
pub(crate) fn split_group_path(path: Option<&str>) -> AppResult<Vec<&str>> {
    let path = match path {
        Some(value) => value,
        None => return Ok(Vec::new()),
    };
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    Ok(parts)
}

fn ensure_group_path<'a>(mut group: &'a mut Group, path: &[&str]) -> &'a mut Group {
    for segment in path {
        if group.find_group(segment).is_none() {
            group.groups_mut().push(Group::new(segment.to_string()));
        }
        let next = group.find_group_mut(segment).expect("group exists");
        group = next;
    }
    group
}

fn remove_group_by_path(group: &mut Group, path: &[&str]) -> bool {
    if path.len() == 1 {
        let name = path[0];
        let before = group.groups().len();
        group.groups_mut().retain(|child| child.name() != name);
        return group.groups().len() != before;
    }

    let (head, tail) = path.split_at(1);
    if let Some(child) = group.find_group_mut(head[0]) {
        return remove_group_by_path(child, tail);
    }
    false
}

fn remove_entry_from_group(group: &mut Group, path: &[&str], title: &str) -> bool {
    if path.is_empty() {
        let before = group.entries().len();
        group.entries_mut().retain(|entry| entry.title() != title);
        return group.entries().len() != before;
    }
    let (head, tail) = path.split_at(1);
    if let Some(child) = group.find_group_mut(head[0]) {
        return remove_entry_from_group(child, tail, title);
    }
    false
}

fn take_entry(group: &mut Group, path: &[&str], title: &str) -> Option<Entry> {
    if path.is_empty() {
        let mut index = None;
        for (idx, entry) in group.entries().iter().enumerate() {
            if entry.title() == title {
                index = Some(idx);
                break;
            }
        }
        return index.map(|idx| group.entries_mut().remove(idx));
    }
    let (head, tail) = path.split_at(1);
    let child = group.find_group_mut(head[0])?;
    take_entry(child, tail, title)
}

fn collect_search_results(group: &Group, prefix: &str, term: &str, output: &mut Vec<String>) {
    let prefix = if prefix.is_empty() {
        group.name().to_string()
    } else {
        format!("{prefix}/{name}", name = group.name())
    };

    for entry in group.entries() {
        if entry_matches(entry, term) {
            output.push(format!("{prefix}/{title}", title = entry.title()));
        }
    }
    for child in group.groups() {
        collect_search_results(child, &prefix, term, output);
    }
}

fn entry_matches(entry: &Entry, term: &str) -> bool {
    let term = term.to_lowercase();
    let mut haystacks = vec![
        entry.title().to_lowercase(),
        entry.username().to_lowercase(),
        entry.url().to_lowercase(),
        entry.notes().to_lowercase(),
    ];
    for (key, value) in entry.custom_fields() {
        haystacks.push(key.to_lowercase());
        haystacks.push(value.to_lowercase());
    }
    haystacks.iter().any(|hay| hay.contains(&term))
}

fn collect_passwords(group: &Group, prefix: &str) -> Vec<(String, String)> {
    let prefix = if prefix.is_empty() {
        group.name().to_string()
    } else {
        format!("{prefix}/{name}", name = group.name())
    };

    let mut output = Vec::new();
    for entry in group.entries() {
        output.push((
            format!("{prefix}/{title}", title = entry.title()),
            entry.password().expose_secret().to_string(),
        ));
    }
    for child in group.groups() {
        output.extend(collect_passwords(child, &prefix));
    }
    output
}

fn hibp_check(entries: &[(String, String)], path: &PathBuf) -> AppResult<HashMap<String, u64>> {
    let mut hash_to_entry = HashMap::new();
    for (entry_path, password) in entries {
        let hash = sha1_hex_upper(password);
        hash_to_entry.insert(hash, entry_path.clone());
    }

    let mut results = HashMap::new();
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if let Some((hash, count)) = line.split_once(':') {
            if let Some(entry_path) = hash_to_entry.get(hash) {
                let count = count.parse::<u64>().unwrap_or(0);
                results.insert(entry_path.clone(), count);
            }
        }
    }

    Ok(results)
}

fn sha1_hex_upper(password: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    hex::encode_upper(digest)
}

fn count_groups_entries(group: &Group) -> (usize, usize) {
    let mut groups = 1;
    let mut entries = group.entries().len();
    for child in group.groups() {
        let (child_groups, child_entries) = count_groups_entries(child);
        groups += child_groups;
        entries += child_entries;
    }
    (groups, entries)
}

fn strip_attachments(group: &mut Group) {
    for entry in group.entries_mut() {
        entry.attachments_mut().clear();
    }
    for child in group.groups_mut() {
        strip_attachments(child);
    }
}

#[derive(Debug, Clone)]
struct PasswordOptions {
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
        }
    }
}

fn generate_password(options: PasswordOptions) -> AppResult<String> {
    if options.length == 0 {
        return Err(AppError::InvalidInput("length must be > 0".to_string()));
    }

    let mut pools = Vec::new();
    if options.lower {
        pools.push("abcdefghijklmnopqrstuvwxyz");
    }
    if options.upper {
        pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.digits {
        pools.push("0123456789");
    }
    if options.symbols {
        pools.push("!@#$%^&*()-_=+[]{};:,.?");
    }

    if pools.is_empty() {
        return Err(AppError::InvalidInput(
            "no character sets selected".to_string(),
        ));
    }

    let all: String = pools.join("");
    let mut rng = rand::thread_rng();
    let mut chars = Vec::with_capacity(options.length);

    for pool in &pools {
        let bytes = pool.as_bytes();
        let idx = rng.gen_range(0..bytes.len());
        chars.push(bytes[idx] as char);
    }

    for _ in chars.len()..options.length {
        let bytes = all.as_bytes();
        let idx = rng.gen_range(0..bytes.len());
        chars.push(bytes[idx] as char);
    }

    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

fn password_options_from_args(args: &PasswordOptionsArgs) -> PasswordOptions {
    PasswordOptions {
        length: args.length,
        lower: args.lower,
        upper: args.upper,
        digits: args.digits,
        symbols: args.symbols,
    }
}

fn diceware_words() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS
        .get_or_init(|| include_str!("../../assets/diceware.txt").lines().collect())
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_entry_path_ok() {
        let (groups, entry) = split_entry_path("Group/Sub/Entry").expect("path");
        assert_eq!(groups, vec!["Group", "Sub"]);
        assert_eq!(entry, "Entry");
    }

    #[test]
    fn generate_password_length() {
        let password = generate_password(PasswordOptions {
            length: 16,
            ..PasswordOptions::default()
        })
        .expect("password");
        assert_eq!(password.len(), 16);
    }

    fn entry_at(title: &str, password: &str, time: &str) -> Entry {
        let mut entry = Entry::new(title.to_string());
        entry.set_password(SecretString::new(password.to_string()));
        entry.extra_mut().push(crate::model::RawElement::new(
            "Times".to_string(),
            format!("<Times><LastModificationTime>{time}</LastModificationTime></Times>"),
        ));
        entry
    }

    #[test]
    fn merge_keeps_newer_entry_and_history() {
        let mut target = Database::new("Target".to_string());
        let old = entry_at("Bank", "old", "2024-01-01T00:00:00Z");
        let uuid = old.uuid();
        target.root_mut().entries_mut().push(old);

        let mut source = Database::new("Source".to_string());
        let mut newer = entry_at("Bank", "new", "2025-01-01T00:00:00Z");
        newer.set_uuid(uuid);
        source.root_mut().entries_mut().push(newer);
        let mut group = Group::new("Work".to_string());
        group
            .entries_mut()
            .push(entry_at("Mail", "m", "2025-01-01T00:00:00Z"));
        source.root_mut().groups_mut().push(group);

        let stats = merge_databases(&mut target, &source);
        assert_eq!(
            stats,
            MergeStats {
                added: 1,
                updated: 1
            }
        );
        let bank = &target.root().entries()[0];
        assert_eq!(bank.password().expose_secret(), "new");
        assert_eq!(bank.history()[0].password().expose_secret(), "old");
        assert_eq!(target.root().groups()[0].entries()[0].title(), "Mail");

        // Merging the same source again changes nothing.
        let again = merge_databases(&mut target, &source);
        assert_eq!(again, MergeStats::default());
        assert_eq!(target.root().entries().len(), 1);
        assert_eq!(target.root().groups().len(), 1);
    }

    #[test]
    fn merge_keeps_target_when_newer() {
        let mut target = Database::new("Target".to_string());
        let current = entry_at("Bank", "current", "2025-01-01T00:00:00Z");
        let uuid = current.uuid();
        target.root_mut().entries_mut().push(current);
        let mut source = Database::new("Source".to_string());
        let mut stale = entry_at("Bank", "stale", "2024-01-01T00:00:00Z");
        stale.set_uuid(uuid);
        source.root_mut().entries_mut().push(stale);

        merge_databases(&mut target, &source);
        let bank = &target.root().entries()[0];
        assert_eq!(bank.password().expose_secret(), "current");
        assert_eq!(bank.history()[0].password().expose_secret(), "stale");
    }

    #[test]
    fn yubikey_is_rejected() {
        assert!(reject_yubikey(Some(1)).is_err());
        assert!(reject_yubikey(None).is_ok());
    }

    #[test]
    fn parse_cipher_aes() {
        let cipher = parse_cipher("aes256").expect("cipher");
        assert_eq!(cipher, CipherId::Aes256);
    }
}
