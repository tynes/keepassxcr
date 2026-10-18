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
use zeroize::Zeroizing;

use crate::agent::{self, DbState, format_duration};
use crate::cli::{
    AnalyzeArgs, AttachmentExportArgs, AttachmentImportArgs, AttachmentRemoveArgs, ClipArgs,
    Command, DbCreateArgs, DbEditArgs, DbExportArgs, DbImportArgs, DbOpenArgs, DicewareArgs,
    EntryAddArgs, EntryEditArgs, EntryMoveArgs, EntryPathArgs, EntryShowArgs, EstimateArgs,
    GenerateArgs, GroupCreateArgs, GroupPathArgs, LockArgs, MergeArgs, PasswordOptionsArgs,
    SearchArgs, UnlockArgs, YubiKeyCommand,
};
use crate::crypto::{CipherId, KdfConfig, KdfType, KeyFile, ProtectedStreamAlgo};
use crate::error::{AppError, AppResult};
use crate::format::{Compression, Credentials, KdbxFile, KdbxVersion, read_kdbx, write_kdbx};
use crate::model::{Attachment, Database, Entry, Group, Removal, placeholders};
use crate::xml::{BinaryPool, write_database};

/// Seconds before `clip` clears the clipboard, as in keepassxc-cli.
const DEFAULT_CLIP_TIMEOUT_SECS: u64 = 10;

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
        Command::SshAdd(args) => crate::cli::ssh::ssh_add(args).context("ssh-add failed"),
        Command::SshKeyImport(args) => {
            crate::cli::ssh::ssh_key_import(args).context("ssh-key-import failed")
        }
        Command::Analyze(args) => analyze(args).context("analyze failed"),
        Command::Estimate(args) => estimate(args).context("estimate failed"),
        Command::Generate(args) => generate(args).context("generate failed"),
        Command::Diceware(args) => diceware(args).context("diceware failed"),
        Command::Unlock(args) => unlock(args).context("unlock failed"),
        Command::Lock(args) => lock(args).context("lock failed"),
        Command::Status(args) => status(args).context("status failed"),
        Command::Yubikey(command) => yubikey(command).context("yubikey failed"),
        Command::Agent(args) => serve_agent(args).context("agent failed"),
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
        public_custom_data: None,
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
    // The new credentials start from the current ones, so they must be known here.
    let credentials = build_local_credentials(&args.credentials)?;
    let file = read_kdbx(&args.database, &credentials)?;

    let new_credentials = build_new_credentials(&args, &credentials)?;
    if new_credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "db-edit requires new credentials".to_string(),
        )));
    }

    write_kdbx(&args.database, &file, &new_credentials)?;
    println!("Database credentials updated.");
    // A running agent still holds the old key.
    if !agent::lock(Some(&args.database))?.is_empty() {
        println!("Locked the unlock agent; run 'keepassxcr unlock' with the new credentials.");
    }
    Ok(())
}

fn db_info(args: DbOpenArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.database, &args.credentials)?;
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
    let credentials = build_credentials(&args.database, &args.credentials)?;
    let mut target = read_kdbx(&args.database, &credentials)?;

    let source_password = match args.source_password {
        Some(password) => {
            warn_password_argument();
            Some(SecretString::new(password))
        }
        None if args.source_key_file.is_none() => {
            let password = read_secret("Password for source database: ")?;
            (!password.is_empty()).then(|| into_secret(password))
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
        yubikey: args.source_yubikey,
        agent: None,
    };
    let source = read_kdbx(&args.source, &source_credentials)?;

    let stats = crate::model::merge::merge(
        &mut target.database,
        &source.database,
        crate::model::merge::MergeMode::KeepNewer,
    );
    write_kdbx(&args.database, &target, &credentials)?;
    println!(
        "Merged {} into {}: {} added, {} updated, {} moved.",
        args.source.display(),
        args.database.display(),
        stats.added,
        stats.updated,
        stats.moved
    );
    Ok(())
}

fn export_db(args: DbExportArgs) -> anyhow::Result<()> {
    let credentials = build_credentials(&args.database, &args.credentials)?;
    let file = read_kdbx(&args.database, &credentials)?;
    let mut database = file.database.clone();
    strip_attachments(database.root_mut());
    let output = write_database(
        &database,
        &[0u8; 32],
        ProtectedStreamAlgo::Salsa20,
        false,
        BinaryPool::InnerHeader,
        None,
    )?;
    let mut stdout = io::stdout();
    stdout.write_all(&output.xml)?;
    Ok(())
}

fn import_db(args: DbImportArgs) -> anyhow::Result<()> {
    let xml_bytes = fs::read(&args.xml)?;
    let database = crate::xml::read_database(
        &xml_bytes,
        &[],
        &[0u8; 32],
        ProtectedStreamAlgo::Salsa20,
        None,
    )?;

    let credentials = build_new_database_credentials(&args.credentials)?;
    if credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "import requires credentials for new database".to_string(),
        )));
    }

    let file = KdbxFile {
        version: KdbxVersion::V4_0,
        public_custom_data: None,
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
    if file.database.group_by_path(&group_path).is_none() {
        return Err(group_not_found(&file.database, &group_path, &args.database).into());
    }
    let group = file
        .database
        .group_by_path_mut(&group_path)
        .expect("group checked above");

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
        if value.is_empty() {
            None
        } else {
            Some(into_secret(value))
        }
    } else if args.generate {
        Some(SecretString::new(generate_password(
            password_options_from_args(&args.password_options),
        )?))
    } else {
        None
    };
    if let Some(pass) = password {
        entry.set_password(pass);
    }

    group.entries_mut().push(entry);
    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry added.");
    Ok(())
}

fn edit_entry(args: EntryEditArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let limits = file.database.meta().history_limits();
    let entry = file
        .database
        .entry_by_path_mut(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    // Keep the previous version in the entry history, like KeePassXC does.
    entry.begin_update(limits);
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
        if value.is_empty() {
            None
        } else {
            Some(into_secret(value))
        }
    } else if args.generate {
        Some(SecretString::new(generate_password(
            password_options_from_args(&args.password_options),
        )?))
    } else {
        None
    };
    if let Some(pass) = password {
        entry.set_password(pass);
    }

    write_kdbx(&args.database, &file, &credentials)?;
    println!("Entry updated.");
    Ok(())
}

fn show_entry(args: EntryShowArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let Some(entry) = file.database.entry_by_path(&group_path, title) else {
        eprintln!("Could not find entry with path {}.", args.entry);
        return Err(AppError::Reported.into());
    };

    if !args.attributes.is_empty() {
        // Like keepassxc-cli: print what resolves, report the rest on stderr
        // and fail once every attribute has been tried.
        let ctx = placeholders::Context {
            root: file.database.root(),
            database: &args.database,
        };
        let mut failed = false;
        for name in &args.attributes {
            match lookup_attribute(entry, name) {
                Lookup::Field(value) => println!("{value}"),
                Lookup::Attribute(value) => {
                    println!("{}", placeholders::resolve(entry, &value, ctx));
                }
                Lookup::Unknown => {
                    eprintln!("ERROR: unknown attribute {name}.");
                    failed = true;
                }
                Lookup::Ambiguous(matches) => {
                    eprintln!(
                        "ERROR: attribute {name} is ambiguous, it matches {}.",
                        matches.join(", ")
                    );
                    failed = true;
                }
            }
        }
        if failed {
            return Err(AppError::Reported.into());
        }
        return Ok(());
    }

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
    let uuid = file
        .database
        .entry_by_path(&group_path, title)
        .map(Entry::uuid)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;
    // Like keepassxc-cli: to the recycle bin, or for good if it is off or
    // the entry is already there.
    let removal = file.database.recycle_entry(uuid);
    write_kdbx(&args.database, &file, &credentials)?;
    match removal {
        Some(Removal::Recycled) => println!("Entry moved to the recycle bin."),
        _ => println!("Entry removed."),
    }
    Ok(())
}

fn list_group(args: GroupPathArgs) -> anyhow::Result<()> {
    let (file, _credentials) = load_database(&args.database, &args.credentials)?;
    let path = split_group_path(args.group.as_deref())?;
    let group = file
        .database
        .group_by_path(&path)
        .ok_or_else(|| group_not_found(&file.database, &path, &args.database))?;

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
    let uuid = file
        .database
        .group_by_path(&path)
        .map(Group::uuid)
        .ok_or_else(|| group_not_found(&file.database, &path, &args.database))?;
    let removal = file.database.recycle_group(uuid);
    write_kdbx(&args.database, &file, &credentials)?;
    match removal {
        Some(Removal::Recycled) => println!("Group moved to the recycle bin."),
        _ => println!("Group removed."),
    }
    Ok(())
}

fn move_entry(args: EntryMoveArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (source_path, title) = split_entry_path(&args.entry)?;
    let dest_path = split_group_path(Some(&args.group))?;
    let entry = file
        .database
        .entry_by_path(&source_path, title)
        .map(Entry::uuid)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;
    let dest_group = file
        .database
        .group_by_path(&dest_path)
        .map(Group::uuid)
        .ok_or_else(|| AppError::InvalidInput("destination group not found".to_string()))?;
    // Records the previous group and the move time, like KeePassXC.
    file.database.move_entry(entry, dest_group);
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
    let limits = file.database.meta().history_limits();
    let entry = file
        .database
        .entry_by_path_mut(&group_path, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    let data = fs::read(&args.file)?;
    entry.begin_update(limits);
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
        // Attachments are often secrets: never replace an existing file, and
        // keep the new one readable by its owner only.
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut out = options
            .open(&output)
            .with_context(|| format!("cannot create {}", output.display()))?;
        out.write_all(attachment.data())?;
    } else {
        io::stdout().write_all(attachment.data())?;
    }
    Ok(())
}

fn attachment_remove(args: AttachmentRemoveArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let (group_path, title) = split_entry_path(&args.entry)?;
    let limits = file.database.meta().history_limits();
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
    entry.begin_update(limits);
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

    let value = entry_attribute(entry, &args.field)
        .ok_or_else(|| AppError::InvalidInput("unknown field".to_string()))?;

    let mut clipboard = arboard::Clipboard::new()
        .map_err(|err| AppError::Clipboard(format!("clipboard error: {err}")))?;
    clipboard
        .set_text(value.as_str())
        .map_err(|err| AppError::Clipboard(format!("clipboard error: {err}")))?;

    println!("Copied {} to clipboard.", args.field);

    // Like keepassxc-cli: clear after 10 seconds unless told otherwise, and
    // only if the clipboard still holds what we put there.
    let timeout = args.timeout.unwrap_or(DEFAULT_CLIP_TIMEOUT_SECS);
    if timeout > 0 {
        println!("Clearing the clipboard in {timeout} seconds...");
        thread::sleep(Duration::from_secs(timeout));
        let unchanged = clipboard
            .get_text()
            .is_ok_and(|current| current == value.as_str());
        if unchanged && let Err(err) = clipboard.clear() {
            error!("Failed to clear clipboard: {err}");
        }
    }
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
        if let Ok(result) = zxcvbn::zxcvbn(password, &[])
            && result.score() < 3
        {
            weak.push((path.clone(), format!("weak score {}", result.score())));
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

fn unlock(args: UnlockArgs) -> anyhow::Result<()> {
    if let DbState::Unlocked(status) = agent::state(&args.database)? {
        println!("Already unlocked; {}", describe_unlocked(&status));
        return Ok(());
    }
    let credentials = build_local_credentials(&args.credentials)?;
    if credentials.is_empty() {
        return Err(anyhow::anyhow!(AppError::InvalidInput(
            "unlock requires at least one credential".to_string(),
        )));
    }
    let key = credentials.composite_key()?.concatenated();
    let status = agent::unlock(
        &args.database,
        &key,
        credentials.yubikey,
        args.idle,
        args.max,
    )?;
    // Fail on a wrong password now, not on the first command that uses the
    // agent. Opening through the agent also leaves it the YubiKey's answer
    // for the current seed, so reads need no touch.
    let through_agent = agent::credentials_for(&args.database)?;
    let opened = match &through_agent {
        Some(key) => read_kdbx(
            &args.database,
            &Credentials {
                password: None,
                key_file: None,
                yubikey: None,
                agent: Some(key.clone()),
            },
        ),
        None => Err(AppError::InvalidInput(
            "agent started but does not answer".to_string(),
        )),
    };
    let file = match opened {
        Ok(file) => file,
        Err(err) => {
            agent::lock(Some(&args.database))?;
            return Err(err.into());
        }
    };
    println!("Unlocked {}", describe_unlocked(&status));
    if args.ssh_add
        && let Some(key) = &through_agent
    {
        crate::cli::ssh::add_on_unlock(&file, &args.database, key, status.max_left)?;
    }
    Ok(())
}

fn lock(args: LockArgs) -> anyhow::Result<()> {
    let locked = agent::lock(args.database.as_deref())?;
    if locked.is_empty() {
        println!("Nothing was unlocked.");
    }
    for database in locked {
        println!("Locked {}", database.display());
    }
    Ok(())
}

/// Print unlock state. Exits 0 when the database (or any, without one) is
/// unlocked and 1 otherwise, so scripts and shell prompts can test it.
fn status(args: LockArgs) -> anyhow::Result<()> {
    let states = match &args.database {
        Some(database) => vec![agent::state(database)?],
        None => agent::status_all()?,
    };
    if states.is_empty() {
        println!("No database is unlocked.");
    }
    let mut unlocked = false;
    for state in &states {
        match state {
            DbState::Unlocked(status) => {
                unlocked = true;
                println!("unlocked {}", describe_unlocked(status));
            }
            DbState::Expired(marker) => println!(
                "expired  {} ({} ago, {})",
                marker.database.display(),
                format_duration(marker.age()),
                marker.reason
            ),
            DbState::Locked => println!(
                "locked   {}",
                args.database.as_deref().unwrap_or(Path::new("")).display()
            ),
        }
    }
    if !unlocked {
        std::process::exit(1);
    }
    Ok(())
}

fn describe_unlocked(status: &agent::AgentStatus) -> String {
    let yubikey = status
        .yubikey
        .map(|slot| format!(", YubiKey slot {slot}"))
        .unwrap_or_default();
    format!(
        "{} (locks after {} idle, {} at most{yubikey})",
        status.database.display(),
        format_duration(status.idle_left),
        format_duration(status.max_left),
    )
}

fn yubikey(command: YubiKeyCommand) -> anyhow::Result<()> {
    match command {
        YubiKeyCommand::Serve(args) => {
            #[cfg(unix)]
            {
                let socket = match args.socket {
                    Some(socket) => socket,
                    None => crate::yubikey::forward::socket_path()?,
                };
                crate::yubikey::forward::serve(&socket)?;
                Ok(())
            }
            #[cfg(not(unix))]
            {
                let _ = args;
                Err(anyhow::anyhow!(AppError::InvalidInput(
                    "yubikey serve is only supported on Unix".to_string()
                )))
            }
        }
    }
}

fn serve_agent(args: crate::cli::AgentArgs) -> anyhow::Result<()> {
    agent::serve(
        &args.database,
        Duration::from_secs(args.idle_secs),
        Duration::from_secs(args.max_secs),
    )?;
    Ok(())
}

/// Build credentials for `database`: from its unlock agent when one is
/// running and no password option was given, otherwise from the arguments.
pub(crate) fn build_credentials(
    database: &Path,
    args: &crate::cli::CredentialArgs,
) -> AppResult<Credentials> {
    let explicit =
        args.password.is_some() || args.no_password || args.yubikey.is_some() || args.no_agent;
    if !explicit && let Some(key) = agent::credentials_for(database)? {
        args.validate()?;
        return Ok(Credentials {
            password: None,
            key_file: None,
            yubikey: None,
            agent: Some(key),
        });
    }
    build_local_credentials(args)
}

/// Build credentials from CLI arguments only, ignoring any agent.
fn build_local_credentials(args: &crate::cli::CredentialArgs) -> AppResult<Credentials> {
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
            Some(into_secret(prompt))
        }
    };

    let key_file = args
        .key_file
        .as_ref()
        .map(|path| KeyFile::load(path))
        .transpose()?;

    Ok(Credentials {
        password,
        key_file,
        yubikey: args.yubikey,
        agent: None,
    })
}

/// Read a secret from the terminal without echo, or a line from stdin when
/// stdin is not a terminal (so passwords can be piped in, like keepassxc-cli).
fn read_secret(prompt: &str) -> io::Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).map(Zeroizing::new);
    }
    let mut line = Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    let len = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(len);
    Ok(line)
}

/// Move a wiped-on-drop secret into a `SecretString` without copying it.
fn into_secret(mut value: Zeroizing<String>) -> SecretString {
    SecretString::new(std::mem::take(&mut *value))
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

fn build_new_credentials(args: &DbEditArgs, current: &Credentials) -> AppResult<Credentials> {
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

    let yubikey = if args.unset_yubikey {
        None
    } else {
        args.new_yubikey.or(current.yubikey)
    };

    Ok(Credentials {
        password,
        key_file,
        yubikey,
        agent: None,
    })
}

fn parse_version(value: u32) -> AppResult<KdbxVersion> {
    match value {
        3 => Ok(KdbxVersion::V3_1),
        4 => Ok(KdbxVersion::V4_0),
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

pub(super) fn load_database(
    path: &Path,
    args: &crate::cli::CredentialArgs,
) -> AppResult<(KdbxFile, Credentials)> {
    let credentials = build_credentials(path, args)?;
    let file = read_kdbx(path, &credentials)?;
    Ok((file, credentials))
}

/// Result of looking up an attribute name for `show -a`.
#[derive(Debug, PartialEq, Eq)]
enum Lookup {
    /// `Uuid` or `Tags`, printed as is.
    Field(String),
    /// An attribute's raw value; placeholders are not resolved yet.
    Attribute(Zeroizing<String>),
    Unknown,
    /// Several attributes match case-insensitively, sorted by name.
    Ambiguous(Vec<String>),
}

/// Look up an attribute like keepassxc-cli: the `Uuid` and `Tags` fields by
/// exact name, then an attribute by exact name, then case-insensitively.
fn lookup_attribute(entry: &Entry, name: &str) -> Lookup {
    match name {
        "Uuid" => return Lookup::Field(format!("{{{}}}", entry.uuid().hyphenated())),
        "Tags" => return Lookup::Field(entry_tags(entry)),
        _ => {}
    }
    let mut attributes = placeholders::attributes(entry);
    if let Some(value) = attributes.remove(name) {
        return Lookup::Attribute(value);
    }
    let mut matches: Vec<(String, Zeroizing<String>)> = attributes
        .into_iter()
        .filter(|(key, _)| key.to_lowercase() == name.to_lowercase())
        .collect();
    match matches.len() {
        0 => Lookup::Unknown,
        1 => Lookup::Attribute(matches.remove(0).1),
        _ => Lookup::Ambiguous(matches.into_iter().map(|(key, _)| key).collect()),
    }
}

/// Tags as KeePassXC 2.7 shows them: split on `,`, `;` or tab, trimmed,
/// deduplicated, sorted and joined with `,`.
fn entry_tags(entry: &Entry) -> String {
    entry.tags().join(",")
}

fn entry_attribute(entry: &Entry, name: &str) -> Option<Zeroizing<String>> {
    match lookup_attribute(entry, name) {
        Lookup::Field(value) => Some(Zeroizing::new(value)),
        Lookup::Attribute(value) => Some(value),
        Lookup::Unknown | Lookup::Ambiguous(_) => None,
    }
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

/// Build a "group not found" error that names the first missing group and
/// says how to create it.
pub(crate) fn group_not_found(database: &Database, path: &[&str], db_path: &Path) -> AppError {
    let mut current = database.root();
    let mut missing = Vec::new();
    for segment in path {
        missing.push(*segment);
        match current.find_group(segment) {
            Some(next) => current = next,
            None => break,
        }
    }
    let missing = missing.join("/");
    AppError::InvalidInput(format!(
        "group not found: {missing} (create it with: keepassxcr mkdir {db} {full})",
        db = db_path.display(),
        full = path.join("/"),
    ))
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
        if let Some((hash, count)) = line.split_once(':')
            && let Some(entry_path) = hash_to_entry.get(hash)
        {
            let count = count.parse::<u64>().unwrap_or(0);
            results.insert(entry_path.clone(), count);
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
    fn entry_attribute_matches_standard_and_custom_names() {
        let mut entry = Entry::new("Api".to_string());
        entry.set_username("alice".to_string());
        entry.set_password(SecretString::new("pw\nsecond line".to_string()));
        entry.set_custom_field("RPC_URL".to_string(), "http://x".to_string(), false);
        assert_eq!(
            entry_attribute(&entry, "UserName")
                .as_deref()
                .map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            entry_attribute(&entry, "password")
                .as_deref()
                .map(String::as_str),
            Some("pw\nsecond line")
        );
        assert_eq!(
            entry_attribute(&entry, "RPC_URL")
                .as_deref()
                .map(String::as_str),
            Some("http://x")
        );
        assert_eq!(
            entry_attribute(&entry, "rpc_url")
                .as_deref()
                .map(String::as_str),
            Some("http://x")
        );
        assert_eq!(entry_attribute(&entry, "missing"), None);
    }

    #[test]
    fn split_entry_path_ok() {
        let (groups, entry) = split_entry_path("Group/Sub/Entry").expect("path");
        assert_eq!(groups, vec!["Group", "Sub"]);
        assert_eq!(entry, "Entry");
    }

    #[test]
    fn group_not_found_names_first_missing_group() {
        let mut database = Database::new("Root".to_string());
        ensure_group_path(database.root_mut(), &["Email"]);
        let err = group_not_found(&database, &["Email", "Work", "Old"], Path::new("db.kdbx"));
        let message = err.to_string();
        assert!(
            message.contains("group not found: Email/Work "),
            "{message}"
        );
        assert!(
            message.contains("keepassxcr mkdir db.kdbx Email/Work/Old"),
            "{message}"
        );
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

    #[test]
    fn parse_cipher_aes() {
        let cipher = parse_cipher("aes256").expect("cipher");
        assert_eq!(cipher, CipherId::Aes256);
    }
}
