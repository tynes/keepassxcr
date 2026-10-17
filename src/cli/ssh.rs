//! `ssh-add`, `ssh-key-import` and `unlock --ssh-add`.

use std::fs;
use std::path::Path;
use std::time::Duration;

use tracing::warn;

use crate::agent::{self, AgentKey, DbState, format_duration};
use crate::cli::commands::{load_database, split_entry_path};
use crate::cli::{SshAddArgs, SshKeyImportArgs};
use crate::error::{AppError, AppResult};
use crate::format::{KdbxFile, write_kdbx};
use crate::model::{Attachment, Entry};
use crate::ssh::agent::{Constraints, SshAgent};
use crate::ssh::{self, KeeAgentSettings, SETTINGS_ATTACHMENT};

/// An unlock agent session the keys are tied to.
struct Session<'a> {
    key: &'a AgentKey,
    /// Time until the session's hard maximum: ssh-agent never keeps a key longer.
    max_left: Duration,
}

pub(super) fn ssh_add(args: SshAddArgs) -> anyhow::Result<()> {
    let (file, credentials) = load_database(&args.database, &args.credentials)?;
    let ssh_agent = SshAgent::from_env()?;

    if args.list {
        return list(&file, &args.database, &ssh_agent);
    }

    let selected: Vec<(String, &Entry, KeeAgentSettings)> = if args.all {
        ssh::entries(&file.database)
            .into_iter()
            .filter_map(|(path, entry, settings)| match settings {
                Ok(settings) => Some((path, entry, settings)),
                Err(err) => {
                    warn!("skipping {path}: {err}");
                    None
                }
            })
            .filter(|(_, _, settings)| settings.allow_use && (args.remove || settings.add_at_open))
            .collect()
    } else {
        args.entries
            .iter()
            .map(|path| {
                let (group, title) = split_entry_path(path)?;
                let entry = file
                    .database
                    .entry_by_path(&group, title)
                    .ok_or_else(|| AppError::InvalidInput(format!("entry {path} not found")))?;
                let settings = KeeAgentSettings::from_entry(entry).ok_or_else(|| {
                    AppError::InvalidInput(format!(
                        "{path} has no SSH key settings; store a key with \
                         'keepassxcr ssh-key-import' or in KeePassXC's SSH Agent tab"
                    ))
                })??;
                Ok((path.clone(), entry, settings))
            })
            .collect::<AppResult<_>>()?
    };
    if selected.is_empty() {
        println!(
            "No SSH keys to {}.",
            if args.remove { "remove" } else { "add" }
        );
        return Ok(());
    }

    let mut failed = false;
    if args.remove {
        for (path, entry, settings) in &selected {
            let result = ssh::key::load(entry, settings, &args.database, false)
                .and_then(|key| Ok((ssh_agent.remove(&key.public_blob)?, key)));
            match result {
                Ok((true, key)) => println!("Removed {path} ({})", key.fingerprint),
                Ok((false, _)) => println!("{path} was not in ssh-agent"),
                Err(err) => {
                    failed = true;
                    eprintln!("{path}: {err}");
                }
            }
        }
    } else {
        let session = session(&args.database, credentials.agent.as_ref())?;
        for (path, entry, settings) in &selected {
            let constraints = Constraints {
                lifetime_secs: lifetime(settings, args.lifetime, session.as_ref()),
                confirm: args.confirm || settings.confirm,
            };
            match add_one(
                &ssh_agent,
                entry,
                settings,
                &args.database,
                constraints,
                session.as_ref(),
            ) {
                Ok(message) => println!("Added {path} {message}"),
                Err(err) => {
                    failed = true;
                    eprintln!("{path}: {err}");
                }
            }
        }
    }
    if failed {
        return Err(AppError::Reported.into());
    }
    Ok(())
}

/// Load the keys KeePassXC loads on unlock. Problems are warnings: the
/// database is unlocked either way.
pub(super) fn add_on_unlock(
    file: &KdbxFile,
    database: &Path,
    key: &AgentKey,
    max_left: Duration,
) -> anyhow::Result<()> {
    let ssh_agent = match SshAgent::from_env() {
        Ok(ssh_agent) => ssh_agent,
        Err(err) => {
            eprintln!("Not loading SSH keys: {err}");
            return Ok(());
        }
    };
    let session = Session { key, max_left };
    for (path, entry, settings) in ssh::entries(&file.database) {
        let settings = match settings {
            Ok(settings) => settings,
            Err(err) => {
                eprintln!("{path}: {err}");
                continue;
            }
        };
        if !settings.allow_use || !settings.add_at_open {
            continue;
        }
        let constraints = Constraints {
            lifetime_secs: lifetime(&settings, None, Some(&session)),
            confirm: settings.confirm,
        };
        match add_one(
            &ssh_agent,
            entry,
            &settings,
            database,
            constraints,
            Some(&session),
        ) {
            Ok(message) => println!("Added SSH key {path} {message}"),
            Err(err) => eprintln!("{path}: {err}"),
        }
    }
    Ok(())
}

pub(super) fn ssh_key_import(args: SshKeyImportArgs) -> anyhow::Result<()> {
    let (mut file, credentials) = load_database(&args.database, &args.credentials)?;
    let name = match args.name {
        Some(name) => name,
        None => args
            .key
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| AppError::InvalidInput("cannot name the attachment".to_string()))?,
    };
    if name == SETTINGS_ATTACHMENT {
        return Err(AppError::InvalidInput(format!("{SETTINGS_ATTACHMENT} is reserved")).into());
    }
    let data = fs::read(&args.key)?;

    let mut settings = KeeAgentSettings::for_attachment(&name);
    settings.add_at_open = !args.no_add_on_unlock;
    settings.remove_at_close = !args.keep_on_lock;
    settings.confirm = args.confirm;
    if let Some(lifetime) = args.lifetime {
        settings.use_lifetime = true;
        settings.lifetime_secs = u32::try_from(lifetime.as_secs())
            .map_err(|_| AppError::InvalidInput("lifetime is too long".to_string()))?;
    }

    let (group, title) = split_entry_path(&args.entry)?;
    let limits = file.database.meta().history_limits();
    let entry = file
        .database
        .entry_by_path_mut(&group, title)
        .ok_or_else(|| AppError::InvalidInput("entry not found".to_string()))?;

    // Check before storing that the entry's password opens the key.
    let mut candidate = entry.clone();
    set_attachment(&mut candidate, &name, data.clone());
    let key = ssh::key::load(&candidate, &settings, &args.database, true).map_err(|err| {
        anyhow::anyhow!("{err} (set the entry's password with 'keepassxcr edit -p')")
    })?;

    entry.begin_update(limits);
    set_attachment(entry, &name, data);
    set_attachment(entry, SETTINGS_ATTACHMENT, settings.to_xml());
    write_kdbx(&args.database, &file, &credentials)?;
    println!(
        "Stored {} key {} in {} as attachment '{name}'.",
        key.algorithm, key.fingerprint, args.entry
    );
    Ok(())
}

fn set_attachment(entry: &mut Entry, name: &str, data: Vec<u8>) {
    let attachments = entry.attachments_mut();
    attachments.retain(|attachment| attachment.name() != name);
    attachments.push(Attachment::new(name.to_string(), data));
}

fn list(file: &KdbxFile, database: &Path, ssh_agent: &SshAgent) -> anyhow::Result<()> {
    let loaded = match ssh_agent.identities() {
        Ok(loaded) => Some(loaded),
        Err(err) => {
            warn!("cannot list ssh-agent keys: {err}");
            None
        }
    };
    let entries = ssh::entries(&file.database);
    if entries.is_empty() {
        println!("No entries with SSH keys.");
    }
    for (path, entry, settings) in entries {
        let key = settings.and_then(|settings| ssh::key::load(entry, &settings, database, false));
        match key {
            Ok(key) => {
                let state = match &loaded {
                    Some(loaded) if loaded.contains(&key.public_blob) => "loaded",
                    Some(_) => "not loaded",
                    None => "unknown",
                };
                println!("{path}\t{}\t{}\t{state}", key.fingerprint, key.algorithm);
            }
            Err(err) => println!("{path}\terror: {err}"),
        }
    }
    Ok(())
}

/// The unlock session, when the database was opened through the agent.
fn session<'a>(database: &Path, key: Option<&'a AgentKey>) -> AppResult<Option<Session<'a>>> {
    let Some(key) = key else {
        return Ok(None);
    };
    match agent::state(database)? {
        DbState::Unlocked(status) => Ok(Some(Session {
            key,
            max_left: status.max_left,
        })),
        _ => Ok(None),
    }
}

/// ssh-agent lifetime: the option, else the entry's setting, capped by the
/// unlock session's time left so keys never outlive it.
fn lifetime(
    settings: &KeeAgentSettings,
    option: Option<Duration>,
    session: Option<&Session<'_>>,
) -> Option<u32> {
    let secs = |duration: Duration| u32::try_from(duration.as_secs()).unwrap_or(u32::MAX).max(1);
    let wanted =
        option
            .map(secs)
            .or((settings.use_lifetime && settings.lifetime_secs > 0)
                .then_some(settings.lifetime_secs));
    match session.map(|session| secs(session.max_left)) {
        Some(cap) => Some(wanted.map_or(cap, |wanted| wanted.min(cap))),
        None => wanted,
    }
}

/// Add one key; returns how long it stays, for the message.
fn add_one(
    ssh_agent: &SshAgent,
    entry: &Entry,
    settings: &KeeAgentSettings,
    database: &Path,
    constraints: Constraints,
    session: Option<&Session<'_>>,
) -> AppResult<String> {
    let key = ssh::key::load(entry, settings, database, true)?;
    ssh_agent.add(&key, constraints)?;
    let tracked = match session {
        Some(session) if settings.remove_at_close => {
            session
                .key
                .track_ssh_key(ssh_agent.socket(), &key.public_blob)?;
            true
        }
        _ => false,
    };
    let mut notes = Vec::new();
    if tracked {
        notes.push("removed on lock".to_string());
    }
    if let Some(lifetime) = constraints.lifetime_secs {
        notes.push(format!(
            "expires in {}",
            format_duration(Duration::from_secs(u64::from(lifetime)))
        ));
    }
    if constraints.confirm {
        notes.push("asks before each use".to_string());
    }
    if notes.is_empty() {
        notes.push("until removed".to_string());
    }
    Ok(format!("({}, {})", key.fingerprint, notes.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_never_outlives_the_session() {
        let mut settings = KeeAgentSettings::default();
        assert_eq!(lifetime(&settings, None, None), None);
        settings.use_lifetime = true;
        settings.lifetime_secs = 600;
        assert_eq!(lifetime(&settings, None, None), Some(600));
        assert_eq!(
            lifetime(&settings, Some(Duration::from_secs(60)), None),
            Some(60)
        );
    }
}
