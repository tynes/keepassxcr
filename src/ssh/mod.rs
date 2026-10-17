//! SSH keys stored in entries, KeePassXC style, loaded into ssh-agent.
//!
//! An entry holds the private key as an attachment (or names a key file) and
//! a `KeeAgent.settings` attachment says how to load it. The entry's password
//! is the key's passphrase. keepassxcr reads the same settings as KeePassXC's
//! SSH agent integration, so entries set up in either work in both.

pub mod agent;
#[cfg(feature = "cli")]
pub mod key;
pub mod settings;

use crate::model::{Database, Entry, Group};

#[cfg(feature = "cli")]
pub use key::SshKey;
pub use settings::{KeeAgentSettings, SETTINGS_ATTACHMENT};

/// Every entry with SSH key settings, outside the recycle bin, with its path
/// (`Group/Entry`, without the root group) and its parsed settings.
pub fn entries(
    database: &Database,
) -> Vec<(String, &Entry, crate::error::AppResult<KeeAgentSettings>)> {
    let recycle_bin = database.meta().recycle_bin();
    let mut found = Vec::new();
    walk(database.root(), "", recycle_bin, &mut found);
    found
}

fn walk<'a>(
    group: &'a Group,
    prefix: &str,
    recycle_bin: Option<uuid::Uuid>,
    found: &mut Vec<(String, &'a Entry, crate::error::AppResult<KeeAgentSettings>)>,
) {
    for entry in group.entries() {
        if let Some(settings) = KeeAgentSettings::from_entry(entry) {
            found.push((format!("{prefix}{}", entry.title()), entry, settings));
        }
    }
    for child in group.groups() {
        if Some(child.uuid()) == recycle_bin {
            continue;
        }
        walk(
            child,
            &format!("{prefix}{}/", child.name()),
            recycle_bin,
            found,
        );
    }
}
