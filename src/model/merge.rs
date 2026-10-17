//! Merge one database into another, following KeePassXC's `Merger`.
//!
//! Entries and groups are matched by UUID wherever they are in the tree.
//! New items are added under their (matched or newly created) parent group.
//! When both sides have an entry, the one modified later becomes the current
//! version and the other goes into its history, so no version is lost. An
//! item that moved more recently on the source side moves in the target too.
//! The source root group maps onto the target root group.

use std::collections::{BTreeMap, HashMap};

use secrecy::ExposeSecret;
use uuid::Uuid;

use super::{Database, DeletedObject, Entry, Group, HistoryLimits, RawElement, Timestamp};

/// How deletions are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeMode {
    /// Keep the newer version of each item and apply no deletions.
    /// This is what `keepassxc-cli merge` does.
    #[default]
    KeepNewer,
    /// Also apply the deletions both databases record, unless the item was
    /// changed after it was deleted (KeePassXC's "synchronize" mode).
    Synchronize,
}

/// What a merge changed in the target.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeStats {
    /// Entries and groups added.
    pub added: usize,
    /// Entries and groups whose data or history changed.
    pub updated: usize,
    /// Entries and groups moved to another group.
    pub moved: usize,
    /// Entries and groups deleted.
    pub deleted: usize,
}

impl MergeStats {
    /// True if the merge changed nothing.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Merge `source` into `target`.
pub fn merge(target: &mut Database, source: &Database, mode: MergeMode) -> MergeStats {
    let mut merger = Merger {
        target,
        limits: HistoryLimits::default(),
        stats: MergeStats::default(),
    };
    merger.limits = merger.target.meta().history_limits();
    let root = merger.target.root().uuid();
    merger.merge_group(source.root(), root);
    if mode == MergeMode::Synchronize {
        merger.merge_deletions(source.deleted_objects());
    }
    merger.merge_custom_icons(source.meta().custom_icons());
    merger.stats
}

struct Merger<'a> {
    target: &'a mut Database,
    limits: HistoryLimits,
    stats: MergeStats,
}

impl Merger<'_> {
    /// Merge the contents of `source` into the target group `target_group`.
    fn merge_group(&mut self, source: &Group, target_group: Uuid) {
        for source_entry in source.entries() {
            self.merge_entry(source_entry, target_group);
        }
        for source_child in source.groups() {
            let child = source_child.uuid();
            match self.target.root().group_by_uuid(child) {
                None => {
                    if let Some(parent) = self.target.root_mut().group_by_uuid_mut(target_group) {
                        parent.groups_mut().push(source_child.shell());
                        self.stats.added += 1;
                    }
                }
                Some(existing) => {
                    let moved_later =
                        existing.times().location_changed < source_child.times().location_changed;
                    let parent = self.target.root().parent_of_group(child);
                    if moved_later && parent != Some(target_group) {
                        self.relocate_group(child, target_group, source_child);
                    }
                    self.resolve_group(source_child);
                }
            }
            self.merge_group(source_child, child);
        }
    }

    fn merge_entry(&mut self, source: &Entry, target_group: Uuid) {
        let uuid = source.uuid();
        let Some(existing) = self.target.root().entry_by_uuid(uuid) else {
            if let Some(group) = self.target.root_mut().group_by_uuid_mut(target_group) {
                group.entries_mut().push(source.clone());
                self.stats.added += 1;
            }
            return;
        };
        let moved_later = existing.times().location_changed < source.times().location_changed;
        let parent = self.target.root().parent_of_entry(uuid);
        if moved_later
            && parent != Some(target_group)
            && let Some(mut entry) = self.target.root_mut().take_entry_by_uuid(uuid)
            && let Some(group) = self.target.root_mut().group_by_uuid_mut(target_group)
        {
            entry.set_previous_parent_group(parent);
            entry.times_mut().location_changed = source.times().location_changed;
            group.entries_mut().push(entry);
            self.stats.moved += 1;
        }

        let limits = self.limits;
        let Some(target) = self.target.root_mut().entry_by_uuid_mut(uuid) else {
            return;
        };
        if target.times().last_modification < source.times().last_modification {
            // The source is newer: it becomes the current version, with the
            // target's version and history merged into its history.
            let mut newer = source.clone();
            merge_history(target, &mut newer, limits);
            // The source's own history may be longer than the target allows.
            newer.truncate_history(limits);
            // The entry stays where it is now, so keep the target's record
            // of its last move when that is the later one.
            if target.times().location_changed > newer.times().location_changed {
                newer.times_mut().location_changed = target.times().location_changed;
                newer.set_previous_parent_group(target.previous_parent_group());
            }
            *target = newer;
            self.stats.updated += 1;
        } else if merge_history(source, target, limits) {
            self.stats.updated += 1;
        }
    }

    /// Move a group after the source moved it more recently, keeping the
    /// source's move time. Skipped if it would put a group inside itself.
    fn relocate_group(&mut self, uuid: Uuid, target_group: Uuid, source: &Group) {
        let inside = self
            .target
            .root()
            .group_by_uuid(uuid)
            .is_some_and(|group| group.group_by_uuid(target_group).is_some());
        if inside {
            return;
        }
        let parent = self.target.root().parent_of_group(uuid);
        let Some(mut group) = self.target.root_mut().take_group_by_uuid(uuid) else {
            return;
        };
        group.set_previous_parent_group(parent);
        group.times_mut().location_changed = source.times().location_changed;
        if let Some(destination) = self.target.root_mut().group_by_uuid_mut(target_group) {
            destination.groups_mut().push(group);
            self.stats.moved += 1;
        }
    }

    /// Take the source group's own data if it was modified later.
    fn resolve_group(&mut self, source: &Group) {
        let Some(target) = self.target.root_mut().group_by_uuid_mut(source.uuid()) else {
            return;
        };
        if target.times().last_modification >= source.times().last_modification {
            return;
        }
        target.set_name(source.name().to_string());
        target.set_tags(source.tags().to_string());
        *target.extra_mut() = source.extra().to_vec();
        let times = target.times_mut();
        times.last_modification = source.times().last_modification;
        times.expiry = source.times().expiry;
        times.expires = source.times().expires;
        self.stats.updated += 1;
    }

    /// Apply the deletions recorded on either side, as KeePassXC's
    /// synchronize mode does.
    fn merge_deletions(&mut self, source: &[DeletedObject]) {
        // The earliest deletion of each item wins.
        let mut earliest: HashMap<Uuid, DeletedObject> = HashMap::new();
        let mut order = Vec::new();
        for object in self.target.deleted_objects().iter().chain(source) {
            match earliest.get_mut(&object.uuid) {
                Some(seen) if seen.deletion_time > object.deletion_time => *seen = *object,
                Some(_) => {}
                None => {
                    earliest.insert(object.uuid, *object);
                    order.push(object.uuid);
                }
            }
        }

        let mut kept = Vec::new();
        let mut groups = Vec::new();
        for uuid in order {
            let object = earliest[&uuid];
            let root = self.target.root();
            if let Some(entry) = root.entry_by_uuid(uuid) {
                // An entry changed after it was deleted stays, and so does
                // not need the record any more.
                if entry.times().last_modification <= object.deletion_time {
                    self.target.root_mut().take_entry_by_uuid(uuid);
                    self.stats.deleted += 1;
                    kept.push(object);
                }
            } else if root.group_by_uuid(uuid).is_some() && root.uuid() != uuid {
                groups.push(object);
            } else {
                kept.push(object);
            }
        }

        // Deepest groups first, so a parent sees whether its children went.
        groups.sort_by_key(|object| std::cmp::Reverse(self.depth_of(object.uuid)));
        for object in groups {
            let Some(group) = self.target.root().group_by_uuid(object.uuid) else {
                continue;
            };
            let changed_later = group.times().last_modification > object.deletion_time;
            let has_content = !group.entries().is_empty() || !group.groups().is_empty();
            if changed_later || has_content {
                continue;
            }
            self.target.root_mut().take_group_by_uuid(object.uuid);
            self.stats.deleted += 1;
            kept.push(object);
        }

        if kept != self.target.deleted_objects() {
            *self.target.deleted_objects_mut() = kept;
        }
    }

    fn depth_of(&self, uuid: Uuid) -> usize {
        let mut depth = 0;
        let mut current = uuid;
        while let Some(parent) = self.target.root().parent_of_group(current) {
            depth += 1;
            current = parent;
        }
        depth
    }

    /// Add the source's custom icons that the target lacks, and take a
    /// source icon whose KDBX 4.1 modification time is later.
    fn merge_custom_icons(&mut self, source: &[RawElement]) {
        for icon in source {
            let Some(uuid) = icon_uuid(icon) else {
                continue;
            };
            let icons = self.target.meta_mut().custom_icons_mut();
            match icons
                .iter_mut()
                .find(|known| icon_uuid(known).as_deref() == Some(&uuid))
            {
                None => icons.push(icon.clone()),
                Some(known) if icon_modified(icon) > icon_modified(known) && known != icon => {
                    *known = icon.clone();
                }
                Some(_) => continue,
            }
            self.stats.updated += 1;
        }
    }
}

fn icon_uuid(icon: &RawElement) -> Option<String> {
    super::element_text(icon.xml(), "UUID").map(|text| text.trim().to_string())
}

fn icon_modified(icon: &RawElement) -> Option<Timestamp> {
    super::element_text(icon.xml(), "LastModificationTime").and_then(Timestamp::parse)
}

/// Merge the history of `source` and the version it represents into
/// `target`'s history, as KeePassXC's `Merger::mergeHistory` does.
///
/// History items are matched by modification time: two items with the same
/// time are the same version. Returns true if the newest `max_items` of the
/// history changed.
fn merge_history(source: &Entry, target: &mut Entry, limits: HistoryLimits) -> bool {
    let source_time = source.times().last_modification;
    let target_time = target.times().last_modification;
    let prefer_remote = source_time > target_time;

    let mut merged: BTreeMap<Timestamp, Entry> = BTreeMap::new();
    for item in target.history() {
        merged.insert(item.times().last_modification, without_history(item));
    }
    for item in source.history() {
        let time = item.times().last_modification;
        if prefer_remote || !merged.contains_key(&time) {
            merged.insert(time, without_history(item));
        }
    }
    if target_time < source_time {
        merged
            .entry(target_time)
            .or_insert_with(|| without_history(target));
    } else if target_time > source_time {
        merged
            .entry(source_time)
            .or_insert_with(|| without_history(source));
    }

    let updated: Vec<Entry> = merged.into_values().collect();
    let window = usize::try_from(limits.max_items).unwrap_or(usize::MAX);
    let old = target.history();
    let changed = old.len().min(window) != updated.len().min(window)
        || old
            .iter()
            .rev()
            .zip(updated.iter().rev())
            .take(window)
            .any(|(a, b)| !same_version(a, b));
    if changed {
        *target.history_mut() = updated;
        target.truncate_history(limits);
    }
    changed
}

fn without_history(entry: &Entry) -> Entry {
    let mut copy = entry.clone();
    copy.history_mut().clear();
    copy
}

/// True if two entries hold the same data, ignoring their history.
fn same_version(a: &Entry, b: &Entry) -> bool {
    let attachments = |entry: &Entry| {
        entry
            .attachments()
            .iter()
            .map(|item| {
                (
                    item.name().to_string(),
                    item.data().to_vec(),
                    item.protected(),
                )
            })
            .collect::<Vec<_>>()
    };
    a.uuid() == b.uuid()
        && a.title() == b.title()
        && a.username() == b.username()
        && a.password().expose_secret() == b.password().expose_secret()
        && a.url() == b.url()
        && a.notes() == b.notes()
        && a.custom_fields() == b.custom_fields()
        && a.protected_fields() == b.protected_fields()
        && a.tags() == b.tags()
        && a.times() == b.times()
        && a.extra() == b.extra()
        && attachments(a) == attachments(b)
}

/// Scenarios ported from keepass-rs's merge tests (MIT licensed; the
/// license is in `tests/data/keepass-rs/README.md`), adapted to KeePassXC's
/// rules: history is oldest first, and deletions apply only in
/// [`MergeMode::Synchronize`].
#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed starting time; the scenarios count seconds from it.
    const T0: i64 = 63_800_000_000;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_secs(T0 + seconds)
    }

    fn all_times(seconds: i64) -> super::super::Times {
        let time = at(seconds);
        super::super::Times {
            creation: time,
            last_modification: time,
            last_access: time,
            expiry: time,
            expires: false,
            usage_count: 0,
            location_changed: time,
        }
    }

    #[derive(Clone, Copy)]
    struct Ids {
        root: Uuid,
        entry1: Uuid,
        entry2: Uuid,
        group1: Uuid,
        subgroup1: Uuid,
        group2: Uuid,
        subgroup2: Uuid,
    }

    fn new_entry(title: &str, seconds: i64) -> Entry {
        let mut entry = Entry::new(title.to_string());
        *entry.times_mut() = all_times(seconds);
        entry
    }

    fn new_group(name: &str, seconds: i64) -> Group {
        let mut group = Group::new(name.to_string());
        *group.times_mut() = all_times(seconds);
        group
    }

    /// root
    /// ├── entry1
    /// ├── group1
    /// │   └── subgroup1
    /// │       └── entry2
    /// └── group2
    ///     └── subgroup2
    fn database() -> (Database, Ids) {
        let mut db = Database::new("Root".to_string());
        *db.root_mut().times_mut() = all_times(0);
        let entry1 = new_entry("entry1", 0);
        let entry2 = new_entry("entry2", 0);
        let mut subgroup1 = new_group("subgroup1", 0);
        let mut group1 = new_group("group1", 0);
        let subgroup2 = new_group("subgroup2", 0);
        let mut group2 = new_group("group2", 0);
        let ids = Ids {
            root: db.root().uuid(),
            entry1: entry1.uuid(),
            entry2: entry2.uuid(),
            group1: group1.uuid(),
            subgroup1: subgroup1.uuid(),
            group2: group2.uuid(),
            subgroup2: subgroup2.uuid(),
        };
        subgroup1.entries_mut().push(entry2);
        group1.groups_mut().push(subgroup1);
        group2.groups_mut().push(subgroup2);
        db.root_mut().entries_mut().push(entry1);
        db.root_mut().groups_mut().push(group1);
        db.root_mut().groups_mut().push(group2);
        (db, ids)
    }

    fn entry(db: &Database, uuid: Uuid) -> &Entry {
        db.root().entry_by_uuid(uuid).expect("entry")
    }

    fn group(db: &Database, uuid: Uuid) -> &Group {
        db.root().group_by_uuid(uuid).expect("group")
    }

    /// Change an entry at `seconds`, keeping the old version in its history.
    fn edit(db: &mut Database, uuid: Uuid, seconds: i64, change: impl FnOnce(&mut Entry)) {
        let entry = db.root_mut().entry_by_uuid_mut(uuid).expect("entry");
        entry.begin_update(HistoryLimits::default());
        change(entry);
        entry.times_mut().last_modification = at(seconds);
        entry.times_mut().last_access = at(seconds);
    }

    fn rename_group(db: &mut Database, uuid: Uuid, seconds: i64, name: &str) {
        let group = db.root_mut().group_by_uuid_mut(uuid).expect("group");
        group.set_name(name.to_string());
        group.times_mut().last_modification = at(seconds);
    }

    fn move_entry(db: &mut Database, uuid: Uuid, to: Uuid, seconds: i64) {
        assert!(db.move_entry(uuid, to));
        let entry = db.root_mut().entry_by_uuid_mut(uuid).expect("entry");
        entry.times_mut().location_changed = at(seconds);
    }

    fn move_group(db: &mut Database, uuid: Uuid, to: Uuid, seconds: i64) {
        assert!(db.move_group(uuid, to));
        let group = db.root_mut().group_by_uuid_mut(uuid).expect("group");
        group.times_mut().location_changed = at(seconds);
    }

    /// Delete an item and date the deletion records `seconds`.
    fn delete(db: &mut Database, uuid: Uuid, seconds: i64) {
        let before = db.deleted_objects().len();
        if db.delete_entry(uuid).is_none() {
            db.delete_group(uuid).expect("item to delete");
        }
        for record in &mut db.deleted_objects_mut()[before..] {
            record.deletion_time = at(seconds);
        }
    }

    fn mark_deleted(db: &mut Database, uuid: Uuid, seconds: i64) {
        db.deleted_objects_mut().push(DeletedObject {
            uuid,
            deletion_time: at(seconds),
        });
    }

    fn is_deleted(db: &Database, uuid: Uuid) -> bool {
        db.deleted_objects()
            .iter()
            .any(|record| record.uuid == uuid)
    }

    fn count(group: &Group) -> (usize, usize) {
        group
            .groups()
            .iter()
            .map(count)
            .fold((group.entries().len(), group.groups().len()), |acc, sub| {
                (acc.0 + sub.0, acc.1 + sub.1)
            })
    }

    fn titles(entry: &Entry) -> Vec<String> {
        entry
            .history()
            .iter()
            .map(|item| item.title().to_string())
            .collect()
    }

    fn stats(added: usize, updated: usize, moved: usize, deleted: usize) -> MergeStats {
        MergeStats {
            added,
            updated,
            moved,
            deleted,
        }
    }

    fn keep_newer(target: &mut Database, source: &Database) -> MergeStats {
        merge(target, source, MergeMode::KeepNewer)
    }

    fn sync(target: &mut Database, source: &Database) -> MergeStats {
        merge(target, source, MergeMode::Synchronize)
    }

    #[test]
    fn merging_a_copy_changes_nothing() {
        let (mut target, ids) = database();
        let source = target.clone();
        assert!(sync(&mut target, &source).is_empty());
        assert_eq!(count(target.root()), (2, 4));

        // A newer change in the target is kept and merging again is stable.
        edit(&mut target, ids.entry1, 10, |e| {
            e.set_title("entry1_updated".to_string())
        });
        assert!(sync(&mut target, &source).is_empty());
        assert!(sync(&mut target, &source).is_empty());
        assert_eq!(entry(&target, ids.entry1).title(), "entry1_updated");
    }

    #[test]
    fn a_new_entry_is_added_once() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        let new = new_entry("new_entry", 5);
        let new_uuid = new.uuid();
        source.root_mut().entries_mut().push(new);

        assert_eq!(keep_newer(&mut target, &source), stats(1, 0, 0, 0));
        assert_eq!(entry(&target, new_uuid).title(), "new_entry");
        assert_eq!(target.root().entries().len(), 2);
        assert!(keep_newer(&mut target, &source).is_empty());
        assert_eq!(count(target.root()), (3, 4));
        let _ = ids;
    }

    #[test]
    fn an_entry_deleted_in_the_target_stays_deleted() {
        let (mut target, _) = database();
        let mut source = target.clone();
        let new = new_entry("deleted_entry", 5);
        let new_uuid = new.uuid();
        source.root_mut().entries_mut().push(new);
        mark_deleted(&mut target, new_uuid, 10);

        assert_eq!(sync(&mut target, &source), stats(1, 0, 0, 1));
        assert!(target.root().entry_by_uuid(new_uuid).is_none());
        assert!(is_deleted(&target, new_uuid));

        // keepassxc-cli applies no deletions, so the entry comes back.
        let (mut target, _) = database();
        mark_deleted(&mut target, new_uuid, 10);
        keep_newer(&mut target, &source);
        assert!(target.root().entry_by_uuid(new_uuid).is_some());
    }

    #[test]
    fn an_entry_moved_into_a_group_deleted_later_brings_the_group_back() {
        let (mut target, _) = database();
        let entry_uuid = {
            let entry = new_entry("original_title", 0);
            let uuid = entry.uuid();
            target.root_mut().entries_mut().push(entry);
            uuid
        };
        let doomed = new_group("deleted_group", 0);
        let doomed_uuid = doomed.uuid();
        target.root_mut().groups_mut().push(doomed);
        let mut source = target.clone();

        edit(&mut source, entry_uuid, 1, |e| {
            e.set_title("modified_title".to_string())
        });
        move_entry(&mut source, entry_uuid, doomed_uuid, 1);
        delete(&mut target, doomed_uuid, 2);

        // Group re-created, entry moved and updated.
        assert_eq!(sync(&mut target, &source), stats(1, 1, 1, 0));
        let group = group(&target, doomed_uuid);
        assert_eq!(group.entries()[0].title(), "modified_title");
        assert!(!is_deleted(&target, doomed_uuid));
    }

    #[test]
    fn a_group_deleted_in_the_target_stays_deleted() {
        let (mut target, _) = database();
        let mut source = target.clone();
        let new = new_group("deleted_group", 5);
        let new_uuid = new.uuid();
        source.root_mut().groups_mut().push(new);
        mark_deleted(&mut target, new_uuid, 10);

        sync(&mut target, &source);
        assert!(target.root().group_by_uuid(new_uuid).is_none());
        assert_eq!(count(target.root()), (2, 4));
    }

    #[test]
    fn an_entry_deleted_in_the_source_is_deleted() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.entry1, 5);

        assert!(keep_newer(&mut target.clone(), &source).is_empty());
        assert_eq!(sync(&mut target, &source), stats(0, 0, 0, 1));
        assert!(target.root().entry_by_uuid(ids.entry1).is_none());
        assert!(is_deleted(&target, ids.entry1));
    }

    #[test]
    fn a_group_deleted_in_the_source_is_deleted() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.subgroup2, 5);

        assert_eq!(sync(&mut target, &source), stats(0, 0, 0, 1));
        assert!(target.root().group_by_uuid(ids.subgroup2).is_none());
        assert!(is_deleted(&target, ids.subgroup2));
    }

    #[test]
    fn an_entry_changed_after_its_deletion_stays() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.entry1, 5);
        edit(&mut target, ids.entry1, 10, |e| {
            e.set_title("modified_in_destination".to_string());
        });

        assert!(sync(&mut target, &source).is_empty());
        assert_eq!(
            entry(&target, ids.entry1).title(),
            "modified_in_destination"
        );
        assert!(!is_deleted(&target, ids.entry1));
    }

    #[test]
    fn a_deleted_subtree_is_deleted() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.group1, 5);

        assert_eq!(sync(&mut target, &source), stats(0, 0, 0, 3));
        for uuid in [ids.group1, ids.subgroup1, ids.entry2] {
            assert!(is_deleted(&target, uuid));
        }
        assert!(target.root().group_by_uuid(ids.group1).is_none());
        assert!(target.root().entry_by_uuid(ids.entry2).is_none());
    }

    #[test]
    fn a_deleted_subtree_keeps_a_group_changed_since() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.group1, 5);
        rename_group(&mut target, ids.group1, 10, "modified in destination");

        assert_eq!(sync(&mut target, &source), stats(0, 0, 0, 2));
        assert!(target.root().group_by_uuid(ids.group1).is_some());
        assert!(target.root().group_by_uuid(ids.subgroup1).is_none());
        assert!(target.root().entry_by_uuid(ids.entry2).is_none());
        assert!(is_deleted(&target, ids.subgroup1));
        assert!(is_deleted(&target, ids.entry2));
        assert!(!is_deleted(&target, ids.group1));
    }

    #[test]
    fn a_group_changed_after_its_deletion_stays() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.subgroup2, 5);
        rename_group(&mut target, ids.subgroup2, 10, "modified_in_destination");

        assert!(sync(&mut target, &source).is_empty());
        assert!(target.root().group_by_uuid(ids.subgroup2).is_some());
        assert!(!is_deleted(&target, ids.subgroup2));
    }

    #[test]
    fn a_deleted_group_with_new_entries_stays() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.subgroup2, 5);
        let new = new_entry("new_entry_in_deleted_group", 10);
        let new_uuid = new.uuid();
        target
            .root_mut()
            .group_by_uuid_mut(ids.subgroup2)
            .expect("group")
            .entries_mut()
            .push(new);

        assert!(sync(&mut target, &source).is_empty());
        assert!(target.root().group_by_uuid(ids.subgroup2).is_some());
        assert!(target.root().entry_by_uuid(new_uuid).is_some());
        assert!(!is_deleted(&target, ids.subgroup2));
    }

    #[test]
    fn a_new_entry_in_a_subgroup_is_added_there() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        let new = new_entry("new_entry", 5);
        let new_uuid = new.uuid();
        source
            .root_mut()
            .group_by_uuid_mut(ids.group1)
            .expect("group")
            .entries_mut()
            .push(new);

        assert_eq!(keep_newer(&mut target, &source), stats(1, 0, 0, 0));
        assert_eq!(target.root().parent_of_entry(new_uuid), Some(ids.group1));
    }

    #[test]
    fn a_new_entry_in_new_groups_is_added_with_them() {
        let (mut target, _) = database();
        let mut source = target.clone();
        let new = new_entry("new_entry", 5);
        let new_uuid = new.uuid();
        let mut subgroup = new_group("new_subgroup", 5);
        let subgroup_uuid = subgroup.uuid();
        subgroup.entries_mut().push(new);
        let mut group = new_group("new_group", 5);
        let group_uuid = group.uuid();
        group.groups_mut().push(subgroup);
        source.root_mut().groups_mut().push(group);

        assert_eq!(keep_newer(&mut target, &source), stats(3, 0, 0, 0));
        assert_eq!(
            target.root().parent_of_group(group_uuid),
            Some(target.root().uuid())
        );
        assert_eq!(
            target.root().parent_of_group(subgroup_uuid),
            Some(group_uuid)
        );
        assert_eq!(target.root().parent_of_entry(new_uuid), Some(subgroup_uuid));
    }

    #[test]
    fn an_entry_moved_in_the_source_moves() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        move_entry(&mut source, ids.entry2, ids.group2, 5);

        assert_eq!(keep_newer(&mut target, &source), stats(0, 0, 1, 0));
        assert_eq!(target.root().parent_of_entry(ids.entry2), Some(ids.group2));
        let moved = entry(&target, ids.entry2);
        assert_eq!(moved.times().location_changed, at(5));
        assert_eq!(moved.previous_parent_group(), Some(ids.subgroup1));
        assert!(keep_newer(&mut target, &source).is_empty());
    }

    #[test]
    fn an_entry_moved_in_the_source_keeps_a_later_target_change() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        edit(&mut source, ids.entry2, 1, |e| {
            e.set_title("entry2_modified_in_source".to_string());
        });
        move_entry(&mut source, ids.entry2, ids.group2, 1);
        edit(&mut target, ids.entry2, 2, |e| {
            e.set_title("entry2_modified_in_destination".to_string());
        });

        let result = keep_newer(&mut target, &source);
        assert_eq!(result.moved, 1);
        let merged = entry(&target, ids.entry2);
        assert_eq!(target.root().parent_of_entry(ids.entry2), Some(ids.group2));
        assert_eq!(merged.times().location_changed, at(1));
        assert_eq!(merged.title(), "entry2_modified_in_destination");
        assert_eq!(merged.times().last_modification, at(2));
        assert_eq!(titles(merged), ["entry2", "entry2_modified_in_source"]);
    }

    #[test]
    fn an_entry_moved_in_the_target_keeps_its_place_and_takes_a_later_source_change() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        edit(&mut source, ids.entry2, 1, |e| {
            e.set_title("entry2_modified_in_source".to_string());
        });
        move_entry(&mut target, ids.entry2, ids.group2, 2);

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        let merged = entry(&target, ids.entry2);
        assert_eq!(target.root().parent_of_entry(ids.entry2), Some(ids.group2));
        assert_eq!(merged.times().location_changed, at(2));
        assert_eq!(merged.previous_parent_group(), Some(ids.subgroup1));
        assert_eq!(merged.title(), "entry2_modified_in_source");
        assert_eq!(merged.times().last_modification, at(1));
    }

    #[test]
    fn an_entry_moved_into_a_new_group_follows() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        let new = new_group("new_group", 0);
        let new_uuid = new.uuid();
        source.root_mut().groups_mut().push(new);
        edit(&mut source, ids.entry1, 1, |e| {
            e.set_title("new_entry_modified_in_source".to_string());
        });
        move_entry(&mut source, ids.entry1, new_uuid, 1);

        assert_eq!(keep_newer(&mut target, &source), stats(1, 1, 1, 0));
        assert_eq!(target.root().parent_of_entry(ids.entry1), Some(new_uuid));
        assert_eq!(
            entry(&target, ids.entry1).title(),
            "new_entry_modified_in_source"
        );
    }

    #[test]
    fn a_group_moved_in_the_source_moves_with_its_contents() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        move_group(&mut source, ids.subgroup1, ids.group2, 5);

        assert_eq!(keep_newer(&mut target, &source), stats(0, 0, 1, 0));
        assert_eq!(
            target.root().parent_of_group(ids.subgroup1),
            Some(ids.group2)
        );
        assert_eq!(
            target.root().parent_of_entry(ids.entry2),
            Some(ids.subgroup1)
        );
        assert_eq!(
            group(&target, ids.subgroup1).times().location_changed,
            at(5)
        );
        assert!(keep_newer(&mut target, &source).is_empty());
    }

    #[test]
    fn a_newer_target_entry_is_untouched() {
        let (mut target, ids) = database();
        let source = target.clone();
        edit(&mut target, ids.entry1, 1, |e| {
            e.set_title("entry1_updated".to_string())
        });

        assert!(keep_newer(&mut target, &source).is_empty());
        let merged = entry(&target, ids.entry1);
        assert_eq!(merged.title(), "entry1_updated");
        assert_eq!(titles(merged), ["entry1"]);
    }

    #[test]
    fn a_newer_source_entry_wins_and_keeps_the_old_version() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        edit(&mut source, ids.entry1, 1, |e| {
            e.set_title("entry1_updated".to_string())
        });

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        let merged = entry(&target, ids.entry1);
        assert_eq!(merged.title(), "entry1_updated");
        assert_eq!(titles(merged), ["entry1"]);
        assert!(keep_newer(&mut target, &source).is_empty());
    }

    #[test]
    fn changes_on_both_sides_keep_every_version() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        edit(&mut target, ids.entry1, 1, |e| {
            e.set_title("entry1_updated_from_destination".to_string());
        });
        edit(&mut source, ids.entry1, 2, |e| {
            e.set_title("entry1_updated_from_source".to_string());
        });

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        let merged = entry(&target, ids.entry1);
        assert_eq!(merged.title(), "entry1_updated_from_source");
        // Oldest first, as KeePassXC stores history.
        assert_eq!(
            titles(merged),
            ["entry1", "entry1_updated_from_destination"]
        );

        let copy = target.clone();
        assert!(keep_newer(&mut target, &copy).is_empty());
        // The source side gains nothing new either.
        assert!(keep_newer(&mut target, &source).is_empty());
    }

    #[test]
    fn a_newer_source_group_wins() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        rename_group(&mut source, ids.subgroup1, 1, "subgroup1_updated_name");

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        let merged = group(&target, ids.subgroup1);
        assert_eq!(merged.name(), "subgroup1_updated_name");
        assert_eq!(merged.times().last_modification, at(1));
    }

    #[test]
    fn a_newer_target_group_is_untouched() {
        let (mut target, ids) = database();
        let source = target.clone();
        rename_group(&mut target, ids.subgroup1, 1, "subgroup1_updated_name");

        assert!(keep_newer(&mut target, &source).is_empty());
        let merged = group(&target, ids.subgroup1);
        assert_eq!(merged.name(), "subgroup1_updated_name");
        assert_eq!(merged.times().last_modification, at(1));
    }

    #[test]
    fn a_group_changed_and_moved_in_the_source_follows() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        rename_group(&mut source, ids.subgroup1, 1, "subgroup1_updated_name");
        move_group(&mut source, ids.subgroup1, ids.group2, 1);

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 1, 0));
        let merged = group(&target, ids.subgroup1);
        assert_eq!(merged.name(), "subgroup1_updated_name");
        assert_eq!(
            target.root().parent_of_group(ids.subgroup1),
            Some(ids.group2)
        );
        assert_eq!(merged.times().last_modification, at(1));
        assert_eq!(merged.times().location_changed, at(1));
    }

    #[test]
    fn a_group_renamed_in_the_source_and_moved_in_the_target_gets_both() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        rename_group(&mut source, ids.subgroup1, 1, "subgroup1_updated_name");
        move_group(&mut target, ids.subgroup1, ids.group2, 2);

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        let merged = group(&target, ids.subgroup1);
        assert_eq!(merged.name(), "subgroup1_updated_name");
        assert_eq!(
            target.root().parent_of_group(ids.subgroup1),
            Some(ids.group2)
        );
        assert_eq!(merged.times().last_modification, at(1));
        assert_eq!(merged.times().location_changed, at(2));
    }

    /// keepass-rs reports an error here; KeePassXC keeps the target, since
    /// a change that did not update the modification time cannot be ordered.
    #[test]
    fn a_group_change_without_a_new_time_is_ignored() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        source
            .root_mut()
            .group_by_uuid_mut(ids.group1)
            .expect("group")
            .set_name("group1_updated_name".to_string());

        assert!(keep_newer(&mut target, &source).is_empty());
        assert_eq!(group(&target, ids.group1).name(), "group1");
    }

    #[test]
    fn an_entry_change_without_a_new_time_is_ignored() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        source
            .root_mut()
            .entry_by_uuid_mut(ids.entry1)
            .expect("entry")
            .set_title("entry1_updated_title".to_string());

        assert!(keep_newer(&mut target, &source).is_empty());
        assert_eq!(entry(&target, ids.entry1).title(), "entry1");
    }

    fn icon(uuid: &str, data: &str, modified: Option<i64>) -> RawElement {
        let modified = modified
            .map(|seconds| {
                format!(
                    "<LastModificationTime>{}</LastModificationTime>",
                    at(seconds).to_base64()
                )
            })
            .unwrap_or_default();
        RawElement::new(
            "Icon".to_string(),
            format!("<Icon><UUID>{uuid}</UUID><Data>{data}</Data>{modified}</Icon>"),
        )
    }

    const ICON: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";

    #[test]
    fn a_new_source_icon_is_added() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        source
            .meta_mut()
            .custom_icons_mut()
            .push(icon(ICON, "AQIDBA==", None));
        edit(&mut source, ids.entry1, 1, |e| {
            e.extra_mut().push(RawElement::new(
                "CustomIconUUID".to_string(),
                format!("<CustomIconUUID>{ICON}</CustomIconUUID>"),
            ));
        });

        assert_eq!(keep_newer(&mut target, &source), stats(0, 2, 0, 0));
        assert_eq!(target.meta().custom_icons(), source.meta().custom_icons());
        assert!(keep_newer(&mut target, &source).is_empty());
    }

    #[test]
    fn a_newer_source_icon_replaces_the_target_icon() {
        let (mut target, _) = database();
        target
            .meta_mut()
            .custom_icons_mut()
            .push(icon(ICON, "AQIDBA==", Some(0)));
        let mut source = target.clone();
        source.meta_mut().custom_icons_mut()[0] = icon(ICON, "BQYHCA==", Some(1));

        assert_eq!(keep_newer(&mut target, &source), stats(0, 1, 0, 0));
        assert!(target.meta().custom_icons()[0].xml().contains("BQYHCA=="));
    }

    #[test]
    fn a_newer_target_icon_is_kept() {
        let (mut target, _) = database();
        target
            .meta_mut()
            .custom_icons_mut()
            .push(icon(ICON, "AQIDBA==", Some(0)));
        let source = target.clone();
        target.meta_mut().custom_icons_mut()[0] = icon(ICON, "BQYHCA==", Some(1));

        assert!(keep_newer(&mut target, &source).is_empty());
        assert!(target.meta().custom_icons()[0].xml().contains("BQYHCA=="));
    }

    #[test]
    fn merged_history_follows_the_target_limits() {
        let (mut target, ids) = database();
        target.meta_mut().set_history_limits(HistoryLimits {
            max_items: 2,
            max_size: -1,
        });
        let mut source = target.clone();
        for round in 1..=4 {
            edit(&mut source, ids.entry1, round, |e| {
                e.set_title(format!("v{round}"))
            });
        }
        keep_newer(&mut target, &source);
        let merged = entry(&target, ids.entry1);
        assert_eq!(merged.title(), "v4");
        assert_eq!(titles(merged), ["v2", "v3"]);
    }

    #[test]
    fn the_earliest_deletion_is_kept() {
        let (mut target, ids) = database();
        let mut source = target.clone();
        delete(&mut source, ids.entry1, 3);
        let gone = Uuid::new_v4();
        mark_deleted(&mut target, gone, 9);
        mark_deleted(&mut source, gone, 4);

        sync(&mut target, &source);
        let times: Vec<(Uuid, Timestamp)> = target
            .deleted_objects()
            .iter()
            .map(|record| (record.uuid, record.deletion_time))
            .collect();
        assert!(times.contains(&(gone, at(4))));
        assert!(times.contains(&(ids.entry1, at(3))));
        assert_eq!(times.len(), 2);
        let _ = (ids.root, ids.subgroup2);
    }
}
