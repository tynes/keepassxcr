//! Databases written by KeePassXC, KeePass and keepass-rs, taken from the
//! keepass-rs test suite (see `tests/data/keepass-rs/README.md`).
//!
//! Every fixture must open with the expected content, survive a save and
//! reopen unchanged, and every damaged variant must fail with an error rather
//! than a panic.

use std::path::{Path, PathBuf};

use keepassxcr::crypto::KeyFile;
use keepassxcr::format::{Credentials, KdbxVersion, read_kdbx, write_kdbx};
use keepassxcr::model::{Entry, Group};
use secrecy::{ExposeSecret, SecretString};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/keepass-rs")
        .join(name)
}

fn credentials(password: Option<&str>, key_file: Option<&str>) -> Credentials {
    Credentials {
        password: password.map(|value| SecretString::new(value.to_string())),
        yubikey: None,
        key_file: key_file.map(|name| KeyFile::load(&fixture(name)).expect("key file")),
        agent: None,
    }
}

struct Expected {
    file: &'static str,
    password: Option<&'static str>,
    key_file: Option<&'static str>,
    version: KdbxVersion,
    root_name: &'static str,
    root_groups: usize,
    root_entries: usize,
    /// Groups including the root, and entries, in the whole tree.
    totals: Option<(usize, usize)>,
}

const DEMO: Option<&str> = Some("demopass");

/// Expected values come from the keepass-rs tests (`tests/file_read_tests.rs`),
/// so they are an independent check of what each file contains.
const FIXTURES: &[Expected] = &[
    Expected {
        file: "test_db_with_password.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V3_1,
        root_name: "sample",
        root_groups: 3,
        root_entries: 2,
        totals: Some((5, 6)),
    },
    Expected {
        file: "test_db_kdbx3_with_attachments.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V3_1,
        root_name: "Root",
        root_groups: 0,
        root_entries: 2,
        totals: None,
    },
    Expected {
        file: "test_db_with_keyfile.kdbx",
        password: None,
        key_file: Some("test_key.key"),
        version: KdbxVersion::V3_1,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: Some((1, 1)),
    },
    Expected {
        file: "test_db_with_keyfile_xml.kdbx",
        password: None,
        key_file: Some("test_key_xml.key"),
        version: KdbxVersion::V3_1,
        root_name: "Root",
        root_groups: 2,
        root_entries: 2,
        totals: Some((5, 6)),
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 2,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2id.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 2,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_aes.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_1,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2_twofish.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2_chacha20.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2id_twofish.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_password_argon2id_chacha20.kdbx",
        password: DEMO,
        key_file: None,
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_keyfile.kdbx",
        password: None,
        key_file: Some("test_key.key"),
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_keyfile_v2.kdbx",
        password: DEMO,
        key_file: Some("test_db_kdbx4_with_keyfile_v2.keyx"),
        version: KdbxVersion::V4_0,
        root_name: "Root",
        root_groups: 0,
        root_entries: 1,
        totals: None,
    },
    Expected {
        file: "test_db_kdbx4_with_keyfile_v2_alt.kdbx",
        password: DEMO,
        key_file: Some("test_db_kdbx4_with_keyfile_v2_alt.keyx"),
        version: KdbxVersion::V4_0,
        root_name: "testdb02",
        root_groups: 6,
        root_entries: 2,
        totals: None,
    },
];

/// Files whose content keepass-rs checks in other ways; they must open and
/// round-trip like the rest.
const OTHER_FIXTURES: &[(&str, &str)] = &[
    ("test_db_kdbx4_with_password_deleted_entry.kdbx", "demopass"),
    ("test_db_kdbx41_with_password_aes.kdbx", "demopass"),
    ("test_db_kdbx41_features.kdbx", "demopass"),
    ("test_db_few_rounds.kdbx", "demopass"),
    (
        "test_db_kdbx3_with_chacha20_protected_fields.kdbx",
        "password",
    ),
    ("test_db_kdbx4_with_totp_entry.kdbx", "test"),
    ("test_db_kdbx4_with_totp_sha512_entry.kdbx", "test"),
];

fn totals(group: &Group) -> (usize, usize) {
    group
        .groups()
        .iter()
        .map(totals)
        .fold((1, group.entries().len()), |(g, e), (cg, ce)| {
            (g + cg, e + ce)
        })
}

/// A readable dump of everything the model holds, for comparing two loads.
fn describe(group: &Group, out: &mut Vec<String>) {
    out.push(format!(
        "group {} {} tags={:?} times={:?} previous={:?}",
        group.uuid(),
        group.name(),
        group.tags(),
        group.times(),
        group.previous_parent_group()
    ));
    for raw in group.extra() {
        out.push(format!("  group xml {}", raw.xml()));
    }
    for entry in group.entries() {
        describe_entry(entry, "  ", out);
        for item in entry.history() {
            describe_entry(item, "    history ", out);
        }
    }
    for child in group.groups() {
        describe(child, out);
    }
}

fn describe_entry(entry: &Entry, indent: &str, out: &mut Vec<String>) {
    out.push(format!(
        "{indent}entry {} title={:?} user={:?} pass={:?} url={:?} notes={:?}",
        entry.uuid(),
        entry.title(),
        entry.username(),
        entry.password().expose_secret(),
        entry.url(),
        entry.notes()
    ));
    out.push(format!(
        "{indent}  tags={:?} times={:?} previous={:?}",
        entry.tags(),
        entry.times(),
        entry.previous_parent_group()
    ));
    for (key, value) in entry.custom_fields() {
        let protected = entry.protected_fields().contains(key);
        out.push(format!(
            "{indent}  field {key:?}={value:?} protected={protected}"
        ));
    }
    for attachment in entry.attachments() {
        out.push(format!(
            "{indent}  attachment {:?} {:?}",
            attachment.name(),
            attachment.data()
        ));
    }
    for raw in entry.extra() {
        out.push(format!("{indent}  xml {}", raw.xml()));
    }
}

fn snapshot(file: &keepassxcr::format::KdbxFile) -> Vec<String> {
    let mut out = vec![
        format!("meta name={:?}", file.database.meta().name()),
        format!("meta description={:?}", file.database.meta().description()),
    ];
    let meta = file.database.meta();
    out.push(format!(
        "meta recycle bin enabled={} uuid={:?} changed={:?} limits={:?}",
        meta.recycle_bin_enabled(),
        meta.recycle_bin(),
        meta.recycle_bin_changed(),
        meta.history_limits()
    ));
    for icon in meta.custom_icons() {
        out.push(format!("meta icon {}", icon.xml()));
    }
    for raw in meta.extra() {
        out.push(format!("meta xml {}", raw.xml()));
    }
    for object in file.database.deleted_objects() {
        out.push(format!("deleted {object:?}"));
    }
    for raw in file.database.root_extra() {
        out.push(format!("root xml {}", raw.xml()));
    }
    describe(file.database.root(), &mut out);
    out
}

/// Save `file` to a temporary copy and read it back.
fn save_and_reopen(
    file: &keepassxcr::format::KdbxFile,
    credentials: &Credentials,
    name: &str,
) -> keepassxcr::format::KdbxFile {
    let dir = std::env::temp_dir().join(format!("keepassxcr-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(name);
    write_kdbx(&path, file, credentials).expect("save");
    let reopened = read_kdbx(&path, credentials).expect("reopen");
    std::fs::remove_dir_all(&dir).expect("cleanup");
    reopened
}

fn assert_round_trip(name: &str, credentials: &Credentials) {
    let file = read_kdbx(&fixture(name), credentials).unwrap_or_else(|err| panic!("{name}: {err}"));
    let reopened = save_and_reopen(&file, credentials, name);
    assert_eq!(file.version, reopened.version, "{name}: version changed");
    assert_eq!(file.cipher, reopened.cipher, "{name}: cipher changed");
    assert_eq!(
        snapshot(&file),
        snapshot(&reopened),
        "{name}: content changed"
    );
}

#[test]
fn fixtures_open_with_expected_content() {
    for expected in FIXTURES {
        let credentials = credentials(expected.password, expected.key_file);
        let file = read_kdbx(&fixture(expected.file), &credentials)
            .unwrap_or_else(|err| panic!("{}: {err}", expected.file));
        let root = file.database.root();
        assert_eq!(file.version, expected.version, "{}", expected.file);
        assert_eq!(root.name(), expected.root_name, "{}", expected.file);
        assert_eq!(
            root.groups().len(),
            expected.root_groups,
            "{}",
            expected.file
        );
        assert_eq!(
            root.entries().len(),
            expected.root_entries,
            "{}",
            expected.file
        );
        if let Some(expected_totals) = expected.totals {
            assert_eq!(totals(root), expected_totals, "{}", expected.file);
        }
    }
}

#[test]
fn fixtures_survive_a_save() {
    for expected in FIXTURES {
        assert_round_trip(
            expected.file,
            &credentials(expected.password, expected.key_file),
        );
    }
    for (name, password) in OTHER_FIXTURES {
        assert_round_trip(name, &credentials(Some(password), None));
    }
}

/// KeePassXC writes an empty KDBX 3.1 attachment as a self-closing,
/// `Compressed="True"` element with no data, which used to fail to open.
#[test]
fn kdbx3_attachments_including_an_empty_one() {
    let file = read_kdbx(
        &fixture("test_db_kdbx3_with_attachments.kdbx"),
        &credentials(DEMO, None),
    )
    .expect("open");
    let attachments = |title: &str| {
        let entry = file
            .database
            .root()
            .find_entry(title)
            .unwrap_or_else(|| panic!("entry {title}"));
        let mut named: Vec<(String, Vec<u8>)> = entry
            .attachments()
            .iter()
            .map(|attachment| (attachment.name().to_string(), attachment.data().to_vec()))
            .collect();
        named.sort();
        named
    };
    assert_eq!(
        attachments("first"),
        vec![
            ("a.txt".to_string(), b"alpha".to_vec()),
            ("b.txt".to_string(), b"bravo".to_vec()),
            ("empty.txt".to_string(), Vec::new()),
        ]
    );
    assert_eq!(
        attachments("second"),
        vec![("c.txt".to_string(), b"charlie".to_vec())]
    );
}

#[test]
fn broken_files_fail_cleanly() {
    let empty = credentials(Some(""), None);
    for name in ["broken_random_data.kdbx", "broken_kdbx_version.kdbx"] {
        assert!(read_kdbx(&fixture(name), &empty).is_err(), "{name} opened");
    }
}

#[test]
fn wrong_credentials_are_rejected() {
    let wrong = credentials(Some("not the password"), None);
    for name in [
        "test_db_with_password.kdbx",
        "test_db_kdbx4_with_password_aes.kdbx",
        "test_db_few_rounds.kdbx",
    ] {
        match read_kdbx(&fixture(name), &wrong) {
            Err(keepassxcr::error::AppError::InvalidCredentials) => {}
            other => panic!("{name}: expected invalid credentials, got {other:?}"),
        }
    }
}

/// Write `data` to a scratch file and try to open it; it must not panic.
fn open_bytes(data: &[u8], credentials: &Credentials, path: &Path) -> bool {
    std::fs::write(path, data).expect("write");
    read_kdbx(path, credentials).is_ok()
}

#[test]
fn truncated_and_corrupted_files_fail_cleanly() {
    let credentials = credentials(DEMO, None);
    let original = std::fs::read(fixture("test_db_few_rounds.kdbx")).expect("read");
    let dir = std::env::temp_dir().join(format!("keepassxcr-corrupt-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("corrupt.kdbx");

    assert!(
        open_bytes(&original, &credentials, &path),
        "original must open"
    );
    for len in 0..original.len() {
        assert!(
            !open_bytes(&original[..len], &credentials, &path),
            "a file truncated to {len} bytes opened"
        );
    }
    for index in 0..original.len() {
        let mut damaged = original.clone();
        damaged[index] ^= 0x5a;
        assert!(
            !open_bytes(&damaged, &credentials, &path),
            "a file with byte {index} changed opened"
        );
    }
    let mut trailing = original.clone();
    trailing.extend_from_slice(b"trailing garbage");
    // KeePassXC ignores data after the final block, and so do we.
    assert!(open_bytes(&trailing, &credentials, &path));

    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn recycle_bin_is_read_and_used() {
    let credentials = credentials(Some("demopass"), None);
    let mut file = read_kdbx(
        &fixture("test_db_kdbx4_with_password_deleted_entry.kdbx"),
        &credentials,
    )
    .expect("open");
    let bin = uuid::uuid!("563171fe-6598-42dc-8003-f98dde32e872");
    let meta = file.database.meta();
    assert!(meta.recycle_bin_enabled());
    assert_eq!(meta.recycle_bin(), Some(bin));
    let bin_group = file.database.root().group_by_uuid(bin).expect("bin group");
    assert_eq!(bin_group.name(), "Recycle Bin");

    // Removing an entry puts it in the existing bin rather than a new one.
    let groups_before = file.database.root().groups().len();
    let entry = first_entry_outside(file.database.root(), bin).expect("an entry");
    assert_eq!(
        file.database.recycle_entry(entry),
        Some(keepassxcr::model::Removal::Recycled)
    );
    assert_eq!(file.database.root().groups().len(), groups_before);
    let reopened = save_and_reopen(&file, &credentials, "recycled.kdbx");
    let bin_group = reopened.database.root().group_by_uuid(bin).expect("bin");
    assert!(bin_group.entry_by_uuid(entry).is_some());
    // Moving needs KDBX 4.1 for the previous parent group.
    assert_eq!(reopened.version, KdbxVersion::V4_1);
}

fn first_entry_outside(group: &Group, skip: uuid::Uuid) -> Option<uuid::Uuid> {
    if group.uuid() == skip {
        return None;
    }
    group.entries().first().map(Entry::uuid).or_else(|| {
        group
            .groups()
            .iter()
            .find_map(|child| first_entry_outside(child, skip))
    })
}
