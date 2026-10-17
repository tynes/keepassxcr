//! Placeholder resolution in entry values, following keepassxc-cli 2.7.
//!
//! `keepassxc-cli show -a` prints values with placeholders such as `{USERNAME}`,
//! `{S:attr}` and `{REF:P@T:Other}` resolved, so `show -a` does the same. The
//! rules mirror `Entry::resolveMultiplePlaceholdersRecursive` in KeePassXC,
//! including its quirks (whole-string replacement, re-resolving until nothing
//! changes, a depth limit of 10). `{TOTP}` resolves to an empty string, since
//! keepassxcr does not generate TOTP codes.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use secrecy::ExposeSecret;

use crate::model::{Entry, Group};

/// KeePassXC's `Entry::ResolveMaximumDepth`.
const MAX_DEPTH: i32 = 10;

/// What a value is resolved against.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// Root group, searched by `{REF:…}` placeholders.
    pub root: &'a Group,
    /// Database file path, for `{DB_DIR}`.
    pub database: &'a Path,
}

/// Every attribute of an entry by name: the five standard ones and the custom ones.
pub fn attributes(entry: &Entry) -> BTreeMap<String, String> {
    let mut attributes = entry.custom_fields().clone();
    attributes.insert("Title".to_string(), entry.title().to_string());
    attributes.insert("UserName".to_string(), entry.username().to_string());
    attributes.insert(
        "Password".to_string(),
        entry.password().expose_secret().to_string(),
    );
    attributes.insert("URL".to_string(), entry.url().to_string());
    attributes.insert("Notes".to_string(), entry.notes().to_string());
    attributes
}

/// Resolve the placeholders in `value`, a value of `entry`.
pub fn resolve(entry: &Entry, value: &str, ctx: Context<'_>) -> String {
    resolve_all(entry, value, MAX_DEPTH, ctx)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    NotPlaceholder,
    Unknown,
    Title,
    UserName,
    Password,
    Notes,
    Url,
    Totp,
    DbDir,
    Url_(UrlPart),
    Custom,
    Reference,
    DateTime { utc: bool, part: DtPart },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlPart {
    WithoutScheme,
    Scheme,
    Host,
    Port,
    Path,
    Query,
    Fragment,
    UserInfo,
    UserName,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtPart {
    Simple,
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
}

fn kind(placeholder: &str) -> Kind {
    if !placeholder.starts_with('{') || !placeholder.ends_with('}') {
        return Kind::NotPlaceholder;
    }
    if placeholder.starts_with("{S:") {
        return Kind::Custom;
    }
    if placeholder.starts_with("{REF:") {
        return Kind::Reference;
    }
    let upper = placeholder.to_uppercase();
    let inner = &upper[1..upper.len() - 1];
    match inner {
        "TITLE" => Kind::Title,
        "USERNAME" => Kind::UserName,
        "PASSWORD" => Kind::Password,
        "NOTES" => Kind::Notes,
        "TOTP" => Kind::Totp,
        "URL" => Kind::Url,
        "URL:RMVSCM" | "URL:WITHOUTSCHEME" => Kind::Url_(UrlPart::WithoutScheme),
        "URL:SCM" | "URL:SCHEME" => Kind::Url_(UrlPart::Scheme),
        "URL:HOST" => Kind::Url_(UrlPart::Host),
        "URL:PORT" => Kind::Url_(UrlPart::Port),
        "URL:PATH" => Kind::Url_(UrlPart::Path),
        "URL:QUERY" => Kind::Url_(UrlPart::Query),
        "URL:FRAGMENT" => Kind::Url_(UrlPart::Fragment),
        "URL:USERINFO" => Kind::Url_(UrlPart::UserInfo),
        "URL:USERNAME" => Kind::Url_(UrlPart::UserName),
        "URL:PASSWORD" => Kind::Url_(UrlPart::Password),
        "DB_DIR" => Kind::DbDir,
        _ => {
            let (utc, rest) = match inner.strip_prefix("DT_UTC_") {
                Some(rest) => (true, rest),
                None => match inner.strip_prefix("DT_") {
                    Some(rest) => (false, rest),
                    None => return Kind::Unknown,
                },
            };
            let part = match rest {
                "SIMPLE" => DtPart::Simple,
                "YEAR" => DtPart::Year,
                "MONTH" => DtPart::Month,
                "DAY" => DtPart::Day,
                "HOUR" => DtPart::Hour,
                "MINUTE" => DtPart::Minute,
                "SECOND" => DtPart::Second,
                _ => return Kind::Unknown,
            };
            Kind::DateTime { utc, part }
        }
    }
}

/// Matches of KeePassXC's `\{[^\}]+?\}`: a `{`, at least one character that
/// is not `}`, then the first `}`.
fn placeholder_matches(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'{' {
            index += 1;
            continue;
        }
        match bytes[index + 1..].iter().position(|&b| b == b'}') {
            None => break,
            Some(0) => index += 1,
            Some(offset) => {
                let end = index + 1 + offset;
                found.push(&text[index..=end]);
                index = end + 1;
            }
        }
    }
    found
}

fn resolve_all(entry: &Entry, text: &str, depth: i32, ctx: Context<'_>) -> String {
    if depth <= 0 {
        return text.to_string();
    }
    let mut result = text.to_string();
    for found in placeholder_matches(text) {
        let replacement = resolve_one(entry, found, depth - 1, ctx);
        result = result.replace(found, &replacement);
    }
    if result != text {
        result = resolve_all(entry, &result, depth - 1, ctx);
    }
    result
}

fn resolve_field(entry: &Entry, value: &str, field: Kind, depth: i32, ctx: Context<'_>) -> String {
    // A field holding exactly its own placeholder resolves to itself.
    if kind(value) == field {
        return value.to_string();
    }
    resolve_all(entry, value, depth - 1, ctx)
}

fn resolve_one(entry: &Entry, placeholder: &str, depth: i32, ctx: Context<'_>) -> String {
    if depth <= 0 {
        return placeholder.to_string();
    }
    let placeholder_kind = kind(placeholder);
    match placeholder_kind {
        Kind::NotPlaceholder | Kind::Unknown => resolve_all(entry, placeholder, depth - 1, ctx),
        Kind::Title => resolve_field(entry, entry.title(), placeholder_kind, depth, ctx),
        Kind::UserName => resolve_field(entry, entry.username(), placeholder_kind, depth, ctx),
        Kind::Password => resolve_field(
            entry,
            entry.password().expose_secret(),
            placeholder_kind,
            depth,
            ctx,
        ),
        Kind::Notes => resolve_field(entry, entry.notes(), placeholder_kind, depth, ctx),
        Kind::Url => resolve_field(entry, entry.url(), placeholder_kind, depth, ctx),
        Kind::DbDir => database_dir(ctx.database),
        Kind::Url_(part) => {
            let url = resolve_all(entry, entry.url(), depth - 1, ctx);
            url_part(&url, part)
        }
        Kind::Totp => String::new(),
        Kind::Custom => {
            let key = &placeholder[3..placeholder.len() - 1];
            attributes(entry).remove(key).unwrap_or_default()
        }
        Kind::Reference => resolve_reference(placeholder, depth, ctx),
        Kind::DateTime { utc, part } => resolve_all(entry, &date_time(utc, part), depth - 1, ctx),
    }
}

/// `{REF:<wanted>@<search in>:<search text>}`, matched anywhere in the placeholder.
fn parse_reference(placeholder: &str) -> Option<(char, char, &str)> {
    const WANTED: &str = "TUPANI";
    const SEARCH_IN: &str = "TUPANIO";
    let upper = placeholder.to_ascii_uppercase();
    let mut from = 0;
    while let Some(offset) = upper[from..].find("{REF:") {
        let start = from + offset;
        let bytes = upper.as_bytes();
        let fields = start + 5;
        if bytes.len() > fields + 3 && bytes[fields + 1] == b'@' && bytes[fields + 3] == b':' {
            let wanted = bytes[fields] as char;
            let search_in = bytes[fields + 2] as char;
            let text_start = fields + 4;
            if WANTED.contains(wanted)
                && SEARCH_IN.contains(search_in)
                && let Some(len) = placeholder[text_start..].find('}')
                && len > 0
            {
                return Some((
                    wanted,
                    search_in,
                    &placeholder[text_start..text_start + len],
                ));
            }
        }
        from = start + 1;
    }
    None
}

fn resolve_reference(placeholder: &str, depth: i32, ctx: Context<'_>) -> String {
    if depth <= 0 {
        return placeholder.to_string();
    }
    let Some((wanted, search_in, search_text)) = parse_reference(placeholder) else {
        return placeholder.to_string();
    };
    let Some(found) = find_entry(ctx.root, search_in, search_text) else {
        return String::new();
    };
    let value = match wanted {
        'T' => found.title().to_string(),
        'U' => found.username().to_string(),
        'P' => found.password().expose_secret().to_string(),
        'A' => found.url().to_string(),
        'N' => found.notes().to_string(),
        'I' => found.uuid().simple().to_string(),
        _ => String::new(),
    };
    resolve_all(found, &value, depth - 1, ctx)
}

/// First entry, groups in pre-order, whose field equals `term`.
fn find_entry<'a>(group: &'a Group, search_in: char, term: &str) -> Option<&'a Entry> {
    let uuid = (search_in == 'I').then(|| uuid_from_hex(term));
    for entry in group.entries() {
        let found = match search_in {
            'T' => entry.title() == term,
            'U' => entry.username() == term,
            'P' => entry.password().expose_secret() == term,
            'A' => entry.url() == term,
            'N' => entry.notes() == term,
            'I' => uuid.flatten() == Some(entry.uuid()),
            'O' => attributes(entry).values().any(|value| value == term),
            _ => false,
        };
        if found {
            return Some(entry);
        }
    }
    group
        .groups()
        .iter()
        .find_map(|child| find_entry(child, search_in, term))
}

/// Like Qt's `QUuid::fromRfc4122(QByteArray::fromHex(text))`: characters that
/// are not hex digits are skipped, and anything but 16 bytes is no UUID.
fn uuid_from_hex(text: &str) -> Option<uuid::Uuid> {
    let digits: String = text.chars().filter(char::is_ascii_hexdigit).collect();
    let bytes = hex::decode(digits).ok()?;
    let uuid = uuid::Uuid::from_slice(&bytes).ok()?;
    (!uuid.is_nil()).then_some(uuid)
}

fn database_dir(database: &Path) -> String {
    let absolute = std::path::absolute(database).unwrap_or_else(|_| database.to_path_buf());
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            other => clean.push(other),
        }
    }
    clean
        .parent()
        .unwrap_or(&clean)
        .to_string_lossy()
        .into_owned()
}

/// The parts of a URL, split as `QUrl` does for well-formed URLs.
#[derive(Debug, Default, PartialEq, Eq)]
struct UrlParts<'a> {
    scheme: &'a str,
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

fn split_url(url: &str) -> UrlParts<'_> {
    let mut parts = UrlParts::default();
    let mut rest = url;
    if let Some((fragment_start, fragment)) = rest.find('#').map(|i| (i, &rest[i + 1..])) {
        parts.fragment = Some(fragment);
        rest = &rest[..fragment_start];
    }
    if let Some(index) = rest.find('?') {
        parts.query = Some(&rest[index + 1..]);
        rest = &rest[..index];
    }
    if let Some(index) = rest.find(':') {
        let scheme = &rest[..index];
        let valid = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            parts.scheme = scheme;
            rest = &rest[index + 1..];
        }
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find('/').unwrap_or(after.len());
        parts.authority = Some(&after[..end]);
        rest = &after[end..];
    }
    parts.path = rest;
    parts
}

/// `(userinfo, host, port)` of an authority.
fn split_authority(authority: &str) -> (Option<&str>, &str, Option<&str>) {
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(index) => (Some(&authority[..index]), &authority[index + 1..]),
        None => (None, authority),
    };
    let port_sep = if host_port.starts_with('[') {
        host_port
            .find(']')
            .and_then(|end| host_port[end..].starts_with("]:").then_some(end + 1))
    } else {
        host_port.rfind(':')
    };
    match port_sep {
        Some(index) => (userinfo, &host_port[..index], Some(&host_port[index + 1..])),
        None => (userinfo, host_port, None),
    }
}

/// Characters `QUrl` keeps percent-encoded in its pretty-decoded output.
const DELIMITERS: &str = ":/?#[]@!$&'()*+,;=";

/// Decode `%XX` escapes. With `keep`, escapes of those characters, `%`
/// itself and control characters stay encoded, as in `QUrl::PrettyDecoded`.
fn percent_decode(text: &str, keep: Option<&str>) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let digits = [bytes[index + 1], bytes[index + 2]];
            let digits = std::str::from_utf8(&digits).expect("hex digits are ASCII");
            let byte = u8::from_str_radix(digits, 16).expect("checked hex digits");
            let kept = keep.is_some_and(|keep| {
                byte == b'%' || byte.is_ascii_control() || keep.as_bytes().contains(&byte)
            });
            if !kept {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn full(text: &str) -> String {
    percent_decode(text, None)
}

fn pretty(text: &str) -> String {
    percent_decode(text, Some(DELIMITERS))
}

fn url_part(url: &str, part: UrlPart) -> String {
    if url.is_empty() {
        return String::new();
    }
    let parts = split_url(url);
    let (userinfo, host, port) = parts.authority.map(split_authority).unwrap_or_default();
    let (username, password) = match userinfo {
        Some(info) => match info.split_once(':') {
            Some((user, pass)) => (user, Some(pass)),
            None => (info, None),
        },
        None => ("", None),
    };
    let valid_port = port.is_none_or(|port| port.is_empty() || port.parse::<u16>().is_ok());
    match part {
        // QUrl refuses to rebuild an invalid URL and returns nothing.
        UrlPart::WithoutScheme if !valid_port => String::new(),
        UrlPart::WithoutScheme => {
            let mut out = String::new();
            if parts.authority.is_some() {
                out.push_str("//");
                if let Some(info) = userinfo {
                    out.push_str(info);
                    out.push('@');
                }
                out.push_str(&host.to_ascii_lowercase());
                if let Some(port) = port.filter(|port| !port.is_empty()) {
                    out.push(':');
                    out.push_str(port);
                }
            }
            out.push_str(parts.path);
            if let Some(query) = parts.query {
                out.push('?');
                out.push_str(query);
            }
            if let Some(fragment) = parts.fragment {
                out.push('#');
                out.push_str(fragment);
            }
            pretty(&out)
        }
        UrlPart::Scheme => parts.scheme.to_ascii_lowercase(),
        UrlPart::Host => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
        UrlPart::Port => port
            .and_then(|port| port.parse::<u16>().ok())
            .map_or(-1, i32::from)
            .to_string(),
        UrlPart::Path => full(parts.path),
        UrlPart::Query => pretty(parts.query.unwrap_or_default()),
        UrlPart::Fragment => pretty(parts.fragment.unwrap_or_default()),
        // Inside the user info only `:` separates, so `@` is decoded.
        UrlPart::UserInfo => percent_decode(
            userinfo.unwrap_or_default(),
            Some(&DELIMITERS.replace('@', "")),
        ),
        UrlPart::UserName => full(username),
        UrlPart::Password => full(password.unwrap_or_default()),
    }
}

fn date_time(utc: bool, part: DtPart) -> String {
    let now = libc_now(utc);
    match part {
        DtPart::Simple => format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            now.year, now.month, now.day, now.hour, now.minute, now.second
        ),
        DtPart::Year => format!("{:04}", now.year),
        DtPart::Month => format!("{:02}", now.month),
        DtPart::Day => format!("{:02}", now.day),
        DtPart::Hour => format!("{:02}", now.hour),
        DtPart::Minute => format!("{:02}", now.minute),
        DtPart::Second => format!("{:02}", now.second),
    }
}

struct Civil {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
}

#[cfg(unix)]
fn libc_now(utc: bool) -> Civil {
    // SAFETY: time(NULL) has no preconditions; localtime_r and gmtime_r only
    // write to the tm we pass in.
    let tm = unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if utc {
            libc::gmtime_r(&now, &mut tm);
        } else {
            libc::localtime_r(&now, &mut tm);
        }
        tm
    };
    Civil {
        year: tm.tm_year + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        second: tm.tm_sec as u32,
    }
}

#[cfg(not(unix))]
fn libc_now(_utc: bool) -> Civil {
    let now = time::OffsetDateTime::now_utc();
    Civil {
        year: now.year(),
        month: u8::from(now.month()) as u32,
        day: now.day() as u32,
        hour: now.hour() as u32,
        minute: now.minute() as u32,
        second: now.second() as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn database() -> Group {
        let mut root = Group::new("Root".to_string());
        let mut api = Entry::new("Api".to_string());
        api.set_username("{TITLE}-user".to_string());
        api.set_password(SecretString::new("p-{USERNAME}".to_string()));
        api.set_url("https://bob:pw@Example.COM:8443/a/b?x=1#frag".to_string());
        api.set_custom_field("region".to_string(), "eu".to_string(), false);
        let mut other = Entry::new("Other".to_string());
        other.set_password(SecretString::new("{REF:P@T:Api}".to_string()));
        other.set_notes("{S:missing}|{S:Title}|{unknown}|{}".to_string());
        root.entries_mut().push(api);
        let mut child = Group::new("Child".to_string());
        child.entries_mut().push(other);
        root.groups_mut().push(child);
        root
    }

    fn resolved(root: &Group, path: (usize, Option<usize>), value: &str) -> String {
        let entry = match path.1 {
            Some(index) => &root.groups()[path.0].entries()[index],
            None => &root.entries()[path.0],
        };
        let ctx = Context {
            root,
            database: Path::new("/data/x/../db.kdbx"),
        };
        resolve(entry, value, ctx)
    }

    #[test]
    fn resolves_fields_custom_attributes_and_references() {
        let root = database();
        assert_eq!(resolved(&root, (0, None), "{USERNAME}"), "Api-user");
        assert_eq!(resolved(&root, (0, None), "{password}"), "p-Api-user");
        assert_eq!(resolved(&root, (0, None), "{S:region}"), "eu");
        assert_eq!(resolved(&root, (0, Some(0)), "{PASSWORD}"), "p-Api-user");
        assert_eq!(
            resolved(&root, (0, Some(0)), "{NOTES}"),
            "|Other|{unknown}|{}"
        );
        assert_eq!(resolved(&root, (0, None), "{DB_DIR}"), "/data");
        assert_eq!(resolved(&root, (0, None), "{REF:U@T:Nobody}"), "");
    }

    #[test]
    fn resolves_url_parts() {
        let root = database();
        let url = |part| resolved(&root, (0, None), part);
        assert_eq!(url("{URL:SCM}"), "https");
        assert_eq!(url("{URL:HOST}"), "example.com");
        assert_eq!(url("{URL:PORT}"), "8443");
        assert_eq!(url("{URL:PATH}"), "/a/b");
        assert_eq!(url("{URL:QUERY}"), "x=1");
        assert_eq!(url("{URL:FRAGMENT}"), "frag");
        assert_eq!(url("{URL:USERINFO}"), "bob:pw");
        assert_eq!(url("{URL:USERNAME}"), "bob");
        assert_eq!(url("{URL:PASSWORD}"), "pw");
        assert_eq!(
            url("{URL:RMVSCM}"),
            "//bob:pw@example.com:8443/a/b?x=1#frag"
        );
    }

    #[test]
    fn self_reference_stops_at_the_depth_limit() {
        let mut root = Group::new("Root".to_string());
        let mut entry = Entry::new("Loop".to_string());
        entry.set_username("{USERNAME}".to_string());
        entry.set_notes("{NOTES}x".to_string());
        root.entries_mut().push(entry);
        assert_eq!(resolved(&root, (0, None), "{USERNAME}"), "{USERNAME}");
        assert!(resolved(&root, (0, None), "{NOTES}").ends_with('x'));
    }

    #[test]
    fn finds_placeholders_like_keepassxc() {
        assert_eq!(placeholder_matches("a{b}c{}{d{e}f}"), vec!["{b}", "{d{e}"]);
        assert_eq!(placeholder_matches("{unclosed"), Vec::<&str>::new());
    }
}
