//! Persistent lock list: paths that janitor refuses to mutate.
//!
//! Stored as a newline-delimited file (`locks.txt`) in the backup directory.
//! Each line is `PATH\tREASON` (reason may be empty). A directory lock implies
//! every descendant is locked.
//!
//! Both fields are escaped so the record format cannot be confused by the
//! data: a backslash becomes `\\`, tab `\t`, newline `\n`, carriage return
//! `\r`, and any other control byte or byte that is not valid UTF-8 becomes
//! `\xHH`. Paths are stored from their raw bytes, so a non-UTF-8 name locks
//! the file that was named rather than a lossy look-alike that never
//! matches again. Lines written before the escaping existed contain no
//! backslashes in practice and parse unchanged.

use crate::errors::{PmError, Result};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

fn locks_file() -> PathBuf {
    crate::config::backup_root().join("locks.txt")
}

#[derive(Debug, Clone)]
pub struct LockEntry {
    pub path: PathBuf,
    pub reason: String,
}

/// Escape one record field. Printable text (including non-ASCII UTF-8)
/// passes through; everything that could break the line format is encoded.
fn escape_field(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\t' => out.push_str("\\t"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                c if c.is_control() => {
                    let mut buf = [0u8; 4];
                    for b in c.encode_utf8(&mut buf).bytes() {
                        out.push_str(&format!("\\x{b:02x}"));
                    }
                }
                c => out.push(c),
            }
        }
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// Inverse of [`escape_field`]. An escape it does not recognise is kept
/// literally, so a pre-escaping line that happened to contain a backslash
/// still round-trips.
fn unescape_field(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    let push_char = |out: &mut Vec<u8>, c: char| {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    };
    while let Some(c) = chars.next() {
        if c != '\\' {
            push_char(&mut out, c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push(b'\\'),
            Some('t') => out.push(b'\t'),
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('x') => {
                let rest = chars.as_str();
                let hex: String = rest.chars().take(2).collect();
                match (hex.len() == 2)
                    .then(|| u8::from_str_radix(&hex, 16).ok())
                    .flatten()
                {
                    Some(b) => {
                        out.push(b);
                        chars = rest[hex.len()..].chars();
                    }
                    None => out.extend_from_slice(b"\\x"),
                }
            }
            Some(other) => {
                out.push(b'\\');
                push_char(&mut out, other);
            }
            None => out.push(b'\\'),
        }
    }
    out
}

fn format_entry(e: &LockEntry) -> String {
    format!(
        "{}\t{}",
        escape_field(e.path.as_os_str().as_bytes()),
        escape_field(e.reason.as_bytes())
    )
}

fn parse_entry(line: &str) -> Option<LockEntry> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() || line.starts_with('#') {
        return None;
    }
    let (path, reason) = match line.split_once('\t') {
        Some((p, r)) => (p, r),
        None => (line, ""),
    };
    let path = PathBuf::from(OsString::from_vec(unescape_field(path.trim())));
    let reason = String::from_utf8_lossy(&unescape_field(reason.trim())).into_owned();
    Some(LockEntry { path, reason })
}

pub fn load() -> Result<Vec<LockEntry>> {
    let p = locks_file();
    if !p.exists() {
        return Ok(Vec::new());
    }
    let f = fs::File::open(&p).map_err(|e| PmError::Other(format!("open locks: {e}")))?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        // A read error mid-file would otherwise silently truncate the lock
        // list, quietly unlocking every path recorded after that point.
        let line = line.map_err(|e| PmError::Other(format!("read locks: {e}")))?;
        if let Some(entry) = parse_entry(&line) {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Write the lock list atomically: unique temp file created 0600, fsync'd,
/// renamed into place, then the directory itself fsync'd. The temp name
/// carries the pid so two concurrent writers never share it.
fn save(entries: &[LockEntry]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = crate::config::ensure_backup_root()
        .map_err(|e| PmError::Other(format!("mkdir backup: {e}")))?;
    let p = locks_file();
    let tmp = dir.join(format!("locks.txt.{}.tmp", std::process::id()));
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| PmError::Other(format!("write locks: {e}")))?;
    for e in entries {
        writeln!(f, "{}", format_entry(e))
            .map_err(|e| PmError::Other(format!("write locks: {e}")))?;
    }
    f.sync_all()
        .map_err(|e| PmError::Other(format!("fsync locks: {e}")))?;
    drop(f);
    fs::rename(&tmp, &p).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        PmError::Other(format!("rename locks: {e}"))
    })?;
    // fsync the directory so the rename survives a crash.
    if let Ok(d) = fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Read-modify-write the lock list under the global mutation lock, so two
/// concurrent `janitor lock` calls cannot lose each other's entry.
pub fn add(path: &Path, reason: Option<&str>) -> Result<()> {
    crate::locking::with_lock(|| {
        let mut locks = load()?;
        if locks.iter().any(|l| l.path == path) {
            return Err(PmError::Other(format!(
                "already locked: {}",
                path.display()
            )));
        }
        locks.push(LockEntry {
            path: path.to_path_buf(),
            reason: reason.unwrap_or("").to_string(),
        });
        save(&locks)
    })
}

pub fn remove(path: &Path) -> Result<()> {
    crate::locking::with_lock(|| {
        let mut locks = load()?;
        let len0 = locks.len();
        locks.retain(|l| l.path != path);
        if locks.len() == len0 {
            return Err(PmError::Other(format!("not locked: {}", path.display())));
        }
        save(&locks)
    })
}

/// Identity of the lock file as last parsed: (dev, ino, size, mtime). A
/// recursive mutation calls [`ensure_not_locked`] once per path, and
/// re-reading and re-parsing the file every time turned a million-entry
/// `chmod -R` into a million opens of `locks.txt`. One `stat` per call
/// keeps the check current (a lock added by another process is still
/// seen) while the parse happens only when the file actually changed.
type FileKey = (u64, u64, u64, i64, i64);

struct Cached {
    key: Option<FileKey>,
    entries: Vec<LockEntry>,
}

fn cache() -> &'static Mutex<Option<Cached>> {
    static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn with_current_locks<T>(f: impl FnOnce(&[LockEntry]) -> T) -> Result<T> {
    let key = match fs::metadata(locks_file()) {
        Ok(md) => Some((md.dev(), md.ino(), md.len(), md.mtime(), md.mtime_nsec())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(PmError::Other(format!("stat locks: {e}"))),
    };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    let fresh = matches!(&*guard, Some(c) if c.key == key);
    if !fresh {
        let entries = if key.is_some() { load()? } else { Vec::new() };
        *guard = Some(Cached { key, entries });
    }
    let entries = &guard.as_ref().map(|c| c.entries.as_slice()).unwrap_or(&[]);
    Ok(f(entries))
}

/// Error out if `path` or any ancestor directory is locked.
///
/// Fail-closed: an unreadable lock list is an error, not an empty list. The
/// whole point of a lock is to stop a mutation, so "I could not tell" has to
/// stop it too.
pub fn ensure_not_locked(path: &Path) -> Result<()> {
    with_current_locks(|locks| {
        for l in locks {
            if path == l.path || path.starts_with(&l.path) {
                let r = if l.reason.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", l.reason)
                };
                return Err(PmError::Other(format!(
                    "path is locked by `janitor lock`: {}{r}",
                    l.path.display()
                )));
            }
        }
        Ok(())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn lock_record_round_trips_awkward_bytes() {
        let cases: &[&[u8]] = &[
            b"/srv/plain",
            b"/srv/a\tb",
            b"/srv/a\nb",
            b"/srv/back\\slash",
            b"/srv/caf\xe9",
            b"/srv/\xc4\x8desky",
            b"/srv/#hash",
            b"/srv/bell\x07",
        ];
        for c in cases {
            let e = LockEntry {
                path: PathBuf::from(OsStr::from_bytes(c)),
                reason: "why\tnot\nnow \\ then".into(),
            };
            let line = format_entry(&e);
            assert_eq!(line.matches('\t').count(), 1, "one separator in {line:?}");
            assert!(!line.contains('\n'), "no raw newline in {line:?}");
            let back = parse_entry(&line).expect("parses");
            assert_eq!(back.path, e.path, "path round-trip for {c:?}");
            assert_eq!(back.reason, e.reason, "reason round-trip for {c:?}");
        }
    }

    #[test]
    fn legacy_lock_lines_still_parse() {
        let back = parse_entry("/srv/old\told reason").unwrap();
        assert_eq!(back.path, PathBuf::from("/srv/old"));
        assert_eq!(back.reason, "old reason");
        let bare = parse_entry("/srv/bare").unwrap();
        assert_eq!(bare.path, PathBuf::from("/srv/bare"));
        assert_eq!(bare.reason, "");
        // A stray backslash from before escaping existed is kept as-is.
        let odd = parse_entry("/srv/a\\qb\t").unwrap();
        assert_eq!(odd.path, PathBuf::from("/srv/a\\qb"));
        assert!(parse_entry("# comment").is_none());
        assert!(parse_entry("   ").is_none());
    }

    #[test]
    fn readable_names_stay_readable_on_disk() {
        assert_eq!(escape_field("/srv/česky".as_bytes()), "/srv/česky");
        assert_eq!(escape_field(b"/srv/a\tb"), "/srv/a\\tb");
        assert_eq!(escape_field(b"\xff"), "\\xff");
    }
}
