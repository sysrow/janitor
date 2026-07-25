//! Persistent lock list: paths that janitor refuses to mutate.
//!
//! Stored as a newline-delimited file (`locks.txt`) in the backup directory.
//! Each line is `PATH\tREASON` (reason may be empty). A directory lock implies
//! every descendant is locked.

use crate::errors::{PmError, Result};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

fn locks_file() -> PathBuf {
    crate::config::backup_root().join("locks.txt")
}

#[derive(Debug, Clone)]
pub struct LockEntry {
    pub path: PathBuf,
    pub reason: String,
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
        let line = line.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (path, reason) = match line.split_once('\t') {
            Some((p, r)) => (p.to_string(), r.to_string()),
            None => (line, String::new()),
        };
        out.push(LockEntry {
            path: PathBuf::from(path),
            reason,
        });
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
        writeln!(f, "{}\t{}", e.path.display(), e.reason)
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

/// Error out if `path` or any ancestor directory is locked.
///
/// Fail-closed: an unreadable lock list is an error, not an empty list. The
/// whole point of a lock is to stop a mutation, so "I could not tell" has to
/// stop it too.
pub fn ensure_not_locked(path: &Path) -> Result<()> {
    let locks = load()?;
    for l in &locks {
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
}
