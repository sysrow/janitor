//! Reading, writing, listing, and restoring MessagePack permission snapshots.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use chrono::Local;
use uuid::Uuid;

use crate::config::{backup_root, ensure_backup_root};
use crate::errors::{PmError, Result};
use crate::types::{Backup, Operation, SnapEntry};

const EXT: &str = "mpk";

/// Save a backup to disk in MessagePack format. Returns the backup ID.
pub fn save_backup(entries: Vec<SnapEntry>, operation: Operation) -> Result<String> {
    let root = ensure_backup_root()?;
    let ts = Local::now();
    let bid = format!(
        "{}-{}",
        ts.format("%Y%m%d-%H%M%S"),
        &Uuid::new_v4().to_string()[..8]
    );
    let path = root.join(format!("{bid}.{EXT}"));
    let payload = Backup {
        id: bid.clone(),
        timestamp: ts.to_rfc3339(),
        operation,
        entries,
    };
    // Write to a temp file and rename into place. Writing straight to the
    // final name meant an interrupted write left a truncated .mpk sitting
    // there as the newest backup — exactly the one `undo` would pick up.
    let tmp = root.join(format!(".{bid}.{EXT}.tmp"));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    let mut writer = BufWriter::new(file);
    let write_result = rmp_serde::encode::write_named(&mut writer, &payload)
        .map_err(|e| PmError::Other(format!("msgpack write: {e}")));
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let file = writer.into_inner().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        PmError::Other(format!("flush: {e}"))
    })?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        PmError::Other(format!("rename backup: {e}"))
    })?;
    // fsync the directory so the rename itself survives a crash.
    if let Ok(d) = File::open(&root) {
        let _ = d.sync_all();
    }
    Ok(bid)
}

/// Reject anything that is not a backup id janitor itself generated.
///
/// `load_backup` used to interpolate the argument straight into a path, so
/// `restore ../../tmp/evil` happily loaded and applied a payload from
/// outside the backup directory — with whatever paths the payload named.
fn validate_backup_id(bid: &str) -> Result<()> {
    // Generated form: YYYYMMDD-HHMMSS-<8 hex>.
    let ok = bid.len() == 24
        && bid.as_bytes()[8] == b'-'
        && bid.as_bytes()[15] == b'-'
        && bid[..8].bytes().all(|c| c.is_ascii_digit())
        && bid[9..15].bytes().all(|c| c.is_ascii_digit())
        && bid[16..].bytes().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(PmError::Other(format!(
            "invalid backup id {bid:?}  (expected YYYYMMDD-HHMMSS-XXXXXXXX; \
             see `janitor list-backups`)"
        )));
    }
    Ok(())
}

/// True for ids janitor itself generated; `undo` uses it to skip files a
/// human dropped into the backup directory.
pub fn is_valid_backup_id(bid: &str) -> bool {
    validate_backup_id(bid).is_ok()
}

/// Load a backup from disk by its ID.
/// Tries MessagePack first, falls back to legacy JSON.
pub fn load_backup(bid: &str) -> Result<Backup> {
    validate_backup_id(bid)?;
    let root = backup_root();
    // Try .mpk first, then .json (legacy).
    let mpk = root.join(format!("{bid}.{EXT}"));
    let json = root.join(format!("{bid}.json"));
    let (path, is_mpk) = if mpk.exists() {
        (mpk, true)
    } else if json.exists() {
        (json, false)
    } else {
        return Err(PmError::BackupNotFound(bid.to_string()));
    };
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    if is_mpk {
        rmp_serde::from_read(reader)
            .map_err(|e| PmError::Other(format!("msgpack read {}: {e}", path.display())))
    } else {
        serde_json::from_reader(reader).map_err(Into::into)
    }
}

/// List all backup files sorted by name (.mpk and legacy .json).
pub fn list_backup_files() -> Result<Vec<PathBuf>> {
    let root = ensure_backup_root()?;
    let mut files: Vec<PathBuf> = fs::read_dir(&root)?
        .filter_map(|e| {
            let e = e.ok()?;
            let p = e.path();
            let ext = p.extension().and_then(|e| e.to_str())?;
            if ext == EXT || ext == "json" {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    files.sort();
    Ok(files)
}
