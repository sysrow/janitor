//! Reading, writing, listing, and restoring MessagePack permission snapshots.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
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
    let file = File::create(&path)?;
    let mut writer = BufWriter::new(file);
    rmp_serde::encode::write_named(&mut writer, &payload)
        .map_err(|e| PmError::Other(format!("msgpack write: {e}")))?;
    let file = writer
        .into_inner()
        .map_err(|e| PmError::Other(format!("flush: {e}")))?;
    file.sync_all()?;
    Ok(bid)
}

/// Load a backup from disk by its ID.
/// Tries MessagePack first, falls back to legacy JSON.
pub fn load_backup(bid: &str) -> Result<Backup> {
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
