//! Resolves the backup directory based on effective UID and `XDG_DATA_HOME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use nix::unistd::geteuid;

/// Where to put backups. System-wide if root, per-user otherwise.
pub fn backup_root() -> PathBuf {
    if geteuid().is_root() {
        PathBuf::from("/var/lib/janitor/backups")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join(".local/share/janitor/backups")
    }
}

pub fn ensure_backup_root() -> std::io::Result<PathBuf> {
    let root = backup_root();
    fs::create_dir_all(&root)?;
    // Harden backup directory: 0700 (owner only) to prevent backup injection.
    let md = fs::symlink_metadata(&root)?;
    let mode = md.permissions().mode() & 0o777;
    if mode != 0o700 {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(root)
}
