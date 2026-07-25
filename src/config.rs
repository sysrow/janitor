//! Resolves the backup directory based on effective UID and `XDG_DATA_HOME`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use nix::unistd::geteuid;

/// Where to put backups. System-wide if root, per-user otherwise.
///
/// With no `$HOME`, fall back to the account's passwd entry, and only then
/// to a UID-qualified directory under the temp dir. A bare `/tmp/.local/...`
/// would be shared by every HOME-less user on the box: whoever created it
/// first would own everyone else's backups, and the others would just fail.
pub fn backup_root() -> PathBuf {
    if geteuid().is_root() {
        return PathBuf::from("/var/lib/janitor/backups");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .or_else(|| {
            nix::unistd::User::from_uid(geteuid())
                .ok()
                .flatten()
                .map(|u| u.dir)
        })
        .unwrap_or_else(|| std::env::temp_dir().join(format!("janitor-{}", geteuid().as_raw())));
    home.join(".local/share/janitor/backups")
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
