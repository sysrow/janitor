//! Resolves the backup directory based on the effective UID and `$HOME`.

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
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::MetadataExt;
    let root = backup_root();
    // Refuse a symlink or a foreign directory in the final position.
    // `create_dir_all` accepts an existing symlink to a directory, and the
    // 0700 chmod below would then land on whatever it points at. With no
    // $HOME the fallback lives under the world-writable temp dir, where any
    // local user can plant such a link ahead of time.
    match fs::symlink_metadata(&root) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "backup directory {} is a symlink; refusing to use it",
                    root.display()
                ),
            ));
        }
        Ok(md) if !md.is_dir() => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("backup directory {} is not a directory", root.display()),
            ));
        }
        Ok(md) if md.uid() != geteuid().as_raw() => {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "backup directory {} is owned by uid {}, not by the current user (uid {})",
                    root.display(),
                    md.uid(),
                    geteuid().as_raw()
                ),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => fs::create_dir_all(&root)?,
        Err(e) => return Err(e),
    }
    // Harden backup directory: 0700 (owner only) to prevent backup injection.
    let md = fs::symlink_metadata(&root)?;
    if md.file_type().is_symlink() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "backup directory {} became a symlink; refusing to use it",
                root.display()
            ),
        ));
    }
    let mode = md.permissions().mode() & 0o777;
    if mode != 0o700 {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(root)
}
