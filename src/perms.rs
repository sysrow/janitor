//! Low-level mode/owner mutations (raw `chmod`/`lchown`), with no snapshotting.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, Uid};

use crate::acl::{acl_text_differs, read_acl_pair, restore_acl};
use crate::errors::{PmError, Result};
use crate::render::{paint, Style};
use crate::types::{AccessBits, SnapEntry};
use crate::users::{gid_to_name, lookup_group, uid_to_name};

/// `lchown(2)`: change ownership without ever following a symlink, unlike
/// `std::os::unix::fs::chown`. `None` leaves that id untouched.
pub fn lchown(path: &Path, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let u = uid.unwrap_or(u32::MAX); // -1 = don't change
    let g = gid.unwrap_or(u32::MAX);
    if unsafe { libc::lchown(c_path.as_ptr(), u, g) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Build a human-readable diff preview: current-vs-recorded lines. Skips
/// entries whose live state already matches the snapshot.
pub fn preview_restore(entries: &[SnapEntry]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in entries {
        let md = match fs::symlink_metadata(&e.path) {
            Ok(m) => m,
            Err(_) => {
                out.push(format!(
                    "{}  {}",
                    paint(Style::Danger, "missing"),
                    e.path.display()
                ));
                continue;
            }
        };
        let cur_mode = md.mode() & 0o7777;
        let cur_uid = md.uid();
        let cur_gid = md.gid();
        let rec_mode = e.perm & 0o7777;
        let mode_diff = cur_mode != rec_mode && !e.is_symlink;
        let uid_diff = cur_uid != e.uid;
        let gid_diff = cur_gid != e.gid;
        // ACLs have to be part of the preview, not just of the apply. The
        // caller gates its confirmation prompt (and its refusal to run
        // unattended without --yes) on this list being non-empty, so an
        // ACL-only restore used to slip through both.
        let acl_diff = if e.acl.is_some() || e.default_acl.is_some() {
            let (cur_acl, cur_default) = read_acl_pair(&e.path);
            acl_text_differs(e.acl.as_deref(), cur_acl.as_deref())
                || acl_text_differs(e.default_acl.as_deref(), cur_default.as_deref())
        } else {
            false
        };
        if !mode_diff && !uid_diff && !gid_diff && !acl_diff {
            continue;
        }
        let mut line = format!("  {}", paint(Style::Primary, &e.path.display().to_string()));
        if mode_diff {
            line.push_str(&format!(
                "\n      mode   {:04o} {} {:04o}",
                cur_mode,
                paint(Style::Separator, "→"),
                rec_mode
            ));
        }
        if uid_diff || gid_diff {
            let cu = uid_to_name(Uid::from_raw(cur_uid));
            let cg = gid_to_name(Gid::from_raw(cur_gid));
            let ru = uid_to_name(Uid::from_raw(e.uid));
            let rg = gid_to_name(Gid::from_raw(e.gid));
            line.push_str(&format!(
                "\n      owner  {}:{}  {}  {}:{}",
                paint(Style::User, &cu),
                paint(Style::Group, &cg),
                paint(Style::Separator, "→"),
                paint(Style::User, &ru),
                paint(Style::Group, &rg)
            ));
        }
        if acl_diff {
            line.push_str(&format!(
                "\n      acl    {}",
                paint(Style::Label, "differs from snapshot")
            ));
        }
        out.push(line);
    }
    out
}

/// Describe why the live path no longer matches what the snapshot recorded.
///
/// Restoring metadata onto an entry that was swapped out since the snapshot
/// was taken would apply the recorded mode/owner to whatever now sits at that
/// path — a symlink or hard link planted by whoever controls the parent
/// directory. Both are privilege-escalation primitives when janitor runs as
/// root, so any drift aborts that entry instead.
fn entry_drift(entry: &SnapEntry, md: &fs::Metadata) -> Option<String> {
    let now_symlink = md.file_type().is_symlink();
    if now_symlink != entry.is_symlink {
        return Some(format!(
            "type changed since the snapshot ({} → {})",
            kind_word(entry.is_symlink, entry.is_dir),
            kind_word(now_symlink, md.is_dir())
        ));
    }
    if !now_symlink && md.is_dir() != entry.is_dir {
        return Some(format!(
            "type changed since the snapshot ({} → {})",
            kind_word(entry.is_symlink, entry.is_dir),
            kind_word(now_symlink, md.is_dir())
        ));
    }
    // Backups written before identity capture store zeroes; there is nothing
    // to compare against, so the type check above is all we can enforce.
    if entry.dev == 0 && entry.ino == 0 {
        return None;
    }
    if md.dev() != entry.dev || md.ino() != entry.ino {
        return Some("inode changed since the snapshot (path was replaced)".to_string());
    }
    None
}

fn kind_word(is_symlink: bool, is_dir: bool) -> &'static str {
    if is_symlink {
        "symlink"
    } else if is_dir {
        "directory"
    } else {
        "file"
    }
}

/// Restore mode/uid/gid (and ACLs, if captured) from a snapshot.
///
/// Processes entries in reverse (leaves first) so that restoring a
/// parent's stricter perms doesn't block access to children we still
/// need to restore.
///
/// Entries whose live inode no longer matches the snapshot are refused (see
/// [`entry_drift`]). Missing paths count as errors unless `skip_missing`.
pub fn apply_restore(entries: &[SnapEntry], dry_run: bool, skip_missing: bool) -> u32 {
    let mut errors = 0u32;
    for entry in entries.iter().rev() {
        let p = &entry.path;
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => {
                if skip_missing {
                    eprintln!("skip (missing): {}", p.display());
                } else {
                    eprintln!(
                        "error: {} is gone since the snapshot  (use --skip-missing to ignore)",
                        p.display()
                    );
                    errors += 1;
                }
                continue;
            }
        };
        if let Some(reason) = entry_drift(entry, &md) {
            eprintln!("error: refusing to restore {}: {reason}", p.display());
            errors += 1;
            continue;
        }
        let perm = entry.perm & 0o7777;
        let uid = entry.uid;
        let gid = entry.gid;

        if entry.is_symlink {
            if dry_run {
                // Preview already shows diffs; don't emit raw command lines.
            } else if let Err(e) = lchown(p, Some(uid), Some(gid)) {
                eprintln!("error restoring ownership on {}: {e}", p.display());
                errors += 1;
            }
            continue;
        }

        if dry_run {
            // Preview already shows diffs; don't emit raw command lines.
        } else {
            let set_perms = || -> std::io::Result<()> {
                // Ownership first: chown clears setuid/setgid, so the
                // subsequent chmod re-applies them correctly. lchown is used
                // even though the entry is not a symlink, so that a path
                // swapped between the check above and here still cannot
                // redirect the ownership change to another inode.
                lchown(p, Some(uid), Some(gid))?;
                fs::set_permissions(p, fs::Permissions::from_mode(perm))?;
                // Rust's set_permissions may drop bits above 0o777 on
                // some versions; re-apply via raw libc::chmod.
                if perm & 0o7000 != 0 {
                    use std::ffi::CString;
                    use std::os::unix::ffi::OsStrExt;
                    let c_path = CString::new(p.as_os_str().as_bytes())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                    let rc = unsafe { libc::chmod(c_path.as_ptr(), perm as libc::mode_t) };
                    if rc != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            };
            if let Err(e) = set_perms() {
                eprintln!("error restoring {}: {e}", p.display());
                errors += 1;
            }
        }

        // Restore ACLs if captured. Do this AFTER chmod, since chmod can
        // rewrite the mask and drop ACL entries.
        if entry.acl.is_some() || entry.default_acl.is_some() {
            if let Err(e) = restore_acl(
                p,
                entry.acl.as_deref(),
                entry.default_acl.as_deref(),
                dry_run,
            ) {
                eprintln!("error restoring ACL on {}: {e}", p.display());
                errors += 1;
            }
        }
    }
    errors
}

/// chgrp + set group permission triad on a path.
///
/// If `replace` is true, group triad is set to exactly `add_bits`
/// (used on parent dirs; strips any pre-existing group read/write).
///
/// If `replace` is false, `add_bits` is OR-ed into existing triad
/// (used on the target itself).
///
/// Never touches user or other bits. If path is a directory and we're
/// adding `r`, forces `x` on too.
pub fn apply_group_bits(
    path: &Path,
    group: &str,
    add_bits: AccessBits,
    dry_run: bool,
    replace: bool,
) -> Result<()> {
    let md = fs::symlink_metadata(path).map_err(|e| PmError::InsufficientPrivileges {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    if md.file_type().is_symlink() {
        return Ok(()); // never chmod symlinks
    }

    let current = md.mode() & 0o7777;
    let existing_group_triad = (current & 0o070) >> 3;

    let new_triad = if replace {
        add_bits.0
    } else {
        existing_group_triad | add_bits.0
    };

    // If directory and adding read, force exec too (listing without traversal is useless).
    let new_triad = if md.is_dir() && (add_bits.0 & 0o4 != 0) {
        new_triad | 0o1
    } else {
        new_triad
    };

    let new_mode = (current & !0o070) | (new_triad << 3);

    if dry_run {
        // Narration (✓ would chgrp / ✓ would chmod) in commands.rs covers this.
        return Ok(());
    }

    let gid = lookup_group(group)?.gid;

    // chgrp
    lchown(path, None, Some(gid.as_raw())).map_err(|e| PmError::InsufficientPrivileges {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    // chmod unconditionally, even when new_mode == current. `new_mode` was
    // computed from the mode read *before* the chgrp above, and chown clears
    // setuid/setgid on executables — so skipping the chmod when nothing
    // "changed" is exactly the case that silently drops those bits.
    fs::set_permissions(path, fs::Permissions::from_mode(new_mode)).map_err(|e| {
        PmError::InsufficientPrivileges {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }
    })?;
    // set_permissions can drop bits above 0o777 on some std versions.
    if new_mode & 0o7000 != 0 {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| PmError::Other(format!("invalid path: {e}")))?;
        if unsafe { libc::chmod(c_path.as_ptr(), new_mode as libc::mode_t) } != 0 {
            return Err(PmError::InsufficientPrivileges {
                path: path.to_path_buf(),
                reason: std::io::Error::last_os_error().to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_for(path: &Path) -> SnapEntry {
        let md = fs::symlink_metadata(path).unwrap();
        SnapEntry {
            path: path.to_path_buf(),
            mode: md.mode(),
            perm: md.mode() & 0o7777,
            uid: md.uid(),
            gid: md.gid(),
            is_symlink: md.file_type().is_symlink(),
            is_dir: md.is_dir(),
            dev: md.dev(),
            ino: md.ino(),
            acl: None,
            default_acl: None,
            acl_unavailable: false,
            attrs: None,
        }
    }

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("janitor-perms-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Scratch(p.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn drift_none_when_inode_unchanged() {
        let s = Scratch::new("same");
        let f = s.0.join("f");
        fs::write(&f, b"x").unwrap();
        let e = entry_for(&f);
        assert!(entry_drift(&e, &fs::symlink_metadata(&f).unwrap()).is_none());
    }

    /// §C-01: the recorded file was swapped for a symlink. Restoring would
    /// chown/chmod whatever the link points at, so it must be refused.
    #[test]
    fn drift_detects_file_replaced_by_symlink() {
        let s = Scratch::new("swap");
        let f = s.0.join("f");
        fs::write(&f, b"x").unwrap();
        let e = entry_for(&f);

        fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink(s.0.join("victim"), &f).unwrap();

        let drift = entry_drift(&e, &fs::symlink_metadata(&f).unwrap());
        assert!(drift.unwrap().contains("type changed"));
    }

    /// Same type, different inode: a hard link swap is just as exploitable
    /// as a symlink swap when janitor runs as root.
    #[test]
    fn drift_detects_replaced_inode() {
        let s = Scratch::new("relink");
        let f = s.0.join("f");
        fs::write(&f, b"x").unwrap();
        let e = entry_for(&f);
        replace_with_fresh_inode(&s.0, &f);

        let drift = entry_drift(&e, &fs::symlink_metadata(&f).unwrap());
        assert!(drift.unwrap().contains("inode changed"));
    }

    /// Rename a *concurrently existing* file over `f`, so the replacement is
    /// guaranteed a different inode number (a plain remove+create often
    /// recycles the just-freed one on tmpfs).
    fn replace_with_fresh_inode(dir: &Path, f: &Path) {
        let other = dir.join("other");
        fs::write(&other, b"y").unwrap();
        fs::remove_file(f).unwrap();
        fs::rename(&other, f).unwrap();
    }

    /// Backups written before identity capture carry zeroes; those must
    /// still restore, guarded by the file-type check alone.
    #[test]
    fn drift_skips_identity_check_for_legacy_entries() {
        let s = Scratch::new("legacy");
        let f = s.0.join("f");
        fs::write(&f, b"x").unwrap();
        let mut e = entry_for(&f);
        e.dev = 0;
        e.ino = 0;
        replace_with_fresh_inode(&s.0, &f);

        assert!(entry_drift(&e, &fs::symlink_metadata(&f).unwrap()).is_none());
    }

    #[test]
    fn drift_detects_file_replaced_by_directory() {
        let s = Scratch::new("dir");
        let f = s.0.join("f");
        fs::write(&f, b"x").unwrap();
        let e = entry_for(&f);

        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();

        let drift = entry_drift(&e, &fs::symlink_metadata(&f).unwrap());
        assert!(drift.unwrap().contains("type changed"));
    }
}
