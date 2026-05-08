//! Low-level mode/owner mutations (raw `chmod`/`lchown`), with no snapshotting.

use std::fs;
use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, Uid};

use crate::acl::restore_acl;
use crate::errors::{PmError, Result};
use crate::render::{paint, Style};
use crate::types::{AccessBits, SnapEntry};
use crate::users::{gid_to_name, lookup_group, uid_to_name};

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
        if !mode_diff && !uid_diff && !gid_diff {
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
        out.push(line);
    }
    out
}

/// Restore mode/uid/gid (and ACLs, if captured) from a snapshot.
/// Processes entries in reverse (leaves first) so that restoring a
/// parent's stricter perms doesn't block access to children we still
/// need to restore.
pub fn apply_restore(entries: &[SnapEntry], dry_run: bool) -> u32 {
    let mut errors = 0u32;
    for entry in entries.iter().rev() {
        let p = &entry.path;
        if p.symlink_metadata().is_err() {
            eprintln!("skip (missing): {}", p.display());
            continue;
        }
        let perm = entry.perm & 0o7777;
        let uid = entry.uid;
        let gid = entry.gid;

        if entry.is_symlink {
            if dry_run {
                // Preview already shows diffs; don't emit raw command lines.
            } else {
                // lchown: do NOT follow symlinks (unlike std::os::unix::fs::chown).
                use std::ffi::CString;
                use std::os::unix::ffi::OsStrExt;
                let c_path = match CString::new(p.as_os_str().as_bytes()) {
                    Ok(c) => c,
                    Err(_) => {
                        eprintln!("error: invalid path (NUL byte): {}", p.display());
                        errors += 1;
                        continue;
                    }
                };
                let ret = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
                if ret != 0 {
                    let e = std::io::Error::last_os_error();
                    eprintln!("error restoring ownership on {}: {e}", p.display());
                    errors += 1;
                }
            }
            continue;
        }

        if dry_run {
            // Preview already shows diffs; don't emit raw command lines.
        } else {
            let set_perms = || -> std::io::Result<()> {
                // Ownership first: chown clears setuid/setgid, so the
                // subsequent chmod re-applies them correctly.
                chown(p, Some(uid), Some(gid))?;
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
    chown(path, None::<u32>, Some(gid.as_raw())).map_err(|e| PmError::InsufficientPrivileges {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    // chmod (only if changed)
    if new_mode != current {
        fs::set_permissions(path, fs::Permissions::from_mode(new_mode)).map_err(|e| {
            PmError::InsufficientPrivileges {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })?;
    }

    Ok(())
}
