//! Walk a path (optionally recursively, optionally with ACLs) and record it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::acl::{acl_available, get_acl, get_default_acl, supports_acl};
use crate::errors::{PmError, Result};
use crate::types::SnapEntry;

/// Capture mode/uid/gid for each path. Does not follow symlinks.
#[allow(dead_code)]
pub fn snapshot(paths: &[impl AsRef<Path>]) -> Result<Vec<SnapEntry>> {
    snapshot_with_acl(paths, false)
}

/// Same as `snapshot`, plus optional ACL capture via `getfacl`.
///
/// Fail-closed: a path that cannot be stat'ed, or an ACL that cannot be read
/// on a filesystem that supports ACLs, aborts the whole snapshot. Callers
/// take a backup from this and then mutate, so a partial snapshot means a
/// mutation that cannot be reverted — the command must not get that far.
///
/// Filesystems without ACL support, and systems without `getfacl` installed,
/// are *not* failures: those entries are flagged `acl_unavailable` so restore
/// knows the ACL state was never captured rather than absent.
pub fn snapshot_with_acl(paths: &[impl AsRef<Path>], capture_acl: bool) -> Result<Vec<SnapEntry>> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let p = p.as_ref();
        let md = fs::symlink_metadata(p).map_err(|e| PmError::SnapshotFailed {
            path: p.to_path_buf(),
            reason: e.to_string(),
        })?;
        let mode = md.mode();
        let is_symlink = md.file_type().is_symlink();
        let is_dir = md.is_dir();
        let (acl, default_acl, acl_unavailable) = if capture_acl && !is_symlink {
            capture_acls(p, is_dir)?
        } else {
            (None, None, false)
        };
        out.push(SnapEntry {
            path: p.to_path_buf(),
            mode,
            perm: mode & 0o7777,
            uid: md.uid(),
            gid: md.gid(),
            is_symlink,
            is_dir,
            dev: md.dev(),
            ino: md.ino(),
            acl,
            default_acl,
            acl_unavailable,
            attrs: None,
        });
    }
    Ok(out)
}

/// Read the access and default ACL of `p`, or report that ACLs are not
/// obtainable here. Returns `(acl, default_acl, unavailable)`.
fn capture_acls(p: &Path, is_dir: bool) -> Result<(Option<String>, Option<String>, bool)> {
    if !acl_available() {
        warn_acl_tooling_missing();
        return Ok((None, None, true));
    }
    if !supports_acl(p) {
        // The filesystem cannot hold ACLs, so there is nothing to lose.
        return Ok((None, None, true));
    }
    let acl = get_acl(p).map_err(|e| PmError::SnapshotFailed {
        path: p.to_path_buf(),
        reason: e.to_string(),
    })?;
    let default_acl = if is_dir {
        get_default_acl(p).map_err(|e| PmError::SnapshotFailed {
            path: p.to_path_buf(),
            reason: e.to_string(),
        })?
    } else {
        None
    };
    Ok((acl, default_acl, false))
}

/// One warning per process, not one per path — a recursive snapshot would
/// otherwise bury the real output under thousands of identical lines.
fn warn_acl_tooling_missing() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "warning: getfacl/setfacl not installed; ACLs are not captured in this backup \
             (install the `acl` package)"
        );
    }
}
