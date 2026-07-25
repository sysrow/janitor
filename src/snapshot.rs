//! Walk a path (optionally recursively, optionally with ACLs) and record it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::acl::{get_acl, get_default_acl};
use crate::types::SnapEntry;

/// Capture mode/uid/gid for each path. Does not follow symlinks.
pub fn snapshot(paths: &[impl AsRef<Path>]) -> Vec<SnapEntry> {
    snapshot_with_acl(paths, false)
}

/// Same as `snapshot`, plus optional ACL capture via `getfacl`.
pub fn snapshot_with_acl(paths: &[impl AsRef<Path>], capture_acl: bool) -> Vec<SnapEntry> {
    paths
        .iter()
        .filter_map(|p| {
            let p = p.as_ref();
            let md = fs::symlink_metadata(p).ok()?;
            let mode = md.mode();
            let is_symlink = md.file_type().is_symlink();
            let is_dir = md.is_dir();
            let (acl, default_acl) = if capture_acl && !is_symlink {
                let a = get_acl(p).ok().flatten();
                let d = if is_dir {
                    get_default_acl(p).ok().flatten()
                } else {
                    None
                };
                (a, d)
            } else {
                (None, None)
            };
            Some(SnapEntry {
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
            })
        })
        .collect()
}
