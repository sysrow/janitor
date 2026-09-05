//! `acl` subcommands: grant, revoke, strip, show (as a standalone facility
//! on top of `setfacl` / `getfacl`).

use crate::acl::{acl_modify, acl_remove, acl_strip, get_acl, get_default_acl, supports_acl};
use crate::backup::save_backup;
use crate::errors::{PmError, Result};
use crate::helpers::{parse_access, resolve_path_nofollow};
use crate::locking::with_lock;
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use crate::users::{lookup_group, lookup_user};
use std::path::{Path, PathBuf};

/// Collect every path an ACL command will touch, refusing the whole operation
/// if any of them is locked.
///
/// `setfacl -R` rewrites descendants, so checking only the root would let a
/// recursive call walk straight over an explicitly locked child. The walk is
/// fail-closed for the same reason the snapshot is: a subtree we cannot
/// enumerate is a subtree we cannot back up.
fn collect_acl_targets(target: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut paths = vec![target.to_path_buf()];
    let is_dir = std::fs::symlink_metadata(target)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if recursive && is_dir {
        for entry in walkdir::WalkDir::new(target)
            .min_depth(1)
            .follow_links(false)
        {
            let entry = entry
                .map_err(|e| PmError::Other(format!("cannot walk {}: {e}", target.display())))?;
            paths.push(entry.into_path());
        }
    }
    for p in &paths {
        crate::locks::ensure_not_locked(p)?;
    }
    Ok(paths)
}

/// `acl grant --user|--group PATH --access rwx [--default] [--recursive]`
pub fn cmd_acl_grant(
    user: Option<&str>,
    group: Option<&str>,
    path: &str,
    access: &str,
    default_acl: bool,
    recursive: bool,
    dry_run: bool,
) -> Result<()> {
    if user.is_none() && group.is_none() {
        return Err(PmError::NoUserOrGroup);
    }
    let target = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&target)?;
    if !supports_acl(&target) {
        return Err(PmError::AclUnsupported { path: target });
    }
    let bits = parse_access(access)?;
    let perm_str = format_perms(bits.0);

    let mut spec_parts: Vec<String> = Vec::new();
    if default_acl {
        spec_parts.push("d".into());
    }
    if let Some(u) = user {
        lookup_user(u)?;
        spec_parts.push(format!("u:{u}:{perm_str}"));
    }
    if let Some(g) = group {
        lookup_group(g)?;
        let mut s = String::new();
        if default_acl {
            s.push_str("d:");
        }
        s.push_str(&format!("g:{g}:{perm_str}"));
        spec_parts.push(s);
    }
    // If both user+group, and default_acl true, the first "d" is redundant; rebuild cleanly.
    let specs: Vec<String> = build_specs(user, group, &perm_str, default_acl);

    // Snapshot first.
    let paths = collect_acl_targets(&target, recursive)?;

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, true)?;
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "acl-grant".into(),
                    user: user.map(String::from),
                    group: group.map(String::from),
                    explicit_group: None,
                    target: Some(target.display().to_string()),
                    access: Some(access.to_string()),
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                    group_created: false,
                    user_added: false,
                    user_removed: false,
                },
            )?;
            println!("backup: {bid}");
        }
        for spec in &specs {
            acl_modify(&target, spec, recursive, dry_run)?;
        }
        Ok(())
    })
}

/// `acl revoke --user|--group PATH [--default] [--recursive]`
pub fn cmd_acl_revoke(
    user: Option<&str>,
    group: Option<&str>,
    path: &str,
    default_acl: bool,
    recursive: bool,
    dry_run: bool,
) -> Result<()> {
    if user.is_none() && group.is_none() {
        return Err(PmError::NoUserOrGroup);
    }
    let target = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&target)?;
    if !supports_acl(&target) {
        return Err(PmError::AclUnsupported { path: target });
    }
    let specs = build_remove_specs(user, group, default_acl);

    let paths = collect_acl_targets(&target, recursive)?;

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, true)?;
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "acl-revoke".into(),
                    user: user.map(String::from),
                    group: group.map(String::from),
                    explicit_group: None,
                    target: Some(target.display().to_string()),
                    access: None,
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                    group_created: false,
                    user_added: false,
                    user_removed: false,
                },
            )?;
            println!("backup: {bid}");
        }
        for spec in &specs {
            acl_remove(&target, spec, recursive, dry_run)?;
        }
        Ok(())
    })
}

/// `acl strip PATH [--recursive]`: remove all ACLs.
pub fn cmd_acl_strip(path: &str, recursive: bool, dry_run: bool) -> Result<()> {
    let target = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&target)?;
    if !supports_acl(&target) {
        return Err(PmError::AclUnsupported { path: target });
    }
    let paths = collect_acl_targets(&target, recursive)?;

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, true)?;
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "acl-strip".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(target.display().to_string()),
                    access: None,
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                    group_created: false,
                    user_added: false,
                    user_removed: false,
                },
            )?;
            println!("backup: {bid}");
        }
        acl_strip(&target, recursive, dry_run)?;
        Ok(())
    })
}

/// `acl show PATH`: print both access and default ACL.
pub fn cmd_acl_show(path: &str) -> Result<()> {
    let target = resolve_path_nofollow(path)?;
    println!("# path: {}", target.display());
    match get_acl(&target)? {
        Some(a) => println!("{a}"),
        None => println!("(no access ACL)"),
    }
    if target.is_dir() {
        match get_default_acl(&target)? {
            Some(d) if !d.is_empty() => {
                println!("# default:");
                println!("{d}");
            }
            _ => {}
        }
    }
    Ok(())
}

fn format_perms(bits: u32) -> String {
    let mut s = String::new();
    s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
    s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
    s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    s
}

fn build_specs(
    user: Option<&str>,
    group: Option<&str>,
    perm_str: &str,
    default_acl: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let d = if default_acl { "d:" } else { "" };
    if let Some(u) = user {
        out.push(format!("{d}u:{u}:{perm_str}"));
    }
    if let Some(g) = group {
        out.push(format!("{d}g:{g}:{perm_str}"));
    }
    out
}

fn build_remove_specs(user: Option<&str>, group: Option<&str>, default_acl: bool) -> Vec<String> {
    let mut out = Vec::new();
    let d = if default_acl { "d:" } else { "" };
    if let Some(u) = user {
        out.push(format!("{d}u:{u}"));
    }
    if let Some(g) = group {
        out.push(format!("{d}g:{g}"));
    }
    out
}
