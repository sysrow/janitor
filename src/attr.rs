//! `attr`: thin wrapper around `chattr`/`lsattr` for immutable/append-only flags.

use crate::backup::save_backup;
use crate::errors::{PmError, Result};
use crate::helpers::{resolve_path, resolve_path_nofollow};
use crate::locking::with_lock;
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use std::path::Path;
use std::process::Command;

fn which(cmd: &str) -> Result<()> {
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(PmError::Other(format!(
            "`{cmd}` not found; install `e2fsprogs` (provides chattr/lsattr)"
        ))),
    }
}

pub fn cmd_attr_show(path: &str) -> Result<()> {
    which("lsattr")?;
    let p = resolve_path(path)?;
    print!("{}", read_attrs(&p)?);
    Ok(())
}

/// Raw `lsattr -d` output for one path.
fn read_attrs(p: &Path) -> Result<String> {
    let out = Command::new("lsattr")
        .arg("-d")
        .arg(p)
        .output()
        .map_err(|e| PmError::Other(format!("lsattr: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "lsattr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Set or clear an inode flag.
///
/// Wrapped like every other mutation: honours `--dry-run`, records a
/// snapshot first, and runs under the global lock. It previously did none
/// of those — `--dry-run attr set-immutable` really ran chattr, and the
/// change could not be reverted with `janitor undo` at all.
fn chattr(path: &str, flag: &str, dry_run: bool) -> Result<()> {
    which("chattr")?;
    // Resolve once and hand the *same* PathBuf to the lock check, the
    // snapshot and the subprocess: passing the raw argument through would
    // let `~/f` pass validation and then reach chattr as a literal tilde,
    // and would open a second window for the path to be swapped in between.
    let p = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&p)?;

    if dry_run {
        println!("[dry-run] chattr {flag} {}", p.display());
        return Ok(());
    }

    with_lock(|| {
        let mut snap = snapshot_with_acl(std::slice::from_ref(&p), true)?;
        // Record the current flags so `restore` can report (and a human can
        // see) what they were; chattr state itself is reapplied by hand.
        let attrs = read_attrs(&p).unwrap_or_default().trim().to_string();
        for e in &mut snap {
            e.attrs = Some(attrs.clone());
        }
        let bid = save_backup(
            snap,
            Operation {
                op_type: "attr".into(),
                user: None,
                group: None,
                explicit_group: None,
                target: Some(p.display().to_string()),
                access: Some(flag.to_string()),
                max_level: None,
                recursive: Some(false),
                parent_op: None,
                group_created: false,
                user_added: false,
            },
        )?;
        println!("backup: {bid}");

        let out = Command::new("chattr")
            .arg(flag)
            .arg(&p)
            .output()
            .map_err(|e| PmError::Other(format!("chattr: {e}")))?;
        if !out.status.success() {
            return Err(PmError::Other(format!(
                "chattr {flag} {}: {}",
                p.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        println!("chattr {flag} {}", p.display());
        Ok(())
    })
}

pub fn cmd_attr_set_immutable(path: &str, dry_run: bool) -> Result<()> {
    chattr(path, "+i", dry_run)
}
pub fn cmd_attr_clear_immutable(path: &str, dry_run: bool) -> Result<()> {
    chattr(path, "-i", dry_run)
}
pub fn cmd_attr_set_append(path: &str, dry_run: bool) -> Result<()> {
    chattr(path, "+a", dry_run)
}
pub fn cmd_attr_clear_append(path: &str, dry_run: bool) -> Result<()> {
    chattr(path, "-a", dry_run)
}
