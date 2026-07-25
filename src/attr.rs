//! `attr`: thin wrapper around `chattr`/`lsattr` for immutable/append-only flags.

use crate::errors::{PmError, Result};
use crate::helpers::{resolve_path, resolve_path_nofollow};
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
    let out = Command::new("lsattr")
        .arg("-d")
        .arg(&p)
        .output()
        .map_err(|e| PmError::Other(format!("lsattr: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "lsattr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn chattr(path: &str, flag: &str) -> Result<()> {
    which("chattr")?;
    // Resolve once and hand the *same* PathBuf to both the lock check and
    // the subprocess: passing the raw argument through would let `~/f` pass
    // validation and then reach chattr as a literal tilde, and would open a
    // second window for the path to be swapped in between.
    let p = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&p)?;
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
}

pub fn cmd_attr_set_immutable(path: &str) -> Result<()> {
    chattr(path, "+i")
}
pub fn cmd_attr_clear_immutable(path: &str) -> Result<()> {
    chattr(path, "-i")
}
pub fn cmd_attr_set_append(path: &str) -> Result<()> {
    chattr(path, "+a")
}
pub fn cmd_attr_clear_append(path: &str) -> Result<()> {
    chattr(path, "-a")
}
