//! POSIX ACL support via `getfacl` / `setfacl` shell-outs.
//!
//! We shell out (rather than using libacl bindings) to keep the dep surface
//! minimal and match the approach used for group management (`gpasswd`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::errors::{PmError, Result};

const GETFACL: &str = "/usr/bin/getfacl";
const SETFACL: &str = "/usr/bin/setfacl";

/// Return true if `setfacl` / `getfacl` binaries are installed.
pub fn acl_available() -> bool {
    Path::new(GETFACL).exists() && Path::new(SETFACL).exists()
}

/// Check whether the filesystem backing `path` supports POSIX ACLs.
///
/// Uses `lgetxattr(path, "system.posix_acl_access", NULL, 0)`:
///   * returns `ENOTSUP` / `EOPNOTSUPP` on filesystems without ACL
///     support (overlayfs default, tmpfs on some kernel configs, NFS
///     mounted without the `acl` option, …);
///   * returns `ENODATA` when the FS supports ACLs but no ACL is set —
///     this is the common case and means "yes";
///   * returns a non-negative length when an ACL is already present —
///     also "yes".
///
/// This must be called *before* writing a backup so that unsupported
/// filesystems don't leave behind an orphaned snapshot (§3.11).
pub fn supports_acl(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return true, // can't check — let setfacl fail loudly later
    };
    let c_name = c"system.posix_acl_access";
    let ret = unsafe { libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), std::ptr::null_mut(), 0) };
    if ret >= 0 {
        return true;
    }
    // On Linux, ENOTSUP and EOPNOTSUPP are the same errno value — the
    // second arm of an OR-pattern would be unreachable. On some other
    // Unixes they differ, so we still want to match both conceptually;
    // collapse to a single arm using equality to dodge the compiler
    // warning while remaining portable.
    let err = std::io::Error::last_os_error().raw_os_error();
    match err {
        Some(e) if e == libc::ENOTSUP || e == libc::EOPNOTSUPP => false,
        // ENODATA / ENOATTR: attribute absent, FS still supports ACLs.
        // Anything else (ENOENT, EACCES, …): can't tell — assume yes
        // and let the real setfacl surface the error.
        _ => true,
    }
}

/// Get the access ACL of a path in canonical (compact) form.
///
/// Returns `Ok(None)` when the ACL tooling is not installed or the path
/// carries only its base mode. A `getfacl` that runs but *fails* is an
/// error: silently turning it into "no ACL" would let a mutation proceed
/// with a backup that cannot restore the original ACL.
pub fn get_acl(path: &Path) -> Result<Option<String>> {
    if !acl_available() {
        return Ok(None);
    }
    // -c: no header, --absolute-names: don't strip leading /
    let out = Command::new(GETFACL)
        .args(["-c", "--absolute-names", "--"])
        .arg(path)
        .output()
        .map_err(|e| PmError::Other(format!("getfacl failed: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "getfacl {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

/// Get the default ACL of a directory (inherited by new children).
pub fn get_default_acl(path: &Path) -> Result<Option<String>> {
    if !acl_available() {
        return Ok(None);
    }
    let out = Command::new(GETFACL)
        .args(["-cd", "--absolute-names", "--"])
        .arg(path)
        .output()
        .map_err(|e| PmError::Other(format!("getfacl -d failed: {e}")))?;
    if !out.status.success() {
        return Err(PmError::Other(format!(
            "getfacl -d {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    // Filter out lines that aren't actual ACL entries.
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .collect();
    if lines.is_empty() {
        Ok(None)
    } else {
        Ok(Some(lines.join("\n")))
    }
}

/// Restore both access and default ACL from captured text.
/// Uses `setfacl --set-file=-` which replaces the ACL completely.
pub fn restore_acl(
    path: &Path,
    acl_text: Option<&str>,
    default_acl_text: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    if !acl_available() {
        return Ok(());
    }
    if let Some(text) = acl_text {
        apply_acl_text(path, text, false, dry_run)?;
    }
    if let Some(text) = default_acl_text {
        apply_acl_text(path, text, true, dry_run)?;
    }
    Ok(())
}

fn apply_acl_text(path: &Path, text: &str, is_default: bool, dry_run: bool) -> Result<()> {
    if dry_run {
        let tag = if is_default { "-d " } else { "" };
        println!("[dry-run] setfacl {tag}--set-file=- {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical"); // no follow symlinks
    if is_default {
        cmd.arg("-d");
    }
    cmd.arg("--set-file=-");
    cmd.arg("--");
    cmd.arg(path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| PmError::Other(format!("setfacl spawn: {e}")))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| PmError::Other("setfacl stdin".into()))?;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| PmError::Other(format!("setfacl write: {e}")))?;
        if !text.ends_with('\n') {
            stdin.write_all(b"\n").ok();
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| PmError::Other(format!("setfacl wait: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(PmError::Other(format!(
            "setfacl failed on {}: {}",
            path.display(),
            err.trim()
        )));
    }
    Ok(())
}

/// Modify ACL entries: `setfacl -m <spec>` (merge).
pub fn acl_modify(path: &Path, spec: &str, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-m {spec} {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-m", spec, "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -m {spec} failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Remove ACL entries: `setfacl -x <spec>` (entry removal).
pub fn acl_remove(path: &Path, spec: &str, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-x {spec} {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-x", spec, "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -x {spec} failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Strip all ACLs (keep only base mode).
pub fn acl_strip(path: &Path, recursive: bool, dry_run: bool) -> Result<()> {
    if !acl_available() {
        return Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package".into(),
        ));
    }
    if dry_run {
        let r = if recursive { "-R " } else { "" };
        println!("[dry-run] setfacl {r}-b {}", path.display());
        return Ok(());
    }
    let mut cmd = Command::new(SETFACL);
    cmd.arg("--physical");
    if recursive {
        cmd.arg("-R");
    }
    cmd.args(["-b", "--"]);
    cmd.arg(path);
    let status = cmd
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -b failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Check if a path has any non-trivial ACL entries beyond the base mode.
pub fn has_extended_acl(path: &Path) -> bool {
    match get_acl(path) {
        Ok(Some(text)) => text.lines().any(|l| {
            let t = l.trim();
            // Trivial entries are user::, group::, other::. Anything else = extended.
            if t.is_empty() || t.starts_with('#') {
                return false;
            }
            !(t.starts_with("user::") || t.starts_with("group::") || t.starts_with("other::"))
        }),
        _ => false,
    }
}
