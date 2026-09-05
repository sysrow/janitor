//! POSIX ACL support.
//!
//! ACLs are *read* straight from the `system.posix_acl_access` and
//! `system.posix_acl_default` extended attributes and rendered in the
//! `getfacl -c` text form the rest of the crate speaks. A file without the
//! attribute carries exactly the ACL its mode bits imply, so the common case
//! costs one `lgetxattr` and no process spawn at all. Reading used to fork
//! `getfacl` once per path (twice per directory), which dominated every
//! recursive snapshot and made `who-can` unusable on large NSS databases.
//!
//! ACLs are *written* through `setfacl` (absolute path, argv only, ACL text
//! over stdin), matching the approach used for group management.

use std::ffi::{CStr, CString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use nix::unistd::{Gid, Uid};

use crate::errors::{PmError, Result};
use crate::users::{gid_to_name, uid_to_name};

const GETFACL: &str = "/usr/bin/getfacl";
const SETFACL: &str = "/usr/bin/setfacl";

const XATTR_ACCESS: &CStr = c"system.posix_acl_access";
const XATTR_DEFAULT: &CStr = c"system.posix_acl_default";

/// Return true if `setfacl` is installed, which every ACL *write* needs.
/// Reads no longer depend on the `acl` package. Memoised: this used to be
/// two `stat` calls on every ACL operation, per path.
pub fn acl_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| Path::new(SETFACL).exists())
}

// ── Reading: extended attributes ─────────────────────────────────────────

/// Outcome of one `lgetxattr` on an ACL attribute.
enum XattrRead {
    /// The attribute exists; the raw kernel payload.
    Data(Vec<u8>),
    /// No attribute: the object carries no ACL of that type.
    Absent,
    /// The filesystem (or a symlink) cannot hold ACLs at all.
    Unsupported,
    /// Anything else (EACCES, EIO, ...): the state is unknown.
    Error(std::io::Error),
}

fn read_xattr(path: &Path, name: &CStr) -> XattrRead {
    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            return XattrRead::Error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path contains a NUL byte",
            ))
        }
    };
    let classify = |e: std::io::Error| match e.raw_os_error() {
        Some(libc::ENODATA) => XattrRead::Absent,
        Some(n) if n == libc::ENOTSUP || n == libc::EOPNOTSUPP => XattrRead::Unsupported,
        _ => XattrRead::Error(e),
    };
    loop {
        // Size probe first, then the real read; retry if the attribute grew
        // in between.
        let len =
            unsafe { libc::lgetxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            return classify(std::io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len as usize];
        let got = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if got < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return classify(e);
        }
        buf.truncate(got as usize);
        return XattrRead::Data(buf);
    }
}

/// Check whether the filesystem backing `path` supports POSIX ACLs.
///
/// `ENOTSUP` / `EOPNOTSUPP` means no (overlayfs default, tmpfs on some
/// kernel configs, NFS mounted without the `acl` option, ...). `ENODATA`
/// means the filesystem supports ACLs and none is set, which is the common
/// case. Any other error means "cannot tell", and the caller lets the real
/// `setfacl` surface it.
///
/// This must be called *before* writing a backup so that unsupported
/// filesystems don't leave behind an orphaned snapshot (§3.11).
pub fn supports_acl(path: &Path) -> bool {
    !matches!(read_xattr(path, XATTR_ACCESS), XattrRead::Unsupported)
}

// Kernel layout of `system.posix_acl_*` (include/uapi/linux/posix_acl_xattr.h):
// a u32 version header followed by 8-byte entries {u16 tag, u16 perm, u32 id},
// all little-endian, entries sorted by tag as `getfacl` prints them.
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

fn perm_str(bits: u32) -> String {
    format!(
        "{}{}{}",
        if bits & 0o4 != 0 { 'r' } else { '-' },
        if bits & 0o2 != 0 { 'w' } else { '-' },
        if bits & 0o1 != 0 { 'x' } else { '-' }
    )
}

/// Render a kernel ACL payload in `getfacl -c` form. `None` if the payload
/// is not the version-2 layout, in which case the caller falls back to the
/// `getfacl` binary rather than guessing.
fn render_posix_acl_xattr(raw: &[u8]) -> Option<String> {
    if raw.len() < 4 || (raw.len() - 4) % 8 != 0 {
        return None;
    }
    let version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if version != POSIX_ACL_XATTR_VERSION {
        return None;
    }
    let mut lines: Vec<String> = Vec::new();
    for e in raw[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes([e[0], e[1]]);
        let bits = perm_str(u16::from_le_bytes([e[2], e[3]]) as u32 & 0o7);
        let id = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        let line = match tag {
            ACL_USER_OBJ => format!("user::{bits}"),
            ACL_USER => format!("user:{}:{bits}", uid_to_name(Uid::from_raw(id))),
            ACL_GROUP_OBJ => format!("group::{bits}"),
            ACL_GROUP => format!("group:{}:{bits}", gid_to_name(Gid::from_raw(id))),
            ACL_MASK => format!("mask::{bits}"),
            ACL_OTHER => format!("other::{bits}"),
            _ => return None,
        };
        lines.push(line);
    }
    if lines.is_empty() {
        return None;
    }
    Some(lines.join("\n"))
}

/// The ACL a file without an extended ACL has: its mode triads, exactly as
/// `getfacl -c` prints them.
pub fn base_acl_text(mode: u32) -> String {
    format!(
        "user::{}\ngroup::{}\nother::{}",
        perm_str((mode >> 6) & 0o7),
        perm_str((mode >> 3) & 0o7),
        perm_str(mode & 0o7)
    )
}

/// True when the text carries entries beyond the three base triads.
pub fn is_extended_text(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim();
        !(t.is_empty()
            || t.starts_with('#')
            || t.starts_with("user::")
            || t.starts_with("group::")
            || t.starts_with("other::"))
    })
}

fn stat_err(path: &Path, e: std::io::Error) -> PmError {
    PmError::Other(format!("stat {}: {e}", path.display()))
}

/// Legacy reader for the cases the attribute cannot answer: a symlink
/// operand (`getfacl` follows it, as every caller expected) or a payload in
/// a layout this crate does not know.
fn get_acl_via_getfacl(path: &Path, default: bool) -> Result<Option<String>> {
    if !Path::new(GETFACL).exists() {
        return Ok(None);
    }
    let flags: &[&str] = if default {
        &["-cd", "--absolute-names", "--"]
    } else {
        &["-c", "--absolute-names", "--"]
    };
    let out = Command::new(GETFACL)
        .args(flags)
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

/// Get the access ACL of a path in canonical (compact) form.
///
/// Fail-closed: an attribute that exists but cannot be read is an error,
/// never "no ACL". Silently turning it into the base triads would let a
/// mutation proceed with a backup that cannot restore the original ACL, and
/// let `explain` report a verdict the ACL contradicts.
pub fn get_acl(path: &Path) -> Result<Option<String>> {
    let md = fs::symlink_metadata(path).map_err(|e| stat_err(path, e))?;
    if md.file_type().is_symlink() {
        return get_acl_via_getfacl(path, false);
    }
    match read_xattr(path, XATTR_ACCESS) {
        XattrRead::Data(raw) => match render_posix_acl_xattr(&raw) {
            Some(text) => Ok(Some(text)),
            None => get_acl_via_getfacl(path, false),
        },
        XattrRead::Absent | XattrRead::Unsupported => Ok(Some(base_acl_text(md.mode() & 0o777))),
        XattrRead::Error(e) => Err(PmError::Other(format!(
            "read ACL of {}: {e}",
            path.display()
        ))),
    }
}

/// Get the default ACL of a directory (inherited by new children).
pub fn get_default_acl(path: &Path) -> Result<Option<String>> {
    let md = fs::symlink_metadata(path).map_err(|e| stat_err(path, e))?;
    if md.file_type().is_symlink() {
        return get_acl_via_getfacl(path, true);
    }
    if !md.is_dir() {
        return Ok(None);
    }
    match read_xattr(path, XATTR_DEFAULT) {
        XattrRead::Data(raw) => match render_posix_acl_xattr(&raw) {
            Some(text) => Ok(Some(text)),
            None => get_acl_via_getfacl(path, true),
        },
        XattrRead::Absent | XattrRead::Unsupported => Ok(None),
        XattrRead::Error(e) => Err(PmError::Other(format!(
            "read default ACL of {}: {e}",
            path.display()
        ))),
    }
}

/// Does the path carry ACL entries beyond its base mode? A directory with
/// only a default ACL counts too.
///
/// `None` means the question could not be answered (the attribute exists
/// but is unreadable); callers that scan for ACLs must report that rather
/// than treat it as "no".
pub fn has_extended_acl(path: &Path) -> Option<bool> {
    match read_xattr(path, XATTR_ACCESS) {
        XattrRead::Data(_) => return Some(true),
        XattrRead::Unsupported => return Some(false),
        XattrRead::Absent => {}
        XattrRead::Error(_) => return None,
    }
    let is_dir = fs::symlink_metadata(path).map(|m| m.is_dir()).ok()?;
    if !is_dir {
        return Some(false);
    }
    match read_xattr(path, XATTR_DEFAULT) {
        XattrRead::Data(_) => Some(true),
        XattrRead::Absent | XattrRead::Unsupported => Some(false),
        XattrRead::Error(_) => None,
    }
}

/// Read both ACLs of a path for comparison purposes.
/// Returns `(access, default)`; unreadable ACLs come back as `None`.
pub fn read_acl_pair(path: &Path) -> (Option<String>, Option<String>) {
    let access = get_acl(path).ok().flatten();
    let default = get_default_acl(path).ok().flatten();
    (access, default)
}

// ── Writing: setfacl ─────────────────────────────────────────────────────

fn need_setfacl() -> Result<()> {
    if acl_available() {
        Ok(())
    } else {
        Err(PmError::Other(
            "ACL support unavailable: install the 'acl' package (setfacl)".into(),
        ))
    }
}

/// Restore both access and default ACL from captured text.
///
/// Compares with the live state first: most entries of a recursive restore
/// still carry the ACL they had, and a `setfacl` spawn per path was the
/// expensive part. A directory whose snapshot recorded *no* default ACL has
/// any default ACL it gained since removed; `--set` on the access ACL alone
/// leaves the default ACL untouched, which is how `undo` after
/// `acl grant -d` used to report success and change nothing.
pub fn restore_acl(
    path: &Path,
    acl_text: Option<&str>,
    default_acl_text: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    let md = fs::symlink_metadata(path).map_err(|e| stat_err(path, e))?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    let current = get_acl(path)?;
    let acl_changed = acl_text.is_some() && acl_text_differs(acl_text, current.as_deref());
    let default_changed = md.is_dir() && {
        let live = get_default_acl(path)?;
        acl_text_differs(default_acl_text, live.as_deref())
    };
    if !acl_changed && !default_changed {
        return Ok(());
    }
    need_setfacl()?;
    if acl_changed {
        if let Some(text) = acl_text {
            apply_acl_text(path, text, false, dry_run)?;
        }
    }
    if default_changed {
        match default_acl_text {
            Some(text) => apply_acl_text(path, text, true, dry_run)?,
            None => remove_default_acl(path, dry_run)?,
        }
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

/// Remove a directory's default ACL: `setfacl -k`.
fn remove_default_acl(path: &Path, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("[dry-run] setfacl -k {}", path.display());
        return Ok(());
    }
    let status = Command::new(SETFACL)
        .args(["--physical", "-k", "--"])
        .arg(path)
        .status()
        .map_err(|e| PmError::Other(format!("setfacl: {e}")))?;
    if !status.success() {
        return Err(PmError::Other(format!(
            "setfacl -k failed on {}",
            path.display()
        )));
    }
    Ok(())
}

/// Modify ACL entries: `setfacl -m <spec>` (merge).
pub fn acl_modify(path: &Path, spec: &str, recursive: bool, dry_run: bool) -> Result<()> {
    need_setfacl()?;
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
    need_setfacl()?;
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
    need_setfacl()?;
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

// ── Comparison ───────────────────────────────────────────────────────────

/// Canonical form of an ACL text for comparison.
///
/// `getfacl` output is not stable enough to diff as a string: it carries
/// `# file:` headers, blank lines and `#effective:` annotations, and entry
/// order is not guaranteed. Strip the commentary and sort what is left, so
/// two ACLs compare equal exactly when they grant the same thing.
pub fn normalize_acl(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    lines.sort();
    lines.dedup();
    lines
}

/// True when two captured ACL texts describe different permissions.
/// `None` and an ACL that normalizes to nothing are treated as equal.
pub fn acl_text_differs(a: Option<&str>, b: Option<&str>) -> bool {
    let na = a.map(normalize_acl).unwrap_or_default();
    let nb = b.map(normalize_acl).unwrap_or_default();
    na != nb
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn entry(tag: u16, perm: u16, id: u32) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend_from_slice(&perm.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
        v
    }

    #[test]
    fn posix_acl_xattr_renders_like_getfacl() {
        let mut raw = POSIX_ACL_XATTR_VERSION.to_le_bytes().to_vec();
        raw.extend(entry(ACL_USER_OBJ, 6, u32::MAX));
        raw.extend(entry(ACL_USER, 4, 0));
        raw.extend(entry(ACL_GROUP_OBJ, 4, u32::MAX));
        raw.extend(entry(ACL_GROUP, 1, 0));
        raw.extend(entry(ACL_MASK, 5, u32::MAX));
        raw.extend(entry(ACL_OTHER, 0, u32::MAX));
        let text = render_posix_acl_xattr(&raw).unwrap();
        assert_eq!(
            text,
            "user::rw-\nuser:root:r--\ngroup::r--\ngroup:root:--x\nmask::r-x\nother::---"
        );
        assert!(is_extended_text(&text));
    }

    #[test]
    fn posix_acl_xattr_rejects_other_layouts() {
        assert!(render_posix_acl_xattr(&[]).is_none());
        assert!(render_posix_acl_xattr(&1u32.to_le_bytes()).is_none());
        let mut short = POSIX_ACL_XATTR_VERSION.to_le_bytes().to_vec();
        short.extend_from_slice(&[1, 0, 6]);
        assert!(render_posix_acl_xattr(&short).is_none());
        let mut unknown_tag = POSIX_ACL_XATTR_VERSION.to_le_bytes().to_vec();
        unknown_tag.extend(entry(0x40, 7, 0));
        assert!(render_posix_acl_xattr(&unknown_tag).is_none());
    }

    #[test]
    fn base_acl_matches_the_mode() {
        assert_eq!(base_acl_text(0o640), "user::rw-\ngroup::r--\nother::---");
        assert_eq!(base_acl_text(0o4755), "user::rwx\ngroup::r-x\nother::r-x");
        assert!(!is_extended_text(&base_acl_text(0o644)));
        assert!(!acl_text_differs(
            Some("user::rw-\ngroup::r--\t#effective:r--\nother::---"),
            Some(&base_acl_text(0o640))
        ));
    }

    #[test]
    fn plain_files_read_without_any_tooling() {
        let dir = std::env::temp_dir().join(format!("janitor-acl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("f");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o640)).unwrap();
        // tmpfs/ext4/overlay all answer ENODATA or ENOTSUP here; either way
        // the ACL is the mode.
        assert_eq!(
            get_acl(&f).unwrap().as_deref(),
            Some(base_acl_text(0o640).as_str())
        );
        assert_eq!(has_extended_acl(&f), Some(false));
        assert_eq!(get_default_acl(&dir).unwrap(), None);
        assert_eq!(has_extended_acl(&dir), Some(false));
        let link = dir.join("l");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert_eq!(has_extended_acl(&link), Some(false));
        let _ = fs::remove_dir_all(&dir);
    }
}
