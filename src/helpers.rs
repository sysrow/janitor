//! Small path utilities shared across commands.

use std::path::{Path, PathBuf};

use crate::errors::{PmError, Result};
use crate::types::AccessBits;

/// Parse "r", "rw", "rx", "rwx" etc. into permission bits (0..7).
pub fn parse_access(s: &str) -> Result<AccessBits> {
    let s = s.to_lowercase();
    if s.is_empty() || s.chars().any(|c| !matches!(c, 'r' | 'w' | 'x')) {
        return Err(PmError::BadAccess(s));
    }
    let mut bits: u32 = 0;
    if s.contains('r') {
        bits |= 0o4;
    }
    if s.contains('w') {
        bits |= 0o2;
    }
    if s.contains('x') {
        bits |= 0o1;
    }
    Ok(AccessBits(bits))
}

/// Expand a leading `~` into `$HOME` (falling back to `/root`).
fn expand_tilde(p: &str) -> PathBuf {
    if p.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        PathBuf::from(p.replacen('~', &home, 1))
    } else {
        PathBuf::from(p)
    }
}

/// `canonicalize` with janitor's error mapping.
///
/// Distinguishes ENOENT ("does not exist") from EACCES ("exists but
/// you lack search permission on a parent") — conflating them gives
/// misleading errors when running unprivileged against paths whose
/// ancestors are mode 700 for someone else.
fn canonicalize_checked(p: &Path) -> Result<PathBuf> {
    match p.canonicalize() {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(PmError::PathInaccessible(p.to_path_buf()))
        }
        Err(_) => Err(PmError::PathNotFound(p.to_path_buf())),
    }
}

/// Resolve a path: expand `~`, canonicalize, fail if missing.
///
/// Dereferences the whole path, including a symlink in the final
/// component. Use this for read-only inspection (`info`, `audit`,
/// `tree`, `--reference` sources); mutating commands must use
/// [`resolve_path_nofollow`] instead.
pub fn resolve_path(p: &str) -> Result<PathBuf> {
    canonicalize_checked(&expand_tilde(p))
}

/// Resolve a path without dereferencing its final component.
///
/// The parent directory is canonicalized — so `..`, relative paths and
/// symlinked *ancestors* are still normalized — but the last component is
/// kept verbatim. Every mutating command resolves its operands this way so
/// that `janitor chown u:g link` acts on the symlink itself, matching the
/// `lchown(2)` semantics documented in the README ("symlinks are never
/// followed for ownership or mode changes").
pub fn resolve_path_nofollow(p: &str) -> Result<PathBuf> {
    let expanded = expand_tilde(p);
    // `/`, `.` and `..` have no distinct final component to preserve;
    // there is no symlink to protect either, so canonicalize outright.
    let file_name = match expanded.file_name() {
        Some(f) => f.to_os_string(),
        None => return canonicalize_checked(&expanded),
    };
    let parent = match expanded.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let resolved = canonicalize_checked(&parent)?.join(file_name);
    match std::fs::symlink_metadata(&resolved) {
        Ok(_) => Ok(resolved),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(PmError::PathInaccessible(resolved))
        }
        Err(_) => Err(PmError::PathNotFound(resolved)),
    }
}

/// Return every path segment from (but not including) `stop_at` down to
/// and including `target`, in top-down order.
///
/// For `/home/user1/a/b/file.txt` with stop_at=`/`:
///   `[/home, /home/user1, /home/user1/a, /home/user1/a/b, /home/user1/a/b/file.txt]`
pub fn path_chain(target: &Path, stop_at: &Path) -> Vec<PathBuf> {
    let mut segs = Vec::new();
    let mut cur = target.to_path_buf();
    while cur != stop_at && cur.parent().is_some() && cur != cur.parent().unwrap().to_path_buf() {
        segs.push(cur.clone());
        cur = cur.parent().unwrap().to_path_buf();
    }
    segs.reverse();
    segs
}

/// Validate a group name matches Linux conventions: [a-z_][a-z0-9_-]{0,31}
pub fn validate_group_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 32 {
        return Err(PmError::InvalidGroupName(name.to_string()));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() && first != '_' {
        return Err(PmError::InvalidGroupName(name.to_string()));
    }
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_' && c != '-' {
            return Err(PmError::InvalidGroupName(name.to_string()));
        }
    }
    Ok(())
}

/// Derive a stable, human-readable managed group name for a target path.
///
/// Schema: `pm_<slug>_<hash8>` where:
///   * `slug` is a short lowercase snippet of the last 1–2 path segments
///     (≤ 20 chars), kept purely for operator readability;
///   * `hash8` is the lower 32 bits of a deterministic FNV-1a 64-bit
///     hash of the **absolute canonical path**, rendered as 8 hex chars.
///
/// The hash disambiguator prevents the v0.1.0 collision bug where two
/// different paths sharing the first 28 chars of their slug collapsed
/// to the same managed group (§3.12 — caused a silent access-bypass).
/// Total length is ≤ 32 chars (Linux `NAME_MAX` for group names).
///
/// Examples:
///   `/srv/project`                              → `pm_srv_project_1a2b3c4d`
///   `/home/u/a/b/c/jwt.secret`                  → `pm_c_jwt_a1b2c3d4`
///   `/home/u/a/b/d/schema.sql` (same prefix)    → `pm_d_schema_9f8e7d6c`
///     (different final hash => different group => no collision)
pub fn default_group_name(target: &Path) -> String {
    let base = if target.is_file() {
        target.parent().unwrap_or(target)
    } else {
        target
    };

    // Build a deterministic absolute-path key for the hash. We use
    // components() so `./a` and `a` collapse identically after
    // canonicalisation at the caller; here we just make a byte-stable
    // form of whatever Path we were given.
    let key: String = base
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect::<Vec<_>>()
        .join("/");
    let hash8 = fnv1a_hex8(key.as_bytes());

    // Human-readable slug from last two non-trivial segments.
    let parts: Vec<&str> = base
        .components()
        .filter_map(|c| {
            let s = c.as_os_str().to_str()?;
            if s == "/" || s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect();
    let tail = if parts.len() >= 2 {
        format!("{}_{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else if parts.len() == 1 {
        parts[0].to_string()
    } else {
        "root".to_string()
    };
    let slug: String = tail
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Cap slug at 20 chars so total name `pm_<slug>_<8hex>` ≤ 32.
    let slug = if slug.len() > 20 {
        slug[..20].trim_end_matches(['_', '-']).to_string()
    } else {
        slug
    };
    let slug = if slug.is_empty() {
        "root".to_string()
    } else {
        slug
    };
    format!("pm_{slug}_{hash8}")
}

/// Deterministic FNV-1a 64-bit hash, rendered as lower 32 bits in 8 hex
/// chars. Stable across Rust versions (unlike `std::hash::DefaultHasher`)
/// and across platforms. Not cryptographic — used purely as a collision
/// disambiguator, not a security primitive.
fn fnv1a_hex8(bytes: &[u8]) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h: u64 = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    format!("{:08x}", (h as u32))
}

// ── Pseudo-filesystem detection (§3.16) ───────────────────────────────
//
// Magic numbers from <linux/magic.h>. `statfs.f_type` is `i64` on glibc
// (via libc::__fsword_t) but the constants are the same regardless of
// platform word size.
const PSEUDO_FS_MAGIC: &[i64] = &[
    0x9fa0,               // PROC_SUPER_MAGIC        /proc
    0x62656572,           // SYSFS_MAGIC             /sys
    0x01021994,           // TMPFS_MAGIC             /tmp, /run, /dev/shm, /dev (devtmpfs)
    0x1cd1,               // DEVPTS_SUPER_MAGIC      /dev/pts
    0x27e0eb,             // CGROUP_SUPER_MAGIC
    0x63677270,           // CGROUP2_SUPER_MAGIC
    0x19800202,           // MQUEUE_MAGIC
    0x64626720,           // DEBUGFS_MAGIC
    0x74726163,           // TRACEFS_MAGIC
    0x62656570,           // CONFIGFS_MAGIC
    0x858458f6u32 as i64, // RAMFS_MAGIC
    0x958458f6u32 as i64, // HUGETLBFS_MAGIC
    0x6165676C,           // PSTOREFS_MAGIC
    0xcafe4a11u32 as i64, // BPF_FS_MAGIC
    0x65735543,           // FUSECTL_SUPER_MAGIC
    0x42494e4d,           // BINFMTFS_MAGIC
    0x67596969,           // RPC_PIPEFS_SUPER_MAGIC
    0x6e667364,           // NFSD_MAGIC
    0x0187,               // AUTOFS_SUPER_MAGIC
    0x73636673,           // SECURITYFS_MAGIC
    0xf97cff8cu32 as i64, // SELINUX_MAGIC
    0x6e736673,           // NSFS_MAGIC
];

/// Return true if `path` resides on a kernel-managed pseudo-filesystem
/// (see `PSEUDO_FS_MAGIC`). Used by scan commands (audit, find-orphans,
/// find) to skip /proc /sys /dev etc., where "orphan" UIDs are usually
/// LXC user-namespace remappings rather than leftover accounts.
pub fn is_pseudo_fs(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut sb: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut sb) } != 0 {
        return false;
    }
    let fs_type = sb.f_type as i64;
    PSEUDO_FS_MAGIC.contains(&fs_type)
}

/// Render bytes as `\xNN` escapes so an undecodable path can at least be
/// named in an error message.
fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(64)
        .map(|b| {
            if b.is_ascii_graphic() || *b == b'/' {
                (*b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

/// Read extra paths from stdin (NUL-separated if `stdin0`) and/or a file
/// (newline-separated; `-` means stdin). Extends `base` with them.
pub fn read_extra_paths(
    base: &mut Vec<String>,
    stdin0: bool,
    from_file: Option<&str>,
) -> Result<()> {
    use std::io::Read;
    if stdin0 {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| PmError::Other(format!("stdin: {e}")))?;
        for chunk in buf.split(|b| *b == 0) {
            if chunk.is_empty() {
                continue;
            }
            // `from_utf8_lossy` would replace the undecodable bytes with
            // U+FFFD and hand back a path that names a *different* file (or
            // none). For a tool that then chmods whatever it was given,
            // guessing is the wrong answer — refuse instead.
            let s = std::str::from_utf8(chunk).map_err(|_| {
                PmError::Other(format!(
                    "--stdin0: path is not valid UTF-8 and cannot be handled safely: {}",
                    hex_preview(chunk)
                ))
            })?;
            base.push(s.to_string());
        }
    }
    if let Some(f) = from_file {
        let text = if f == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| PmError::Other(format!("stdin: {e}")))?;
            s
        } else {
            std::fs::read_to_string(f).map_err(|e| PmError::Other(format!("read {f}: {e}")))?
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            base.push(line.to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_access() {
        assert_eq!(parse_access("r").unwrap().0, 0o4);
        assert_eq!(parse_access("rw").unwrap().0, 0o6);
        assert_eq!(parse_access("rwx").unwrap().0, 0o7);
        assert_eq!(parse_access("rx").unwrap().0, 0o5);
        assert!(parse_access("").is_err());
        assert!(parse_access("z").is_err());
        assert!(parse_access("rz").is_err());
    }

    /// Scratch directory unique to one test, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("janitor-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p.canonicalize().unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The whole point of `resolve_path_nofollow`: a symlink named as the
    /// final component stays the symlink (§H-01), while `resolve_path`
    /// dereferences it.
    #[test]
    fn nofollow_keeps_final_symlink_component() {
        let s = Scratch::new("nofollow");
        let target = s.0.join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = s.0.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let followed = resolve_path(link.to_str().unwrap()).unwrap();
        let kept = resolve_path_nofollow(link.to_str().unwrap()).unwrap();

        assert_eq!(followed, target);
        assert_eq!(kept, link);
    }

    /// Symlinked *ancestors* must still be normalized — only the last
    /// component is preserved verbatim.
    #[test]
    fn nofollow_still_canonicalizes_parents() {
        let s = Scratch::new("nofollow-parent");
        let real_dir = s.0.join("real");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(real_dir.join("f.txt"), b"x").unwrap();
        let dir_link = s.0.join("dirlink");
        std::os::unix::fs::symlink(&real_dir, &dir_link).unwrap();

        let resolved = resolve_path_nofollow(dir_link.join("f.txt").to_str().unwrap()).unwrap();
        assert_eq!(resolved, real_dir.join("f.txt"));
    }

    /// A path with no distinct final component falls back to full
    /// canonicalization rather than erroring out.
    #[test]
    fn nofollow_handles_root_and_dot_dot() {
        assert_eq!(resolve_path_nofollow("/").unwrap(), PathBuf::from("/"));
        assert!(resolve_path_nofollow("/..").is_ok());
    }

    #[test]
    fn nofollow_reports_missing_paths() {
        let s = Scratch::new("nofollow-missing");
        let missing = s.0.join("not-here");
        assert!(resolve_path_nofollow(missing.to_str().unwrap()).is_err());
    }

    #[test]
    fn test_path_chain() {
        let chain = path_chain(Path::new("/home/user1/a/b/file.txt"), Path::new("/"));
        assert_eq!(
            chain,
            vec![
                PathBuf::from("/home"),
                PathBuf::from("/home/user1"),
                PathBuf::from("/home/user1/a"),
                PathBuf::from("/home/user1/a/b"),
                PathBuf::from("/home/user1/a/b/file.txt"),
            ]
        );
    }

    #[test]
    fn test_validate_group_name() {
        assert!(validate_group_name("pm_test").is_ok());
        assert!(validate_group_name("pm_srv_project").is_ok());
        assert!(validate_group_name("a-b_c").is_ok());
        assert!(validate_group_name("").is_err());
        assert!(validate_group_name("1bad").is_err());
        assert!(validate_group_name("has space").is_err());
        assert!(validate_group_name(&"a".repeat(33)).is_err());
    }

    // ── §3.12 regression: pm_ naming collision must not recur ──────────

    /// The v0.1.0 exploit: two different paths sharing the first 28
    /// chars of their slug collapsed to the same `pm_<trunc>` name.
    /// With the hash disambiguator they must differ.
    #[test]
    fn group_names_differ_for_long_shared_prefix() {
        let a = default_group_name(Path::new(
            "/srv/acme/engineering/src/backend/auth/session/jwt.secret",
        ));
        let b = default_group_name(Path::new("/srv/acme/engineering/src/backend/db/schema.sql"));
        assert_ne!(a, b, "collision regression: {a} == {b}");
    }

    /// Generator must be deterministic: same path → same name across
    /// invocations. Required for restore/undo to find the right group.
    #[test]
    fn group_name_is_deterministic() {
        let p = Path::new("/srv/acme/engineering/docs");
        assert_eq!(default_group_name(p), default_group_name(p));
    }

    /// All generated names must fit Linux's 32-char group name limit.
    #[test]
    fn group_name_respects_32_char_limit() {
        for p in [
            "/",
            "/srv",
            "/srv/acme",
            "/srv/acme/engineering/src/backend/auth/session/jwt.secret",
            "/home/user1/a/b/c/d/e/f/g/h/i/j/k/very/deep/path/to/file.txt",
        ] {
            let n = default_group_name(Path::new(p));
            assert!(n.len() <= 32, "{p:?} -> {n:?} ({} chars)", n.len());
            assert!(n.starts_with("pm_"), "{n:?}");
        }
    }

    /// Hash is path-sensitive: a one-char change yields a different
    /// hash (extremely likely for FNV-1a).
    #[test]
    fn hash_changes_with_path() {
        let a = default_group_name(Path::new("/srv/project_a"));
        let b = default_group_name(Path::new("/srv/project_b"));
        assert_ne!(a, b);
    }

    // ── §3.16 regression: pseudo-FS detection ──────────────────────────

    /// /proc is always a pseudo-filesystem on Linux.
    #[test]
    fn is_pseudo_fs_detects_proc() {
        assert!(is_pseudo_fs(Path::new("/proc")));
    }

    /// /sys is always a pseudo-filesystem on Linux.
    #[test]
    fn is_pseudo_fs_detects_sys() {
        assert!(is_pseudo_fs(Path::new("/sys")));
    }

    /// A non-existent path can't be probed; `statfs` fails and we
    /// conservatively report `false` (i.e. don't skip — let the real
    /// code path emit a proper error).
    #[test]
    fn is_pseudo_fs_false_for_missing_path() {
        assert!(!is_pseudo_fs(Path::new(
            "/definitely/does/not/exist/here/at/all"
        )));
    }
}
