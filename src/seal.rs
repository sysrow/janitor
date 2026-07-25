//! `seal`: atomic "uniform baseline + surgical pinholes" over a directory.
//!
//! Motivation: applying `chown -R root:root` + `chmod -R 700` + `setfacl`
//! pinholes for a handful of exceptions is notoriously error-prone. Users
//! forget to add `u:USER:--x` on parent directories, ending up with
//! pinholes that silently do nothing. `seal` does the whole thing in one
//! transaction with one snapshot, and auto-propagates the traversal bit
//! through the parent chain.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::acl::{acl_modify, supports_acl};
use crate::backup::save_backup;
use crate::errors::{PmError, Result};
use crate::helpers::{parse_access, resolve_path_nofollow};
use crate::locking::with_lock;
use crate::matcher::ExcludeSet;
use crate::render::{self, paint, Style};
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use crate::users::{lookup_group, lookup_user};

// ── Spec parsing ─────────────────────────────────────────────────────────

/// Parsed `--base USER:GROUP:MODE` triple. Empty user/group means "keep
/// whatever is already there"; mode is required.
#[derive(Debug, Clone)]
struct BaseSpec {
    user: Option<String>,
    group: Option<String>,
    mode: u32,
}

fn parse_base_spec(s: &str) -> Result<BaseSpec> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(PmError::Other(format!(
            "--base expects USER:GROUP:MODE (got {s:?})"
        )));
    }
    let user = if parts[0].is_empty() {
        None
    } else {
        lookup_user(parts[0])?;
        Some(parts[0].to_string())
    };
    let group = if parts[1].is_empty() {
        None
    } else {
        lookup_group(parts[1])?;
        Some(parts[1].to_string())
    };
    let mode = u32::from_str_radix(parts[2], 8)
        .map_err(|_| PmError::Other(format!("--base mode must be octal (got {:?})", parts[2])))?;
    if mode > 0o7777 {
        return Err(PmError::Other(format!(
            "--base mode {:o} out of range (max 7777)",
            mode
        )));
    }
    Ok(BaseSpec { user, group, mode })
}

/// Parsed `--allow USER:PERM PATH` pair.
#[derive(Debug, Clone)]
struct Pinhole {
    /// "u" for user, "g" for group.
    kind: char,
    /// Principal name (user or group).
    name: String,
    /// setfacl-style perms ("r", "rw", "rx", "rwx", …).
    perm: String,
    /// Target (must live under seal base).
    path: PathBuf,
}

fn parse_allow(spec: &str, target: &str, kind: char) -> Result<Pinhole> {
    let (name, perm) = spec
        .split_once(':')
        .ok_or_else(|| PmError::Other(format!("--allow expects NAME:PERM (got {spec:?})")))?;
    if name.is_empty() {
        return Err(PmError::Other(format!("--allow: empty name in {spec:?}")));
    }
    match kind {
        'u' => {
            lookup_user(name)?;
        }
        'g' => {
            lookup_group(name)?;
        }
        _ => unreachable!(),
    }
    // Normalise perm string via parse_access.
    let bits = parse_access(perm)?;
    let mut canonical = String::with_capacity(3);
    if bits.has_read() {
        canonical.push('r');
    }
    if bits.has_write() {
        canonical.push('w');
    }
    if bits.has_exec() {
        canonical.push('x');
    }
    Ok(Pinhole {
        kind,
        name: name.to_string(),
        perm: canonical,
        path: resolve_path_nofollow(target)?,
    })
}

// ── Chain derivation ─────────────────────────────────────────────────────

/// Ancestors of `file`, up to and including `base`, in root-to-leaf order.
/// Returns an error if `file` does not live under `base`.
fn chain_from_base(base: &Path, file: &Path) -> Result<Vec<PathBuf>> {
    let rel = file
        .strip_prefix(base)
        .map_err(|_| PmError::SealAllowOutsideBase {
            allow: file.to_path_buf(),
            base: base.to_path_buf(),
        })?;
    let mut out = vec![base.to_path_buf()];
    let mut cur = base.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if cur != *file {
            out.push(cur.clone());
        }
    }
    Ok(out)
}

// ── Main entry point ─────────────────────────────────────────────────────

pub fn cmd_seal(
    base: &str,
    base_spec: &str,
    recursive: bool,
    allow_user: &[String],
    allow_group: &[String],
    exclude: &[String],
    dry_run: bool,
) -> Result<()> {
    let base_path = resolve_path_nofollow(base)?;
    crate::locks::ensure_not_locked(&base_path)?;
    if !base_path.is_dir() {
        return Err(PmError::SealBaseNotDir(base_path));
    }

    let spec = parse_base_spec(base_spec)?;
    let ex = ExcludeSet::new(exclude)?;

    // --- parse pinholes (every pair is "NAME:PERM" then PATH) ---
    if allow_user.len() % 2 != 0 {
        return Err(PmError::Other(
            "--allow expects pairs: NAME:PERM followed by PATH".into(),
        ));
    }
    if allow_group.len() % 2 != 0 {
        return Err(PmError::Other(
            "--allow-group expects pairs: NAME:PERM followed by PATH".into(),
        ));
    }
    let mut pinholes: Vec<Pinhole> = Vec::new();
    for pair in allow_user.chunks_exact(2) {
        pinholes.push(parse_allow(&pair[0], &pair[1], 'u')?);
    }
    for pair in allow_group.chunks_exact(2) {
        pinholes.push(parse_allow(&pair[0], &pair[1], 'g')?);
    }

    // --- validate every pinhole is inside base ---
    for p in &pinholes {
        if !p.path.starts_with(&base_path) {
            return Err(PmError::SealAllowOutsideBase {
                allow: p.path.clone(),
                base: base_path.clone(),
            });
        }
        if !p.path.exists() {
            return Err(PmError::PathNotFound(p.path.clone()));
        }
    }

    // --- if any pinholes, FS must support ACL ---
    if !pinholes.is_empty() && !supports_acl(&base_path) {
        return Err(PmError::AclUnsupported { path: base_path });
    }

    // --- collect baseline targets (walk), checking locks on each ---
    let mut baseline_paths: Vec<PathBuf> = Vec::new();
    if recursive {
        for entry in walkdir::WalkDir::new(&base_path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !ex.is_excluded(e.path()))
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            crate::locks::ensure_not_locked(p)?;
            baseline_paths.push(p.to_path_buf());
        }
    } else {
        baseline_paths.push(base_path.clone());
    }

    // --- derive parent chain for each pinhole, dedup ---
    use std::collections::BTreeSet;
    let mut chains: BTreeSet<PathBuf> = BTreeSet::new();
    for p in &pinholes {
        for c in chain_from_base(&base_path, &p.path)? {
            chains.insert(c);
        }
    }

    if dry_run {
        print_card(
            &base_path,
            &spec,
            recursive,
            baseline_paths.len(),
            &pinholes,
            None,
            true,
        );
        return Ok(());
    }

    // --- transactional apply under single lock + single backup ---
    with_lock(|| {
        let mut snap_set: Vec<PathBuf> = baseline_paths.clone();
        for c in &chains {
            snap_set.push(c.clone());
        }
        for p in &pinholes {
            snap_set.push(p.path.clone());
        }
        let snap = snapshot_with_acl(&snap_set, !pinholes.is_empty());

        let bid = save_backup(
            snap,
            Operation {
                op_type: "seal".into(),
                user: None,
                group: None,
                explicit_group: None,
                target: Some(base_path.display().to_string()),
                access: Some(base_spec.to_string()),
                max_level: None,
                recursive: Some(recursive),
                parent_op: None,
            },
        )?;

        apply_baseline(&baseline_paths, &spec)?;

        for p in &pinholes {
            for dir in &chains {
                if dir == &p.path {
                    continue;
                }
                let s = format!("{}:{}:--x", p.kind, p.name);
                acl_modify(dir, &s, false, false)?;
            }
            let s = format!("{}:{}:{}", p.kind, p.name, p.perm);
            acl_modify(&p.path, &s, false, false)?;
        }

        print_card(
            &base_path,
            &spec,
            recursive,
            baseline_paths.len(),
            &pinholes,
            Some(&bid),
            false,
        );
        Ok(())
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn apply_baseline(paths: &[PathBuf], spec: &BaseSpec) -> Result<()> {
    use nix::unistd::{Gid, Uid};
    let uid = match &spec.user {
        Some(u) => Some(Uid::from_raw(
            nix::unistd::User::from_name(u)
                .ok()
                .flatten()
                .ok_or_else(|| PmError::UserNotFound(u.clone()))?
                .uid
                .as_raw(),
        )),
        None => None,
    };
    let gid = match &spec.group {
        Some(g) => Some(Gid::from_raw(
            nix::unistd::Group::from_name(g)
                .ok()
                .flatten()
                .ok_or_else(|| PmError::GroupNotFound(g.clone()))?
                .gid
                .as_raw(),
        )),
        None => None,
    };

    for p in paths {
        let md = std::fs::symlink_metadata(p)?;
        if md.file_type().is_symlink() {
            // Symlinks: lchown only (never follow), skip chmod.
            if uid.is_some() || gid.is_some() {
                let u = uid.map(|u| u.as_raw()).unwrap_or(u32::MAX);
                let g = gid.map(|g| g.as_raw()).unwrap_or(u32::MAX);
                let c_path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
                    .map_err(|_| PmError::Other(format!("bad path: {}", p.display())))?;
                let ret = unsafe { libc::lchown(c_path.as_ptr(), u, g) };
                if ret != 0 {
                    return Err(PmError::Other(format!(
                        "lchown {}: {}",
                        p.display(),
                        std::io::Error::last_os_error()
                    )));
                }
            }
            continue;
        }
        // Non-symlink: chown first, then chmod (so chown's setuid/setgid
        // clear is overwritten by the subsequent chmod).
        if uid.is_some() || gid.is_some() {
            let u = uid.map(|u| u.as_raw()).unwrap_or(u32::MAX);
            let g = gid.map(|g| g.as_raw()).unwrap_or(u32::MAX);
            let c_path = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
                .map_err(|_| PmError::Other(format!("bad path: {}", p.display())))?;
            let ret = unsafe { libc::lchown(c_path.as_ptr(), u, g) };
            if ret != 0 {
                return Err(PmError::Other(format!(
                    "lchown {}: {}",
                    p.display(),
                    std::io::Error::last_os_error()
                )));
            }
        }
        let mut mode = spec.mode;
        // Traditional "X" semantics: if spec mode has no x bits and
        // target is a directory, we still apply as-is (user asked
        // explicitly for that mode). No magic.
        let _ = md;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            .map_err(|e| PmError::Other(format!("chmod {}: {e}", p.display())))?;
        // Rust's set_permissions clears high bits above 0o777 on some
        // versions; re-chmod raw for setuid/setgid/sticky.
        if mode & 0o7000 != 0 {
            let cstr = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
                .map_err(|_| PmError::Other(format!("bad path: {}", p.display())))?;
            let rc = unsafe { libc::chmod(cstr.as_ptr(), mode as libc::mode_t) };
            if rc != 0 {
                return Err(PmError::Other(format!(
                    "chmod special-bits on {} failed",
                    p.display()
                )));
            }
            mode |= 0; // silence unused
        }
        let _ = mode;
    }
    Ok(())
}

fn print_card(
    base: &Path,
    spec: &BaseSpec,
    recursive: bool,
    entry_count: usize,
    pinholes: &[Pinhole],
    backup_id: Option<&str>,
    dry_run: bool,
) {
    let g = render::glyphs();
    let (bullet, header) = if dry_run {
        (g.midot, "would seal")
    } else {
        (g.check, "sealed")
    };
    println!(
        "{} {}",
        paint(Style::Highlight, bullet),
        paint(Style::Highlight, header)
    );
    if let Some(bid) = backup_id {
        println!(
            "  {}  {}",
            paint(Style::Label, "backup   "),
            paint(Style::BackupId, bid)
        );
    }
    println!(
        "  {}  {}",
        paint(Style::Label, "base     "),
        paint(Style::Dir, &base.display().to_string())
    );

    let who = format!(
        "{}:{}",
        spec.user.as_deref().unwrap_or("(keep)"),
        spec.group.as_deref().unwrap_or("(keep)")
    );
    println!(
        "  {}  {}  {}  {}",
        paint(Style::Label, "baseline "),
        paint(Style::Primary, &who),
        paint(Style::Separator, "·"),
        paint(Style::Primary, &format!("{:04o}", spec.mode))
    );
    let word = if entry_count == 1 { "entry" } else { "entries" };
    let scope_note = if recursive {
        "recursive"
    } else {
        "top-level only"
    };
    println!(
        "  {}  {} {}  ({})",
        paint(Style::Label, "scope    "),
        entry_count,
        word,
        scope_note
    );
    // Surface a hint when the user sealed a directory non-recursively
    // but the directory has children. Without -R only the directory's
    // own metadata was sealed — files inside keep their previous mode /
    // owner / ACL, which is almost never what a sysadmin expects on a
    // first invocation. Nudge, don't force.
    if !recursive {
        if let Ok(md) = std::fs::symlink_metadata(base) {
            if md.is_dir() {
                let has_children = std::fs::read_dir(base)
                    .map(|mut it| it.next().is_some())
                    .unwrap_or(false);
                if has_children {
                    println!(
                        "  {}  {}",
                        paint(Style::Label, "hint     "),
                        paint(
                            Style::Highlight,
                            "only the directory itself was sealed — pass -R to include its contents"
                        )
                    );
                }
            }
        }
    }
    if pinholes.is_empty() {
        println!(
            "  {}  {}",
            paint(Style::Label, "pinholes "),
            paint(Style::Separator, "(none)")
        );
    } else {
        println!("  {}  {}", paint(Style::Label, "pinholes "), pinholes.len());
        for p in pinholes {
            let principal = if p.kind == 'u' {
                paint(Style::User, &p.name)
            } else {
                paint(Style::Group, &p.name)
            };
            // Right-pad perm to 3 chars for visual alignment across r/rw/rwx.
            let perm_padded = format!("{:<3}", p.perm);
            println!(
                "    {}  {}  {}  {}",
                paint(Style::Separator, "→"),
                principal,
                paint(Style::Primary, &perm_padded),
                paint(Style::Dir, &p.path.display().to_string())
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_spec_full() {
        // root + root exist on every Linux system.
        let s = parse_base_spec("root:root:700").unwrap();
        assert_eq!(s.user.as_deref(), Some("root"));
        assert_eq!(s.group.as_deref(), Some("root"));
        assert_eq!(s.mode, 0o700);
    }

    #[test]
    fn parses_base_spec_keep_owner() {
        let s = parse_base_spec("::644").unwrap();
        assert!(s.user.is_none());
        assert!(s.group.is_none());
        assert_eq!(s.mode, 0o644);
    }

    #[test]
    fn rejects_non_octal_mode() {
        assert!(parse_base_spec("root:root:xyz").is_err());
    }

    #[test]
    fn rejects_too_large_mode() {
        assert!(parse_base_spec("root:root:12345").is_err());
    }

    #[test]
    fn chain_from_base_yields_ancestors_only() {
        let base = Path::new("/srv/secrets");
        let leaf = Path::new("/srv/secrets/a/b/c.txt");
        let chain = chain_from_base(base, leaf).unwrap();
        assert_eq!(
            chain,
            vec![
                PathBuf::from("/srv/secrets"),
                PathBuf::from("/srv/secrets/a"),
                PathBuf::from("/srv/secrets/a/b"),
            ]
        );
    }

    #[test]
    fn chain_rejects_path_outside_base() {
        let base = Path::new("/srv/secrets");
        let leaf = Path::new("/etc/passwd");
        assert!(chain_from_base(base, leaf).is_err());
    }

    #[test]
    fn chain_for_leaf_directly_under_base() {
        let base = Path::new("/srv/secrets");
        let leaf = Path::new("/srv/secrets/file.txt");
        let chain = chain_from_base(base, leaf).unwrap();
        assert_eq!(chain, vec![PathBuf::from("/srv/secrets")]);
    }
}
