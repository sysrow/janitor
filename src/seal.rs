//! `seal`: atomic "uniform baseline + surgical pinholes" over a directory.
//!
//! Motivation: applying `chown -R root:root` + `chmod -R 700` + `setfacl`
//! pinholes for a handful of exceptions is notoriously error-prone. Users
//! forget to add `u:USER:--x` on parent directories, ending up with
//! pinholes that silently do nothing. `seal` does the whole thing in one
//! transaction with one snapshot, and auto-propagates the traversal bit
//! through the parent chain.

use std::os::unix::fs::MetadataExt;
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
    let base_md = std::fs::symlink_metadata(&base_path)
        .map_err(|e| PmError::Other(format!("stat {}: {e}", base_path.display())))?;
    if base_md.file_type().is_symlink() {
        // `is_dir()` follows the link and walkdir descends through a root
        // symlink by default, so a linked base used to seal a whole foreign
        // tree through the link.
        return Err(PmError::Other(format!(
            "seal base {} is a symlink; seal the directory it points to instead",
            base_path.display()
        )));
    }
    if !base_md.is_dir() {
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
            .follow_root_links(false)
            .into_iter()
            .filter_entry(|e| !ex.is_excluded(e.path()))
        {
            let entry = entry.map_err(|e| crate::chperm::walk_error(&base_path, &e))?;
            let p = entry.path();
            crate::locks::ensure_not_locked(p)?;
            baseline_paths.push(p.to_path_buf());
        }
    } else {
        baseline_paths.push(base_path.clone());
    }

    // --- derive the parent chain of each pinhole, kept SEPARATE ---
    //
    // Merging every pinhole's chain into one set and then granting each
    // principal traversal over all of it is how a user allowed only under
    // /base/a also ended up with --x on /base/b. The union is still what the
    // snapshot has to cover; the ACL writes must stay per-pinhole.
    use std::collections::{BTreeMap, BTreeSet};
    let mut chains: Vec<Vec<PathBuf>> = Vec::with_capacity(pinholes.len());
    for p in &pinholes {
        chains.push(chain_from_base(&base_path, &p.path)?);
    }
    let chain_union: BTreeSet<PathBuf> = chains.iter().flatten().cloned().collect();

    // Pinhole targets and their chains receive ACL writes whether or not
    // the baseline walk visited them (no `-R`, or pruned by `--exclude`),
    // so they get their own lock check.
    for p in chain_union.iter().chain(pinholes.iter().map(|p| &p.path)) {
        crate::locks::ensure_not_locked(p)?;
    }

    // One ACL entry per (principal, path). `setfacl -m` replaces the entry
    // for a qualifier rather than merging, so a pinhole on a directory and
    // another pinhole below it used to fight: whichever was written last
    // won, and the directory ended up with either the explicit perms and
    // no traverse or with `--x` and no explicit perms.
    let mut wanted: BTreeMap<(String, PathBuf), u32> = BTreeMap::new();
    for (p, chain) in pinholes.iter().zip(&chains) {
        let principal = format!("{}:{}", p.kind, p.name);
        for dir in chain {
            if dir == &p.path {
                continue;
            }
            *wanted.entry((principal.clone(), dir.clone())).or_insert(0) |= 0o1;
        }
        *wanted.entry((principal, p.path.clone())).or_insert(0) |= perm_bits(&p.perm);
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
        for c in &chain_union {
            snap_set.push(c.clone());
        }
        for p in &pinholes {
            snap_set.push(p.path.clone());
        }
        let snap = snapshot_with_acl(&snap_set, true)?;

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
                group_created: false,
                user_added: false,
                user_removed: false,
            },
        )?;

        apply_baseline(&baseline_paths, &spec)?;

        // Each principal gets traversal on its OWN ancestors only; the
        // union above already merged every pinhole's demand on a path.
        for ((principal, path), bits) in &wanted {
            let s = format!("{principal}:{}", perm_string(*bits));
            acl_modify(path, &s, false, false)?;
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

/// `"rwx"`-style perm string to bits.
fn perm_bits(perm: &str) -> u32 {
    let mut bits = 0;
    if perm.contains('r') {
        bits |= 0o4;
    }
    if perm.contains('w') {
        bits |= 0o2;
    }
    if perm.contains('x') {
        bits |= 0o1;
    }
    bits
}

/// Bits to the `setfacl` perm form (`r-x`).
fn perm_string(bits: u32) -> String {
    format!(
        "{}{}{}",
        if bits & 0o4 != 0 { 'r' } else { '-' },
        if bits & 0o2 != 0 { 'w' } else { '-' },
        if bits & 0o1 != 0 { 'x' } else { '-' }
    )
}

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

    // Deepest paths first: a baseline without owner-x applied to a directory
    // before its children would lock the run out of its own subtree.
    for p in &crate::chperm::depth_first(paths) {
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
        // Traditional "X" semantics: if spec mode has no x bits and
        // target is a directory, we still apply as-is (user asked
        // explicitly for that mode). No magic. The inode read above is
        // pinned so a swap after the check cannot redirect the chmod.
        crate::perms::chmod_nofollow(p, spec.mode, Some((md.dev(), md.ino())))
            .map_err(|e| PmError::Other(format!("chmod {}: {e}", p.display())))?;
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
