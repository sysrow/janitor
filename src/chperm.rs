//! `chmod` and `chown` subcommands with automatic snapshot/backup.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::backup::save_backup;
use crate::errors::{PmError, Result};
use crate::helpers::{resolve_path, resolve_path_nofollow};
use crate::locking::with_lock;
use crate::matcher::ExcludeSet;
use crate::perms::lchown;
use crate::render::{paint, summary_line, Style};
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use crate::users::{gid_to_name, lookup_group, lookup_user, uid_to_name};

/// Resolve each input path, enforce `ensure_not_locked`, and expand to a flat
/// list honoring `recursive` + `exclude`. Returns `(resolved_targets, paths)`.
/// Fail-closed: any missing / locked path aborts before any mutation.
///
/// Operands are resolved with [`resolve_path_nofollow`], so a symlink named
/// directly on the command line is operated on as a symlink and never
/// dereferenced into its target.
pub fn expand_targets(
    paths_in: &[String],
    recursive: bool,
    exclude: &ExcludeSet,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut paths = Vec::new();
    let mut resolved_targets = Vec::new();
    for p in paths_in {
        let t = resolve_path_nofollow(p)?;
        crate::locks::ensure_not_locked(&t)?;
        resolved_targets.push(t.clone());
        if exclude.is_excluded(&t) {
            continue;
        }
        let is_dir = fs::symlink_metadata(&t)
            .map(|m| m.is_dir())
            .unwrap_or(false);
        paths.push(t.clone());
        if recursive && is_dir {
            for entry in walkdir::WalkDir::new(&t)
                .min_depth(1)
                .follow_links(false)
                .follow_root_links(false)
                .into_iter()
                .filter_entry(|e| !exclude.is_excluded(e.path()))
            {
                // A subtree that cannot be enumerated cannot be backed up,
                // so it cannot be mutated either. Dropping the error here
                // used to turn a partial walk into a "successful" run.
                let entry = entry.map_err(|e| walk_error(&t, &e))?;
                let ep = entry.into_path();
                crate::locks::ensure_not_locked(&ep)?;
                paths.push(ep);
            }
        }
    }
    Ok((resolved_targets, paths))
}

/// Describe a `walkdir` failure as the refusal it is.
pub(crate) fn walk_error(root: &Path, e: &walkdir::Error) -> PmError {
    let at = e
        .path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| root.display().to_string());
    PmError::Other(format!(
        "cannot walk {at}: {e}\n       refusing to mutate a tree that could not be fully \
         enumerated (nothing was changed)"
    ))
}

/// Order paths deepest-first so children are chmod'ed before their parents.
///
/// `expand_targets` hands back a pre-order walk. Applying it in that order
/// means a recursive tighten (`chmod 000 dir -R`) strips the traverse bit
/// from the root and then fails on every descendant underneath it, leaving
/// the tree half-changed. Post-order avoids that: by the time a directory
/// loses its own permissions, everything below it is already done.
///
/// The walk itself already happened in `expand_targets`, so reordering here
/// cannot affect which paths are visited.
pub(crate) fn depth_first(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = paths.to_vec();
    out.sort_by_key(|b| std::cmp::Reverse(b.components().count()));
    out
}

/// Apply a chmod (octal or symbolic, or a fixed `ref_mode`) to each path in
/// `paths`. Does NOT take a snapshot; the caller must record its own backup.
/// Applies deepest paths first (see [`depth_first`]).
/// Returns (changed, unchanged, failed) counts.
pub fn apply_chmod_to_paths(
    paths: &[PathBuf],
    mode_spec: &str,
    ref_mode: Option<u32>,
    dry_run: bool,
) -> Result<(usize, usize, usize)> {
    let mut changed = 0usize;
    let mut unchanged = 0usize;
    let mut failed = 0usize;
    for p in depth_first(paths) {
        let p = &p;
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        if md.file_type().is_symlink() {
            continue;
        }
        let current = md.permissions().mode() & 0o7777;
        let new_mode = if let Some(m) = ref_mode {
            m
        } else if mode_spec
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            parse_octal(mode_spec)?
        } else {
            apply_symbolic(current, mode_spec, md.is_dir())?
        };
        if new_mode == current {
            unchanged += 1;
            continue;
        }
        if dry_run {
            eprintln!(
                "  [dry-run] {:04o} {} {:04o}  {}",
                current,
                paint(Style::Separator, "→"),
                new_mode,
                paint(Style::Primary, &p.display().to_string())
            );
            changed += 1;
        } else {
            match fs::set_permissions(p, fs::Permissions::from_mode(new_mode)) {
                Ok(()) => {
                    // Print the before→after diff line unconditionally
                    // so piped / logged output stays auditable. `paint`
                    // already auto-disables color when stdout is not a
                    // tty or $NO_COLOR is set.
                    println!(
                        "  {:04o} {} {:04o}  {}",
                        current,
                        paint(Style::Separator, "→"),
                        new_mode,
                        paint(Style::Primary, &p.display().to_string())
                    );
                    changed += 1;
                }
                Err(e) => {
                    failed += 1;
                    eprintln!(
                        "  {}: {}  {}",
                        paint(Style::Danger, "error"),
                        p.display(),
                        e
                    );
                }
            }
        }
    }
    Ok((changed, unchanged, failed))
}

/// Apply a chown (uid / gid, either optional) to each path. No snapshot.
/// Returns (changed, unchanged, failed).
pub fn apply_chown_to_paths(
    paths: &[PathBuf],
    new_uid: Option<u32>,
    new_gid: Option<u32>,
    dry_run: bool,
) -> Result<(usize, usize, usize)> {
    use nix::unistd::{Gid, Uid};
    let mut changed = 0usize;
    let mut unchanged = 0usize;
    let mut failed = 0usize;
    let u_name = new_uid
        .map(|u| uid_to_name(Uid::from_raw(u)))
        .unwrap_or_else(|| "(keep)".into());
    let g_name = new_gid
        .map(|g| gid_to_name(Gid::from_raw(g)))
        .unwrap_or_else(|| "(keep)".into());
    for p in depth_first(paths) {
        let p = &p;
        let before = fs::symlink_metadata(p).ok();
        let (bu, bg) = match &before {
            Some(m) => (
                uid_to_name(Uid::from_raw(m.uid())),
                gid_to_name(Gid::from_raw(m.gid())),
            ),
            None => ("?".into(), "?".into()),
        };
        let will_change = match &before {
            Some(m) => {
                let u_diff = new_uid.map(|u| u != m.uid()).unwrap_or(false);
                let g_diff = new_gid.map(|g| g != m.gid()).unwrap_or(false);
                u_diff || g_diff
            }
            None => true,
        };
        if !will_change {
            unchanged += 1;
            continue;
        }
        if dry_run {
            eprintln!(
                "  [dry-run] {}:{} {} {}:{}  {}",
                paint(Style::User, &bu),
                paint(Style::Group, &bg),
                paint(Style::Separator, "→"),
                paint(Style::User, &u_name),
                paint(Style::Group, &g_name),
                paint(Style::Primary, &p.display().to_string())
            );
            changed += 1;
        } else {
            match lchown(p, new_uid, new_gid) {
                Ok(()) => {
                    println!(
                        "  {}:{} {} {}:{}  {}",
                        paint(Style::User, &bu),
                        paint(Style::Group, &bg),
                        paint(Style::Separator, "→"),
                        paint(Style::User, &u_name),
                        paint(Style::Group, &g_name),
                        paint(Style::Primary, &p.display().to_string())
                    );
                    changed += 1;
                }
                Err(e) => {
                    failed += 1;
                    eprintln!(
                        "  {}: {}  {}",
                        paint(Style::Danger, "error"),
                        p.display(),
                        e
                    );
                }
            }
        }
    }
    Ok((changed, unchanged, failed))
}

/// Resolve a chown `SPEC` (or `--reference FILE`) to `(uid, gid)`.
pub fn resolve_chown_target(
    spec: &str,
    reference: Option<&str>,
) -> Result<(Option<u32>, Option<u32>)> {
    if let Some(r) = reference {
        let rp = resolve_path(r)?;
        let md = fs::metadata(&rp).map_err(|e| PmError::InsufficientPrivileges {
            path: rp.clone(),
            reason: e.to_string(),
        })?;
        Ok((Some(md.uid()), Some(md.gid())))
    } else {
        parse_chown_spec(spec)
    }
}

/// Parse an octal mode string like "755" or "0755" or "4755" into u32.
pub fn parse_octal(s: &str) -> Result<u32> {
    let trimmed = s.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    u32::from_str_radix(trimmed, 8)
        .map_err(|_| PmError::Other(format!("invalid octal mode: {s:?}")))
        .and_then(|v| {
            if v > 0o7777 {
                Err(PmError::Other(format!("mode out of range: {s:?}")))
            } else {
                Ok(v)
            }
        })
}

/// The process umask, read once.
///
/// There is no way to *read* the umask without setting it, so this does the
/// standard set-and-restore dance. It runs from `main` before any file is
/// created, and the result is cached, so no other thread can observe the
/// momentary change.
pub fn process_umask() -> u32 {
    use nix::sys::stat::{umask, Mode};
    use std::sync::OnceLock;
    static UMASK: OnceLock<u32> = OnceLock::new();
    *UMASK.get_or_init(|| {
        let current = umask(Mode::from_bits_truncate(0o022));
        umask(current);
        current.bits() as u32 & 0o777
    })
}

/// Apply symbolic mode like "u+r", "g-w", "o=rx", "a+X", "u+s".
/// Returns the new mode given the current one.
pub fn apply_symbolic(current: u32, spec: &str, is_dir: bool) -> Result<u32> {
    apply_symbolic_with_umask(current, spec, is_dir, process_umask())
}

/// `apply_symbolic` with the umask supplied explicitly, so tests are not at
/// the mercy of whatever umask the shell running them happened to have.
pub fn apply_symbolic_with_umask(
    current: u32,
    spec: &str,
    is_dir: bool,
    umask: u32,
) -> Result<u32> {
    let mut mode = current & 0o7777;
    for part in spec.split(',') {
        mode = apply_one(mode, part.trim(), is_dir, umask)?;
    }
    Ok(mode)
}

fn apply_one(mode: u32, spec: &str, is_dir: bool, umask: u32) -> Result<u32> {
    // Split into whos and op+perms.
    let op_pos = spec
        .find(|c: char| ['+', '-', '='].contains(&c))
        .ok_or_else(|| PmError::Other(format!("missing +/-/= in symbolic mode: {spec:?}")))?;
    let (whos, rest) = spec.split_at(op_pos);
    let op = rest.chars().next().unwrap();
    let perms = &rest[1..];

    // `affected` is the set of bits this clause may touch, mirroring GNU
    // coreutils' modechange.c: each explicit who selects its rwx triad plus
    // its special bit (setuid for `u`, setgid for `g`, sticky for `o`), and
    // no who at all selects every bit. POSIX adds that with no who, bits in
    // the file mode creation mask are not *set* (they are still cleared by
    // `=`), which is why `umask 022; chmod =rwx f` yields 0755 and
    // `chmod = f` yields 0000 rather than 0022.
    let mut affected: u32 = 0;
    if whos.is_empty() || whos.contains('a') {
        affected = 0o7777;
    } else {
        for c in whos.chars() {
            match c {
                'u' => affected |= 0o4700,
                'g' => affected |= 0o2070,
                'o' => affected |= 0o1007,
                _ => return Err(PmError::Other(format!("bad who in {spec:?}: {c}"))),
            }
        }
    }

    let mut value: u32 = 0;
    let mut mentioned: u32 = 0;
    for c in perms.chars() {
        match c {
            'r' => value |= 0o444,
            'w' => value |= 0o222,
            'x' => value |= 0o111,
            'X' => {
                // Execute only if is a dir OR any existing exec bit.
                if is_dir || (mode & 0o111) != 0 {
                    value |= 0o111;
                }
            }
            's' => {
                value |= 0o6000;
                mentioned |= 0o6000;
            }
            't' => {
                value |= 0o1000;
                mentioned |= 0o1000;
            }
            _ => return Err(PmError::Other(format!("bad perm in {spec:?}: {c}"))),
        }
    }
    value &= affected;
    if whos.is_empty() {
        value &= !(umask & 0o777);
    }

    let new_mode = match op {
        '+' => mode | value,
        '-' => mode & !value,
        '=' => value | (mode & !affected),
        _ => unreachable!(),
    };
    // GNU chmod preserves a directory's setuid and setgid bits unless the
    // clause names them: `chmod =rwx dir` keeps setgid, `chmod g=rxs dir`
    // sets it, `chmod g-s dir` clears it.
    let omit_change = if is_dir { 0o6000 & !mentioned } else { 0 };
    let new_mode = (new_mode & !omit_change) | (mode & omit_change);
    Ok(new_mode & 0o7777)
}

/// `chmod` command: change mode (octal or symbolic) with auto-backup.
/// Accepts one or more target paths; a single snapshot covers the whole batch.
pub fn cmd_chmod(
    mode_spec: &str,
    paths_in: &[String],
    recursive: bool,
    capture_acl: bool,
    reference: Option<&str>,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    if paths_in.is_empty() {
        return Err(PmError::Other("chmod: no target paths".into()));
    }
    // Resolve reference mode once up front (if any).
    let ref_mode: Option<u32> = if let Some(r) = reference {
        let rp = resolve_path(r)?;
        let md = fs::metadata(&rp).map_err(|e| PmError::InsufficientPrivileges {
            path: rp.clone(),
            reason: e.to_string(),
        })?;
        Some(md.permissions().mode() & 0o7777)
    } else {
        None
    };
    let (resolved_targets, paths) = expand_targets(paths_in, recursive, exclude)?;
    if paths.is_empty() {
        eprintln!("chmod: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, capture_acl)?;
            let target_str = resolved_targets
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "chmod".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(target_str),
                    access: Some(
                        ref_mode
                            .map(|m| format!("ref:{m:04o}"))
                            .unwrap_or_else(|| mode_spec.to_string()),
                    ),
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
        let (c, u, f) = apply_chmod_to_paths(&paths, mode_spec, ref_mode, dry_run)?;
        let c_s = c.to_string();
        let u_s = u.to_string();
        let f_s = f.to_string();
        let segs: Vec<(&str, &str)> = vec![
            (
                c_s.as_str(),
                if dry_run { "would change" } else { "changed" },
            ),
            (u_s.as_str(), "unchanged"),
            (if f > 0 { f_s.as_str() } else { "" }, "failed"),
        ];
        eprintln!("{}", summary_line(&segs));
        if f > 0 {
            Err(PmError::Other(format!("{f} path(s) failed")))
        } else {
            Ok(())
        }
    })
}

/// `chown` command: change owner and/or group with auto-backup.
/// Accepts one or more target paths.
pub fn cmd_chown(
    spec: &str,
    paths_in: &[String],
    recursive: bool,
    capture_acl: bool,
    reference: Option<&str>,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    if paths_in.is_empty() {
        return Err(PmError::Other("chown: no target paths".into()));
    }
    let (new_uid, new_gid) = resolve_chown_target(spec, reference)?;
    let (resolved_targets, paths) = expand_targets(paths_in, recursive, exclude)?;
    if paths.is_empty() {
        eprintln!("chown: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        if !dry_run {
            let snap = snapshot_with_acl(&paths, capture_acl)?;
            let target_str = resolved_targets
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "chown".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(target_str),
                    access: Some(if reference.is_some() {
                        format!(
                            "ref:{}:{}",
                            new_uid.map(|u| u.to_string()).unwrap_or("-".into()),
                            new_gid.map(|g| g.to_string()).unwrap_or("-".into())
                        )
                    } else {
                        spec.to_string()
                    }),
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
        let (c, u, f) = apply_chown_to_paths(&paths, new_uid, new_gid, dry_run)?;
        let c_s = c.to_string();
        let u_s = u.to_string();
        let f_s = f.to_string();
        let segs: Vec<(&str, &str)> = vec![
            (
                c_s.as_str(),
                if dry_run { "would change" } else { "changed" },
            ),
            (u_s.as_str(), "unchanged"),
            (if f > 0 { f_s.as_str() } else { "" }, "failed"),
        ];
        eprintln!("{}", summary_line(&segs));
        if f > 0 {
            Err(PmError::Other(format!("{f} path(s) failed")))
        } else {
            Ok(())
        }
    })
}

fn parse_chown_spec(spec: &str) -> Result<(Option<u32>, Option<u32>)> {
    if spec.is_empty() {
        return Err(PmError::Other("empty chown spec".into()));
    }
    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = if user_part.is_empty() {
        None
    } else if let Ok(n) = user_part.parse::<u32>() {
        Some(n)
    } else {
        Some(lookup_user(user_part)?.uid.as_raw())
    };
    let gid = match group_part {
        None => None,
        Some(g) if g.is_empty() => None,
        Some(g) => {
            if let Ok(n) = g.parse::<u32>() {
                Some(n)
            } else {
                Some(lookup_group(g)?.gid.as_raw())
            }
        }
    };
    Ok((uid, gid))
}

// Keep imports alive
#[allow(dead_code)]
fn _keep() {
    let _ = Path::new("/");
}

/// `copy-perms SRC DST`: copy mode + owner + group (+ optionally ACLs) from
/// SRC to DST, with an auto-snapshot of DST. When `recursive` is set, DST must
/// be a directory and every entry under it receives SRC's mode / ownership.
pub fn cmd_copy_perms(
    src: &str,
    dst: &str,
    include_acl: bool,
    recursive: bool,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    use nix::unistd::{Gid, Uid};
    // SRC is only read from, so its symlink is followed like `--reference`
    // does. DST is mutated, so its final component stays un-dereferenced.
    let src_path = resolve_path(src)?;
    let dst_path = resolve_path_nofollow(dst)?;
    crate::locks::ensure_not_locked(&dst_path)?;
    let src_md = fs::symlink_metadata(&src_path).map_err(|e| PmError::InsufficientPrivileges {
        path: src_path.clone(),
        reason: e.to_string(),
    })?;
    let src_mode = src_md.permissions().mode() & 0o7777;
    let src_uid = src_md.uid();
    let src_gid = src_md.gid();
    let src_user = uid_to_name(Uid::from_raw(src_uid));
    let src_group = gid_to_name(Gid::from_raw(src_gid));
    let src_has_acl = crate::acl::has_extended_acl(&src_path);

    let stdout_tty = is_terminal::is_terminal(std::io::stdout());

    // ── Source profile header (TTY only) ─────────────────────────────
    if stdout_tty {
        let marker = if dry_run { "  [DRY RUN]" } else { "" };
        println!(
            "\n  {}  {}",
            paint(Style::Label, "source:"),
            paint(Style::Primary, &src_path.display().to_string())
        );
        println!(
            "           mode  {:04o} {}",
            src_mode,
            paint(
                Style::Label,
                &crate::render::format_symbolic(src_mode, src_md.is_dir(), false)
            )
        );
        println!(
            "           owner {}:{} (uid {} : gid {})",
            paint(Style::User, &src_user),
            paint(Style::Group, &src_group),
            src_uid,
            src_gid
        );
        println!(
            "           acl   {}",
            paint(
                Style::Label,
                if src_has_acl {
                    "present (will be copied)"
                } else {
                    "none"
                }
            )
        );
        println!(
            "\n  {}  {}{}",
            paint(Style::Label, "target:"),
            paint(Style::Primary, &dst_path.display().to_string()),
            paint(Style::WarnMajor, marker)
        );
    }

    // Collect targets (dst + optionally children), honoring --exclude.
    // Check locks on every expanded descendant, not just the root.
    let mut targets: Vec<std::path::PathBuf> = Vec::new();
    if !exclude.is_excluded(&dst_path) {
        targets.push(dst_path.clone());
    }
    if recursive {
        for entry in walkdir::WalkDir::new(&dst_path)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| !exclude.is_excluded(e.path()))
            .filter_map(|e| e.ok())
        {
            let ep = entry.path().to_path_buf();
            crate::locks::ensure_not_locked(&ep)?;
            targets.push(ep);
        }
    }
    if targets.is_empty() {
        eprintln!("copy-perms: no paths left after --exclude");
        return Ok(());
    }

    with_lock(|| {
        let snap_entries = snapshot_with_acl(&targets, include_acl)?;
        let mut backup_id: Option<String> = None;
        if !dry_run {
            let bid = save_backup(
                snap_entries,
                Operation {
                    op_type: "copy-perms".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(dst_path.display().to_string()),
                    access: Some(format!("from:{}", src_path.display())),
                    max_level: None,
                    recursive: Some(recursive),
                    parent_op: None,
                    group_created: false,
                    user_added: false,
                    user_removed: false,
                },
            )?;
            backup_id = Some(bid);
        }

        if dry_run {
            if stdout_tty {
                println!();
                let max_show = 8;
                for (i, t) in targets.iter().enumerate() {
                    if i >= max_show {
                        println!(
                            "  {} ... and {} more",
                            paint(Style::Separator, "…"),
                            targets.len() - max_show
                        );
                        break;
                    }
                    println!(
                        "  [dry-run] {}  {}",
                        paint(
                            Style::Label,
                            &format!("chmod {src_mode:04o} chown {src_user}:{src_group}")
                        ),
                        paint(Style::Primary, &t.display().to_string())
                    );
                }
                if include_acl && src_has_acl {
                    println!(
                        "  [dry-run] {}",
                        paint(Style::Label, "copy ACL from source to each target")
                    );
                }
            } else {
                for t in &targets {
                    println!(
                        "[dry-run] chmod {src_mode:o} {}  (from {})",
                        t.display(),
                        src_path.display()
                    );
                    println!("[dry-run] lchown {src_uid}:{src_gid} {}", t.display());
                }
            }
            return Ok(());
        }

        // Apply ownership first, then mode (so chown's setuid/setgid
        // clear is overwritten by the subsequent chmod).
        let mut changed = 0usize;
        for t in &targets {
            let tmd = fs::symlink_metadata(t).map_err(|e| PmError::InsufficientPrivileges {
                path: t.clone(),
                reason: e.to_string(),
            })?;
            lchown(t, Some(src_uid), Some(src_gid)).map_err(|e| {
                PmError::InsufficientPrivileges {
                    path: t.clone(),
                    reason: e.to_string(),
                }
            })?;
            if !tmd.file_type().is_symlink() {
                fs::set_permissions(t, fs::Permissions::from_mode(src_mode)).map_err(|e| {
                    PmError::InsufficientPrivileges {
                        path: t.clone(),
                        reason: e.to_string(),
                    }
                })?;
            }
            changed += 1;
        }

        if include_acl {
            let src_acl = crate::acl::get_acl(&src_path)?;
            for t in &targets {
                match &src_acl {
                    Some(text) => {
                        crate::acl::restore_acl(t, Some(text), None, false)?;
                    }
                    None => {
                        let _ = crate::acl::acl_strip(t, false, false);
                    }
                }
            }
        }

        if let Some(bid) = &backup_id {
            println!(
                "\n{}  {}",
                paint(Style::Label, "backup:"),
                paint(Style::Primary, bid)
            );
        }
        let n_s = changed.to_string();
        let segs: Vec<(&str, &str)> = vec![(
            n_s.as_str(),
            if changed == 1 {
                "path updated"
            } else {
                "paths updated"
            },
        )];
        eprintln!("{}", summary_line(&segs));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── apply_symbolic: POSIX-ish coverage ────────────────────────────

    #[test]
    fn sym_add_single_class() {
        // u+x on 0o644 → 0o744
        assert_eq!(apply_symbolic(0o644, "u+x", false).unwrap(), 0o744);
        // g+w on 0o644 → 0o664
        assert_eq!(apply_symbolic(0o644, "g+w", false).unwrap(), 0o664);
        // o+r on 0o640 → 0o644
        assert_eq!(apply_symbolic(0o640, "o+r", false).unwrap(), 0o644);
    }

    #[test]
    fn sym_remove_single_class() {
        assert_eq!(apply_symbolic(0o777, "o-rwx", false).unwrap(), 0o770);
        assert_eq!(apply_symbolic(0o664, "g-w", false).unwrap(), 0o644);
    }

    #[test]
    fn sym_equals_clears_class() {
        // g=r on 0o777 → 0o747 (group wiped, set to r only)
        assert_eq!(apply_symbolic(0o777, "g=r", false).unwrap(), 0o747);
        // o= on 0o777 → 0o770 (no perms given → clear other)
        assert_eq!(apply_symbolic(0o777, "o=", false).unwrap(), 0o770);
    }

    /// POSIX: an omitted `who` behaves like `a` "except that bits in the
    /// file mode creation mask are not affected". With umask 0 that is
    /// literally a+x; with a real umask, coreutils drops the masked bits.
    #[test]
    fn sym_empty_who_means_all_minus_umask() {
        assert_eq!(
            apply_symbolic_with_umask(0o644, "+x", false, 0o000).unwrap(),
            0o755
        );
        assert_eq!(
            apply_symbolic_with_umask(0o7777, "=r", false, 0o000).unwrap(),
            0o444
        );
        // umask 077: only the owner triad is affected (the §M-07 case).
        assert_eq!(
            apply_symbolic_with_umask(0o600, "+x", false, 0o077).unwrap(),
            0o700
        );
        // umask 022: group and other keep their write bits untouched.
        assert_eq!(
            apply_symbolic_with_umask(0o666, "-w", false, 0o022).unwrap(),
            0o466
        );
        // An explicit `a` ignores the umask entirely.
        assert_eq!(
            apply_symbolic_with_umask(0o600, "a+x", false, 0o077).unwrap(),
            0o711
        );
    }

    /// Measured against GNU coreutils with umask 022: `=` with no who clears
    /// every bit and sets the requested ones minus the umask, and a
    /// directory keeps setuid/setgid unless the clause names `s`.
    #[test]
    fn sym_equals_without_who_matches_coreutils() {
        let um = 0o022;
        assert_eq!(
            apply_symbolic_with_umask(0o666, "=rwx", false, um).unwrap(),
            0o755
        );
        assert_eq!(
            apply_symbolic_with_umask(0o666, "=", false, um).unwrap(),
            0o000
        );
        assert_eq!(
            apply_symbolic_with_umask(0o6755, "=r", false, um).unwrap(),
            0o444
        );
        assert_eq!(
            apply_symbolic_with_umask(0o3777, "=rwx", true, um).unwrap(),
            0o2755
        );
        assert_eq!(
            apply_symbolic_with_umask(0o2775, "=", true, um).unwrap(),
            0o2000
        );
        assert_eq!(
            apply_symbolic_with_umask(0o666, "=rwx,o-w", false, um).unwrap(),
            0o755
        );
    }

    #[test]
    fn sym_directories_keep_setid_unless_named() {
        assert_eq!(apply_symbolic(0o2775, "g=rx", true).unwrap(), 0o2755);
        assert_eq!(apply_symbolic(0o0755, "g=rxs", true).unwrap(), 0o2755);
        assert_eq!(apply_symbolic(0o3775, "o=rx", true).unwrap(), 0o2775);
        assert_eq!(apply_symbolic(0o2775, "a=rwx", true).unwrap(), 0o2777);
        assert_eq!(apply_symbolic(0o2775, "u=rwx", true).unwrap(), 0o2775);
        assert_eq!(apply_symbolic(0o6775, "o=rx", true).unwrap(), 0o6775);
        // Files get no such protection.
        assert_eq!(apply_symbolic(0o2755, "g=rx", false).unwrap(), 0o0755);
    }

    #[test]
    fn sym_special_bits_follow_their_who() {
        // `u+t` and `o+s` name a bit outside the selected class: no-op.
        assert_eq!(apply_symbolic(0o755, "u+t", true).unwrap(), 0o755);
        assert_eq!(apply_symbolic(0o755, "o+s", false).unwrap(), 0o755);
        assert_eq!(apply_symbolic(0o755, "+s", false).unwrap(), 0o6755);
    }

    #[test]
    fn sym_a_is_all() {
        assert_eq!(apply_symbolic(0o000, "a+rw", false).unwrap(), 0o666);
        assert_eq!(apply_symbolic(0o777, "a-x", false).unwrap(), 0o666);
    }

    #[test]
    fn sym_multi_whos() {
        // ug+x on 0o600 → 0o710
        assert_eq!(apply_symbolic(0o600, "ug+x", false).unwrap(), 0o710);
        // go-rwx on 0o777 → 0o700
        assert_eq!(apply_symbolic(0o777, "go-rwx", false).unwrap(), 0o700);
    }

    #[test]
    fn sym_comma_chain() {
        // u=rwx,go=rx on anything → 0o755
        assert_eq!(apply_symbolic(0o000, "u=rwx,go=rx", false).unwrap(), 0o755);
        // Order matters: u+x,u-x → cleared
        assert_eq!(apply_symbolic(0o600, "u+x,u-x", false).unwrap(), 0o600);
    }

    #[test]
    fn sym_whitespace_in_parts() {
        assert_eq!(apply_symbolic(0o600, " u+x , g+r ", false).unwrap(), 0o740);
    }

    #[test]
    fn sym_capital_x_on_dir() {
        // X on dir acts like x regardless of existing exec bits
        assert_eq!(apply_symbolic(0o644, "a+X", true).unwrap(), 0o755);
        // X on file without any exec bit is a no-op for exec
        assert_eq!(apply_symbolic(0o644, "a+X", false).unwrap(), 0o644);
        // X on file with at least one exec bit propagates
        assert_eq!(apply_symbolic(0o744, "g+X", false).unwrap(), 0o754);
    }

    #[test]
    fn sym_suid_sgid_sticky_add() {
        // u+s sets setuid
        assert_eq!(apply_symbolic(0o755, "u+s", false).unwrap(), 0o4755);
        // g+s sets setgid
        assert_eq!(apply_symbolic(0o755, "g+s", false).unwrap(), 0o2755);
        // +t sets sticky regardless of who
        assert_eq!(apply_symbolic(0o755, "+t", true).unwrap(), 0o1755);
    }

    #[test]
    fn sym_suid_sgid_remove() {
        assert_eq!(apply_symbolic(0o4755, "u-s", false).unwrap(), 0o0755);
        assert_eq!(apply_symbolic(0o2755, "g-s", false).unwrap(), 0o0755);
        assert_eq!(apply_symbolic(0o1755, "-t", true).unwrap(), 0o0755);
    }

    #[test]
    fn sym_equals_clears_specials() {
        // u=rwx on 0o4755 must clear suid (= replaces class, clearing special)
        assert_eq!(apply_symbolic(0o4755, "u=rwx", false).unwrap(), 0o0755);
        // g=rx on 0o2755 clears sgid
        assert_eq!(apply_symbolic(0o2755, "g=rx", false).unwrap(), 0o0755);
    }

    #[test]
    fn sym_bad_who_rejected() {
        assert!(apply_symbolic(0o644, "z+r", false).is_err());
    }

    #[test]
    fn sym_bad_perm_rejected() {
        assert!(apply_symbolic(0o644, "u+z", false).is_err());
    }

    #[test]
    fn sym_missing_op_rejected() {
        assert!(apply_symbolic(0o644, "urwx", false).is_err());
        assert!(apply_symbolic(0o644, "", false).is_err());
    }

    #[test]
    fn sym_high_bits_truncated() {
        // Stray bits above 7777 are masked off.
        assert_eq!(
            apply_symbolic(0o170000 | 0o0644, "u+x", false).unwrap(),
            0o0744
        );
    }

    #[test]
    fn sym_idempotent_add() {
        let r1 = apply_symbolic(0o644, "u+x", false).unwrap();
        let r2 = apply_symbolic(r1, "u+x", false).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn sym_preserves_special_on_unrelated_add() {
        // setgid must survive o+r
        assert_eq!(
            apply_symbolic(0o2750, "o+r", true).unwrap(),
            0o2754,
            "setgid must not be cleared by unrelated +r"
        );
    }
}
