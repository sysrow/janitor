//! `grant` / `revoke` / `preset` and other high-level mutation entry points.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::backup::{load_backup, save_backup};
use crate::errors::{PmError, Result};
use crate::groups::{add_user_to_group, ensure_group, remove_user_from_group};
use crate::helpers::{
    default_group_name, parse_access, path_chain, resolve_path_nofollow, validate_group_name,
};
use crate::locking::with_lock;
use crate::perms::{apply_group_bits, apply_restore};
use crate::render::{self, glyphs, paint, summary_line, DiagLevel, Style};
use crate::snapshot::snapshot_with_acl;
use crate::types::{AccessBits, Operation};
use crate::users::{group_exists, lookup_user, user_in_group};

pub fn cmd_grant(
    user: Option<&str>,
    group: Option<&str>,
    path: &str,
    access: &str,
    max_level: Option<usize>,
    recursive: bool,
    force_all_parents: bool,
    capture_acl: bool,
    exclude: &[String],
    dry_run: bool,
) -> Result<()> {
    if user.is_none() && group.is_none() {
        return Err(PmError::NoUserOrGroup);
    }
    if let Some(u) = user {
        lookup_user(u)?; // fail fast
    }

    let target = resolve_path_nofollow(path)?;
    crate::locks::ensure_not_locked(&target)?;
    let access_bits = parse_access(access)?;

    // Decide managed group.
    let group_name = match group {
        Some(g) => {
            validate_group_name(g)?;
            g.to_string()
        }
        None => default_group_name(&target),
    };

    let stdout_tty = is_terminal::is_terminal(std::io::stdout());
    let g = glyphs();

    // ── Title line (TTY only) ────────────────────────────────────────
    if stdout_tty {
        let u_disp = user.unwrap_or("-");
        let marker = if dry_run { "  [DRY RUN]" } else { "" };
        println!(
            "{} janitor grant {} {} {}{}",
            paint(Style::Separator, g.header_marker),
            paint(Style::User, u_disp),
            paint(Style::Primary, access),
            paint(Style::Primary, &target.display().to_string()),
            paint(Style::WarnMajor, marker)
        );
        println!();
    }

    // ── World-readable warning (top of block) ────────────────────────
    if let Ok(md) = std::fs::symlink_metadata(&target) {
        let other_bits = md.mode() & 0o007;
        if other_bits & 0o004 != 0 {
            render::eprint_diag(
                DiagLevel::Warning,
                &format!(
                    "{} is world-readable (o={:03o}); managed-group isolation won't help \
                     until 'other' read bit is cleared.",
                    target.display(),
                    other_bits
                ),
                Some(&format!(
                    "fix first: janitor chmod o-r {}",
                    target.display()
                )),
                &[],
            );
        }
    }

    // ── Narrate: group ensure + user add ─────────────────────────────
    // Narration only. The groupadd/gpasswd calls themselves happen inside
    // the transaction below, after the backup exists — doing them here
    // meant a later failure left account changes behind with no backup
    // recording that they had been made.
    let group_existed = group_exists(&group_name);
    let user_in = user.map(|u| user_in_group(u, &group_name)).unwrap_or(true);
    narrate_action(
        stdout_tty,
        dry_run,
        group_existed,
        "ensure group",
        &paint(Style::Group, &group_name),
    );
    if let Some(u) = user {
        narrate_action(
            stdout_tty,
            dry_run,
            user_in,
            "add user  ",
            &format!(
                "{} {} {}",
                paint(Style::User, u),
                paint(Style::Separator, "→"),
                paint(Style::Group, &group_name)
            ),
        );
    }

    // Build list of paths to touch.
    let chain = path_chain(&target, Path::new("/"));
    // `/` has no chain: path_chain stops at the root, so there is no target
    // segment to grant on. Refuse before anything mutates rather than
    // panicking on an empty chain further down.
    if chain.is_empty() {
        return Err(PmError::Other(format!(
            "refusing to grant on {}: it has no parent chain to make traversable\n       \
             (grant on a specific path inside it instead)",
            target.display()
        )));
    }
    let parents = if let Some(n) = max_level {
        let all_parents = &chain[..chain.len().saturating_sub(1)];
        let start = all_parents.len().saturating_sub(n);
        all_parents[start..].to_vec()
    } else {
        chain[..chain.len().saturating_sub(1)].to_vec()
    };

    let filtered_parents: Vec<PathBuf> = parents
        .iter()
        .filter(|p| {
            if force_all_parents {
                return true;
            }
            match std::fs::symlink_metadata(p) {
                Ok(md) => (md.mode() & 0o001) == 0,
                Err(_) => false,
            }
        })
        .cloned()
        .collect();

    // Narrate skipped world-traversable parents.
    for p in &parents {
        if !filtered_parents.contains(p) {
            if stdout_tty {
                println!(
                    "  {} {}  {}  {}",
                    paint(Style::Separator, "─"),
                    paint(Style::Label, "skipped           "),
                    paint(Style::Primary, &p.display().to_string()),
                    paint(Style::Label, "(already world-traversable)")
                );
            }
        }
    }

    let ex = crate::matcher::ExcludeSet::new(exclude)?;

    // Build full touched set: parents + target + recursive descendants.
    let mut touched: Vec<PathBuf> = filtered_parents.clone();
    touched.push(chain.last().unwrap().clone());
    let extra: Vec<PathBuf> = if recursive && target.is_dir() {
        collect_recursive(&target, &ex)
    } else {
        Vec::new()
    };
    let mut all_paths = touched.clone();
    all_paths.extend(extra.iter().cloned());

    with_lock(|| {
        // Single backup covering parents + target + recursive descendants.
        // It also records which account changes this grant is about to make,
        // so `restore` / `undo` can take them back out again.
        let mut backup_id: Option<String> = None;
        if !dry_run {
            let snap = snapshot_with_acl(&all_paths, capture_acl)?;
            let op = Operation {
                op_type: "grant".into(),
                user: user.map(String::from),
                group: Some(group_name.clone()),
                explicit_group: group.map(String::from),
                target: Some(target.display().to_string()),
                access: Some(access.to_string()),
                max_level,
                recursive: Some(recursive),
                parent_op: None,
                group_created: !group_existed,
                user_added: !user_in,
            };
            backup_id = Some(save_backup(snap, op)?);

            // Only now, with the backup on disk, touch the account database.
            ensure_group(&group_name, false)?;
            if let Some(u) = user {
                add_user_to_group(u, &group_name, false)?;
            }
        }

        // Parents: exactly `x` (traverse), replace existing group triad.
        let traverse_bits = AccessBits(0o1);
        for p in &filtered_parents {
            let before_mode = std::fs::symlink_metadata(p).map(|m| m.mode() & 0o7777).ok();
            apply_group_bits(p, &group_name, traverse_bits, dry_run, true)?;
            let after_mode = std::fs::symlink_metadata(p).map(|m| m.mode() & 0o7777).ok();
            let verb = if dry_run {
                "would g+rx        "
            } else {
                "chmod g+rx        "
            };
            if stdout_tty {
                let was = match before_mode {
                    Some(m) => format!("  (was {:04o})", m),
                    None => String::new(),
                };
                let now = match (after_mode, dry_run) {
                    (_, true) => String::new(),
                    (Some(m), false) => format!(" → {:04o}", m),
                    _ => String::new(),
                };
                println!(
                    "  {} {}  {}{}{}  {}",
                    paint(Style::Ok, g.check),
                    paint(Style::Label, verb),
                    paint(Style::Primary, &p.display().to_string()),
                    paint(Style::Label, &was),
                    paint(Style::Label, &now),
                    paint(Style::Label, "(parent traverse)")
                );
            }
        }

        // Target.
        let t_before = std::fs::symlink_metadata(&target)
            .map(|m| m.mode() & 0o7777)
            .ok();
        apply_group_bits(
            touched.last().unwrap(),
            &group_name,
            access_bits,
            dry_run,
            false,
        )?;
        let t_after = std::fs::symlink_metadata(&target)
            .map(|m| m.mode() & 0o7777)
            .ok();
        if stdout_tty {
            let verb = if dry_run {
                format!("would chgrp       ")
            } else {
                format!("chgrp             ")
            };
            println!(
                "  {} {}  {} → {}",
                paint(Style::Ok, g.check),
                paint(Style::Label, &verb),
                paint(Style::Primary, &target.display().to_string()),
                paint(Style::Group, &group_name)
            );
            let verb2 = if dry_run {
                "would chmod       "
            } else {
                "chmod             "
            };
            let was = t_before
                .map(|m| format!("  (was {:04o})", m))
                .unwrap_or_default();
            let now = match (t_after, dry_run) {
                (_, true) => String::new(),
                (Some(m), false) => format!(" → {:04o}", m),
                _ => String::new(),
            };
            println!(
                "  {} {}  {}{}{}  {}",
                paint(Style::Ok, g.check),
                paint(Style::Label, verb2),
                paint(Style::Primary, &target.display().to_string()),
                paint(Style::Label, &was),
                paint(Style::Label, &now),
                paint(Style::Label, &format!("(group +{})", access))
            );
        }

        // Recursive descendants.
        if !extra.is_empty() {
            if stdout_tty {
                println!(
                    "  {} {}  {} {}",
                    paint(Style::Ok, g.check),
                    paint(Style::Label, "recursive         "),
                    paint(Style::Primary, &extra.len().to_string()),
                    paint(Style::Label, "entries")
                );
            }
            extra
                .par_iter()
                .try_for_each(|p| apply_group_bits(p, &group_name, access_bits, dry_run, false))?;
        }

        // ── Footer: backup/undo/verify block ─────────────────────────
        println!();
        if let Some(bid) = &backup_id {
            println!(
                "{}  {}",
                paint(Style::Label, "backup:"),
                paint(Style::Primary, bid)
            );
            if stdout_tty {
                println!(
                    "{}    {}",
                    paint(Style::Label, "undo:"),
                    paint(Style::Primary, "janitor undo")
                );
                if let Some(u) = user {
                    println!(
                        "{}  {}",
                        paint(Style::Label, "verify:"),
                        paint(
                            Style::Primary,
                            &format!("sudo -u {} cat {}", u, target.display())
                        )
                    );
                }
            }
        } else {
            // dry-run footer
            let segs: Vec<(&str, &str)> = vec![("dry run", "— nothing changed")];
            let mut s = summary_line(&segs);
            s.push_str("  ");
            s.push_str(&paint(Style::Label, "(re-run without --dry-run to apply)"));
            println!("{s}");
        }
        Ok(())
    })
}

fn narrate_action(tty: bool, dry_run: bool, already_ok: bool, verb: &str, subject: &str) {
    if !tty {
        return;
    }
    let g = glyphs();
    // Pad verb to a fixed visible width so target columns align with
    // the rest of the grant output (skipped / chgrp / chmod lines).
    const VERB_COL: usize = 18;
    let verb_core = verb.trim();
    let verb_full = if dry_run && !already_ok {
        format!("would {verb_core}")
    } else {
        verb_core.to_string()
    };
    let pad = VERB_COL.saturating_sub(verb_full.chars().count());
    let padded_verb = format!("{verb_full}{}", " ".repeat(pad));
    let (bullet_style, bullet) = if already_ok {
        (Style::Separator, "─")
    } else if dry_run {
        (Style::Separator, "·")
    } else {
        (Style::Ok, g.check)
    };
    if already_ok {
        println!(
            "  {} {}  {}  {}",
            paint(bullet_style, bullet),
            paint(Style::Label, &padded_verb),
            subject,
            paint(Style::Label, "(already present)")
        );
    } else {
        println!(
            "  {} {}  {}",
            paint(bullet_style, bullet),
            paint(Style::Label, &padded_verb),
            subject
        );
    }
}

/// Collect all entries under a directory (excluding root itself).
/// Excluded directories are pruned: their children are never visited.
fn collect_recursive(target: &Path, exclude: &crate::matcher::ExcludeSet) -> Vec<PathBuf> {
    walkdir::WalkDir::new(target)
        .min_depth(1)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !exclude.is_excluded(e.path()))
        .filter_map(|e| e.ok())
        .map(|e| e.into_path())
        .collect()
}

pub fn cmd_revoke(user: &str, path: &str, group: Option<&str>, dry_run: bool) -> Result<()> {
    let target = resolve_path_nofollow(path)?;
    let group_name = match group {
        Some(g) => g.to_string(),
        None => default_group_name(&target),
    };
    let changed = remove_user_from_group(user, &group_name, dry_run)?;
    if changed && !dry_run {
        println!("removed {user} from {group_name}");
        println!("note: file mode/ownership unchanged; use `restore <id>` for full revert.");
    }
    Ok(())
}

pub fn cmd_backup(path: &str, recursive: bool, capture_acl: bool) -> Result<()> {
    let target = resolve_path_nofollow(path)?;
    let mut paths = vec![target.clone()];
    if recursive && target.is_dir() {
        let empty = crate::matcher::ExcludeSet::new(&[])?;
        paths.extend(collect_recursive(&target, &empty));
    }
    with_lock(|| {
        let snap = snapshot_with_acl(&paths, capture_acl)?;
        let count = snap.len();
        let bid = save_backup(
            snap,
            Operation {
                op_type: "manual-backup".into(),
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
            },
        )?;
        println!("backup: {bid}  ({count} entries)");
        Ok(())
    })
}

pub fn cmd_restore(
    backup_id: &str,
    dry_run: bool,
    assume_yes: bool,
    skip_missing: bool,
) -> Result<()> {
    let data = load_backup(backup_id)?;
    restore_with_preview(&data, dry_run, assume_yes, skip_missing, "restore")
}

/// Undo the most recent backup (newest by file mtime).
pub fn cmd_undo(dry_run: bool, assume_yes: bool, skip_missing: bool) -> Result<()> {
    let files = crate::backup::list_backup_files()?;
    let latest = files
        .iter()
        .max_by_key(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH)
        })
        .ok_or_else(|| PmError::Other("no backups to undo  (try `janitor list-backups`)".into()))?;
    let bid = latest
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| PmError::Other("invalid backup filename".into()))?
        .to_string();
    let data = load_backup(&bid)?;
    restore_with_preview(&data, dry_run, assume_yes, skip_missing, "undo")
}

fn restore_with_preview(
    data: &crate::types::Backup,
    dry_run: bool,
    assume_yes: bool,
    skip_missing: bool,
    verb: &str,
) -> Result<()> {
    let stdout_tty = is_terminal::is_terminal(std::io::stdout());
    let g = glyphs();

    // Age / stale warning.
    let age_str = backup_age(&data.timestamp);
    let is_stale = backup_age_hours(&data.timestamp).unwrap_or(0) > 24;

    if stdout_tty {
        println!(
            "\n  {} {}  {}",
            paint(Style::Separator, g.header_marker),
            paint(Style::Primary, &format!("janitor {verb}")),
            paint(Style::BackupId, &data.id)
        );
        println!();
        let (action, target) = format_op_split(&data.operation);
        println!("  {}", paint(Style::Label, "target operation"));
        println!(
            "    {}  {}",
            paint(Style::Label, "id:        "),
            paint(Style::BackupId, &data.id)
        );
        println!(
            "    {}  {}  {}",
            paint(Style::Label, "created:   "),
            paint(Style::Primary, &data.timestamp),
            paint(Style::Label, &format!("({age_str} ago)"))
        );
        println!(
            "    {}  {}",
            paint(Style::Label, "operation: "),
            paint(Style::Primary, &action)
        );
        println!(
            "    {}  {}",
            paint(Style::Label, "target:    "),
            paint(Style::Primary, &target)
        );
        println!(
            "    {}  {}  {}",
            paint(Style::Label, "entries:   "),
            paint(Style::Primary, &data.entries.len().to_string()),
            paint(Style::Label, "paths")
        );
        if is_stale {
            println!();
            render::eprint_diag(
                DiagLevel::Warning,
                &format!(
                    "backup is {} old — state may have drifted since it was taken.",
                    age_str
                ),
                Some("review the diff below carefully."),
                &[],
            );
        }
    } else {
        println!(
            "{verb} {} (op: {}, {} entries)",
            data.id,
            data.operation.op_type,
            data.entries.len()
        );
    }

    // Compute and show the diff preview (current vs. recorded state).
    let diffs = crate::perms::preview_restore(&data.entries);
    if stdout_tty {
        println!();
        println!(
            "  {} {}",
            paint(Style::Label, "changes"),
            paint(Style::Label, &format!("({} entries)", diffs.len()))
        );
        let max_show = 20;
        for (i, line) in diffs.iter().enumerate() {
            if i >= max_show {
                println!(
                    "    {} ... and {} more",
                    paint(Style::Separator, "…"),
                    diffs.len() - max_show
                );
                break;
            }
            println!("    {}", line);
        }
        if diffs.is_empty() {
            println!(
                "    {}",
                paint(Style::Label, "(no changes — current state matches backup)")
            );
        }
    }

    // Confirm.
    if !dry_run && !diffs.is_empty() && !assume_yes {
        if !stdout_tty {
            return Err(PmError::Other(
                "refusing to apply non-dry-run restore without --yes on a pipe".into(),
            ));
        }
        println!();
        print!("  Proceed?  [y/N]: ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut reply = String::new();
        std::io::stdin().read_line(&mut reply).ok();
        let ok = reply.trim().eq_ignore_ascii_case("y") || reply.trim().eq_ignore_ascii_case("yes");
        if !ok {
            println!("  {}", paint(Style::Label, "cancelled."));
            return Ok(());
        }
    }

    // Restore is a mutation like any other: it must respect `janitor lock`
    // and hold the global lock so it cannot interleave with a concurrent
    // grant/chmod that is halfway through its own backup.
    let errors = with_lock(|| {
        for e in &data.entries {
            crate::locks::ensure_not_locked(&e.path)?;
        }
        let mut errors = apply_restore(&data.entries, dry_run, skip_missing);
        errors += revert_account_changes(&data.operation, dry_run);
        Ok(errors)
    })?;
    if errors > 0 {
        return Err(PmError::Other(format!("{errors} error(s) during restore")));
    }
    if stdout_tty && !dry_run {
        println!();
        println!(
            "  {} {}: {}  ({} entries)",
            paint(Style::Ok, g.check),
            paint(Style::Label, &format!("{verb} applied")),
            paint(Style::Primary, &data.id),
            data.entries.len()
        );
        println!(
            "  {}",
            paint(
                Style::Label,
                "note: the reverse operation creates no new backup."
            )
        );
    } else if !stdout_tty && !dry_run {
        println!("backup: {}", data.id);
    }
    Ok(())
}

/// Undo the group membership and group creation a `grant` performed.
///
/// A grant is two things: file metadata and account bookkeeping. Restoring
/// only the former left the user inside the managed group forever, so the
/// access the grant handed out survived its own "full revert". Only changes
/// this backup recorded making are undone, and `delete_managed_group`
/// refuses anything that is not a `pm_` group.
///
/// Returns the number of failures, so they land in the restore error count.
fn revert_account_changes(op: &crate::types::Operation, dry_run: bool) -> u32 {
    let mut errors = 0u32;
    let group = match &op.group {
        Some(g) if op.user_added || op.group_created => g,
        _ => return 0,
    };
    if op.user_added {
        if let Some(u) = &op.user {
            if dry_run {
                println!("[dry-run] gpasswd -d {u} {group}");
            } else if let Err(e) = remove_user_from_group(u, group, false) {
                eprintln!("error removing {u} from {group}: {e}");
                errors += 1;
            }
        }
    }
    if op.group_created {
        if dry_run {
            println!("[dry-run] groupdel {group}");
        } else {
            match crate::groups::delete_managed_group(group) {
                Ok(true) => println!("removed group {group}"),
                Ok(false) => {}
                Err(e) => {
                    eprintln!("error deleting group {group}: {e}");
                    errors += 1;
                }
            }
        }
    }
    errors
}

fn format_op_summary(op: &crate::types::Operation) -> String {
    let mut parts = vec![op.op_type.clone()];
    if let Some(a) = &op.access {
        parts.push(a.clone());
    }
    if let Some(u) = &op.user {
        parts.push(format!("(user {u})"));
    }
    if let Some(t) = &op.target {
        parts.push(t.clone());
    }
    parts.join(" ")
}

/// Split op into (action, target) for tabular rendering.
fn format_op_split(op: &crate::types::Operation) -> (String, String) {
    let mut head = op.op_type.clone();
    if let Some(a) = &op.access {
        head.push(' ');
        head.push_str(a);
    }
    if let Some(u) = &op.user {
        head.push_str(&format!(" (user {u})"));
    }
    let tgt = op.target.clone().unwrap_or_else(|| "-".into());
    (head, tgt)
}

fn parse_backup_ts(ts: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|naive| naive.and_utc())
        })
}

/// Returns something like "2h 14m ago" or "3d" etc.
fn backup_age(ts: &str) -> String {
    let now = chrono::Utc::now();
    let when = parse_backup_ts(ts).unwrap_or(now);
    let d = now.signed_duration_since(when);
    let secs = d.num_seconds().max(0);
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs < 86_400 * 30 {
        format!("{}d", secs / 86_400)
    } else {
        format!("{}mo", secs / (86_400 * 30))
    }
}

fn backup_age_hours(ts: &str) -> Option<i64> {
    let now = chrono::Utc::now();
    parse_backup_ts(ts).map(|d| now.signed_duration_since(d).num_hours())
}

/// Parse `1h`, `30m`, `2d`, `1w`, `45s` into a `chrono::Duration`.
fn parse_since(s: &str) -> Result<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PmError::Other("empty --since duration".into()));
    }
    let (num, unit) = s.split_at(
        s.char_indices()
            .find(|(_, c)| !c.is_ascii_digit())
            .map(|(i, _)| i)
            .unwrap_or(s.len()),
    );
    let n: i64 = num
        .parse()
        .map_err(|_| PmError::Other(format!("invalid --since: {s}")))?;
    // The unchecked constructors panic on overflow, so `--since
    // 9223372036854775807w` used to abort with exit 101 instead of a
    // validation error.
    let d = match unit {
        "s" | "" => chrono::Duration::try_seconds(n),
        "m" => chrono::Duration::try_minutes(n),
        "h" => chrono::Duration::try_hours(n),
        "d" => chrono::Duration::try_days(n),
        "w" => chrono::Duration::try_weeks(n),
        other => {
            return Err(PmError::Other(format!(
                "invalid --since unit `{other}` (use s/m/h/d/w)"
            )))
        }
    };
    d.ok_or_else(|| PmError::Other(format!("--since duration out of range: {s}")))
}

/// Print backup history for a path substring (newest first).
pub fn cmd_history(path: &str, since: Option<&str>, as_json: bool) -> Result<()> {
    let cutoff = since
        .map(parse_since)
        .transpose()?
        .map(|d| chrono::Utc::now() - d);
    let files = crate::backup::list_backup_files()?;
    let mut rows: Vec<crate::types::Backup> = Vec::new();
    for f in &files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        let data: std::result::Result<crate::types::Backup, String> = match ext {
            "mpk" => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                }),
            _ => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(fh))
                        .map_err(|e| e.to_string())
                }),
        };
        if let Ok(b) = data {
            let target_match = b
                .operation
                .target
                .as_deref()
                .map(|t| t.contains(path))
                .unwrap_or(false);
            if !target_match {
                continue;
            }
            if let Some(cut) = cutoff {
                if let Some(ts) = parse_backup_ts(&b.timestamp) {
                    if ts < cut {
                        continue;
                    }
                }
            }
            rows.push(b);
        }
    }
    rows.reverse(); // newest first
    if as_json {
        let out: Vec<serde_json::Value> = rows
            .iter()
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "timestamp": b.timestamp,
                    "type": b.operation.op_type,
                    "user": b.operation.user,
                    "target": b.operation.target,
                    "entries": b.entries.len(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if rows.is_empty() {
        println!(
            "{}",
            paint(Style::Label, &format!("(no backups touching {path})"))
        );
        return Ok(());
    }
    let stdout_tty = is_terminal::is_terminal(std::io::stdout());
    if !stdout_tty {
        // pipe mode: id per line
        for b in &rows {
            println!("{}", b.id);
        }
        return Ok(());
    }
    println!();
    println!(
        "  {}",
        paint(
            Style::Primary,
            &format!(
                "history for {path}  ({} operation{})",
                rows.len(),
                if rows.len() == 1 { "" } else { "s" }
            )
        )
    );
    println!();
    let header = &["when", "operation", "target", "by", "entries", "id"];
    let table_rows: Vec<Vec<String>> = rows
        .iter()
        .map(|b| {
            let age = backup_age(&b.timestamp);
            let (action, target) = format_op_split(&b.operation);
            let user = b.operation.user.as_deref().unwrap_or("-");
            let id_tail = b.id.rsplit('-').next().unwrap_or(&b.id);
            vec![
                paint(Style::Label, &format!("{age} ago")),
                paint(Style::Primary, &action),
                paint(Style::Primary, &target),
                paint(Style::Label, user),
                paint(Style::Label, &b.entries.len().to_string()),
                paint(Style::BackupId, &format!("…{id_tail}")),
            ]
        })
        .collect();
    let table = render::aligned_table(header, &table_rows);
    for line in table.lines() {
        println!("  {line}");
    }
    Ok(())
}

pub fn cmd_lock(path: &str, reason: Option<&str>) -> Result<()> {
    let p = resolve_path_nofollow(path)?;
    crate::locks::add(&p, reason)?;
    let g = glyphs();
    println!(
        "  {} {}  {}",
        paint(Style::Ok, g.check),
        paint(Style::Label, "locked"),
        paint(Style::Primary, &p.display().to_string())
    );
    if let Some(r) = reason {
        println!(
            "     {}  {}",
            paint(Style::Label, "reason:"),
            paint(Style::Primary, r)
        );
    }
    println!(
        "     {}  {}",
        paint(Style::Label, "note:  "),
        paint(
            Style::Label,
            "grant / chmod / chown on this path will now fail fast."
        )
    );
    Ok(())
}

pub fn cmd_unlock(path: &str) -> Result<()> {
    let p = resolve_path_nofollow(path)?;
    crate::locks::remove(&p)?;
    let g = glyphs();
    println!(
        "  {} {}  {}",
        paint(Style::Ok, g.check),
        paint(Style::Label, "unlocked"),
        paint(Style::Primary, &p.display().to_string())
    );
    Ok(())
}

pub fn cmd_locks(as_json: bool) -> Result<()> {
    let locks = crate::locks::load()?;
    if as_json {
        let out: Vec<serde_json::Value> = locks
            .iter()
            .map(|l| serde_json::json!({ "path": l.path, "reason": l.reason }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if locks.is_empty() {
        println!("{}", paint(Style::Label, "(no active locks)"));
        return Ok(());
    }
    println!();
    println!(
        "  {}  {}",
        paint(Style::Primary, "active locks"),
        paint(Style::Label, &format!("({})", locks.len()))
    );
    for l in &locks {
        println!(
            "    {}  {}",
            paint(Style::Primary, &l.path.display().to_string()),
            paint(Style::Label, &format!("— {}", l.reason))
        );
    }
    println!();
    Ok(())
}

pub fn cmd_list_backups(as_json: bool, path_substr: Option<&str>) -> Result<()> {
    let files = crate::backup::list_backup_files()?;
    // Helper closure: check whether a loaded backup matches the optional target filter.
    let matches_filter = |b: &crate::types::Backup| -> bool {
        match path_substr {
            None => true,
            Some(s) => b
                .operation
                .target
                .as_deref()
                .map(|t| t.contains(s))
                .unwrap_or(false),
        }
    };
    if as_json {
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for f in &files {
            let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
            let data_res: std::result::Result<crate::types::Backup, String> = match ext {
                "mpk" => std::fs::File::open(f)
                    .map_err(|e| e.to_string())
                    .and_then(|fh| {
                        rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                    }),
                _ => std::fs::File::open(f)
                    .map_err(|e| e.to_string())
                    .and_then(|fh| {
                        serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(
                            fh,
                        ))
                        .map_err(|e| e.to_string())
                    }),
            };
            if let Ok(data) = data_res {
                if !matches_filter(&data) {
                    continue;
                }
                rows.push(serde_json::json!({
                    "id": data.id,
                    "timestamp": data.timestamp,
                    "type": data.operation.op_type,
                    "user": data.operation.user,
                    "group": data.operation.group,
                    "target": data.operation.target,
                    "entries": data.entries.len(),
                }));
            }
        }
        rows.reverse(); // newest first
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }
    if files.is_empty() {
        println!(
            "{}",
            paint(
                Style::Label,
                &format!("(no backups in {})", crate::config::backup_root().display())
            )
        );
        return Ok(());
    }
    let stdout_tty = is_terminal::is_terminal(std::io::stdout());
    // Collect rows first.
    // (id, age, op_summary, when, entries, action, target)
    let mut rows: Vec<(String, String, String, String, usize, String, String)> = Vec::new();
    let mut corrupt: Vec<String> = Vec::new();
    for f in &files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        let read_result: std::result::Result<crate::types::Backup, String> = match ext {
            "mpk" => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    rmp_serde::from_read(std::io::BufReader::new(fh)).map_err(|e| e.to_string())
                }),
            _ => std::fs::File::open(f)
                .map_err(|e| e.to_string())
                .and_then(|fh| {
                    serde_json::from_reader::<_, crate::types::Backup>(std::io::BufReader::new(fh))
                        .map_err(|e| e.to_string())
                }),
        };
        match read_result {
            Ok(data) => {
                if !matches_filter(&data) {
                    continue;
                }
                let age = backup_age(&data.timestamp);
                let when = data.timestamp.clone();
                let op_sum = format_op_summary(&data.operation);
                let (action, target) = format_op_split(&data.operation);
                rows.push((
                    data.id,
                    age,
                    op_sum,
                    when,
                    data.entries.len(),
                    action,
                    target,
                ));
            }
            Err(e) => {
                let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
                corrupt.push(format!("{stem}: {e}"));
            }
        }
    }
    rows.reverse(); // newest first
    if !stdout_tty {
        for r in &rows {
            println!("{}", r.0);
        }
        return Ok(());
    }
    println!();
    println!(
        "  {}  {}",
        paint(
            Style::Primary,
            &format!("backups in {}", crate::config::backup_root().display())
        ),
        paint(Style::Label, &format!("({} total)", rows.len()))
    );
    println!();
    let header = &["when", "age", "operation", "target", "entries", "id"];
    let trows: Vec<Vec<String>> = rows
        .iter()
        .map(|(id, age, _op_sum, when, entries, action, target)| {
            vec![
                paint(Style::Label, when),
                paint(Style::Label, &format!("{age} ago")),
                paint(Style::Primary, action),
                paint(Style::Primary, target),
                paint(Style::Label, &entries.to_string()),
                paint(Style::BackupId, id),
            ]
        })
        .collect();
    let table = render::aligned_table(header, &trows);
    for line in table.lines() {
        println!("  {line}");
    }
    if !corrupt.is_empty() {
        println!();
        for c in &corrupt {
            render::eprint_diag(
                DiagLevel::Warning,
                &format!("corrupt backup file: {c}"),
                None,
                &[],
            );
        }
    }
    println!();
    println!(
        "  {}  {}",
        paint(Style::Label, "tip:"),
        paint(Style::Primary, "janitor restore <id>  #  or `janitor undo`")
    );
    Ok(())
}
