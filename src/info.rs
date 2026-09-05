//! `janitor info PATH`: one-shot summary of a path's permissions.
//!
//! Uses the shared `render` primitives: a header-marker + kind line, a
//! two-column owner/mode/size/mtime grid, an indented ACL tree, and a
//! separate "Access for <user>" block when `-U` is passed.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::acl::get_acl;
use crate::errors::Result;
use crate::render::{
    self, badge, header_line, kv_grid, paint, rule, section_title, DiagLevel, KvRow, Style,
};

fn file_type_char(md: &fs::Metadata) -> char {
    let ft = md.file_type();
    if ft.is_symlink() {
        'l'
    } else if ft.is_dir() {
        'd'
    } else if ft.is_fifo() {
        'p'
    } else if ft.is_socket() {
        's'
    } else if ft.is_block_device() {
        'b'
    } else if ft.is_char_device() {
        'c'
    } else {
        '-'
    }
}

fn user_name(uid: u32) -> (String, bool) {
    use nix::unistd::{Uid, User};
    match User::from_uid(Uid::from_raw(uid)).ok().flatten() {
        Some(u) => (u.name, false),
        None => (format!("#{uid}"), true),
    }
}

fn group_name(gid: u32) -> (String, bool) {
    use nix::unistd::{Gid, Group};
    match Group::from_gid(Gid::from_raw(gid)).ok().flatten() {
        Some(g) => (g.name, false),
        None => (format!("#{gid}"), true),
    }
}

/// Absolute ISO-8601 UTC plus a relative hint ("3d ago").
///
/// `st_mtime` is signed: pre-1970 timestamps are negative and casting them
/// to u64 turned them into dates tens of billions of years in the future.
fn format_mtime(md: &fs::Metadata) -> String {
    let secs = md.mtime();
    let abs = match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        None => format!("(timestamp out of range: {secs})"),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(secs);
    let rel = if now > secs {
        humanize_age((now - secs) as u64)
    } else {
        "just now".to_string()
    };
    format!("{abs}  ({rel})")
}

fn humanize_age(secs: u64) -> String {
    const M: u64 = 60;
    const H: u64 = 60 * M;
    const D: u64 = 24 * H;
    if secs < M {
        format!("{secs}s ago")
    } else if secs < H {
        format!("{}m ago", secs / M)
    } else if secs < D {
        format!("{}h ago", secs / H)
    } else if secs < 30 * D {
        format!("{}d ago", secs / D)
    } else if secs < 365 * D {
        format!("{}mo ago", secs / (30 * D))
    } else {
        format!("{}y ago", secs / (365 * D))
    }
}

/// Effective (read, write, execute/traverse) for `username` on this inode.
fn effective_for_user(
    path: &std::path::Path,
    username: &str,
) -> Result<(bool, bool, bool, String)> {
    let d = crate::access::effective_for_user_path(path, username)?;
    Ok((d.read, d.write, d.exec, d.reason))
}

fn kind_label(ft: char) -> &'static str {
    match ft {
        'd' => "directory",
        'l' => "symlink",
        'p' => "fifo",
        's' => "socket",
        'b' => "block device",
        'c' => "char device",
        _ => "regular file",
    }
}

pub fn cmd_info(path: &str, for_user: Option<&str>) -> Result<()> {
    // Do not canonicalize: we want to inspect symlinks themselves.
    let p = {
        let expanded = if let Some(stripped) = path.strip_prefix('~') {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            std::path::PathBuf::from(format!("{home}{stripped}"))
        } else {
            std::path::PathBuf::from(path)
        };
        if let Err(e) = expanded.symlink_metadata() {
            return Err(match e.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    crate::errors::PmError::PathInaccessible(expanded)
                }
                _ => crate::errors::PmError::PathNotFound(expanded),
            });
        }
        expanded
    };
    let md = fs::symlink_metadata(&p).map_err(|e| crate::errors::PmError::Other(e.to_string()))?;
    let mode = md.permissions().mode() & 0o7777;
    let is_dir = md.is_dir();
    let is_symlink = md.file_type().is_symlink();
    let ft = file_type_char(&md);

    let (uname, u_orphan) = user_name(md.uid());
    let (gname, g_orphan) = group_name(md.gid());

    // ── Badges (shown in the header after the kind label) ─────────────
    let mut badges: Vec<String> = Vec::new();
    if mode & 0o4000 != 0 {
        badges.push(badge("setuid", Style::WarnMajor));
    }
    if mode & 0o2000 != 0 {
        badges.push(badge("setgid", Style::WarnMajor));
    }
    if mode & 0o1000 != 0 {
        badges.push(badge("sticky", Style::WarnMajor));
    }
    if mode & 0o002 != 0 && !is_symlink {
        badges.push(badge("world-writable", Style::Danger));
    }
    if u_orphan {
        badges.push(badge("orphan uid", Style::Danger));
    }
    if g_orphan {
        badges.push(badge("orphan gid", Style::Danger));
    }

    // ── Header ────────────────────────────────────────────────────────
    let mut kind = kind_label(ft).to_string();
    if is_symlink {
        if let Ok(target) = fs::read_link(&p) {
            kind.push_str(" → ");
            kind.push_str(&target.display().to_string());
        }
    }
    println!();
    println!(
        "{}",
        header_line(&p.display().to_string(), Some(&kind), &badges)
    );
    println!("  {}", rule(61));

    // ── Two-column grid: owner/group  |  mode/size/mtime ──────────────
    let mode_str = format!(
        "{}  {}  {}",
        paint(Style::Primary, &format!("{mode:04o}")),
        paint(Style::Separator, "·"),
        render::mode_symbolic_colored(mode, is_dir, is_symlink)
    );
    let owner_val = format!(
        "{}  {}",
        paint(if u_orphan { Style::Danger } else { Style::User }, &uname),
        paint(Style::Label, &format!("(uid {})", md.uid()))
    );
    let group_val = format!(
        "{}  {}",
        paint(
            if g_orphan {
                Style::Danger
            } else {
                Style::Group
            },
            &gname
        ),
        paint(Style::Label, &format!("(gid {})", md.gid()))
    );

    let key_w = 6;
    let mtime_val = paint(Style::Primary, &format_mtime(&md));
    let mut rows: Vec<KvRow> = Vec::with_capacity(3);
    rows.push((
        ("owner", owner_val.as_str()),
        Some(("mode", mode_str.as_str())),
    ));
    let size_val;
    if ft == '-' || ft == 'd' {
        size_val = format!(
            "{}  {}",
            paint(Style::Primary, &render::format_size(md.len())),
            paint(Style::Label, &format!("({} bytes)", md.len()))
        );
        rows.push((
            ("group", group_val.as_str()),
            Some(("size", size_val.as_str())),
        ));
        rows.push((("mtime", mtime_val.as_str()), None));
    } else {
        rows.push((
            ("group", group_val.as_str()),
            Some(("mtime", mtime_val.as_str())),
        ));
    }
    // kv_grid appends '\n' per row; prefix each line with the two-space
    // indent that the rest of the card uses.
    let grid = kv_grid(&rows, key_w, 2);
    for line in grid.lines() {
        println!("  {}", line);
    }

    // ── ACL section ───────────────────────────────────────────────────
    if ft != 'l' {
        match get_acl(&p) {
            Ok(Some(acl)) => {
                let entries: Vec<String> = acl
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_string())
                    .collect();
                if !entries.is_empty() {
                    println!();
                    println!("  {}", section_title("ACL"));
                    let g = render::glyphs();
                    let n = entries.len();
                    for (i, entry) in entries.iter().enumerate() {
                        let last = i + 1 == n;
                        let connector = if last { g.tree_last } else { g.tree_mid };
                        println!(
                            "  {}{}",
                            paint(Style::Separator, connector),
                            format_acl_entry(entry)
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(_) => {
                println!();
                println!("  {}", paint(Style::Label, "acl   (unavailable)"));
            }
        }
    }

    // ── Access section (only with -U) ─────────────────────────────────
    if let Some(user) = for_user {
        let (r, w, x, reason) = effective_for_user(&p, user)?;
        let bits_raw = format!(
            "{}{}{}",
            if r { 'r' } else { '-' },
            if w { 'w' } else { '-' },
            if x { 'x' } else { '-' }
        );
        let bits = color_bits(r, w, x, &bits_raw);
        println!();
        println!(
            "  {} {}",
            section_title("Access for"),
            paint(Style::User, user)
        );
        let g = render::glyphs();
        println!(
            "  {}{}   {}",
            paint(Style::Separator, g.tree_last),
            bits,
            paint(Style::Label, &format!("via {reason}"))
        );
        println!(
            "  {}   {}",
            " ".repeat(3),
            paint(
                Style::Label,
                "(on this inode; use `explain` for the parent chain)"
            )
        );
    }

    // ── Footer warnings ───────────────────────────────────────────────
    if mode & 0o4000 != 0 {
        println!();
        let g = render::glyphs();
        println!(
            "  {}  {}",
            paint(Style::WarnMajor, g.warn),
            paint(
                Style::WarnMajor,
                &format!("setuid bit is set: file runs as owner ({uname}) when executed.")
            )
        );
    } else if mode & 0o002 != 0 && !is_symlink && !is_dir {
        // Stderr diagnostic so piped stdout stays clean.
        render::eprint_diag(
            DiagLevel::Warning,
            "file is world-writable",
            Some(&p.display().to_string()),
            &[("help", "tighten with: janitor chmod o-w <path>")],
        );
    }

    println!();
    Ok(())
}

fn format_acl_entry(entry: &str) -> String {
    // getfacl -c canonical lines look like `user:bob:r--` / `mask::rw-`.
    let mut parts = entry.splitn(3, ':');
    let kind = parts.next().unwrap_or(entry);
    let qual = parts.next().unwrap_or("");
    let perms = parts.next().unwrap_or("");
    // Build qualifier visible text: `user:` / `user:bob` / `group:` / `mask:` / `other:`.
    let qual_text = if qual.is_empty() {
        format!("{kind}:")
    } else {
        format!("{kind}:{qual}")
    };
    let vis_cols = qual_text.chars().count();
    const QUAL_COL: usize = 16;
    let pad = if vis_cols < QUAL_COL {
        QUAL_COL - vis_cols
    } else {
        2
    };
    // Paint qualifier.
    let qual_style = match kind {
        "user" => Style::User,
        "group" => Style::Group,
        _ => Style::Label,
    };
    let mut out = String::new();
    out.push_str(&paint(Style::Label, &format!("{kind}:")));
    if !qual.is_empty() {
        out.push_str(&paint(qual_style, qual));
    }
    out.push_str(&" ".repeat(pad));
    for c in perms.chars() {
        match c {
            'r' | 'w' => out.push_str(&paint(Style::Ok, &c.to_string())),
            'x' => out.push_str(&paint(Style::Traverse, &c.to_string())),
            '-' => out.push_str(&paint(Style::Separator, "-")),
            _ => out.push(c),
        }
    }
    out
}

fn color_bits(r: bool, w: bool, x: bool, raw: &str) -> String {
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        let ok = match i {
            0 => r,
            1 => w,
            2 => x,
            _ => false,
        };
        if c == '-' {
            out.push_str(&paint(Style::Separator, "-"));
        } else if ok {
            out.push_str(&paint(
                if i == 2 { Style::Traverse } else { Style::Ok },
                &c.to_string(),
            ));
        } else {
            out.push(c);
        }
    }
    out
}
