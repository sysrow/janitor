//! `tree`: colored permission tree with per-user access highlighting.
//!
//! Variant A (Classic+): evolves the `tree(1)` layout with two-space
//! column gutters, ACL/setuid badges, an ACL-aware `-U` access lens, and
//! a summary line with category counts (`dirs · files · setuid · sticky
//! · acl · denied`).

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};

use crate::access::effective_for_user_path;
use crate::acl::has_extended_acl;
use crate::cli::ColorMode;
use crate::errors::Result;
use crate::helpers::{path_chain, resolve_path};
use crate::render::{self, badge, glyphs, paint, summary_line, Style};
use crate::users::{gid_to_name, uid_to_name};

// ── Flags / counters ───────────────────────────────────────────────────

#[derive(Default)]
struct Counts {
    dirs: usize,
    files: usize,
    denied: usize,
    setuid: usize,
    setgid: usize,
    sticky: usize,
    world_write: usize,
    acl: usize,
    orphan: usize,
}

// ── Public entry point ─────────────────────────────────────────────────

pub fn cmd_tree(
    path: &str,
    max_depth: Option<usize>,
    show_parents: bool,
    highlight: Option<&str>,
    for_user: Option<&str>,
    color_mode: ColorMode,
    show_acl: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    // Re-initialize shared color state for this command: --color wins over
    // the global auto-detection that main() already performed.
    render::init_color(color_mode);

    // Highlight chain (top-down path from / to highlighted node).
    let highlight_set: HashSet<PathBuf> = match highlight {
        Some(h) => {
            let hp = resolve_path(h)?;
            path_chain(&hp, Path::new("/")).into_iter().collect()
        }
        None => HashSet::new(),
    };

    let mut counts = Counts::default();

    // Parent-chain banner above the root.
    if show_parents {
        let parents = path_chain(&root, Path::new("/"));
        for p in &parents[..parents.len().saturating_sub(1)] {
            let arrow = paint(Style::Separator, "↑");
            println!(
                "{}  {}",
                arrow,
                paint(Style::Label, &p.display().to_string())
            );
        }
        if parents.len() > 1 {
            println!("{}", render::rule(60));
        }
    }

    walk_tree(
        &root,
        "",
        true,
        true,
        0,
        max_depth,
        &highlight_set,
        for_user,
        true,
        &mut counts,
        show_acl,
    );

    // ── Summary (stderr? no — stay on stdout for tree; this one is the
    // visual end of the render, not an operation report) ─────────────
    println!();
    let dir_word = if counts.dirs == 1 {
        "directory"
    } else {
        "directories"
    };
    let file_word = if counts.files == 1 { "file" } else { "files" };
    let dirs = counts.dirs.to_string();
    let files = counts.files.to_string();
    let setuid = counts.setuid.to_string();
    let setgid = counts.setgid.to_string();
    let sticky = counts.sticky.to_string();
    let ww = counts.world_write.to_string();
    let acl = counts.acl.to_string();
    let den = counts.denied.to_string();
    let orp = counts.orphan.to_string();
    let segs: Vec<(&str, &str)> = vec![
        (dirs.as_str(), dir_word),
        (files.as_str(), file_word),
        (
            if counts.setuid > 0 {
                setuid.as_str()
            } else {
                ""
            },
            "setuid",
        ),
        (
            if counts.setgid > 0 {
                setgid.as_str()
            } else {
                ""
            },
            "setgid",
        ),
        (
            if counts.sticky > 0 {
                sticky.as_str()
            } else {
                ""
            },
            "sticky",
        ),
        (
            if counts.world_write > 0 {
                ww.as_str()
            } else {
                ""
            },
            "world-writable",
        ),
        (if counts.acl > 0 { acl.as_str() } else { "" }, "acl"),
        (if counts.orphan > 0 { orp.as_str() } else { "" }, "orphan"),
        (
            if counts.denied > 0 { den.as_str() } else { "" },
            "unreadable",
        ),
    ];
    println!("{}", summary_line(&segs));

    // Legend (only in TTY with colors on).
    if let Some(u) = for_user {
        if render::colors_on() {
            println!();
            println!(
                "  {} readable by {}    {} traverse-only    {} no access",
                paint(Style::Ok, "●"),
                paint(Style::User, u),
                paint(Style::Traverse, "●"),
                paint(Style::Deny, "●"),
            );
        }
    }
    if !highlight_set.is_empty() && render::colors_on() {
        println!(
            "  {} highlight chain",
            paint(Style::Highlight, glyphs().bullet_filled)
        );
    }

    Ok(())
}

// ── Recursive walk ─────────────────────────────────────────────────────

fn walk_tree(
    path: &Path,
    prefix: &str,
    is_root: bool,
    is_last: bool,
    depth: usize,
    max_depth: Option<usize>,
    highlight_set: &HashSet<PathBuf>,
    for_user: Option<&str>,
    parent_reachable: bool,
    counts: &mut Counts,
    show_acl: bool,
) {
    let g = glyphs();
    let connector = if is_root {
        ""
    } else if is_last {
        g.tree_last
    } else {
        g.tree_mid
    };

    let full_prefix = format!("{prefix}{}", paint(Style::Separator, connector));
    let raw_prefix_cols = depth * 3; // each connector / vert / space block = 3 cols (unicode BMP glyphs)

    let (self_reachable, child_md) = print_line(
        path,
        &full_prefix,
        raw_prefix_cols,
        is_root,
        highlight_set,
        for_user,
        parent_reachable,
        counts,
        show_acl,
    );

    if let Some(max) = max_depth {
        if depth >= max {
            return;
        }
    }

    let md = match child_md {
        Some(m) => m,
        None => return,
    };
    if md.file_type().is_symlink() || !md.is_dir() {
        return;
    }

    let children: Vec<PathBuf> = match fs::read_dir(path) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
            v.sort();
            v
        }
        Err(_) => {
            let child_prefix = if is_last || is_root {
                format!("{prefix}   ")
            } else {
                format!("{prefix}{}", paint(Style::Separator, g.tree_vert))
            };
            println!(
                "{child_prefix}{}{}",
                paint(Style::Separator, g.tree_last),
                paint(Style::Label, "<permission denied>")
            );
            counts.denied += 1;
            return;
        }
    };

    let child_prefix = if is_root {
        prefix.to_string()
    } else if is_last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}{}", paint(Style::Separator, g.tree_vert))
    };

    for (i, child) in children.iter().enumerate() {
        walk_tree(
            child,
            &child_prefix,
            false,
            i == children.len() - 1,
            depth + 1,
            max_depth,
            highlight_set,
            for_user,
            self_reachable,
            counts,
            show_acl,
        );
    }
}

// ── Single-line rendering ──────────────────────────────────────────────

/// Render one entry. Returns (node_reachable_for_for_user, Metadata).
fn print_line(
    path: &Path,
    prefix: &str,
    prefix_cols: usize,
    is_root: bool,
    highlight_set: &HashSet<PathBuf>,
    for_user: Option<&str>,
    parent_reachable: bool,
    counts: &mut Counts,
    show_acl: bool,
) -> (bool, Option<fs::Metadata>) {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            println!(
                "{prefix}{}",
                paint(Style::Label, &format!("{}  <{e}>", path.display()))
            );
            counts.denied += 1;
            return (false, None);
        }
    };

    let mode = md.mode() & 0o7777;
    let is_dir = md.is_dir() && !md.file_type().is_symlink();
    let is_symlink = md.file_type().is_symlink();

    // Update counts.
    if is_dir {
        counts.dirs += 1;
    } else {
        counts.files += 1;
    }
    if mode & 0o4000 != 0 {
        counts.setuid += 1;
    }
    if mode & 0o2000 != 0 {
        counts.setgid += 1;
    }
    if mode & 0o1000 != 0 {
        counts.sticky += 1;
    }
    // World-writable directories count too, matching `audit -W`. Only a
    // sticky directory (/tmp and friends) is exempt: there the write bit is
    // normal and does not let one user replace another's files.
    if mode & 0o002 != 0 && !is_symlink && !(is_dir && mode & 0o1000 != 0) {
        counts.world_write += 1;
    }
    let acl_here = has_extended_acl(path);
    if acl_here {
        counts.acl += 1;
    }

    // Owner / group (+ orphan detection).
    let (uname, u_orphan) = match nix::unistd::User::from_uid(Uid::from_raw(md.uid())) {
        Ok(Some(u)) => (u.name, false),
        _ => (format!("#{}", md.uid()), true),
    };
    let (gname, g_orphan) = match nix::unistd::Group::from_gid(Gid::from_raw(md.gid())) {
        Ok(Some(g)) => (g.name, false),
        _ => (format!("#{}", md.gid()), true),
    };
    if u_orphan || g_orphan {
        counts.orphan += 1;
    }
    let _ = (uid_to_name, gid_to_name);

    // Access-lens coloring for -U.
    let mut self_reachable = parent_reachable;
    let lens = for_user.map(|user| {
        let d =
            effective_for_user_path(path, user).unwrap_or_else(|_| crate::access::AccessDecision {
                read: false,
                write: false,
                exec: false,
                reason: "error".into(),
            });
        if !parent_reachable {
            self_reachable = false;
            Style::Deny
        } else if is_dir {
            if d.read && d.exec {
                self_reachable = true;
                Style::Ok
            } else if d.exec && !d.read {
                self_reachable = true;
                Style::Traverse
            } else {
                self_reachable = false;
                Style::Deny
            }
        } else if d.read {
            Style::Ok
        } else {
            Style::Deny
        }
    });

    // Mode string.
    let mode_str = render::mode_symbolic_colored(mode, is_dir, is_symlink);

    // Owner : group.
    let user_style = if u_orphan { Style::Danger } else { Style::User };
    let group_style = if g_orphan {
        Style::Danger
    } else {
        Style::Group
    };
    let owner = format!(
        "{}{}{}",
        paint(user_style, &uname),
        paint(Style::Separator, ":"),
        paint(group_style, &gname)
    );

    // Name (basename + trailing / for dirs for visual cue; full path for root).
    let name_raw = if is_root {
        path.display().to_string()
    } else {
        let base = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        if is_dir {
            format!("{base}/")
        } else {
            base
        }
    };
    let name_cols = name_raw.chars().count();
    let name_style = match lens {
        Some(s) => s,
        None => {
            if is_symlink {
                Style::Link
            } else if is_dir {
                Style::Dir
            } else {
                Style::Primary
            }
        }
    };
    let mut name = paint(name_style, &name_raw);
    let mut name_vis_extra = 0usize;
    if is_symlink {
        if let Ok(tgt) = fs::read_link(path) {
            let tgt_s = tgt.display().to_string();
            name.push(' ');
            name.push_str(&paint(Style::Separator, glyphs().arrow_right));
            name.push(' ');
            name.push_str(&paint(Style::Label, &tgt_s));
            name_vis_extra = 3 + tgt_s.chars().count();
        }
    }

    // Highlight chain marker (visible width 2: glyph + space).
    let (marker, marker_cols) = if !highlight_set.is_empty() {
        if highlight_set.contains(path) {
            (
                format!("{} ", paint(Style::Highlight, glyphs().bullet_filled)),
                2,
            )
        } else {
            ("  ".to_string(), 2)
        }
    } else {
        (String::new(), 0)
    };

    // Badges (setuid/setgid/sticky/world-writable/acl/orphan).
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
    if mode & 0o002 != 0 && !is_symlink && !is_dir {
        badges.push(badge("world-writable", Style::Danger));
    }
    if show_acl && acl_here {
        badges.push(badge("acl", Style::AclMarker));
    }
    if u_orphan || g_orphan {
        badges.push(badge("orphan", Style::Danger));
    }
    let badges_str = if badges.is_empty() {
        String::new()
    } else {
        format!("  {}", badges.join(" "))
    };

    // ── Layout: NAME left-column, padded, then mode + owner on the right ─
    let left_cols = prefix_cols + marker_cols + name_cols + name_vis_extra;
    const NAME_COL: usize = 28;
    let pad = if left_cols < NAME_COL {
        NAME_COL - left_cols
    } else {
        2
    };
    let gap = " ".repeat(pad);

    println!("{prefix}{marker}{name}{gap}{mode_str}  {owner}{badges_str}");

    (self_reachable, Some(md))
}

#[cfg(test)]
mod tests {
    // The filemode helper is replaced by `render::format_symbolic`; its
    // tests live in `render`.
}
