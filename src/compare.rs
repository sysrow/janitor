//! `compare A B`: report differences in mode/owner/group/ACL.

use crate::acl::{has_extended_acl, normalize_acl, read_acl_pair};
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::render::{self, paint, Style};
use nix::unistd::{Gid, Uid};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Eq, PartialEq)]
struct Snap {
    mode: u32,
    uid: u32,
    gid: u32,
    /// Normalized ACL entries, not just "has one". Comparing presence made
    /// `nobody:r--` and `nobody:rw-` report as identical.
    acl: Vec<String>,
    default_acl: Vec<String>,
    kind: char,
}

impl Snap {
    fn has_acl(&self) -> bool {
        !self.acl.is_empty() || !self.default_acl.is_empty()
    }
}

fn snap(p: &Path) -> Option<Snap> {
    let md = fs::symlink_metadata(p).ok()?;
    let kind = if md.file_type().is_symlink() {
        'l'
    } else if md.is_dir() {
        'd'
    } else {
        'f'
    };
    // Only non-trivial ACLs are worth recording: every file reports
    // user::/group::/other:: entries that merely echo the mode.
    let (acl, default_acl) = if has_extended_acl(p) == Some(true) {
        let (a, d) = read_acl_pair(p);
        (
            a.as_deref().map(normalize_acl).unwrap_or_default(),
            d.as_deref().map(normalize_acl).unwrap_or_default(),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    Some(Snap {
        mode: md.permissions().mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
        acl,
        default_acl,
        kind,
    })
}

fn fmt_snap_kv(s: &Snap) -> String {
    let kind_word = match s.kind {
        'd' => "dir",
        'l' => "symlink",
        _ => "file",
    };
    format!(
        "{} {:04o}  {}:{}{}",
        kind_word,
        s.mode,
        crate::users::uid_to_name(Uid::from_raw(s.uid)),
        crate::users::gid_to_name(Gid::from_raw(s.gid)),
        if s.has_acl() { "  +acl" } else { "" }
    )
}

/// Print the ACL entries that exist on only one side.
fn print_acl_delta(x: &Snap, y: &Snap) {
    let pairs = [
        ("acl", &x.acl, &y.acl),
        ("default", &x.default_acl, &y.default_acl),
    ];
    for (label, a, b) in pairs {
        for entry in a.iter().filter(|e| !b.contains(e)) {
            println!(
                "      {}  {} {}",
                paint(Style::Label, &format!("{label}:")),
                paint(Style::Deny, "only in A"),
                paint(Style::Primary, entry)
            );
        }
        for entry in b.iter().filter(|e| !a.contains(e)) {
            println!(
                "      {}  {} {}",
                paint(Style::Label, &format!("{label}:")),
                paint(Style::Ok, "only in B"),
                paint(Style::Primary, entry)
            );
        }
    }
}

/// Snapshot one side. Fail-closed: a subtree that could not be read is
/// reported and aborts the comparison. Silently dropping it let two trees
/// with the same unreadable directory compare "identical", exit 0, in the
/// CI drift check this command is advertised for.
fn collect(root: &Path, recursive: bool) -> Result<BTreeMap<PathBuf, Snap>> {
    let mut out = BTreeMap::new();
    let mut unreadable: Vec<String> = Vec::new();
    let is_dir = fs::symlink_metadata(root)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if recursive && is_dir {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .follow_root_links(false)
        {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    unreadable.push(match e.path() {
                        Some(p) => format!("{}: {e}", p.display()),
                        None => e.to_string(),
                    });
                    continue;
                }
            };
            let p = entry.path();
            let rel = p.strip_prefix(root).unwrap_or(p).to_path_buf();
            match snap(p) {
                Some(s) => {
                    out.insert(rel, s);
                }
                None => unreadable.push(format!("{}: cannot stat", p.display())),
            }
        }
    } else {
        match snap(root) {
            Some(s) => {
                out.insert(PathBuf::from(""), s);
            }
            None => unreadable.push(format!("{}: cannot stat", root.display())),
        }
    }
    if !unreadable.is_empty() {
        for u in unreadable.iter().take(10) {
            eprintln!("  {} {u}", paint(Style::Danger, "unreadable"));
        }
        if unreadable.len() > 10 {
            eprintln!("  … and {} more", unreadable.len() - 10);
        }
        return Err(crate::errors::PmError::Other(format!(
            "compare: {} path(s) under {} could not be read; refusing to call trees \
             identical that were not fully compared",
            unreadable.len(),
            root.display()
        )));
    }
    Ok(out)
}

pub fn cmd_compare(a: &str, b: &str, recursive: bool) -> Result<()> {
    let ra = resolve_path(a)?;
    let rb = resolve_path(b)?;
    let ma = collect(&ra, recursive)?;
    let mb = collect(&rb, recursive)?;
    let mut keys: Vec<&PathBuf> = ma.keys().chain(mb.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut changed = 0usize;
    let mut only_a = 0usize;
    let mut only_b = 0usize;

    println!();
    println!(
        "  {}  {}  {}  {}  {}",
        paint(Style::Label, "compare"),
        paint(Style::Primary, &ra.display().to_string()),
        paint(Style::Separator, "↔"),
        paint(Style::Primary, &rb.display().to_string()),
        paint(Style::Label, if recursive { "(recursive)" } else { "" })
    );
    println!();

    for k in keys {
        let disp = if k.as_os_str().is_empty() {
            ".".to_string()
        } else {
            k.display().to_string()
        };
        match (ma.get(k), mb.get(k)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => {
                changed += 1;
                println!(
                    "  {}  {}",
                    paint(Style::WarnMajor, "~"),
                    paint(Style::Primary, &disp)
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "A:"),
                    paint(Style::Label, &fmt_snap_kv(x))
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "B:"),
                    paint(Style::Label, &fmt_snap_kv(y))
                );
                // Mode/owner already print above; without this an ACL-only
                // difference shows two identical-looking lines flagged as
                // changed, with no way to see what actually differs.
                if x.acl != y.acl || x.default_acl != y.default_acl {
                    print_acl_delta(x, y);
                }
            }
            (Some(x), None) => {
                only_a += 1;
                println!(
                    "  {}  {}",
                    paint(Style::Deny, "-"),
                    paint(Style::Primary, &disp)
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "A:"),
                    paint(Style::Label, &fmt_snap_kv(x))
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "B:"),
                    paint(Style::Label, "(missing)")
                );
            }
            (None, Some(y)) => {
                only_b += 1;
                println!(
                    "  {}  {}",
                    paint(Style::Ok, "+"),
                    paint(Style::Primary, &disp)
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "A:"),
                    paint(Style::Label, "(missing)")
                );
                println!(
                    "      {}  {}",
                    paint(Style::Label, "B:"),
                    paint(Style::Label, &fmt_snap_kv(y))
                );
            }
            (None, None) => {}
        }
    }

    println!();
    if changed == 0 && only_a == 0 && only_b == 0 {
        println!(
            "  {}  {}",
            paint(Style::Ok, render::glyphs().check),
            paint(Style::Primary, "identical")
        );
        println!();
        return Ok(());
    }
    eprintln!(
        "{}  {} changed · {} only in A · {} only in B",
        paint(Style::Label, "summary:"),
        changed,
        only_a,
        only_b
    );
    // Non-zero exit lets callers (CI, shell `if`) detect drift.
    std::process::exit(1);
}
