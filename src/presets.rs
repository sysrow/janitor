//! Built-in presets for common permission patterns.

use crate::chperm::cmd_chmod;
use crate::errors::{PmError, Result};
use crate::render::{paint, Style};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum PresetKind {
    Dir,
    File,
}

pub const PRESETS: &[(&str, &str, &str, PresetKind)] = &[
    (
        "private",
        "700",
        "owner only (dir or file)",
        PresetKind::Dir,
    ),
    (
        "private-dir",
        "700",
        "directory visible to owner only",
        PresetKind::Dir,
    ),
    (
        "private-file",
        "600",
        "file rw by owner only",
        PresetKind::File,
    ),
    (
        "group-shared",
        "770",
        "rwx owner + group, none other",
        PresetKind::Dir,
    ),
    (
        "group-read",
        "750",
        "rwx owner, rx group, none other",
        PresetKind::Dir,
    ),
    (
        "public-read",
        "755",
        "rwx owner, rx group, rx other",
        PresetKind::Dir,
    ),
    (
        "public-file",
        "644",
        "rw owner, r group, r other",
        PresetKind::File,
    ),
    (
        "sticky-dir",
        "1777",
        "world-writable with sticky bit (/tmp style)",
        PresetKind::Dir,
    ),
    (
        "setgid-dir",
        "2775",
        "group-shared dir, setgid (new files inherit group)",
        PresetKind::Dir,
    ),
    (
        "secret",
        "400",
        "read-only for owner, nobody else",
        PresetKind::File,
    ),
    (
        "secret-dir",
        "500",
        "owner-only directory, read-only",
        PresetKind::Dir,
    ),
    (
        "exec-only",
        "711",
        "owner rwx; others may traverse but not list",
        PresetKind::Dir,
    ),
    (
        "ssh-key",
        "600",
        "private SSH key / secret file (owner rw)",
        PresetKind::File,
    ),
    (
        "ssh-dir",
        "700",
        "SSH / secret directory (owner rwx)",
        PresetKind::Dir,
    ),
    (
        "config",
        "640",
        "service config (owner rw, group r)",
        PresetKind::File,
    ),
    (
        "log-file",
        "640",
        "log file (owner rw, group r)",
        PresetKind::File,
    ),
    (
        "systemd-unit",
        "644",
        "systemd unit / service file (rw/r/r)",
        PresetKind::File,
    ),
    (
        "read-only",
        "444",
        "read-only for everyone (legal-hold style)",
        PresetKind::File,
    ),
    (
        "no-access",
        "000",
        "no access for anyone (placeholder)",
        PresetKind::File,
    ),
];

pub fn cmd_list_presets() {
    use crate::render::{aligned_table, rule};
    println!();
    println!("  {}", paint(Style::Primary, "available presets"));
    println!();
    for (label, kind) in [
        ("directories", PresetKind::Dir),
        ("files", PresetKind::File),
    ] {
        println!("  {}", paint(Style::Label, label));
        let header = &["name", "mode", "description"];
        let rows: Vec<Vec<String>> = PRESETS
            .iter()
            .filter(|(_, _, _, k)| *k == kind)
            .map(|(name, mode, desc, _)| {
                vec![
                    paint(Style::Primary, name),
                    paint(
                        Style::Primary,
                        &format!("0{}", mode.trim_start_matches('0')),
                    ),
                    paint(Style::Label, desc),
                ]
            })
            .collect();
        let table = aligned_table(header, &rows);
        for line in table.lines() {
            println!("    {line}");
        }
        println!("    {}", paint(Style::Separator, &rule(64)));
        println!();
    }
    println!(
        "  {}  {}",
        paint(Style::Label, "use:"),
        paint(Style::Primary, "janitor preset <name> <path> [path...]")
    );
    println!();
}

pub fn cmd_apply_preset(
    name: &str,
    paths: &[String],
    recursive: bool,
    exclude: &crate::matcher::ExcludeSet,
    dry_run: bool,
) -> Result<()> {
    let preset = match PRESETS.iter().find(|(n, _, _, _)| *n == name) {
        Some(p) => p,
        None => {
            let suggestion = closest_preset(name);
            let tail = match suggestion {
                Some(s) => format!("  (did you mean `{s}`?  or run `janitor preset list`)"),
                None => "  (try `janitor preset list` for the full list)".into(),
            };
            return Err(PmError::Other(format!("unknown preset: {name:?}{tail}")));
        }
    };
    if is_terminal::is_terminal(std::io::stdout()) {
        println!(
            "  {} {}  {}  {}",
            paint(Style::Label, "preset"),
            paint(Style::Primary, preset.0),
            paint(Style::Separator, "→"),
            paint(
                Style::Primary,
                &format!("mode 0{}", preset.1.trim_start_matches('0'))
            )
        );
        println!("  {}", paint(Style::Label, preset.2));
    }
    // A preset is a chmod, and chmod rewrites the ACL mask -- capture ACLs so
    // `undo` can put the original effective permissions back.
    cmd_chmod(preset.1, paths, recursive, true, None, exclude, dry_run)
}

/// Look up a preset by name and return its octal mode string.
pub fn resolve_preset(name: &str) -> Result<&'static str> {
    PRESETS
        .iter()
        .find(|(n, _, _, _)| *n == name)
        .map(|(_, m, _, _)| *m)
        .ok_or_else(|| PmError::Other(format!("unknown preset: {name:?}  (try `presets`)")))
}

/// Cheap Levenshtein-ish distance on bytes; returns the closest preset name
/// within distance 3, if any.
fn closest_preset(input: &str) -> Option<&'static str> {
    let mut best: Option<(&str, usize)> = None;
    for (name, _, _, _) in PRESETS {
        let d = edit_distance(input, name);
        if d <= 3 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((name, d));
        }
    }
    best.map(|(n, _)| n)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}
