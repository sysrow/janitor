//! `diff`: show what would change if a backup were restored (vs current state).
//! `export`: dump a backup in human-readable or JSON form.

use std::fs;
use std::os::unix::fs::MetadataExt;

use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crate::acl::{acl_text_differs, read_acl_pair};
use crate::backup::load_backup;
use crate::errors::Result;
use crate::render::{paint, Style};
use crate::users::{gid_to_name, uid_to_name};

#[derive(Debug, Serialize)]
pub struct DiffEntry {
    pub path: String,
    pub current_mode: Option<String>,
    pub snapshot_mode: String,
    pub current_uid: Option<u32>,
    pub snapshot_uid: u32,
    pub current_gid: Option<u32>,
    pub snapshot_gid: u32,
    pub has_acl_change: bool,
}

pub fn cmd_diff(backup_id: &str, as_json: bool) -> Result<()> {
    let data = load_backup(backup_id)?;
    let mut diffs: Vec<DiffEntry> = Vec::new();

    for e in &data.entries {
        let cur = fs::symlink_metadata(&e.path).ok();
        let (cur_mode, cur_uid, cur_gid) = match &cur {
            Some(md) => (Some(md.mode() & 0o7777), Some(md.uid()), Some(md.gid())),
            None => (None, None, None),
        };
        let mode_differs = cur_mode.map(|m| m != e.perm).unwrap_or(true);
        let uid_differs = cur_uid.map(|u| u != e.uid).unwrap_or(true);
        let gid_differs = cur_gid.map(|g| g != e.gid).unwrap_or(true);
        // Compare the captured ACL against the live one. Flagging "changed"
        // whenever the snapshot merely *had* an ACL made every entry look
        // dirty — `getfacl -c` emits base entries for every file — so an
        // immediate backup-then-diff reported changes on an untouched tree
        // and the output was useless as a drift gate.
        let acl_differs = if cur.is_some() && (e.acl.is_some() || e.default_acl.is_some()) {
            let (cur_acl, cur_default) = read_acl_pair(&e.path);
            acl_text_differs(e.acl.as_deref(), cur_acl.as_deref())
                || acl_text_differs(e.default_acl.as_deref(), cur_default.as_deref())
        } else {
            false
        };
        if !mode_differs && !uid_differs && !gid_differs && !acl_differs {
            continue;
        }
        diffs.push(DiffEntry {
            path: e.path.display().to_string(),
            current_mode: cur_mode.map(|m| format!("{m:04o}")),
            snapshot_mode: format!("{:04o}", e.perm),
            current_uid: cur_uid,
            snapshot_uid: e.uid,
            current_gid: cur_gid,
            snapshot_gid: e.gid,
            has_acl_change: acl_differs,
        });
    }

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&diffs).unwrap_or_else(|_| "[]".into())
        );
        return Ok(());
    }

    if diffs.is_empty() {
        println!(
            "{}",
            paint(
                Style::Label,
                &format!("(no differences between backup {backup_id} and current state)")
            )
        );
        return Ok(());
    }

    println!();
    println!(
        "  {}  {}",
        paint(Style::Primary, "diff"),
        paint(
            Style::Label,
            &format!("backup {backup_id}  →  current state")
        )
    );
    println!();
    for d in &diffs {
        println!("  {}", paint(Style::Primary, &d.path));
        let cur_mode = d.current_mode.as_deref().unwrap_or("----");
        if cur_mode != d.snapshot_mode {
            println!(
                "      {}   {}  {}  {}",
                paint(Style::Label, "mode "),
                paint(Style::Primary, &d.snapshot_mode),
                paint(Style::Separator, "→"),
                paint(Style::Primary, cur_mode)
            );
        }
        let snap_user = uid_to_name(Uid::from_raw(d.snapshot_uid));
        let snap_group = gid_to_name(Gid::from_raw(d.snapshot_gid));
        let cur_user = d
            .current_uid
            .map(|u| uid_to_name(Uid::from_raw(u)))
            .unwrap_or_else(|| "-".into());
        let cur_group = d
            .current_gid
            .map(|g| gid_to_name(Gid::from_raw(g)))
            .unwrap_or_else(|| "-".into());
        if d.current_uid != Some(d.snapshot_uid) || d.current_gid != Some(d.snapshot_gid) {
            println!(
                "      {}  {}:{}  {}  {}:{}",
                paint(Style::Label, "owner"),
                paint(Style::User, &snap_user),
                paint(Style::Group, &snap_group),
                paint(Style::Separator, "→"),
                paint(Style::User, &cur_user),
                paint(Style::Group, &cur_group)
            );
        }
        if d.has_acl_change {
            println!(
                "      {}  {}",
                paint(Style::Label, "acl  "),
                paint(Style::AclMarker, "snapshot has ACL (will be restored)")
            );
        }
    }
    println!();
    let n = diffs.len();
    let word = if n == 1 {
        "entry differs"
    } else {
        "entries differ"
    };
    eprintln!(
        "{}  {}  {}",
        paint(Style::Label, "summary:"),
        paint(Style::Primary, &n.to_string()),
        paint(Style::Label, word)
    );
    Ok(())
}

pub fn cmd_export(backup_id: &str, as_json: bool) -> Result<()> {
    let data = load_backup(backup_id)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("backup: {}", data.id);
        println!("timestamp: {}", data.timestamp);
        println!("operation: {}", data.operation.op_type);
        if let Some(u) = &data.operation.user {
            println!("user: {u}");
        }
        if let Some(g) = &data.operation.group {
            println!("group: {g}");
        }
        if let Some(t) = &data.operation.target {
            println!("target: {t}");
        }
        if let Some(a) = &data.operation.access {
            println!("access: {a}");
        }
        println!("entries: {}", data.entries.len());
        println!();
        println!(
            "{:>6}  {:>10}  {:>10}  {:>3}  {:>3}  {}",
            "mode", "owner", "group", "sym", "acl", "path"
        );
        for e in &data.entries {
            println!(
                "{:06o}  {:>10}  {:>10}  {:>3}  {:>3}  {}",
                e.perm,
                uid_to_name(Uid::from_raw(e.uid)),
                gid_to_name(Gid::from_raw(e.gid)),
                if e.is_symlink { "yes" } else { "-" },
                if e.acl.is_some() { "yes" } else { "-" },
                e.path.display()
            );
        }
    }
    Ok(())
}
