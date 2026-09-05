//! `who-can`: reverse query — who can read / write / exec this path?
//!
//! Variant A: groups each user by the rule that gave them access (owner,
//! group member, ACL grant, `other` bits), surfaces a warning when the
//! file is world-readable, and flags users whose file-level ACL grant
//! is defeated by a parent that blocks traversal.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crate::access::{evaluate, InodeFacts, UserCtx};
use crate::acl::has_extended_acl;
use crate::errors::Result;
use crate::helpers::{path_chain, resolve_path};
use crate::render::{self, glyphs, kv_grid, paint, KvRow, Style};
use crate::users::{gid_to_name, uid_to_name};

#[derive(Debug, Serialize)]
pub struct WhoCanReport {
    pub path: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub exec: Vec<String>,
    /// The ancestor that stops the most listed users from reaching the
    /// path, derived from the per-user traverse check (not from a bare
    /// `o+x` heuristic, which flagged the owner of a 0750 home directory).
    pub blocked_by: Option<String>,
    /// Users who appear in a list above but cannot traverse the parent
    /// chain. The human output marks them; JSON consumers need the list.
    pub blocked: Vec<String>,
}

#[derive(Default)]
struct Buckets {
    owner: Vec<String>,
    group: Vec<String>,
    other: Vec<String>,
    acl: Vec<String>,
    root: bool,
    cant_traverse: BTreeSet<String>,
}

pub fn cmd_who_can(path: &str, as_json: bool) -> Result<()> {
    let target = resolve_path(path)?;
    let md = fs::symlink_metadata(&target)?;
    let mode = md.mode() & 0o7777;
    let uid = md.uid();
    let gid = md.gid();

    // Inode facts once per path: the target and every ancestor. Evaluating
    // a user is then pure, so a host with thousands of NSS accounts costs
    // one group lookup per user instead of two ACL reads per user per hop.
    let facts = InodeFacts::read(&target)?;
    let chain = path_chain(&target, Path::new("/"));
    let ancestors: Vec<(PathBuf, InodeFacts)> = chain
        .iter()
        .take(chain.len().saturating_sub(1))
        .map(|p| InodeFacts::read(p).map(|f| (p.clone(), f)))
        .collect::<Result<_>>()?;

    let users = read_passwd_users();

    let mut read_bkt = Buckets::default();
    let mut write_bkt = Buckets::default();
    let mut exec_bkt = Buckets::default();
    let mut blocked: BTreeSet<String> = BTreeSet::new();
    let mut blocker_votes: BTreeMap<PathBuf, usize> = BTreeMap::new();

    for u in &users {
        if u.name == "root" || u.uid == 0 {
            // root bypasses read and write permission checks, but *not*
            // execute: the kernel still requires at least one x bit on a
            // regular file (see generic_permission / MAY_EXEC). Claiming
            // root can run a 0600 file was simply wrong.
            read_bkt.root = true;
            write_bkt.root = true;
            let is_dir = md.is_dir();
            exec_bkt.root = is_dir || (mode & 0o111) != 0;
            continue;
        }
        let ctx = match UserCtx::resolve(&u.name) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let d = evaluate(&facts, &ctx);
        let blocker = ancestors
            .iter()
            .find(|(_, f)| !evaluate(f, &ctx).exec)
            .map(|(p, _)| p.clone());
        let cant_traverse = blocker.is_some();
        let mut listed = false;
        for (bkt, has) in [
            (&mut read_bkt, d.read),
            (&mut write_bkt, d.write),
            (&mut exec_bkt, d.exec),
        ] {
            if has {
                listed = true;
                classify_into(bkt, &u.name, &d.reason);
                if cant_traverse {
                    bkt.cant_traverse.insert(u.name.clone());
                }
            }
        }
        if listed {
            if let Some(b) = blocker {
                blocked.insert(u.name.clone());
                *blocker_votes.entry(b).or_insert(0) += 1;
            }
        }
    }

    let blocked_by = blocker_votes
        .iter()
        .max_by_key(|(_, n)| **n)
        .map(|(p, _)| p.display().to_string());

    let report = WhoCanReport {
        path: target.display().to_string(),
        read: sorted_flat(&read_bkt),
        write: sorted_flat(&write_bkt),
        exec: sorted_flat(&exec_bkt),
        blocked_by: blocked_by.clone(),
        blocked: blocked.iter().cloned().collect(),
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }

    // ── Header card ───────────────────────────────────────────────────
    println!();
    println!(
        "{} {}",
        paint(Style::Separator, glyphs().header_marker),
        paint(Style::Primary, &target.display().to_string())
    );
    println!("  {}", render::rule(61));

    let owner_name = uid_to_name(Uid::from_raw(uid));
    let group_name = gid_to_name(Gid::from_raw(gid));
    let is_dir = md.is_dir();
    let is_symlink = md.file_type().is_symlink();
    let mode_str = format!(
        "{:04o}  {}  {}",
        mode,
        paint(Style::Separator, glyphs().midot),
        render::mode_symbolic_colored(mode, is_dir, is_symlink)
    );
    let acl_txt = if has_extended_acl(&target) == Some(true) {
        paint(Style::AclMarker, "present")
    } else {
        paint(Style::Label, "none")
    };
    let owner_cell = format!(
        "{} {}",
        paint(Style::User, &owner_name),
        paint(Style::Label, &format!("(uid {uid})")),
    );
    let group_cell = format!(
        "{} {}",
        paint(Style::Group, &group_name),
        paint(Style::Label, &format!("(gid {gid})")),
    );
    let key_w = "group".len();
    let rows: Vec<KvRow<'_>> = vec![
        (
            ("owner", owner_cell.as_str()),
            Some(("mode", mode_str.as_str())),
        ),
        (
            ("group", group_cell.as_str()),
            Some(("acl", acl_txt.as_str())),
        ),
    ];
    let grid = kv_grid(&rows, key_w, 2);
    for line in grid.lines() {
        println!("  {}", line);
    }

    if mode & 0o004 != 0 {
        println!();
        println!(
            "  {}  {}",
            paint(Style::WarnMajor, glyphs().warn),
            paint(
                Style::WarnMajor,
                "WORLD-READABLE: 'other' bits grant read to every user on the system."
            )
        );
    }
    if let Some(b) = &blocked_by {
        println!();
        println!(
            "  {}  {}",
            paint(Style::WarnMajor, glyphs().warn),
            paint(
                Style::WarnMajor,
                &format!(
                    "{b} blocks traversal for {} of the users listed below.",
                    blocked.len()
                )
            )
        );
        println!(
            "     {}",
            paint(
                Style::Label,
                &format!(
                    "users below with no traverse are marked with {}",
                    glyphs().warn
                )
            )
        );
    }

    print_section("READ", &read_bkt);
    print_section("WRITE", &write_bkt);
    print_section("EXEC", &exec_bkt);
    println!();

    Ok(())
}

fn classify_into(b: &mut Buckets, user: &str, reason: &str) {
    if reason == "owner" {
        b.owner.push(user.into());
    } else if reason == "group member" {
        b.group.push(user.into());
    } else if reason == "other" {
        b.other.push(user.into());
    } else if reason.starts_with("acl") {
        b.acl.push(user.into());
    } else {
        // Unknown reason -> put in ACL (safe fallback; root handled separately).
        b.acl.push(user.into());
    }
}

/// Flatten a bucket for the JSON report.
///
/// root is tracked in its own field rather than in the name lists, and used
/// to be dropped here — so `who-can --json` on a 0600 file listed only the
/// owner and quietly omitted the one account that can always read it.
fn sorted_flat(b: &Buckets) -> Vec<String> {
    let mut all: BTreeSet<String> = BTreeSet::new();
    if b.root {
        all.insert("root".to_string());
    }
    all.extend(b.owner.iter().cloned());
    all.extend(b.group.iter().cloned());
    all.extend(b.other.iter().cloned());
    all.extend(b.acl.iter().cloned());
    all.into_iter().collect()
}

fn print_section(title: &str, b: &Buckets) {
    let count = b.owner.len() + b.group.len() + b.other.len() + b.acl.len();
    println!();
    let user_word = if count == 1 { "user" } else { "users" };
    println!(
        "  {}  {}",
        paint(Style::Primary, title),
        paint(Style::Label, &format!("({count} {user_word})"))
    );
    if count == 0 {
        println!("    {}", paint(Style::Label, "(none beyond root)"));
        if b.root {
            println!("    {}", paint(Style::Label, "root also (superuser)"));
        }
        return;
    }
    print_bucket("via owner         ", &b.owner, b);
    print_bucket("via group member  ", &b.group, b);
    print_bucket("via 'other' bits  ", &b.other, b);
    print_bucket("via ACL           ", &b.acl, b);
    if b.root {
        println!("    {}", paint(Style::Label, "root also (superuser)"));
    }
}

fn print_bucket(label: &str, users: &[String], b: &Buckets) {
    if users.is_empty() {
        println!(
            "    {}  {}",
            paint(Style::Label, label),
            paint(Style::Separator, "—")
        );
        return;
    }
    // Flag users that can't actually traverse.
    let mut shown = users.to_vec();
    shown.sort();
    let mut rendered: Vec<String> = Vec::with_capacity(shown.len());
    for u in &shown {
        if b.cant_traverse.contains(u) {
            rendered.push(format!(
                "{} {}",
                paint(Style::WarnMajor, glyphs().warn),
                paint(Style::User, u)
            ));
        } else {
            rendered.push(paint(Style::User, u));
        }
    }
    // If very many, collapse with count.
    if rendered.len() > 20 {
        println!(
            "    {}  {} {}",
            paint(Style::Label, label),
            paint(Style::Primary, &format!("{}", rendered.len())),
            paint(Style::Label, "users (collapsed)")
        );
    } else {
        println!(
            "    {}  {}",
            paint(Style::Label, label),
            rendered.join(", ")
        );
    }
}

struct UserRow {
    name: String,
    uid: u32,
}

fn read_passwd_users() -> Vec<UserRow> {
    // Use the NSS enumeration API rather than reading /etc/passwd
    // directly, so users served by LDAP / SSSD / systemd-userdbd /
    // any other NSS backend actually show up in who-can. Falls back
    // to /etc/passwd on platforms where getpwent is unavailable.
    let mut seen: BTreeMap<String, u32> = BTreeMap::new();
    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() {
                break;
            }
            let name_ptr = (*pw).pw_name;
            if name_ptr.is_null() {
                continue;
            }
            let name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let uid = (*pw).pw_uid as u32;
            seen.entry(name).or_insert(uid);
        }
        libc::endpwent();
    }
    // Safety net: if NSS enumeration yielded nothing (misconfigured
    // environment, container with no NSS shim), fall back to the flat
    // /etc/passwd scan so we never regress against the previous
    // implementation.
    if seen.is_empty() {
        if let Ok(content) = fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() < 3 {
                    continue;
                }
                if let Ok(uid) = parts[2].parse::<u32>() {
                    seen.entry(parts[0].to_string()).or_insert(uid);
                }
            }
        }
    }
    seen.into_iter()
        .map(|(name, uid)| UserRow { name, uid })
        .collect()
}
