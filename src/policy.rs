//! `policy apply FILE` / `policy verify FILE`: declarative permission policy.
//!
//! YAML schema:
//! ```yaml
//! rules:
//!   - path: /etc/myapp
//!     mode: "0750"
//!     owner: root
//!     group: myapp
//!     recursive: true
//!     exclude: ["*.log"]
//!   - path: /etc/myapp/secret.key
//!     preset: secret
//! ```
//!
//! `apply` is transactional: one snapshot + one backup id covers every rule,
//! so a single `janitor undo` reverts the whole policy run.

use crate::backup::save_backup;
use crate::chperm::{
    apply_chmod_to_paths, apply_chown_to_paths, expand_targets, parse_octal, resolve_chown_target,
};
use crate::errors::{PmError, Result};
use crate::helpers::resolve_path;
use crate::locking::with_lock;
use crate::matcher::ExcludeSet;
use crate::presets::resolve_preset;
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use nix::unistd::{Gid, Uid};
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Policy {
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    path: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    preset: Option<String>,
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    exclude: Vec<String>,
}

fn load(file: &str) -> Result<Policy> {
    let text = fs::read_to_string(file).map_err(|e| PmError::Other(format!("read {file}: {e}")))?;
    serde_yaml::from_str::<Policy>(&text).map_err(|e| PmError::Other(format!("parse {file}: {e}")))
}

struct Plan<'a> {
    rule: &'a Rule,
    mode: Option<String>, // resolved mode spec (octal str)
    chown: Option<(Option<u32>, Option<u32>)>,
    paths: Vec<PathBuf>,
}

pub fn cmd_policy_apply(file: &str, dry_run: bool) -> Result<()> {
    let pol = load(file)?;
    println!("policy apply: {} rule(s) from {file}", pol.rules.len());

    // Phase 1: resolve every rule fail-closed.
    let mut plans: Vec<Plan> = Vec::new();
    let mut union: Vec<PathBuf> = Vec::new();
    for r in &pol.rules {
        let ex = ExcludeSet::new(&r.exclude)?;
        let paths_in = vec![r.path.clone()];
        let (_, paths) = expand_targets(&paths_in, r.recursive, &ex)?;
        let mode = match (&r.preset, &r.mode) {
            (Some(_), Some(_)) => {
                return Err(PmError::Other(format!(
                    "policy rule for {:?}: `preset` and `mode` are mutually exclusive",
                    r.path
                )));
            }
            (Some(p), None) => Some(resolve_preset(p)?.to_string()),
            (None, Some(m)) => {
                // Validate the octal now so bad input fails before mutation.
                parse_octal(m)?;
                Some(m.clone())
            }
            (None, None) => None,
        };
        let chown = match (&r.owner, &r.group) {
            (None, None) => None,
            (u, g) => {
                let spec = match (u, g) {
                    (Some(u), Some(g)) => format!("{u}:{g}"),
                    (Some(u), None) => u.clone(),
                    (None, Some(g)) => format!(":{g}"),
                    (None, None) => unreachable!(),
                };
                Some(resolve_chown_target(&spec, None)?)
            }
        };
        union.extend(paths.iter().cloned());
        plans.push(Plan {
            rule: r,
            mode,
            chown,
            paths,
        });
    }

    if plans.is_empty() {
        println!("policy apply: no rules, nothing to do");
        return Ok(());
    }

    // Dedup union preserving order.
    let mut seen = std::collections::HashSet::new();
    union.retain(|p| seen.insert(p.clone()));

    with_lock(|| {
        // Phase 2: ONE snapshot + ONE backup id for the entire policy run.
        if !dry_run {
            let snap = snapshot_with_acl(&union, true)?;
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "policy".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(file.to_string()),
                    access: Some(format!("{} rule(s)", plans.len())),
                    max_level: None,
                    recursive: Some(false),
                    parent_op: None,
                },
            )?;
            println!("backup: {bid}");
        }

        // Phase 3: apply each rule. Ownership first, mode second — chown
        // clears setuid/setgid, so doing it the other way round silently
        // dropped those bits and left `policy verify` reporting drift on a
        // policy that had just been applied successfully.
        for pl in &plans {
            if let Some((u, g)) = pl.chown {
                apply_chown_to_paths(&pl.paths, u, g, dry_run)
                    .map(|_| ())
                    .map_err(|e| PmError::Other(format!("policy rule {:?}: {e}", pl.rule.path)))?;
            }
            if let Some(m) = &pl.mode {
                apply_chmod_to_paths(&pl.paths, m, None, dry_run)
                    .map(|_| ())
                    .map_err(|e| PmError::Other(format!("policy rule {:?}: {e}", pl.rule.path)))?;
            }
        }
        Ok(())
    })
}

pub fn cmd_policy_verify(file: &str) -> Result<()> {
    let pol = load(file)?;
    let mut drift = 0usize;
    for r in &pol.rules {
        drift += verify_rule(r)?;
    }
    if drift == 0 {
        println!("policy verify: OK ({} rule(s))", pol.rules.len());
        Ok(())
    } else {
        Err(PmError::Other(format!("{drift} drift(s) detected")))
    }
}

fn verify_rule(r: &Rule) -> Result<usize> {
    let target = resolve_path(&r.path)?;
    let ex = ExcludeSet::new(&r.exclude)?;
    // Resolve expected mode. `preset` beats `mode` semantically should not both exist;
    // if both are set we verify against `mode` to match `apply`'s own check.
    let expected_mode: Option<u32> = match (&r.preset, &r.mode) {
        (_, Some(m)) => Some(parse_octal(m)?),
        (Some(p), None) => Some(parse_octal(resolve_preset(p)?)?),
        (None, None) => None,
    };
    let expected_uid = r.owner.as_deref().and_then(|n| {
        nix::unistd::User::from_name(n)
            .ok()
            .flatten()
            .map(|u| u.uid)
    });
    let expected_gid = r.group.as_deref().and_then(|n| {
        nix::unistd::Group::from_name(n)
            .ok()
            .flatten()
            .map(|g| g.gid)
    });
    let mut drift = 0usize;
    let mut check = |p: &std::path::Path| {
        if ex.is_excluded(p) {
            return;
        }
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => return,
        };
        let mode = md.permissions().mode() & 0o7777;
        if let Some(em) = expected_mode {
            if mode != em {
                println!(
                    "drift: {} mode {:04o} (expected {:04o})",
                    p.display(),
                    mode,
                    em
                );
                drift += 1;
            }
        }
        if let Some(eu) = expected_uid {
            if Uid::from_raw(md.uid()) != eu {
                println!(
                    "drift: {} uid {} (expected {})",
                    p.display(),
                    md.uid(),
                    eu.as_raw()
                );
                drift += 1;
            }
        }
        if let Some(eg) = expected_gid {
            if Gid::from_raw(md.gid()) != eg {
                println!(
                    "drift: {} gid {} (expected {})",
                    p.display(),
                    md.gid(),
                    eg.as_raw()
                );
                drift += 1;
            }
        }
    };
    check(&target);
    if r.recursive && target.is_dir() {
        for e in walkdir::WalkDir::new(&target)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            check(e.path());
        }
    }
    Ok(drift)
}
