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

/// Resolved `(uid, gid)` for a rule; either half may be absent.
type ChownTarget = (Option<u32>, Option<u32>);

struct Plan<'a> {
    rule: &'a Rule,
    mode: Option<String>, // resolved mode spec (octal str)
    chown: Option<ChownTarget>,
    paths: Vec<PathBuf>,
}

/// Resolve one rule into the mode spec and (uid, gid) it demands.
///
/// `apply` and `verify` share this on purpose. They used to interpret rules
/// differently — verify accepted `preset` together with `mode` (which apply
/// rejects) and silently ignored owners and groups that do not exist,
/// because a failed lookup collapsed into `None`. A compliance check that
/// answers OK for a policy that cannot be applied, or that never checked
/// ownership at all, is worse than no check.
fn resolve_rule(r: &Rule) -> Result<(Option<String>, Option<ChownTarget>)> {
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
    Ok((mode, chown))
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
        let (mode, chown) = resolve_rule(r)?;
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
                    group_created: false,
                    user_added: false,
                    user_removed: false,
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
    // Same resolution apply uses, so verify can never bless a rule apply
    // would refuse, and a missing user/group is an error rather than a
    // silently skipped check.
    let (mode_spec, chown) = resolve_rule(r)?;
    let expected_mode: Option<u32> = mode_spec.as_deref().map(parse_octal).transpose()?;
    let expected_uid = chown.and_then(|(u, _)| u).map(Uid::from_raw);
    let expected_gid = chown.and_then(|(_, g)| g).map(Gid::from_raw);
    let mut drift = 0usize;
    let mut check = |p: &std::path::Path| {
        if ex.is_excluded(p) {
            return;
        }
        let md = match fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => return,
        };
        // apply skips symlinks (their mode bits are fixed at 0777 on Linux
        // and ignored by the kernel), so verifying them reported drift that
        // no amount of applying could ever clear.
        if md.file_type().is_symlink() {
            return;
        }
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
