//! `batch FILE`: run many operations in one snapshot transaction.
//!
//! Two-phase execution:
//!
//! 1. Parse every line and resolve every target path (fail-closed: any
//!    malformed line, missing path, invalid preset name, or invalid chown
//!    spec aborts before any mutation).
//! 2. Take a **single** snapshot covering the union of all resolved paths,
//!    write **one** backup, then apply every operation in order.
//!
//! File format (one op per line, `#` for comments, blank lines allowed):
//!
//!     chmod 0644 /etc/foo.conf
//!     chown root:wheel /etc/foo.conf
//!     preset config /etc/foo.conf

use crate::backup::save_backup;
use crate::chperm::{
    apply_chmod_to_paths, apply_chown_to_paths, expand_targets, resolve_chown_target,
};
use crate::errors::{PmError, Result};
use crate::locking::with_lock;
use crate::matcher::ExcludeSet;
use crate::presets::resolve_preset;
use crate::snapshot::snapshot_with_acl;
use crate::types::Operation;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

enum Action {
    Chmod(String),                   // mode_spec
    Chown(Option<u32>, Option<u32>), // resolved (uid, gid)
    Preset(&'static str),            // resolved octal mode
}

struct Op {
    line_no: usize,
    action: Action,
    paths: Vec<PathBuf>,
}

pub fn cmd_batch(file: &str, dry_run: bool) -> Result<()> {
    let src: Box<dyn BufRead> = if file == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let f =
            fs::File::open(file).map_err(|e| PmError::Other(format!("batch open {file}: {e}")))?;
        Box::new(BufReader::new(f))
    };

    let empty = ExcludeSet::default();
    let mut ops: Vec<Op> = Vec::new();
    let mut union: Vec<PathBuf> = Vec::new();

    // Phase 1: parse every line + resolve every path. Fail-closed.
    for (i, line) in src.lines().enumerate() {
        let line = line.map_err(|e| PmError::Other(format!("read: {e}")))?;
        let line_trim = line.trim();
        if line_trim.is_empty() || line_trim.starts_with('#') {
            continue;
        }
        let mut parts = line_trim.splitn(3, char::is_whitespace);
        let op = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("").trim();
        let path = parts.next().unwrap_or("").trim();
        if arg.is_empty() || path.is_empty() {
            return Err(PmError::Other(format!(
                "batch line {}: malformed `{line_trim}` (expected OP ARG PATH)",
                i + 1
            )));
        }
        let path_in = vec![path.to_string()];
        let (_, paths) = expand_targets(&path_in, false, &empty)
            .map_err(|e| PmError::Other(format!("batch line {}: {e}", i + 1)))?;
        let action = match op {
            "chmod" => Action::Chmod(arg.to_string()),
            "chown" => {
                let (u, g) = resolve_chown_target(arg, None)
                    .map_err(|e| PmError::Other(format!("batch line {}: {e}", i + 1)))?;
                Action::Chown(u, g)
            }
            "preset" => Action::Preset(
                resolve_preset(arg)
                    .map_err(|e| PmError::Other(format!("batch line {}: {e}", i + 1)))?,
            ),
            other => {
                return Err(PmError::Other(format!(
                    "batch line {}: unknown op `{other}`",
                    i + 1
                )))
            }
        };
        union.extend(paths.iter().cloned());
        ops.push(Op {
            line_no: i + 1,
            action,
            paths,
        });
    }

    if ops.is_empty() {
        println!("batch: 0 operation(s) applied");
        return Ok(());
    }

    // Dedup union while preserving first-encounter order.
    let mut seen = std::collections::HashSet::new();
    union.retain(|p| seen.insert(p.clone()));

    with_lock(|| {
        // Phase 2: ONE snapshot + ONE backup id covering every op.
        if !dry_run {
            let snap = snapshot_with_acl(&union, true)?;
            let bid = save_backup(
                snap,
                Operation {
                    op_type: "batch".into(),
                    user: None,
                    group: None,
                    explicit_group: None,
                    target: Some(file.to_string()),
                    access: Some(format!("{} op(s)", ops.len())),
                    max_level: None,
                    recursive: Some(false),
                    parent_op: None,
                },
            )?;
            println!("backup: {bid}");
        }

        // Phase 3: apply in order. No per-op snapshot.
        for op in &ops {
            let r: Result<()> = match &op.action {
                Action::Chmod(mode_spec) => {
                    apply_chmod_to_paths(&op.paths, mode_spec, None, dry_run).map(|_| ())
                }
                Action::Chown(u, g) => apply_chown_to_paths(&op.paths, *u, *g, dry_run).map(|_| ()),
                Action::Preset(mode) => {
                    apply_chmod_to_paths(&op.paths, mode, None, dry_run).map(|_| ())
                }
            };
            if let Err(e) = r {
                return Err(PmError::Other(format!("batch line {}: {e}", op.line_no)));
            }
        }
        println!("batch: {} operation(s) applied", ops.len());
        Ok(())
    })
}
