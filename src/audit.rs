//! `audit`: scan a directory tree and list files matching criteria.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::unistd::{Gid, Uid};
use serde::Serialize;

use crate::acl::has_extended_acl;
use crate::errors::Result;
use crate::helpers::resolve_path;
use crate::matcher::ExcludeSet;
use crate::render::{self, aligned_table, glyphs, paint, summary_line, Style};
use crate::users::{gid_exists, gid_to_name, uid_exists, uid_to_name};

#[derive(Debug, Serialize)]
pub struct AuditHit {
    /// Kept as a path so `--print0` can emit the exact bytes; JSON is UTF-8
    /// by definition and gets the lossy rendering.
    #[serde(serialize_with = "ser_path_lossy")]
    pub path: PathBuf,
    pub mode: String,
    pub uid: u32,
    pub user: String,
    pub gid: u32,
    pub group: String,
    pub has_acl: bool,
    pub size: u64,
}

fn ser_path_lossy<S: serde::Serializer>(p: &Path, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&p.to_string_lossy())
}

pub struct AuditFilter<'a> {
    pub world_writable: bool,
    pub world_readable: bool,
    pub world_executable: bool,
    pub setuid: bool,
    pub setgid: bool,
    pub sticky: bool,
    pub owner_uid: Option<u32>,
    pub owner_user: Option<&'a str>,
    pub group_gid: Option<u32>,
    pub group_name: Option<&'a str>,
    pub mode_equals: Option<u32>,
    pub has_acl: bool,
    pub no_owner: bool,
    pub no_group: bool,
}

/// Outcome of one filesystem scan.
pub struct ScanResult {
    pub hits: Vec<AuditHit>,
    pub pseudo_skipped: usize,
    /// Entries the walk could not read. A security scan that cannot see part
    /// of the tree must say so: reporting "no matches" for a subtree it never
    /// entered is the one answer an audit must never give.
    pub unreadable: Vec<String>,
}

impl ScanResult {
    /// Print the unreadable-path summary and return true if the scan was
    /// incomplete. `best_effort` downgrades it to a warning.
    pub fn report_incomplete(&self, best_effort: bool) -> bool {
        if self.unreadable.is_empty() {
            return false;
        }
        let shown = self.unreadable.iter().take(10);
        for p in shown {
            eprintln!("  {} {p}", paint(Style::Danger, "unreadable"));
        }
        if self.unreadable.len() > 10 {
            eprintln!("  … and {} more", self.unreadable.len() - 10);
        }
        eprintln!(
            "{} scan incomplete: {} path(s) could not be read{}",
            paint(Style::Danger, "error:"),
            self.unreadable.len(),
            if best_effort {
                " (continuing: --best-effort)"
            } else {
                " (results below cover only what was reachable)"
            }
        );
        !best_effort
    }
}

/// Turn an incomplete scan into a non-zero exit.
fn incomplete_result(incomplete: bool) -> Result<()> {
    if incomplete {
        return Err(crate::errors::PmError::Other(
            "scan incomplete — rerun with sufficient privileges, or pass --best-effort to \
             accept partial results"
                .into(),
        ));
    }
    Ok(())
}

/// Low-level scan: returns matching hits. Shared by `audit`, `find`, and
/// `audit --fix`.
///
/// When `include_pseudo == false`, entries on kernel pseudo-filesystems
/// (/proc /sys /dev cgroupfs tmpfs etc. — see `helpers::is_pseudo_fs`)
/// are skipped. Callers that need raw inode listings (policy audits on
/// /proc, for example) can opt back in.
///
/// Paths the walk cannot read are collected rather than dropped, so callers
/// can refuse to present a partial scan as a clean one.
pub fn scan(
    path: &Path,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    include_pseudo: bool,
    probe_acl: bool,
) -> ScanResult {
    let mut hits: Vec<AuditHit> = Vec::new();
    let mut pseudo_skipped = 0usize;
    let mut unreadable: Vec<String> = Vec::new();
    let root_dev = std::fs::symlink_metadata(path)
        .map(|m| m.dev())
        .unwrap_or(0);
    let walker = walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if exclude.is_excluded(e.path()) {
                return false;
            }
            if include_pseudo {
                return true;
            }
            if e.file_type().is_dir() {
                if let Ok(md) = e.metadata() {
                    if md.dev() != root_dev && crate::helpers::is_pseudo_fs(e.path()) {
                        pseudo_skipped += 1;
                        return false;
                    }
                }
            }
            true
        });
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                unreadable.push(describe_walk_error(&e));
                continue;
            }
        };
        let p = entry.path();
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                unreadable.push(format!("{}: {e}", p.display()));
                continue;
            }
        };
        let mode = md.mode() & 0o7777;
        let uid = md.uid();
        let gid = md.gid();
        let is_symlink = md.file_type().is_symlink();

        // Symlink mode bits are ignored by the kernel (lrwxrwxrwx is
        // literally fixed on Linux); actual access is evaluated on the
        // target. Reporting symlinks under --world-writable et al. is a
        // noise false-positive, so skip them for every mode-bit filter.
        if is_symlink
            && (filter.world_writable
                || filter.world_readable
                || filter.world_executable
                || filter.setuid
                || filter.setgid
                || filter.sticky)
        {
            continue;
        }

        if filter.world_writable && (mode & 0o002) == 0 {
            continue;
        }
        if filter.world_readable && (mode & 0o004) == 0 {
            continue;
        }
        if filter.world_executable && (mode & 0o001) == 0 {
            continue;
        }
        if filter.setuid && (mode & 0o4000) == 0 {
            continue;
        }
        if filter.setgid && (mode & 0o2000) == 0 {
            continue;
        }
        if filter.sticky && (mode & 0o1000) == 0 {
            continue;
        }
        if let Some(u) = filter.owner_uid {
            if uid != u {
                continue;
            }
        }
        if let Some(g) = filter.group_gid {
            if gid != g {
                continue;
            }
        }
        if let Some(owner) = filter.owner_user {
            if uid_to_name(Uid::from_raw(uid)) != owner {
                continue;
            }
        }
        if let Some(group) = filter.group_name {
            if gid_to_name(Gid::from_raw(gid)) != group {
                continue;
            }
        }
        if let Some(m) = filter.mode_equals {
            if mode != m {
                continue;
            }
        }
        if filter.no_owner && uid_exists(Uid::from_raw(uid)) {
            continue;
        }
        if filter.no_group && gid_exists(Gid::from_raw(gid)) {
            continue;
        }
        // ACL probe is a per-file `lgetxattr` syscall — cheap, but on
        // large trees it still shows up. Skip unless the caller actually
        // needs the ACL bit (audit table column, or `filter.has_acl`).
        // Pipe-pure `find` leaves `probe_acl=false`. An unreadable ACL is
        // an unknown, and a scan for ACLs must not report unknown as "none".
        let acl = if filter.has_acl || probe_acl {
            match has_extended_acl(p) {
                Some(v) => v,
                None => {
                    unreadable.push(format!("{}: ACL unreadable", p.display()));
                    continue;
                }
            }
        } else {
            false
        };
        if filter.has_acl && !acl {
            continue;
        }

        hits.push(AuditHit {
            path: p.to_path_buf(),
            mode: format!("{:04o}", mode),
            uid,
            user: uid_to_name(Uid::from_raw(uid)),
            gid,
            group: gid_to_name(Gid::from_raw(gid)),
            has_acl: acl,
            size: md.len(),
        });
    }
    ScanResult {
        hits,
        pseudo_skipped,
        unreadable,
    }
}

/// walkdir errors may or may not carry a path; keep whichever we get.
fn describe_walk_error(e: &walkdir::Error) -> String {
    match e.path() {
        Some(p) => format!("{}: {e}", p.display()),
        None => e.to_string(),
    }
}

pub fn cmd_audit(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    as_json: bool,
    include_pseudo: bool,
    paths_only: bool,
    print0: bool,
    best_effort: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let t0 = Instant::now();
    // Pipe-pure path output has no ACL column and no ACL filter ==> no
    // need to issue the per-file lgetxattr syscall.
    let probe_acl = !(paths_only || print0) || filter.has_acl;
    let result = scan(&root, filter, exclude, include_pseudo, probe_acl);
    let hits = &result.hits;
    let elapsed_ms = t0.elapsed().as_millis();
    if result.pseudo_skipped > 0 {
        eprintln!(
            "info: skipped {} pseudo-filesystem mount point(s) (use --include-pseudo to include)",
            result.pseudo_skipped
        );
    }
    let incomplete = result.report_incomplete(best_effort);

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&hits).unwrap_or_else(|_| "[]".into())
        );
        return incomplete_result(incomplete);
    }

    // Pipe-pure path output. No header, no colors, no summary on
    // stdout — stderr still carries the scan-time note above. Compose
    // with `janitor chmod --stdin0`, `xargs`, etc.
    if paths_only || print0 {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let sep: u8 = if print0 { 0 } else { b'\n' };
        for h in hits {
            // Raw bytes: this output exists to be piped into `--stdin0`,
            // and a name that is not UTF-8 must come out as the name.
            let _ = out.write_all(h.path.as_os_str().as_bytes());
            let _ = out.write_all(&[sep]);
        }
        return incomplete_result(incomplete);
    }

    // ── Counters for summary (stderr) ────────────────────────────────
    let mut c_setuid = 0u32;
    let mut c_setgid = 0u32;
    let mut c_sticky = 0u32;
    let mut c_ww = 0u32;
    let mut c_wr = 0u32;
    let mut c_acl = 0u32;
    for h in hits {
        let m = u32::from_str_radix(&h.mode, 8).unwrap_or(0);
        if m & 0o4000 != 0 {
            c_setuid += 1;
        }
        if m & 0o2000 != 0 {
            c_setgid += 1;
        }
        if m & 0o1000 != 0 {
            c_sticky += 1;
        }
        if m & 0o002 != 0 {
            c_ww += 1;
        }
        if m & 0o004 != 0 && filter.world_readable {
            c_wr += 1;
        }
        if h.has_acl {
            c_acl += 1;
        }
    }

    if hits.is_empty() {
        eprintln!(
            "{}",
            paint(
                Style::Label,
                &format!("(no matches — scanned in {} ms)", elapsed_ms)
            )
        );
        return incomplete_result(incomplete);
    }

    // ── Render table via render::aligned_table ───────────────────────
    let header = &["mode", "user", "group", "acl", "size", "path", "flags"];
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(hits.len());
    for h in hits {
        let m = u32::from_str_radix(&h.mode, 8).unwrap_or(0);
        // Paint `mode` cell so each row makes the filter-match reason
        // visible at a glance:
        //   * world-writable or any special bit → red (WarnMajor)
        //   * matched `--world-readable` filter with o+r set → yellow
        //     (Highlight) — caller asked for it, show it.
        //   * matched `--world-executable` filter with o+x set → yellow
        //   * everything else → plain Primary.
        let mode_paint = if m & 0o7000 != 0 || m & 0o002 != 0 {
            paint(Style::WarnMajor, &h.mode)
        } else if (filter.world_readable && m & 0o004 != 0)
            || (filter.world_executable && m & 0o001 != 0)
        {
            paint(Style::Highlight, &h.mode)
        } else {
            paint(Style::Primary, &h.mode)
        };
        let acl_cell = if h.has_acl {
            paint(Style::AclMarker, glyphs().bullet_filled)
        } else {
            paint(Style::Separator, "-")
        };
        let mut flags: Vec<String> = Vec::new();
        if m & 0o4000 != 0 {
            flags.push(paint(Style::WarnMajor, "[setuid]"));
        }
        if m & 0o2000 != 0 {
            flags.push(paint(Style::WarnMajor, "[setgid]"));
        }
        if m & 0o1000 != 0 {
            flags.push(paint(Style::WarnMajor, "[sticky]"));
        }
        if m & 0o002 != 0 {
            flags.push(paint(Style::Danger, "[world-writable]"));
        }
        if h.has_acl {
            flags.push(paint(Style::AclMarker, "[acl]"));
        }
        rows.push(vec![
            mode_paint,
            paint(Style::User, &h.user),
            paint(Style::Group, &h.group),
            acl_cell,
            paint(Style::Label, &render::format_size(h.size)),
            paint(Style::Primary, &h.path.display().to_string()),
            flags.join(" "),
        ]);
    }
    println!("{}", aligned_table(header, &rows));

    // Stderr summary.
    let n = hits.len().to_string();
    let su = c_setuid.to_string();
    let sg = c_setgid.to_string();
    let st = c_sticky.to_string();
    let ww = c_ww.to_string();
    let wr = c_wr.to_string();
    let ac = c_acl.to_string();
    let segs: Vec<(&str, &str)> = vec![
        (n.as_str(), "matches"),
        (if c_setuid > 0 { su.as_str() } else { "" }, "setuid"),
        (if c_setgid > 0 { sg.as_str() } else { "" }, "setgid"),
        (if c_sticky > 0 { st.as_str() } else { "" }, "sticky"),
        (if c_ww > 0 { ww.as_str() } else { "" }, "world-writable"),
        (if c_wr > 0 { wr.as_str() } else { "" }, "world-readable"),
        (if c_acl > 0 { ac.as_str() } else { "" }, "acl"),
    ];
    let ms = format!("{elapsed_ms}");
    let mut all = summary_line(&segs);
    all.push_str("  ");
    all.push_str(&paint(Style::Separator, glyphs().midot));
    all.push_str("  ");
    all.push_str(&paint(Style::Label, &format!("{ms} ms")));
    eprintln!("{all}");
    incomplete_result(incomplete)
}

/// `audit --fix ACTION`: find + mutate in one transaction.
pub fn cmd_audit_fix(
    path: &str,
    filter: &AuditFilter,
    exclude: &ExcludeSet,
    action: &str,
    dry_run: bool,
    include_pseudo: bool,
    best_effort: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let result = scan(&root, filter, exclude, include_pseudo, true);
    let hits = &result.hits;
    if result.pseudo_skipped > 0 {
        eprintln!(
            "info: skipped {} pseudo-filesystem mount point(s) (use --include-pseudo to include)",
            result.pseudo_skipped
        );
    }
    // Fixing based on a partial scan is worse than fixing nothing: it leaves
    // the unreachable half untouched while reporting the run as done.
    incomplete_result(result.report_incomplete(best_effort))?;
    if hits.is_empty() {
        println!("(no matches; nothing to fix)");
        return Ok(());
    }
    // The mutation commands take UTF-8 operands. Refuse up front rather than
    // hand them a lossy name that resolves to nothing (or to something else).
    let mut paths: Vec<String> = Vec::with_capacity(hits.len());
    for h in hits {
        match h.path.clone().into_os_string().into_string() {
            Ok(p) => paths.push(p),
            Err(os) => {
                return Err(crate::errors::PmError::Other(format!(
                    "audit --fix: {} is not valid UTF-8; nothing was changed (fix that path \
                     by hand)",
                    os.to_string_lossy()
                )))
            }
        }
    }
    println!("audit --fix: {} path(s) → {action}", paths.len());
    let empty = ExcludeSet::default();
    let parts: Vec<&str> = action.splitn(2, ' ').collect();
    match parts.as_slice() {
        ["chmod", arg] => {
            crate::chperm::cmd_chmod(arg.trim(), &paths, false, true, None, &empty, dry_run)
        }
        ["chown", arg] => {
            crate::chperm::cmd_chown(arg.trim(), &paths, false, true, None, &empty, dry_run)
        }
        ["preset", name] => {
            crate::presets::cmd_apply_preset(name.trim(), &paths, false, &empty, dry_run)
        }
        ["strip-world-write"] => {
            crate::chperm::cmd_chmod("o-w", &paths, false, true, None, &empty, dry_run)
        }
        ["strip-setuid"] => {
            crate::chperm::cmd_chmod("u-s", &paths, false, true, None, &empty, dry_run)
        }
        ["strip-setgid"] => {
            crate::chperm::cmd_chmod("g-s", &paths, false, true, None, &empty, dry_run)
        }
        ["strip-sticky"] => {
            crate::chperm::cmd_chmod("-t", &paths, false, true, None, &empty, dry_run)
        }
        _ => Err(crate::errors::PmError::Other(format!(
            "unsupported --fix action: {action:?}  (try `chmod MODE`, `chown SPEC`, \
`preset NAME`, `strip-world-write`, `strip-setuid`, `strip-setgid`, `strip-sticky`)"
        ))),
    }
}

/// `find-orphans`: files with non-existent owner/group.
pub fn cmd_find_orphans(
    path: &str,
    as_json: bool,
    include_pseudo: bool,
    best_effort: bool,
) -> Result<()> {
    let root = resolve_path(path)?;
    let t0 = Instant::now();
    let mut hits: Vec<(AuditHit, &'static str)> = Vec::new();
    let mut pseudo_skipped = 0usize;
    let root_dev = std::fs::symlink_metadata(&root)
        .map(|m| m.dev())
        .unwrap_or(0);
    let walker = walkdir::WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if include_pseudo {
                return true;
            }
            if e.file_type().is_dir() {
                if let Ok(md) = e.metadata() {
                    if md.dev() != root_dev && crate::helpers::is_pseudo_fs(e.path()) {
                        pseudo_skipped += 1;
                        return false;
                    }
                }
            }
            true
        });
    let mut unreadable: Vec<String> = Vec::new();
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                unreadable.push(describe_walk_error(&e));
                continue;
            }
        };
        let p = entry.path();
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                unreadable.push(format!("{}: {e}", p.display()));
                continue;
            }
        };
        let uid = md.uid();
        let gid = md.gid();
        let has_u = uid_exists(Uid::from_raw(uid));
        let has_g = gid_exists(Gid::from_raw(gid));
        let kind = match (has_u, has_g) {
            (true, true) => continue,
            (false, false) => "uid+gid",
            (false, true) => "uid",
            (true, false) => "gid",
        };
        hits.push((
            AuditHit {
                path: p.to_path_buf(),
                mode: format!("{:04o}", md.mode() & 0o7777),
                uid,
                user: uid_to_name(Uid::from_raw(uid)),
                gid,
                group: gid_to_name(Gid::from_raw(gid)),
                has_acl: has_extended_acl(p) == Some(true),
                size: md.len(),
            },
            kind,
        ));
    }
    let elapsed_ms = t0.elapsed().as_millis();
    if pseudo_skipped > 0 {
        eprintln!(
            "info: skipped {} pseudo-filesystem mount point(s) (use --include-pseudo to include)",
            pseudo_skipped
        );
    }

    let incomplete = incomplete_result(
        ScanResult {
            hits: Vec::new(),
            pseudo_skipped,
            unreadable,
        }
        .report_incomplete(best_effort),
    );

    if as_json {
        let simple: Vec<&AuditHit> = hits.iter().map(|(h, _)| h).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&simple).unwrap_or_else(|_| "[]".into())
        );
        return incomplete;
    }

    if hits.is_empty() {
        eprintln!(
            "{}",
            paint(
                Style::Label,
                &format!(
                    "(no orphaned files under {} — scanned in {} ms)",
                    root.display(),
                    elapsed_ms
                )
            )
        );
        return incomplete;
    }

    let header = &["mode", "owner", "group", "orphan", "size", "path"];
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(hits.len());
    for (h, kind) in &hits {
        rows.push(vec![
            paint(Style::Primary, &h.mode),
            paint(Style::Danger, &h.user),
            paint(Style::Danger, &h.group),
            paint(Style::Danger, &format!("[{kind}]")),
            paint(Style::Label, &render::format_size(h.size)),
            paint(Style::Primary, &h.path.display().to_string()),
        ]);
    }
    println!("{}", aligned_table(header, &rows));

    let n = hits.len().to_string();
    let mut summary = summary_line(&[(n.as_str(), "orphaned"), (&format!("{elapsed_ms}"), "ms")]);
    summary.push_str("\n  ");
    summary.push_str(&paint(
        Style::Label,
        "tip: fix with `janitor chown <user>:<group> PATH [...]`",
    ));
    eprintln!("{summary}");
    incomplete
}

// keep Path import alive
#[allow(dead_code)]
fn _keep() {
    let _ = Path::new("/");
}
