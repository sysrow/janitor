//! Effective-access evaluator, ACL aware.
//!
//! Answers the question "what can user U actually do to this inode?" by
//! consulting the POSIX mode bits **and** any POSIX ACL entries + mask.
//!
//! We intentionally shell out to `getfacl -cn` (via `acl::get_acl`) and
//! parse the canonical entries rather than binding to `libacl`. It keeps
//! the dep surface minimal and matches how the rest of this crate
//! reads/writes ACLs.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

use crate::acl::{get_acl, has_extended_acl};
use crate::errors::Result;
use crate::users::{lookup_user, user_gids};

/// The resulting access verdict: bits plus the rule that decided them.
#[derive(Debug, Clone)]
pub struct AccessDecision {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    /// Human-readable rule describing how the verdict was reached.
    /// Used by `explain` and surfaces in `info -U`.
    pub reason: String,
}

/// Evaluate effective (r, w, x) for `username` on `path`.
///
/// The algorithm follows POSIX.1e §23.4.5:
/// 1. Superuser (uid 0) gets r+w. Execute only if any `x` bit is set, or
///    if the inode is a directory.
/// 2. Owner (uid == file uid) uses `ACL_USER_OBJ` (== owner triad), **no
///    mask** applied.
/// 3. If any `ACL_USER:<user>` entry matches, its bits are ANDed with
///    the mask.
/// 4. Otherwise collect every matching group entry: `ACL_GROUP_OBJ` if
///    the caller is in the file group, plus every `ACL_GROUP:<name>`
///    whose group the caller belongs to. The union of their bits,
///    ANDed with the mask, decides.
/// 5. Else `ACL_OTHER` (== other triad).
///
/// If the file has no extended ACL, steps 3-5 collapse to the standard
/// group/other triads (no mask, since no mask entry exists).
///
/// Takes a path rather than `Metadata` on purpose: `Metadata` does not
/// carry the originating path, and without it the ACL entries above cannot
/// be read at all.
pub fn effective_for_user_path(path: &std::path::Path, username: &str) -> Result<AccessDecision> {
    let md = std::fs::symlink_metadata(path)?;
    let u = lookup_user(username)?;
    let uid = u.uid.as_raw();
    let gids: HashSet<u32> = user_gids(username)?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();

    let mode = md.mode() & 0o7777;
    let is_dir = md.is_dir();

    if uid == 0 {
        return Ok(AccessDecision {
            read: true,
            write: true,
            exec: is_dir || (mode & 0o111 != 0),
            reason: "root (superuser)".into(),
        });
    }
    if uid == md.uid() {
        return Ok(AccessDecision {
            read: mode & 0o400 != 0,
            write: mode & 0o200 != 0,
            exec: mode & 0o100 != 0,
            reason: "owner".into(),
        });
    }

    if has_extended_acl(path) {
        if let Ok(Some(text)) = get_acl(path) {
            if let Some(d) = evaluate_acl(&text, uid, &gids, md.gid(), username) {
                return Ok(d);
            }
        }
    }

    let group_match = gids.contains(&md.gid());
    if group_match {
        Ok(AccessDecision {
            read: mode & 0o040 != 0,
            write: mode & 0o020 != 0,
            exec: mode & 0o010 != 0,
            reason: "group member".into(),
        })
    } else {
        Ok(AccessDecision {
            read: mode & 0o004 != 0,
            write: mode & 0o002 != 0,
            exec: mode & 0o001 != 0,
            reason: "other".into(),
        })
    }
}

/// Parse a canonical `getfacl -c` block and apply POSIX.1e evaluation
/// for user `uid` with supplementary group set `gids`. `file_gid` is the
/// file group ownership (matched by `group::` entries). Returns `None`
/// if evaluation could not be performed (malformed input).
fn evaluate_acl(
    text: &str,
    uid: u32,
    gids: &HashSet<u32>,
    file_gid: u32,
    username: &str,
) -> Option<AccessDecision> {
    let mut group_obj: Option<u32> = None;
    let mut other: Option<u32> = None;
    let mut mask: Option<u32> = Some(0o7); // default: no mask ⇒ no-op
    let mut mask_present = false;
    let mut named_users: Vec<(String, u32)> = Vec::new();
    let mut named_groups: Vec<(String, u32)> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `default:*` entries apply only to newly-created children of a
        // directory, never to access checks on the entry itself. They
        // must be skipped rather than parsed — otherwise a malformed
        // line like `default:user:bob:rwx` (3-colon form) would short
        // out parse_perm_bits and abort evaluation for the whole block.
        if line.starts_with("default:") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        let kind = parts[0].trim();
        let qual = parts[1].trim();
        let bits = parse_perm_bits(parts[2].trim())?;
        match (kind, qual.is_empty()) {
            ("user", true) => { /* owner is handled by caller */ }
            ("user", false) => named_users.push((qual.to_string(), bits)),
            ("group", true) => group_obj = Some(bits),
            ("group", false) => named_groups.push((qual.to_string(), bits)),
            ("mask", _) => {
                mask = Some(bits);
                mask_present = true;
            }
            ("other", _) => other = Some(bits),
            _ => {}
        }
    }
    let _ = uid; // named-user matching uses username/#id, not uid directly
    let _ = &mask; // silence
    let mask_bits = mask.unwrap_or(0o7);

    // Rule 3: named user match.
    for (name, bits) in &named_users {
        if matches_user(name, username, uid) {
            let eff = if mask_present {
                bits & mask_bits
            } else {
                *bits
            };
            return Some(decision_from_bits(eff, format!("acl user:{name} ∧ mask")));
        }
    }

    // Rule 4: collect matching group entries.
    let mut matched_any_group = false;
    let mut union_bits: u32 = 0;
    let mut reasons: Vec<String> = Vec::new();
    if gids.contains(&file_gid) {
        if let Some(b) = group_obj {
            matched_any_group = true;
            union_bits |= b;
            reasons.push("acl group::".into());
        }
    }
    for (name, bits) in &named_groups {
        if matches_group(name, gids) {
            matched_any_group = true;
            union_bits |= *bits;
            reasons.push(format!("acl group:{name}"));
        }
    }
    if matched_any_group {
        let eff = if mask_present {
            union_bits & mask_bits
        } else {
            union_bits
        };
        let reason = format!("{} ∧ mask", reasons.join(" ∪ "));
        return Some(decision_from_bits(eff, reason));
    }

    // Rule 5: other.
    if let Some(b) = other {
        return Some(decision_from_bits(b, "acl other".into()));
    }
    None
}

fn parse_perm_bits(s: &str) -> Option<u32> {
    // "r-x", "rw-", "---", sometimes "rwx	#effective:rw-" — trim at TAB.
    let head = s.split_whitespace().next().unwrap_or(s);
    if head.len() != 3 {
        return None;
    }
    let bs: Vec<char> = head.chars().collect();
    let r = matches!(bs[0], 'r');
    let w = matches!(bs[1], 'w');
    let x = matches!(bs[2], 'x');
    Some(if r { 0o4 } else { 0 } | if w { 0o2 } else { 0 } | if x { 0o1 } else { 0 })
}

fn matches_user(entry: &str, username: &str, uid: u32) -> bool {
    if entry == username {
        return true;
    }
    // `getfacl` renders unresolvable uids as `#1234`.
    if let Some(stripped) = entry.strip_prefix('#') {
        if stripped.parse::<u32>().ok() == Some(uid) {
            return true;
        }
    }
    if entry.parse::<u32>().ok() == Some(uid) {
        return true;
    }
    false
}

fn matches_group(entry: &str, gids: &HashSet<u32>) -> bool {
    use nix::unistd::{Gid, Group};
    if let Ok(Some(g)) = Group::from_name(entry) {
        if gids.contains(&g.gid.as_raw()) {
            return true;
        }
    }
    if let Some(stripped) = entry.strip_prefix('#') {
        if let Ok(n) = stripped.parse::<u32>() {
            if gids.contains(&n) {
                return true;
            }
        }
    }
    if let Ok(n) = entry.parse::<u32>() {
        if gids.contains(&n) {
            return true;
        }
    }
    let _ = Gid::from_raw; // suppress unused
    false
}

fn decision_from_bits(bits: u32, reason: String) -> AccessDecision {
    AccessDecision {
        read: bits & 0o4 != 0,
        write: bits & 0o2 != 0,
        exec: bits & 0o1 != 0,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_perm_basic() {
        assert_eq!(parse_perm_bits("rwx"), Some(0o7));
        assert_eq!(parse_perm_bits("r--"), Some(0o4));
        assert_eq!(parse_perm_bits("rw-"), Some(0o6));
        assert_eq!(parse_perm_bits("---"), Some(0o0));
    }

    #[test]
    fn parse_perm_with_effective_comment() {
        assert_eq!(parse_perm_bits("rwx\t#effective:r-x"), Some(0o7));
    }

    #[test]
    fn acl_named_user_beats_other() {
        let text = "\
user::rw-
user:bob:r--
group::---
mask::r--
other::---
";
        let gids = HashSet::new();
        // bob=uid 1003 hypothetical; match by name.
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(d.read);
        assert!(!d.write);
        assert!(!d.exec);
    }

    #[test]
    fn acl_named_user_masked() {
        let text = "\
user::rw-
user:bob:rw-
mask::r--
other::---
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(d.read);
        assert!(!d.write, "mask must drop write");
    }

    #[test]
    fn acl_group_union() {
        let text = "\
user::rw-
group::r--
group:extra:--x
mask::rwx
other::---
";
        // caller is in both file-group (1006) and 'extra' (7777).
        let mut gids = HashSet::new();
        gids.insert(1006);
        gids.insert(7777);
        // 'extra' is unlikely to resolve; matches_group will fall back.
        // This test primarily covers group_obj + mask.
        let d = evaluate_acl(text, 1003, &gids, 1006, "someone").unwrap();
        assert!(d.read);
    }

    #[test]
    fn acl_falls_through_to_other() {
        let text = "\
user::rw-
group::r--
mask::r--
other::r--
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 9999, &gids, 1006, "nobody").unwrap();
        assert!(d.read);
        assert!(!d.write);
    }

    // ── Extra edge cases ──────────────────────────────────────────────

    #[test]
    fn acl_named_user_zero_mask_denies() {
        // Named user with rwx but mask=0 → no effective access.
        let text = "\
user::rw-
user:bob:rwx
group::---
mask::---
other::---
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(!d.read && !d.write && !d.exec, "mask 0 denies named user");
    }

    #[test]
    fn acl_other_entry_ignores_mask() {
        // The `other::` entry is NOT constrained by mask (POSIX).
        let text = "\
user::---
group::---
mask::---
other::r--
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 9999, &gids, 1006, "stranger").unwrap();
        assert!(d.read, "other bits are outside mask");
    }

    #[test]
    fn acl_trailing_effective_comment_parsed() {
        // Real `getfacl` output often includes `#effective:` comments.
        let text = "\
user::rw-
user:bob:rwx\t\t#effective:r--
mask::r--
other::---
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(d.read);
        assert!(!d.write && !d.exec, "effective comment is metadata only");
    }

    #[test]
    fn acl_blank_and_comment_lines_ignored() {
        let text = "\
# file: /srv/x
# owner: alice

user::rw-
user:bob:r--
group::---
mask::r--
other::---
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(d.read);
    }

    #[test]
    fn acl_default_entries_do_not_grant() {
        // `default:` entries apply to children of directories, not to
        // access checks on the entry itself. They must not grant access
        // to a user who has no access-ACL entry.
        let text = "\
user::rw-
group::---
mask::---
other::---
default:user:bob:rwx
default:group::rwx
default:mask::rwx
default:other::rwx
";
        let gids = HashSet::new();
        let d = evaluate_acl(text, 1003, &gids, 1006, "bob").unwrap();
        assert!(
            !d.read && !d.write && !d.exec,
            "default-ACL must not grant access on the entry itself"
        );
    }
}
