//! Managed-group helpers: create, add user, remove user, and cleanup.

use std::process::Command;

use crate::errors::{PmError, Result};
use crate::users::{group_exists, user_in_group};

pub fn ensure_group(name: &str, dry_run: bool) -> Result<()> {
    if group_exists(name) {
        return Ok(());
    }
    if dry_run {
        println!("[dry-run] groupadd {name}");
        return Ok(());
    }
    let status = Command::new("/usr/sbin/groupadd")
        .arg(name)
        .status()
        .map_err(|e| PmError::GroupCreateFailed {
            name: name.to_string(),
            reason: format!("`groupadd` not found or failed to execute: {e}"),
        })?;
    if !status.success() {
        return Err(PmError::GroupCreateFailed {
            name: name.to_string(),
            reason: format!("exit code {}", status.code().unwrap_or(-1)),
        });
    }
    Ok(())
}

pub fn add_user_to_group(user: &str, group: &str, dry_run: bool) -> Result<()> {
    if user_in_group(user, group) {
        return Ok(());
    }
    if dry_run {
        println!("[dry-run] gpasswd -a {user} {group}");
        return Ok(());
    }
    let status = Command::new("/usr/bin/gpasswd")
        .args(["-a", user, group])
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| PmError::GroupMembershipFailed(e.to_string()))?;
    if !status.success() {
        return Err(PmError::GroupMembershipFailed(format!(
            "could not add {user} to {group} (exit {})",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

/// Delete a group created by an earlier `grant`.
///
/// Only `pm_`-prefixed groups are eligible: restore must never delete a
/// pre-existing system group just because a grant happened to use it.
/// Returns Ok(true) if the group was deleted.
pub fn delete_managed_group(name: &str) -> Result<bool> {
    if !name.starts_with("pm_") {
        return Ok(false);
    }
    if !group_exists(name) {
        return Ok(false);
    }
    let status = Command::new("/usr/sbin/groupdel")
        .arg(name)
        .status()
        .map_err(|e| PmError::GroupMembershipFailed(format!("`groupdel` failed: {e}")))?;
    if !status.success() {
        return Err(PmError::GroupMembershipFailed(format!(
            "could not delete group {name} (exit {})",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(true)
}

/// Remove user from group. Returns Ok(true) if removed, Ok(false) if no-op.
pub fn remove_user_from_group(user: &str, group: &str, dry_run: bool) -> Result<bool> {
    if !group_exists(group) {
        eprintln!("group {group:?} does not exist; nothing to remove");
        return Ok(false);
    }
    if !user_in_group(user, group) {
        eprintln!("user {user:?} is not in {group:?}; nothing to remove");
        return Ok(false);
    }
    if dry_run {
        println!("[dry-run] gpasswd -d {user} {group}");
        return Ok(true);
    }
    let status = Command::new("/usr/bin/gpasswd")
        .args(["-d", user, group])
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| PmError::GroupMembershipFailed(e.to_string()))?;
    if !status.success() {
        return Err(PmError::GroupMembershipFailed(format!(
            "could not remove {user} from {group} (exit {})",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(true)
}
