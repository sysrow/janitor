//! Shared error and result types.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PmError {
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("cannot access {0}: permission denied (missing search permission on a parent directory)\n       (try sudo)")]
    PathInaccessible(PathBuf),

    #[error("--access must be a non-empty combination of r/w/x (got {0:?})")]
    BadAccess(String),

    #[error("user {0:?} does not exist")]
    UserNotFound(String),

    #[error("group {0:?} does not exist")]
    GroupNotFound(String),

    #[error("could not create group {name}: {reason}")]
    GroupCreateFailed { name: String, reason: String },

    #[error("could not modify group membership: {0}")]
    GroupMembershipFailed(String),

    #[error("backup {0:?} not found")]
    BackupNotFound(String),

    #[error("backup directory error: {0}")]
    #[allow(dead_code)]
    BackupDirError(String),

    #[error("insufficient privileges for {path}: {reason}\n       (try sudo)")]
    InsufficientPrivileges { path: PathBuf, reason: String },

    #[error("--user or --group is required")]
    NoUserOrGroup,

    #[error("invalid group name {0:?}: must match [a-z_][a-z0-9_-]{{0,31}}")]
    InvalidGroupName(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Json(#[from] serde_json::Error),

    #[error("filesystem at {path} does not support POSIX ACLs\n       use regular `grant` / `chmod` instead, or remount with the `acl` mount option")]
    AclUnsupported { path: PathBuf },

    #[error("allow path {allow} is not inside seal base {base}\n       seal refuses to touch paths outside the base directory")]
    SealAllowOutsideBase { allow: PathBuf, base: PathBuf },

    #[error("seal --base must be a directory: {0}")]
    SealBaseNotDir(PathBuf),

    #[error(
        "cannot snapshot {path}: {reason}\n       refusing to mutate with an incomplete backup"
    )]
    SnapshotFailed { path: PathBuf, reason: String },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PmError>;
