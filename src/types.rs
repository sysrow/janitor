//! Serializable snapshot record types (MessagePack on disk).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Single filesystem entry captured in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapEntry {
    /// Path stored as bytes for lossless non-UTF-8 round-trip on Unix.
    #[serde(serialize_with = "ser_path", deserialize_with = "de_path")]
    pub path: PathBuf,
    /// Full st_mode including file-type bits.
    pub mode: u32,
    /// Permission bits only (lower 12 bits of st_mode).
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    pub is_symlink: bool,
    pub is_dir: bool,
    /// `st_dev` of the captured inode. Zero in backups written before
    /// identity checking existed, which restore treats as "unknown".
    #[serde(default)]
    pub dev: u64,
    /// `st_ino` of the captured inode. Zero means "unknown" (see `dev`).
    #[serde(default)]
    pub ino: u64,
    /// Raw ACL text (as produced by `getfacl -c`). None if ACLs not captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl: Option<String>,
    /// Raw default ACL text (directories only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_acl: Option<String>,
    /// ACL capture was requested but could not be performed — the tooling is
    /// missing or the filesystem has no ACL support. Distinct from `acl:
    /// None`, which means "captured, and there was nothing to record".
    #[serde(default)]
    pub acl_unavailable: bool,
}

/// Serialize PathBuf as raw bytes (OsStr) so non-UTF-8 filenames survive.
fn ser_path<S: serde::Serializer>(p: &PathBuf, s: S) -> Result<S::Ok, S::Error> {
    use std::os::unix::ffi::OsStrExt;
    s.serialize_bytes(p.as_os_str().as_bytes())
}

/// Deserialize PathBuf from either bytes (msgpack) or string (legacy JSON).
fn de_path<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    struct PathVisitor;
    impl<'de> serde::de::Visitor<'de> for PathVisitor {
        type Value = PathBuf;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a byte array or string representing a path")
        }
        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<PathBuf, E> {
            Ok(PathBuf::from(OsString::from_vec(v.to_vec())))
        }
        fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<PathBuf, E> {
            Ok(PathBuf::from(OsString::from_vec(v)))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<PathBuf, E> {
            Ok(PathBuf::from(v))
        }
        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<PathBuf, E> {
            Ok(PathBuf::from(v))
        }
    }
    d.deserialize_any(PathVisitor)
}

/// Describes which operation produced a backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    #[serde(rename = "type")]
    pub op_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_level: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_op: Option<String>,
}

/// Complete backup payload stored as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub id: String,
    pub timestamp: String,
    pub operation: Operation,
    pub entries: Vec<SnapEntry>,
}

/// Parsed access bits (rwx subset).
#[derive(Debug, Clone, Copy)]
pub struct AccessBits(pub u32);

#[allow(dead_code)]
impl AccessBits {
    pub fn has_read(self) -> bool {
        self.0 & 0o4 != 0
    }
    pub fn has_write(self) -> bool {
        self.0 & 0o2 != 0
    }
    pub fn has_exec(self) -> bool {
        self.0 & 0o1 != 0
    }
}
