//! Clap definitions: the full argument parser and subcommand enum.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Parser, Debug)]
#[command(
    name = "janitor",
    version,
    about = "Hierarchical Unix permissions manager with snapshots and ACL support.",
    long_about = "janitor manages Unix file permissions, ownership, and POSIX ACLs with \
an automatic snapshot taken before every change. Any operation can be reverted exactly \
with `janitor restore <id>`. See janitor(1) for the full manual.",
    after_long_help = EPILOG,
    propagate_version = true,
)]
pub struct Cli {
    /// Print what would happen without touching the filesystem.
    #[arg(short = 'n', long, global = true)]
    pub dry_run: bool,

    /// Emit machine-readable JSON output (where supported).
    #[arg(short = 'j', long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Grant a user or group access to a path (hierarchical, auto-snapshot).
    #[command(
        visible_alias = "g",
        long_about = "Grant access to PATH for a user or group.\n\n\
Access is specified with the short boolean flags -r (read), -w (write), -x \
(execute/traverse). They can be combined in any order or bundled together, \
so `-rx`, `-xr`, `-rwx`, or `-r -w` all work. Use -a/--access \"rw\" as an \
alternative string form. If no access flag is given, defaults to read-only.\n\n\
The full parent chain of PATH is made traversable (`--x`) so the user can \
reach the target, but siblings and other contents of parent directories \
remain hidden. A managed group named `pm_tmp_<owner>_<pathhash>` is created \
(unless -g GROUP is given) and the user is added to it. A snapshot is taken \
first; revert anytime with `janitor restore <id>`."
    )]
    Grant {
        /// Target file or directory.
        path: String,
        /// User to grant access to.
        #[arg(short = 'u', long, conflicts_with = "group")]
        user: Option<String>,
        /// Group to grant access to (instead of a user).
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Read bit.
        #[arg(short = 'r', long = "read")]
        read: bool,
        /// Write bit.
        #[arg(short = 'w', long = "write")]
        write: bool,
        /// Execute (or traverse, on directories) bit.
        #[arg(short = 'x', long = "exec")]
        exec: bool,
        /// Access string form (`r`, `rw`, `rwx`). Alternative to -r/-w/-x.
        #[arg(short = 'a', long, conflicts_with_all = ["read", "write", "exec"])]
        access: Option<String>,
        /// Limit how many parent directory levels above PATH are made traversable.
        #[arg(short = 'L', long)]
        max_level: Option<usize>,
        /// Apply to every file and subdirectory under PATH (walked recursively).
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Modify parents even if one is already world-readable (normally skipped).
        #[arg(long)]
        force_all_parents: bool,
        /// Skip capturing POSIX ACLs in the snapshot (ACLs are recorded by default).
        #[arg(long)]
        no_acl: bool,
        /// Skip any path matching this glob (repeatable, matches full path or basename).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
    },

    /// Revoke a user's access granted by `janitor grant` (all-or-nothing).
    #[command(
        visible_alias = "rv",
        long_about = "Revokes a user's access by removing them from the managed group \
created by `grant`. This is all-or-nothing: the user loses every bit of access that came \
through that group. The managed group itself, the file's mode, and any ACLs are left \
untouched, and other members of the group keep their access.\n\n\
For partial (bit-level) revocation, use one of:\n  \
* `janitor chmod <mode> PATH`       -- adjust traditional mode bits (auto-snapshot)\n  \
* `janitor acl revoke PATH -u USER` -- remove a specific ACL entry\n  \
* `janitor restore <id>`            -- undo a specific earlier `grant` exactly"
    )]
    Revoke {
        /// Target file or directory.
        path: String,
        /// User to remove from the managed group.
        #[arg(short = 'u', long)]
        user: String,
        /// Explicit managed group (auto-derived from PATH by default).
        #[arg(short = 'g', long)]
        group: Option<String>,
    },

    /// Colored permission tree (honors `--for-user`).
    #[command(visible_alias = "t")]
    Tree {
        /// Root of the tree.
        path: String,
        /// Maximum depth.
        #[arg(short = 'L', long)]
        max_depth: Option<usize>,
        /// Also walk and show each parent above PATH.
        #[arg(short = 'P', long)]
        show_parents: bool,
        /// Highlight entries matching this substring.
        #[arg(short = 'H', long)]
        highlight: Option<String>,
        /// Highlight effective access for this user.
        #[arg(short = 'U', long)]
        for_user: Option<String>,
        /// When to colorize output.
        #[arg(short = 'c', long, value_enum, default_value = "auto")]
        color: ColorMode,
        /// Mark entries that carry POSIX ACLs.
        #[arg(short = 'A', long)]
        acl: bool,
    },

    /// Take a manual snapshot without changing anything.
    #[command(visible_alias = "b")]
    Backup {
        /// Path to snapshot.
        path: String,
        /// Recurse into directories.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Skip capturing POSIX ACLs (ACLs are recorded by default).
        #[arg(long)]
        no_acl: bool,
    },

    /// Restore a backup by id (full revert).
    #[command(visible_alias = "r")]
    Restore {
        /// Backup id (see `janitor list-backups`).
        backup_id: String,
        /// Skip the interactive confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Report paths that no longer exist as skipped instead of failing.
        #[arg(long)]
        skip_missing: bool,
    },

    /// Undo the most recent backup (shortcut for `restore $(list-backups | head -1)`).
    #[command(
        visible_alias = "u",
        long_about = "Undo the most recent mutation.\n\n\
Looks up the newest backup and restores it. Equivalent to:\n\n  \
    janitor restore \"$(janitor ls | awk 'NR==3 {print $1}')\"\n\n\
Useful as a one-shot revert after any grant / chmod / chown / acl operation.\n\
Combine with --dry-run to preview what would be reverted."
    )]
    Undo {
        /// Skip the interactive confirmation prompt.
        #[arg(short = 'y', long = "yes")]
        yes: bool,
        /// Report paths that no longer exist as skipped instead of failing.
        #[arg(long)]
        skip_missing: bool,
    },

    /// Show the backup history touching PATH (newest first).
    #[command(
        visible_alias = "h",
        long_about = "Print every saved backup whose target path contains PATH \
(substring match), newest first. Shows id, timestamp, operation type, and \
invoking user. Combine with --json for machine-readable output.\n\n\
Example: `janitor history /srv/app | head` -- what changed here recently?"
    )]
    History {
        /// Path substring to filter by.
        path: String,
        /// Only show backups newer than this duration (`1h`, `30m`, `2d`, `1w`).
        #[arg(short = 's', long = "since", value_name = "DUR")]
        since: Option<String>,
    },

    /// Copy mode, owner, group, and (optionally) ACLs from SRC to DST.
    #[command(
        visible_alias = "cp",
        long_about = "Copy permissions from SRC to DST. By default copies mode \
+ owner + group. With -A also copies POSIX ACLs. With -R the same mode is \
applied to every file and subdirectory under DST. A snapshot of DST is taken \
first; revert with `janitor restore <id>`.\n\n\
Equivalent to running `chmod --reference=SRC DST && chown --reference=SRC DST` \
in one atomic operation, but with audit-logging + snapshot."
    )]
    CopyPerms {
        /// Source path (perms are read from here).
        src: String,
        /// Destination path (perms are written to here).
        dst: String,
        /// Also copy POSIX ACLs.
        #[arg(short = 'A', long)]
        acl: bool,
        /// Apply to every file and subdirectory under DST.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Skip any path matching this glob (repeatable).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
    },

    /// List available backups.
    #[command(visible_alias = "ls")]
    ListBackups {
        /// Only show backups whose target path contains this substring.
        #[arg(short = 'p', long = "path", value_name = "SUBSTR")]
        path: Option<String>,
    },

    /// Keep the most recent N backups, delete the rest.
    #[command(visible_alias = "prune")]
    PruneBackups {
        /// How many backups to keep.
        #[arg(short = 'k', long, default_value = "50")]
        keep: usize,
    },

    /// Show what a backup would revert (vs current state).
    Diff {
        /// Backup id.
        backup_id: String,
    },

    /// Dump a backup as text or JSON.
    Export {
        /// Backup id.
        backup_id: String,
    },

    /// chmod with auto-snapshot (octal or symbolic, e.g. `640`, `u+rw,g=r`).
    #[command(long_about = "Change the mode of PATH with an automatic snapshot.\n\n\
This is NOT a wrapper around the coreutils `/bin/chmod` binary. It invokes the \
`chmod(2)` syscall directly and adds: snapshot + `janitor undo`, lock-check, \
`--exclude` globs, variadic paths, `--stdin0` / `--from-file`, and `--reference`. \
The file-system effect is identical to POSIX chmod.\n\n\
MODE can be:\n  \
* Octal, including special bits: `755`, `0750`, `4755` (setuid), `2755` (setgid), \
`1777` (sticky), `6755` (setuid+setgid), `7777` (all bits).\n  \
* Symbolic, comma-separated: `u+rw,g=r,o=`, `a+X` (exec only for dirs or files \
already exec), `u+s` (setuid), `g+s` (setgid), `+t` (sticky), `u-s,g-s,-t` \
(clear all special bits).\n  \
* Copied from another file via `-F/--reference FILE` (MODE is then ignored but \
must still be provided as `-` or any placeholder).\n\n\
Revert with `janitor restore <id>`.")]
    Chmod {
        /// Mode (octal `750`, `4755`, `2755`, `1777`, or symbolic `u+rw,g=r,+t`).
        mode: String,
        /// Target path(s). One or more. With --stdin0 / --from-file the list is extended.
        #[arg(value_name = "PATH", required_unless_present_any = ["stdin0", "from_file"])]
        paths: Vec<String>,
        /// Apply recursively.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Skip capturing POSIX ACLs in the snapshot (ACLs are recorded by default).
        #[arg(long)]
        no_acl: bool,
        /// Copy the mode from another file (MODE argument is ignored).
        #[arg(short = 'F', long = "reference", value_name = "FILE")]
        reference: Option<String>,
        /// Skip any path matching this glob (repeatable, matches full path or basename).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Read NUL-separated paths from stdin (pair with `find -print0`).
        #[arg(long)]
        stdin0: bool,
        /// Read newline-separated paths from FILE (use `-` for stdin).
        #[arg(long = "from-file", value_name = "FILE")]
        from_file: Option<String>,
    },

    /// chown with auto-snapshot (`user`, `user:group`, `:group`, numeric).
    #[command(
        long_about = "Change owner and/or group of PATH with an automatic snapshot.\n\n\
This is NOT a wrapper around the coreutils `/bin/chown` binary. It invokes the \
`lchown(2)` syscall directly (symlinks are never followed, matching `chown -h`) \
and adds: snapshot + `janitor undo`, lock-check, `--exclude` globs, variadic \
paths, `--stdin0` / `--from-file`, and `--reference`. The file-system effect \
is identical to POSIX chown -h.\n\n\
SPEC can be:\n  \
* `alice`            -- change owner only\n  \
* `alice:www-data`   -- change both\n  \
* `:www-data`        -- change group only\n  \
* `alice:`           -- change owner, group follows owner's primary group\n  \
* `1000:33`          -- numeric uid:gid (bypass name lookup)\n  \
* copied from another file via `-F/--reference FILE` (SPEC is ignored but must \
still be provided as `-` or any placeholder).\n\n\
Revert with `janitor restore <id>`."
    )]
    Chown {
        /// Ownership spec (`alice`, `alice:www-data`, `:www-data`, `1000:33`).
        spec: String,
        /// Target path(s). One or more. With --stdin0 / --from-file the list is extended.
        #[arg(value_name = "PATH", required_unless_present_any = ["stdin0", "from_file"])]
        paths: Vec<String>,
        /// Apply recursively.
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Skip capturing POSIX ACLs in the snapshot (ACLs are recorded by default).
        #[arg(long)]
        no_acl: bool,
        /// Copy the owner/group from another file (SPEC argument is ignored).
        #[arg(short = 'F', long = "reference", value_name = "FILE")]
        reference: Option<String>,
        /// Skip any path matching this glob (repeatable, matches full path or basename).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Read NUL-separated paths from stdin.
        #[arg(long)]
        stdin0: bool,
        /// Read newline-separated paths from FILE (use `-` for stdin).
        #[arg(long = "from-file", value_name = "FILE")]
        from_file: Option<String>,
    },

    /// Summary view of a path: type, owner, mode (octal + symbolic), special bits, ACLs.
    #[command(
        visible_alias = "i",
        long_about = "Print everything you typically want to know about PATH in one view: \
file type, owner and group, octal mode (incl. setuid / setgid / sticky), symbolic mode, \
size, mtime, link target (for symlinks), and POSIX ACL entries if any are set. With -U USER \
also prints whether USER can read, write, and execute/traverse PATH."
    )]
    Info {
        /// Target path.
        path: String,
        /// Also evaluate effective access for this user.
        #[arg(short = 'U', long)]
        for_user: Option<String>,
    },

    /// Scan a tree for suspicious or matching permissions.
    #[command(
        visible_alias = "a",
        long_about = "Audit a directory tree against one or more criteria.\n\n\
Every filter is additive (AND): if you pass -W -s, only entries that are BOTH \
world-writable AND setuid are listed. Run multiple audits to combine (OR).\n\n\
Common recipes:\n  \
    janitor audit / -W -s           # world-writable OR setuid (by running twice, or -j|jq)\n  \
    janitor audit /srv -r -o alice  # world-readable files owned by alice\n  \
    janitor audit /bin -x -A        # exec-anywhere files that also have ACLs\n  \
    janitor audit / -m 777          # files with mode exactly 0777\n  \
    janitor audit / --no-owner      # files whose owning UID is not in /etc/passwd"
    )]
    Audit {
        /// Root of the scan.
        path: String,
        /// Report world-writable entries (other+w).
        #[arg(short = 'W', long)]
        world_writable: bool,
        /// Report world-readable entries (other+r).
        #[arg(short = 'r', long)]
        world_readable: bool,
        /// Report world-executable entries (other+x).
        #[arg(short = 'x', long)]
        world_executable: bool,
        /// Report setuid binaries.
        #[arg(short = 's', long)]
        setuid: bool,
        /// Report setgid binaries/dirs.
        #[arg(short = 'S', long)]
        setgid: bool,
        /// Report sticky-bit directories.
        #[arg(short = 't', long)]
        sticky: bool,
        /// Only include entries owned by USER.
        #[arg(short = 'o', long)]
        owner: Option<String>,
        /// Only include entries with group GROUP.
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Only include entries whose mode exactly equals this octal.
        #[arg(short = 'm', long)]
        mode: Option<String>,
        /// Only include entries that carry POSIX ACLs.
        #[arg(short = 'A', long)]
        has_acl: bool,
        /// Only include entries whose owning UID is not in /etc/passwd.
        #[arg(long = "no-owner")]
        no_owner: bool,
        /// Only include entries whose owning GID is not in /etc/group.
        #[arg(long = "no-group")]
        no_group: bool,
        /// Skip any path matching this glob (repeatable).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
        /// Descend into pseudo-filesystems (/proc, /sys, /dev, cgroup, …).
        /// By default they are skipped because their inodes are kernel-
        /// generated and never "orphaned" in the sense the user means.
        #[arg(long = "include-pseudo")]
        include_pseudo: bool,
        /// Apply an action to every match, in one transaction with a single snapshot.
        /// Supported: `chmod MODE`, `chown SPEC`, `strip-world-write`, `strip-setuid`,
        /// `strip-setgid`, `strip-sticky`, `preset NAME`.
        #[arg(long = "fix", value_name = "ACTION")]
        fix: Option<String>,
        /// Emit just the matching paths (one per line, no table, no colors,
        /// no summary — pipe-pure). Ideal for piping into `janitor chmod`
        /// or `xargs`. Combine with `-0` for NUL-separated output.
        #[arg(long = "paths", conflicts_with_all = ["fix"])]
        paths: bool,
        /// Same as --paths but NUL-separated. Use with
        /// `janitor chmod --stdin0 ...` for safe handling of odd names.
        #[arg(short = '0', long = "print0", conflicts_with_all = ["fix"])]
        print0: bool,
    },

    /// Find files whose UID or GID is not in /etc/passwd or /etc/group.
    FindOrphans {
        /// Root of the scan.
        path: String,
        /// Descend into pseudo-filesystems (/proc, /sys, /dev, cgroup, …).
        #[arg(long = "include-pseudo")]
        include_pseudo: bool,
    },

    /// Reverse access query: which users can read / write / exec PATH.
    #[command(visible_alias = "w")]
    WhoCan {
        /// Target path.
        path: String,
    },

    /// POSIX ACL management (`grant`, `revoke`, `show`, `strip`).
    #[command(subcommand)]
    Acl(AclCmd),

    /// Named permission presets (`preset list`, `preset apply NAME PATH`).
    #[command(
        visible_alias = "p",
        subcommand,
        long_about = "Named permission presets such as `private` (0600/0700), \
`group-shared` (0660/2770), `setgid-dir`, etc. `preset list` shows all \
available presets with their modes; `preset apply NAME PATH` applies one \
(snapshot-first; revert with `janitor restore <id>`)."
    )]
    Preset(PresetCmd),

    /// Seal a directory tree to a uniform baseline, with surgical per-path pinholes.
    #[command(
        long_about = "Seal is the atomic combination of `chown -R` + `chmod -R` + \
`setfacl` for 'make this tree uniform, except for a handful of exceptions'.\n\n\
The baseline (--base USER:GROUP:MODE) uses POSIX mode bits only — no ACLs \
are written unless you add --allow / --allow-group pinholes. So a plain \
`janitor seal DIR -B root:root:700 -R` works on any filesystem, FAT \
included.\n\n\
Typical use: you have /srv/secrets that should be root:root 0700 everywhere, \
but two specific files must be readable by one specific user. Without seal, \
this takes 9+ commands (chown, chmod, then setfacl -m u:USER:--x on every \
parent directory, then the final rwx entry) and one typo silently breaks \
the pinhole. With seal, it's one transaction with one backup.\n\n\
Example (POSIX-only, no ACLs written):\n  \
  janitor seal /srv/secrets -B root:root:700 -R\n\n\
Example with pinholes (adds ACLs only on the pinhole chain):\n  \
  janitor seal /srv/secrets \\\n    \
    --base root:root:700 --recursive \\\n    \
    --allow bob:r  /srv/secrets/company/.env \\\n    \
    --allow alice:rw /srv/secrets/shared/config.yaml \\\n    \
    --dry-run\n\n\
Auto-traverse: when pinholes are given, seal automatically adds \
`u:USER:--x` ACL entries on every parent directory between --base and \
each --allow target, so the pinhole actually reaches the intended file. \
This is the #1 source of silent 'why can't they read it?' failures with \
manual setfacl.\n\n\
One snapshot is taken for the entire operation; revert with `restore <id>`.",
        after_help = "see also: `grant`, `acl grant`, `restore`, `policy apply`"
    )]
    Seal {
        /// Base directory to seal.
        base: String,
        /// Baseline owner:group:mode applied to every entry under base.
        /// Examples: `root:root:700`, `alice:dev:0644`, `:www-data:750` (keep owner).
        #[arg(short = 'B', long = "base", value_name = "USER:GROUP:MODE")]
        base_spec: String,
        /// Apply baseline recursively (seal the whole subtree). Without -R only
        /// the base directory itself is adjusted.
        #[arg(short = 'R', long = "recursive")]
        recursive: bool,
        /// Pinhole: grant USER:PERM to a specific PATH inside base. Repeatable.
        /// Format: `USER:PERM PATH` as two separate values.
        /// PERM is any combination of r/w/x.
        /// Example: `--allow bob:r /srv/x/file.txt`.
        #[arg(long = "allow", value_names = ["USER:PERM", "PATH"], num_args = 2, action = clap::ArgAction::Append)]
        allow: Vec<String>,
        /// Same as --allow but for a group.
        /// Example: `--allow-group devs:rw /srv/x/shared.yaml`.
        #[arg(long = "allow-group", value_names = ["GROUP:PERM", "PATH"], num_args = 2, action = clap::ArgAction::Append)]
        allow_group: Vec<String>,
        /// Skip any path matching this glob (repeatable).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
    },

    /// Explain why a user can (or cannot) read / write / execute PATH.
    #[command(
        visible_alias = "e",
        long_about = "Human-readable explanation of effective access to PATH, walking the \
full parent chain and checking traditional mode bits, POSIX ACLs, group memberships, \
and setuid/setgid/sticky bits. Great for debugging 'why can't alice read this?' \
questions."
    )]
    Explain {
        /// Target path.
        path: String,
        /// Evaluate for this user (default: current user).
        #[arg(short = 'U', long)]
        for_user: Option<String>,
    },

    /// Compare permissions of two paths (or two trees with -R).
    #[command(
        long_about = "Side-by-side comparison of owner / group / mode / ACLs between A and B. \
With -R both trees are walked and any entry that differs is printed. Exit 0 when identical, \
1 when differences are found, so this is CI-friendly (e.g. `janitor compare /etc/prod /etc/staging`)."
    )]
    Compare {
        /// Left-hand path.
        a: String,
        /// Right-hand path.
        b: String,
        /// Walk both trees recursively and diff each matching pair.
        #[arg(short = 'r', long, visible_short_alias = 'R')]
        recursive: bool,
    },

    /// Lock a path to prevent accidental mutation via janitor.
    #[command(
        long_about = "Mark PATH as locked. Any subsequent janitor mutation targeting a \
locked path (or a descendant of a locked directory) fails with a clear error. Use `unlock` \
to clear. Locks are stored in the backup directory and persist across invocations."
    )]
    Lock {
        /// Path to lock.
        path: String,
        /// Optional reason (printed when the lock trips a later operation).
        #[arg(short = 'r', long)]
        reason: Option<String>,
    },

    /// Remove a lock previously set with `lock`.
    Unlock {
        /// Path to unlock.
        path: String,
    },

    /// List currently active locks.
    Locks,

    /// Apply or verify a declarative YAML policy describing desired permissions.
    #[command(
        long_about = "Read a YAML file and either apply it (mutating, one snapshot per run, \
so `janitor undo` reverts the whole policy) or verify it (exit 1 on drift). \
Top-level shape:\n\n\
rules:\n  \
  - path: /srv/app\n    \
    mode: \"750\"\n    \
    owner: alice\n    \
    group: devs\n    \
    recursive: true\n    \
    exclude: [\"*.pyc\", \".git\"]\n  \
  - path: /etc/myapp.conf\n    \
    preset: config\n\n\
Each rule may set any of: mode, owner, group, preset, recursive, exclude. \
`mode` and `preset` are mutually exclusive within one rule."
    )]
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Run a batch of permission ops from a file, under a single snapshot.
    #[command(
        long_about = "Read an action file and execute every line as one transaction. Each \
line is either:\n  \
    chmod MODE PATH\n  \
    chown SPEC PATH\n  \
    preset NAME PATH\n  \
    # comments and blank lines are ignored\n\n\
All paths are snapshotted up front and a single backup id is printed, so one \
`janitor undo` reverts the whole batch."
    )]
    Batch {
        /// File with actions (one per line). Use `-` for stdin.
        file: String,
    },

    /// Read or set Linux extended attributes / immutable flags (chattr / lsattr wrapper).
    #[command(subcommand)]
    Attr(AttrCmd),

    /// Emit shell completions (bash / zsh / fish / powershell / elvish).
    Completions {
        /// Shell to emit completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Emit a roff man page to stdout.
    Man,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Apply the policy: mutate the filesystem to match, with a snapshot.
    Apply {
        /// Policy YAML file.
        file: String,
    },
    /// Verify the policy: print drift and exit 1 if anything differs.
    Verify {
        /// Policy YAML file.
        file: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PresetCmd {
    /// List all available presets with their modes.
    List,
    /// Apply a named preset to one or more paths.
    #[command(
        long_about = "Apply a named permission preset to PATH (see `preset list` for \
the full set). A snapshot is taken first; revert with `janitor restore <id>`.\n\n\
Without -R, only PATH itself is changed. With -R, the same mode is applied to \
every file and subdirectory under PATH (the whole tree is walked)."
    )]
    Apply {
        /// Preset name (see `preset list`).
        name: String,
        /// Target path(s).
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<String>,
        /// Also apply to every file and subdirectory under PATH (walked recursively).
        #[arg(short = 'R', long)]
        recursive: bool,
        /// Skip any path matching this glob (repeatable, matches full path or basename).
        #[arg(short = 'E', long = "exclude", value_name = "GLOB")]
        exclude: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AttrCmd {
    /// Show current attrs (wraps `lsattr`).
    Show {
        /// Path.
        path: String,
    },
    /// Set the immutable flag (+i) on PATH. Requires CAP_LINUX_IMMUTABLE.
    SetImmutable {
        /// Path.
        path: String,
    },
    /// Clear the immutable flag (-i).
    ClearImmutable {
        /// Path.
        path: String,
    },
    /// Set the append-only flag (+a).
    SetAppendOnly {
        /// Path.
        path: String,
    },
    /// Clear the append-only flag (-a).
    ClearAppendOnly {
        /// Path.
        path: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AclCmd {
    /// Add an ACL entry for a user or group (auto-snapshot).
    #[command(long_about = "Add a POSIX ACL entry for USER or GROUP on PATH.\n\n\
Access is specified with -r/-w/-x (combinable, any order), or as a string via \
-a (e.g. `-a rwx`). If neither is given, defaults to read-only.\n\n\
With -d/--default, the entry is added to the directory's default ACL, so \
new children created under it automatically inherit the entry. A snapshot \
of the current ACL is taken first; revert with `janitor restore <id>`.")]
    Grant {
        /// Target path.
        path: String,
        /// User to grant to.
        #[arg(short = 'u', long, conflicts_with = "group")]
        user: Option<String>,
        /// Group to grant to.
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Read bit.
        #[arg(short = 'r', long = "read")]
        read: bool,
        /// Write bit.
        #[arg(short = 'w', long = "write")]
        write: bool,
        /// Execute (or traverse) bit.
        #[arg(short = 'x', long = "exec")]
        exec: bool,
        /// Access string form (`r`, `rw`, `rwx`). Alternative to -r/-w/-x.
        #[arg(short = 'a', long, conflicts_with_all = ["read", "write", "exec"])]
        access: Option<String>,
        /// Add to the default ACL of the directory (inherited by new children).
        #[arg(short = 'd', long)]
        default: bool,
        /// Apply to every file and subdirectory under PATH (walked recursively).
        #[arg(short = 'R', long)]
        recursive: bool,
    },

    /// Remove an ACL entry for a user or group.
    #[command(
        long_about = "Remove a POSIX ACL entry for USER or GROUP from PATH. With -d, \
operates on the default ACL instead of the access ACL. A snapshot is taken first; \
revert with `janitor restore <id>`."
    )]
    Revoke {
        /// Target path.
        path: String,
        /// User to revoke.
        #[arg(short = 'u', long, conflicts_with = "group")]
        user: Option<String>,
        /// Group to revoke.
        #[arg(short = 'g', long)]
        group: Option<String>,
        /// Operate on the default ACL.
        #[arg(short = 'd', long)]
        default: bool,
        /// Apply recursively.
        #[arg(short = 'R', long)]
        recursive: bool,
    },

    /// Show the ACL of PATH (human-readable).
    Show {
        /// Target path.
        path: String,
    },

    /// Remove all ACL entries from PATH (keep traditional mode bits).
    Strip {
        /// Target path.
        path: String,
        /// Apply recursively.
        #[arg(short = 'R', long)]
        recursive: bool,
    },
}

const EPILOG: &str = "COMMON EXAMPLES\n  \
# Grant Alice read-only access to a nested file (siblings stay hidden).\n  \
sudo janitor grant /srv/docs/secret.txt -u alice -r\n\n  \
# Grant the 'devs' group read + write, recursively on /srv/project.\n  \
sudo janitor grant /srv/project -g devs -rw -R\n\n  \
# Same thing using the string form of --access.\n  \
sudo janitor grant /srv/project -g devs -a rw -R\n\n  \
# Full revoke of a user (all access that came via `grant`).\n  \
sudo janitor revoke /srv/project -u alice\n\n  \
# Find the id of the most recent snapshot and revert it.\n  \
sudo janitor list-backups               # newest first, one per line\n  \
sudo janitor ls | head -1               # 'ls' is an alias; head -1 = newest id\n  \
sudo janitor restore <ID>\n\n  \
# chmod + chown (auto-snapshot, same revert flow).\n  \
sudo janitor chmod 640 /etc/app/secret.conf\n  \
sudo janitor chown alice:www-data /srv/site -R\n\n  \
# Audit a tree for common risks.\n  \
sudo janitor audit /srv -W -s -A        # world-writable, SUID, has-ACL\n\n  \
# POSIX ACL: Bob rwx on shared dir, inherited by new children, whole tree.\n  \
sudo janitor acl grant /srv/shared -u bob -rwx -d -R\n\n  \
# Reverse query: who can read /etc/shadow?\n  \
janitor who-can /etc/shadow\n\n  \
# Presets (private, group-shared, setgid-dir, ...). List with `janitor presets`.\n  \
sudo janitor preset group-shared /srv/team -R\n\nSHORT FLAGS\n  \
-n dry-run   -j json\n  \
-u user      -g group  -a access-string    -r read  -w write  -x exec\n  \
-R recursive           -L max-level        -d default (acl)\n  \
-A has-acl / copy-acl / acl-marker\n  \
-W world-writable      -s setuid   -S setgid    -t sticky   -o owner   -m mode\n\nSee `man janitor` for the full manual with workflows and more examples.";

/// Resolve the effective access string from boolean flags and the optional `-a` string.
/// If any of `r`/`w`/`x` is set, the string form is ignored (they're mutually exclusive at
/// the CLI layer). If neither is set, defaults to `"r"` (read-only).
pub fn resolve_access(read: bool, write: bool, exec: bool, access: Option<&str>) -> String {
    if read || write || exec {
        let mut s = String::new();
        if read {
            s.push('r');
        }
        if write {
            s.push('w');
        }
        if exec {
            s.push('x');
        }
        s
    } else {
        access.unwrap_or("r").to_string()
    }
}
