# Changelog

All notable changes to `janitor` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-05-09

Backups now always capture POSIX ACLs. Cross-distribution validation on
CentOS Stream 10, AlmaLinux 10.1, Rocky Linux 10.0, Ubuntu 25.10, and
Ubuntu 24.04 LTS — zero SELinux AVC denials, RPM/DEB packages verified.

### Changed
- **ACLs captured by default in all snapshots:** `backup`, `chmod`, `chown`,
  and `grant` now record POSIX ACLs automatically. The old `-A` /
  `--capture-acl` opt-in flag is replaced by `--no-acl` opt-out. A backup
  is now a true 1:1 copy of filesystem state — `restore` brings back ACLs
  along with mode and ownership.

### Fixed
- **Audit on tmpfs (`/tmp`) returned zero results:** `is_pseudo_fs()` was
  checked on every directory, causing scans under tmpfs-mounted paths
  (standard on modern Ubuntu/Fedora) to silently skip all entries. Now
  pseudo-fs detection only triggers when crossing a mount boundary
  (`st_dev` changes), so auditing `/tmp/mydir` works correctly.

### Added
- **Cross-distribution test suite** (`tests/cross-distro-test.sh`): 138
  assertions covering SELinux context preservation, XFS/ext4 ACL behaviour,
  `chattr` flags, seal pinholes with `runuser` access checks, `find-orphans`,
  concurrent flock serialisation, 10k-file trees on 512 MB hosts, Unicode
  filenames, deep nesting (50 levels), and more.
- **Test orchestrator** (`tests/distro-test-orchestrator.sh`): parallel
  deploy + run across DigitalOcean droplets.
- RPM and DEB packages verified on Rocky Linux 10.0 and Ubuntu 25.10
  (binary, man page, bash/zsh/fish completions all at correct distro paths).

## [0.1.3] - 2026-05-08

Correctness and safety pass: symlink handling, setuid/setgid restore order,
exclude subtree pruning, backup durability, and documentation sync.

### Fixed
- **Symlink safety (seal, chown, chmod, copy-perms):** all ownership changes
  now use `lchown(2)` semantics — symlinks are never followed. `seal`
  baseline skips `chmod` on symlinks (whose mode bits are meaningless on
  Linux). `config::ensure_backup_root` uses `symlink_metadata` to avoid
  TOCTOU via symlink-to-directory swap.
- **Setuid/setgid restore order (perms):** `apply_restore` now calls `chown`
  before `chmod`, because `chown(2)` clears S_ISUID and S_ISGID. The old
  order silently dropped setuid/setgid bits on restore. Additionally uses
  raw `libc::chmod` instead of `fs::set_permissions` to preserve bits above
  0o777.
- **Exclude subtree pruning (grant, chmod, chown, seal, audit, copy-perms):**
  `--exclude` now prunes entire directory subtrees via `WalkDir::filter_entry`,
  not just individual entries. Previously `--exclude logs` excluded the
  `logs/` directory itself but still descended into `logs/archive/old.log`.
- **Grant -R double backup:** recursive grant created two backups (one for
  parents, one for target+descendants). Consolidated into a single backup.
- **Backup durability:** `.mpk` backup files are now flushed and `fsync`ed
  before the mutation begins, preventing crash-induced backup loss.
- **Backup timestamps:** now use RFC 3339 with timezone offset for correct
  age parsing by `history --since`. Legacy offset-less timestamps are still
  parsed for backward compatibility.
- **list-backups order:** JSON output now matches TTY output (newest first).
- **Lock bypass (seal, acl grant/revoke/strip):** `seal` and all `acl`
  mutation subcommands now check path locks before proceeding. Recursive
  walks also check locks on each descendant.
- **NUL-byte path crash (perms):** `CString::new().unwrap()` replaced with
  proper error handling — paths containing NUL bytes produce a diagnostic
  instead of a panic.

### Removed
- **`--quiet` / `-q` global flag:** was defined in CLI but never wired to
  any command. Removed from `cli.rs`, completions, smoke tests, and
  documentation.

### Documentation
- Man page (`janitor.1`): removed stale `--quiet` flag and `find` subcommand
  references. Added `seal`, `--since` for history, and `man` sections. Updated
  command overview table with all subcommands added since v0.1.0.
- README: removed `--quiet` from global flags line.

## [0.1.2] - 2026-04-23

UX polish pass driven by `tmp/demo.sh` review: tighter alignment, more
honest piped output, sysadmin-flavoured glyphs, and a small ACL-parser
correctness fix.

### Fixed
- `access::evaluate_acl` aborted on the first `default:*` line because
  `getfacl`'s 4-colon default form broke `parse_perm_bits` via
  `splitn(3, ':')`, making the whole block return `None`. Real
  `getfacl` output on directories routinely mixes access and default
  entries, so `who-can` / `explain` could silently drop ACL data.
  Default entries are now skipped before parsing; regression-tested.
- `chmod` / `chown`: the per-path `before → after` diff line was gated
  on `stderr` being a tty, which hid it whenever output was piped to
  `tee` / `logger`. Moved to stdout so captured audit trails keep the
  "what changed" detail (colour still auto-disables for non-tty).
- `aligned_table` (audit, history, preset-list): each row now has
  trailing whitespace stripped, so rows with a usually-empty final
  column (e.g. `flags` in `audit`) no longer ship a halo of spaces.
- `explain`: ancestor-chain table now aligns its `traverse ok`, `via …`
  and verdict columns across all rows regardless of `owner:group`
  width. The descent is also rendered as an indented tree (basenames
  with `└─` connectors per level) so it reads unmistakably as a
  filesystem traversal.
- `who-can`: header card (`owner`/`mode` and `group`/`acl`) now uses
  the same dynamic-width kv-grid as `info`, so the right column stays
  put even for long managed group names.
- `tree`: mode/owner column no longer drifts by one space under
  last-child subtrees (`└─` branch). The prefix stride is now a
  consistent 3 columns across `│  ` vert and last-child indent.
- `info`: two-column grid now aligns the right column dynamically from
  the widest left cell, so `mode` / `size` / `mtime` stack at the same
  screen column even when user/group names expand.
- `seal`, `compare`, `who-can`: hard-coded `⚠` / `✓` / `·` replaced
  with `render::glyphs()` lookups so `NO_COLOR=1` / non-UTF-8 locales
  actually get the ASCII fallback.

### Changed
- **Glyphs:** `info` and `warn` markers switched to sysadmin-style
  `::` and `!!` (pacman / makepkg / syslog convention) in the demo
  banner helpers and in `who-can`'s blocked-traversal notice. Same
  tokens in both Unicode and ASCII sets — no translation surprise
  when `LANG=C`.
- **`explain` status marker:** `✗` → `●` for blockers (systemd
  `list-units` convention, single-column in both Unicode and ASCII
  so marker-column alignment holds). `→` still marks the reachable
  target.
- **`audit`:** `mode` cell is now painted yellow (`Highlight`) on
  rows that matched `--world-readable` / `--world-executable`, so
  the filter-match reason is visible per row. World-writable and
  suid/sgid/sticky still render red (`WarnMajor`) as before.
- **`seal`:** when the base is a directory with children and `-R`
  was not passed, the card now prints a `hint:` line:
  `only the directory itself was sealed — pass -R to include its
  contents`. The hint fires only when it's actionable (non-empty
  directory + non-recursive); single-file seals and empty
  directories stay quiet.
- **`render::Glyphs`:** added `info` (`::`) and `fail` (`●` / `X`).
  `fail` is a 1-column failure marker, intentionally distinct from
  `cross` (`✗` / `[X]`) so ASCII-mode marker columns stay aligned.
- Shell completions no longer list short-form flags (`-n`, `-j`, `-q`,
  `-h`, `-V`) or subcommand aliases (`g`, `rv`, `t`, `b`, `r`, `u`, `h`,
  `cp`, `ls`, `prune`, `i`, `a`, `w`, `p`, `e`, and the `-R` short alias
  on `compare --recursive`). The short forms remain fully functional on
  the CLI and are still documented in `--help` and in `janitor(1)`;
  they just don't clutter `janitor <TAB><TAB>` anymore. Implemented as a
  completion-only view of the command tree, so the parser is untouched.
- Dropped the unused `tabled` dependency (dead `simple_table` helper
  removed; all tables now go through the ANSI-aware `aligned_table`).

### Testing
- Test count 36 → 59 (+23). New coverage:
  - `chperm::apply_symbolic` (18): add/remove/`=` per `u`/`g`/`o`/`a`
    class, empty who = all, multi-who (`ug+x`, `go-rwx`), comma
    chains (`u=rwx,go=rx`), whitespace-around-parts, `X`-capital
    semantics on dirs vs. files (with/without existing exec bit),
    suid/sgid/sticky add & remove, `=` clears specials for the
    matched who, high-bit truncation (stray file-type bits masked),
    idempotency, preservation of `sgid` across unrelated `+r`,
    rejection of bad who / bad perm / missing op.
  - `access::evaluate_acl` (5): zero mask denies named user,
    `other::` bypasses mask, trailing `#effective:` comment parsed,
    blank / `#`-comment lines ignored, `default:*` entries never
    grant access (regression test for the parser fix).


## [0.1.1] - 2026-04-22

Pre-1.0 polishing pass: UX triage, packaging, and correctness fixes. **Breaking
CLI changes** — see "Changed" below.

### Changed
- **Breaking:** `preset` is now a subcommand group.
  `janitor preset NAME PATH` ⇒ `janitor preset apply NAME PATH`, and the
  separate `presets` command ⇒ `janitor preset list`. Rationale: UX parity
  with `acl`, `policy`, `attr` (all verb-after-noun), and `presets` as a
  sibling top-level command duplicated the noun.
- **Breaking:** `seal` baseline is now POSIX-only by default. A plain
  `janitor seal DIR -B root:root:700 -R` issues `chown` + `chmod` only and
  writes no ACLs — it works on FAT, tmpfs, and any filesystem without
  `acl` support. ACLs are written only for explicit `--allow USER:PERM
  PATH` / `--allow-group GROUP:PERM PATH` pinholes (and the minimal
  `u:user:--x` / `g:group:--x` entries on the parent chain needed to
  reach them). If pinholes are requested on a filesystem without ACL
  support, `seal` fails fast with a clear error instead of silently
  producing an unreachable target.
- `audit` gained `--paths` and `-0` / `--print0` flags for pipe-pure output
  (one path per line, or NUL-separated). This replaces the old `janitor
  find -0 | janitor chmod --stdin0` pipeline. Both flags skip the ACL
  probe when the filter doesn't need it, keeping large scans fast.

### Removed
- **Breaking:** `janitor find` — its filter set was a subset of `audit`'s, and
  `audit --paths` / `audit -0` now covers the "produce a list of matching
  paths" use case it existed for.

### Fixed
- `who-can` now enumerates users via NSS (`setpwent` / `getpwent` / `endpwent`),
  so LDAP / SSSD / systemd-homed / FreeIPA directories are visible.
  Falls back to `/etc/passwd` if NSS yields nothing.
- `audit` / `find-orphans`: world-writable / world-readable / world-executable
  filters no longer false-positive on symlinks (whose own mode bits are a
  kernel artifact on Linux and carry no real meaning). The link target's
  mode is what governs access, so flagging the link itself was noise.
- `info`, `who-can`, `explain`, and friends now distinguish `EACCES` (you're
  not allowed to stat this) from `ENOENT` (it really doesn't exist) in
  their error messages.

### Packaging
- `.deb` and `.rpm` now install shell completions and the man page to
  standard locations:
  - `bash`: `/usr/share/bash-completion/completions/janitor`
  - `zsh`:  `/usr/share/zsh/vendor-completions/_janitor` (deb) or
    `/usr/share/zsh/site-functions/_janitor` (rpm)
  - `fish`: `/usr/share/fish/vendor_completions.d/janitor.fish`
  - `man`:  `/usr/share/man/man1/janitor.1.gz`
  No post-install hookup needed — bash-completion picks up the file lazily
  the next time the shell sees `janitor`. The deb package `Recommends`
  `bash-completion`.
- `scripts/package.sh` (new) drives the full pipeline: builds the release
  binary, invokes `janitor completions` / `janitor man` to generate
  assets into `target/assets/...`, then runs `cargo deb --no-build` /
  `cargo generate-rpm --no-build`. Subcommands: `deb`, `rpm`, `all`,
  `assets-only`.

## [0.1.0] - 2026-04-21

First public pre-release. API and CLI surface may still change before 1.0.0.

### Added
- `grant` / `revoke`: hierarchical permission management with automatic managed-group creation.
- `restore` / `list-backups` / `prune-backups` / `backup` / `diff` / `export`: full snapshot lifecycle.
- `chmod` (octal + symbolic) and `chown` (`user`, `user:group`, `:group`, `user:`, numeric) with auto-snapshot. `chmod` supports the full 4-digit octal range (setuid `4xxx`, setgid `2xxx`, sticky `1xxx`, combined `6xxx`/`7xxx`) and all symbolic `[ugoa][+-=][rwxXst]` clauses. Both commands accept `-F` / `--reference FILE` to copy the mode or owner from another path.
- `info` (alias `i`): one-shot summary of a path — type, owner (name + uid), group, mode (octal + symbolic, showing setuid/setgid/sticky), size, mtime, symlink target, ACLs, and optional effective `rwx` access for a user via `-U`.
- `undo` (alias `u`): one-shot restore of the most recent backup — an editor-style undo for any `grant` / `chmod` / `chown` / `acl` operation.
- `history` (alias `h`): list every backup whose target contains `PATH`, newest first, with optional `--json` for scripting.
- `copy-perms` (alias `cp`): atomically copy mode + owner + group (and optionally ACLs via `-A`) from `SRC` to `DST`, snapshotting `DST` first. `-R` walks recursively.
- `list-backups -p SUBSTR`: filter saved snapshots by target path.
- `acl grant|revoke|show|strip`: POSIX ACL management, including default ACLs and recursive application.
- `audit` with filters: world-writable (`-W`), world-readable (`-r`), world-executable (`-x`), setuid (`-s`), setgid (`-S`), sticky (`-t`), owner (`-o`), group (`-g`), mode (`-m`), has-acl (`-A`), `--no-owner`, `--no-group`.
- `find-orphans`: files with unresolvable UID or GID.
- `who-can`: reverse access query (parent-chain aware, honors group memberships).
- `tree` with per-user colorization, highlighting, parent chain, depth limit, and ACL marker.
- `preset` and `presets`: 19 named mode presets (`private`, `private-dir`, `private-file`, `group-shared`, `group-read`, `public-read`, `public-file`, `sticky-dir`, `setgid-dir`, `secret`, `secret-dir`, `exec-only`, `ssh-key`, `ssh-dir`, `config`, `log-file`, `systemd-unit`, `read-only`, `no-access`).
- `completions`: bash, zsh, fish, PowerShell, elvish.
- Positional `PATH` argument on every subcommand, matching `chmod(1)` / `chown(1)` conventions.
- Single-letter flags for every common option: `-n` (dry-run), `-j` (json), `-q` (quiet), `-u` (user), `-g` (group), `-a` (access string), `-r` / `-w` / `-x` (access bits, combinable in any order), `-R` (recursive), `-L` (max-level / max-depth), `-d` (default ACL), `-k` (keep), `-W` (world-writable), `-s` (setuid), `-S` (setgid), `-t` (sticky), `-o` (owner), `-m` (mode), `-A` (has-acl / capture-acl / acl marker), `-H` (highlight), `-P` (show-parents), `-U` (for-user), `-c` (color).
- Subcommand aliases: `g`, `rv`, `t`, `b`, `r`, `ls`, `prune`, `a`, `w`, `p`.
- Debian (`.deb`) and Red Hat (`.rpm`) packages for amd64 and arm64, plus portable and static (musl) tarballs. Dynamic builds link against glibc 2.35 and run on Debian 12+, Ubuntu 22.04+, and RHEL 9+; static tarballs cover Alpine, Debian 11, and minimal containers.
- Man page `janitor(1)` with workflows and examples.
- `chmod` / `chown` / `preset` accept **multiple `PATH`s** in one call (single snapshot). Paths can also be streamed via `--from-file FILE` (newline-separated) or `--stdin0` (NUL-separated, pairs with `find -print0` / `janitor find -0`). `-E` / `--exclude GLOB` (repeatable) skips paths by full-path or basename match.
- `audit`: new `-E` / `--exclude GLOB` filter and `--fix ACTION` (one-shot remediation). Supported actions: `chmod MODE`, `chown SPEC`, `preset NAME`, `strip-world-write`, `strip-setuid`, `strip-setgid`, `strip-sticky`. All matches mutate under a single backup.
- `find`: read-only permission-aware search (like coreutils `find`, but focused on mode bits, ownership, ACLs). `-0` NUL-separates output for piping into `janitor chmod --stdin0`.
- `explain` (alias `e`): human-readable read/write/exec verdict for a path, walking the parent chain and evaluating mode bits, group membership, and traversal bits, optionally `-U USER`.
- `compare A B`: side-by-side diff of mode / owner / group / ACL. Exit 1 on drift (CI-friendly). `-R` walks both trees.
- `lock PATH [-r REASON]` / `unlock PATH` / `locks`: persistent per-path mutation guard. Any janitor mutation targeting a locked path or a descendant of a locked directory fails with a clear error.
- `policy apply FILE` / `policy verify FILE`: declarative YAML policy (`path`, `mode`, `owner`, `group`, `preset`, `recursive`, `exclude`). `verify` exits 1 on drift.
- `batch FILE`: run many `chmod` / `chown` / `preset` operations in one transaction; `-` reads from stdin.
- `attr show|set-immutable|clear-immutable|set-append-only|clear-append-only`: thin wrapper around `chattr` / `lsattr` that refuses to run on locked paths.
- `history --since DUR`: filter backups by age (`30m`, `1h`, `2d`, `1w`).
- `copy-perms -E`: honors the same exclude filter as the other mass operations.
- Panic hook, SIGINT handler, advisory file lock, `0700` backup directory, world-readable-target warning.

[0.1.0]: https://github.com/Tristram1337/janitor/releases/tag/v0.1.0
