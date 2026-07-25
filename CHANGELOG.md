# Changelog

All notable changes to `janitor` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2026-07-25

Security and correctness pass over the whole codebase. The theme is
fail-closed: several commands used to treat "I could not determine this"
as "there is nothing there", and the snapshot-before-mutate guarantee had
holes that made some changes unrevertible.

### Security

- **Restore followed a symlink planted after the snapshot.** A regular
  file swapped for a symlink between `backup` and `restore` had the
  recorded mode and ownership applied to the link's *target*; a hard-link
  swap worked the same way. Restore now re-stats every entry and refuses
  it if the file type or `(dev, ino)` no longer matches. Ownership is
  applied with `lchown` even for non-symlink entries, so a swap racing the
  check cannot redirect it either.
- **`chown` / `chmod` dereferenced a symlink named on the command line.**
  Path resolution canonicalized the whole operand, so `janitor chown
  :grp link` changed the target's group instead of the link's —
  contradicting the `lchown(2)` semantics documented in the README.
  Mutating commands now keep the final component intact.
- **`seal` leaked pinhole traversal into unrelated branches.** Parent
  chains of all pinholes were merged into one set and every principal was
  granted `--x` on all of it, so a user allowed only under `/base/a`
  also got traversal on `/base/b`. Each pinhole now applies only to its
  own ancestors.
- **`restore` accepted arbitrary backup ids.** `load_backup` interpolated
  its argument straight into a path, so `restore ../../elsewhere` read
  and applied a payload from outside the backup directory. Ids are
  validated against the generated form.
- **`janitor lock` could be bypassed three ways:** an unreadable
  `locks.txt` was treated as "no locks", recursive `acl grant/revoke/strip`
  checked only the root while `setfacl -R` rewrote every descendant, and
  `restore`/`undo` checked no locks at all and ran outside the global
  flock. All three are closed.
- **`grant` left account changes behind.** `groupadd` and `gpasswd` ran
  before the lock and before the backup existed, and no restore ever
  undid them — so the access a grant handed out survived its own "full
  revert". They now run inside the transaction, and the backup records
  them so `restore` / `undo` take them back out.

### Fixed

- **Snapshots failed open.** Unreadable paths were dropped silently and
  every `getfacl` failure became "no ACL", so a mutation could proceed on
  a backup that could not undo it. Snapshotting now aborts the command
  instead. Missing `getfacl` and filesystems without ACL support are not
  failures — those entries are flagged, with one warning per run.
- **ACLs are captured by every mutating command**, including `batch`,
  `policy`, `seal`, presets and `audit --fix`. All of them run `chmod`,
  which rewrites the ACL mask, so omitting ACLs meant `undo` could not
  restore the original effective permissions.
- **setuid/setgid bits were dropped silently.** `grant` computed the
  target mode before the `chgrp` and skipped the `chmod` when nothing had
  "changed", and `policy apply` ran `chmod` before `chown`. Both now
  apply ownership first and the mode second, unconditionally.
- **Recursive `chmod` left trees half-changed.** Tightening a tree
  removed the traverse bit from the root and then failed on everything
  below it. Paths are now applied deepest-first.
- **`batch` was neither fail-closed nor atomic.** Mode specs were carried
  as unchecked strings and parsed during application, so a bad spec on
  line 2 surfaced after line 1 had been written; per-path failures were
  swallowed entirely. Specs are validated up front and any failure rolls
  the run back.
- **`grant /` panicked** (exit 101) after `groupadd` had already run.
- **`audit` reported clean scans over subtrees it never read.**
- **`compare` stored ACLs as a boolean**, so two paths with the same mode
  but different grants were "identical". It now compares entries and
  shows which side each difference is on.
- **`diff` flagged an ACL change on every entry that had an ACL**, making
  a backup-then-diff report changes on an untouched tree.
- **`policy verify` blessed policies `apply` rejects** and skipped
  ownership checks for users and groups that do not exist. Both now share
  one rule resolver. `verify` also skips symlink modes, as `apply` does,
  so a recursive policy can reach a clean state.
- **`who-can` claimed root could execute any file** (the kernel still
  requires an x bit) and omitted root from its JSON output entirely.
- **`attr` ignored `--dry-run`**, took no snapshot and held no lock.
- **Backups were written non-atomically**, so an interrupted write left a
  truncated file as the newest backup — the one `undo` picks up.
- **The lock list was written non-atomically** through a shared temp name
  and outside any lock, so concurrent `janitor lock` calls lost entries.
- With no `$HOME`, the backup directory fell back to a shared `/tmp` path
  that every HOME-less user would collide in.
- `--since` no longer panics on durations that overflow; `explain` emits
  `grant` commands that actually parse; pre-1970 mtimes no longer render
  as far-future dates; `tree` counts world-writable directories in line
  with `audit`, exempting sticky ones; `Cargo.lock` matches the manifest
  so `--locked` builds work.

### Changed

- CI now runs for `dev`, where all work lands first. Releases run fmt,
  clippy, unit tests and the docker smoke suite against the tagged tree
  instead of publishing unconditionally.
- The distro orchestrator no longer carries host addresses; copy
  `tests/hosts.env.example` to `tests/hosts.env` (git-ignored). It also
  records each job's exit status, so an SSH failure or a run that
  asserted nothing can no longer read as "all tests passed".

### BREAKING

- A symlink named directly as a `chmod` / `chown` operand is no longer
  dereferenced. This matches the documented `lchown(2)` semantics and
  differs from coreutils, which dereferences command-line operands.
- Symbolic modes with no `who` (`chmod +x`) now honour the umask, as
  POSIX requires and coreutils does: under `umask 077`, `+x` on `0600`
  gives `0700`, not `0711`. An explicit `a` still ignores the umask.
- `restore` / `undo` exit non-zero when a snapshotted path no longer
  exists. Pass `--skip-missing` for the old behaviour.
- `audit` and `find-orphans` exit non-zero when part of the tree could
  not be read. Pass `--best-effort` for the old behaviour.
- A `getfacl` failure on an ACL-capable filesystem now aborts the command
  rather than recording "no ACL".
- `restore` refuses entries whose inode changed since the snapshot, which
  includes files legitimately replaced by an editor's write-and-rename.

### Known limitations

- The restore identity check closes the reproduced swap window but is not
  fully TOCTOU-proof for the `chmod` half: Linux has no `lchmod`, so a
  swap between the check and the call is still theoretically possible.
  Closing it entirely needs `openat2(RESOLVE_NO_SYMLINKS)` throughout the
  I/O layer.
- `audit --print0 | janitor chmod --stdin0` still round-trips paths as
  UTF-8, so filenames that are not valid UTF-8 cannot be addressed
  through it. It no longer mangles them into a different path, though:
  `--stdin0` now rejects undecodable input with an error naming the
  offending bytes instead of substituting U+FFFD.

## [0.1.5] - 2026-05-09

Static musl binary for broad distro compatibility and test fixes.

### Added
- **Static musl binary (`janitor-linux-amd64-static`):** zero glibc
  dependency, runs on any Linux from RHEL 8 / Ubuntu 22.04 (kernel 4.18,
  glibc 2.28) to Fedora 43 (kernel 6.17, glibc 2.41). The dynamic build
  still requires glibc 2.39+.
- **12-distro validation matrix:** Rocky 8.8, Rocky 9.2, AlmaLinux 8.10,
  AlmaLinux 9.7, CentOS Stream 9, Fedora 42, Fedora 43, Debian 12,
  Debian 13, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10 — all 401 assertions
  pass on every host. Documented in README.

### Fixed
- **Smoke tests: `restore`/`undo` missing `--yes`:** non-TTY runs silently
  skipped restore operations because the interactive confirmation prompt
  exited without action. Added `--yes` to all restore/undo calls in the
  test suite.

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
