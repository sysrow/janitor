# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is janitor

A single-binary, Linux-only Rust CLI for managing POSIX file permissions, ownership and ACLs. Core invariant: every mutation is preceded by a MessagePack snapshot, so any change can be reverted with `janitor restore <id>` or `janitor undo`. Version and MSRV (Rust 1.85) live in `Cargo.toml`.

## Build, test, lint

These are the exact commands CI runs (`.github/workflows/ci.yml`); use the same flags locally.

```sh
cargo build                                        # debug build
cargo run -- --help                                # run the CLI from source
cargo build --release                              # release build (LTO, stripped)
cargo test --release --all-targets                 # unit tests
cargo test --release nofollow_keeps_final_symlink  # one unit test (substring match on its name)
cargo test --release helpers::                     # all tests of one module
cargo fmt --all -- --check
cargo clippy --all-targets --release -- -D warnings

# End-to-end smoke tests: Docker, Debian trixie-slim, runs as root inside the container.
# The Dockerfile COPYs target/release/janitor, so build the release binary first.
cargo build --release
docker build -f tests/Dockerfile -t janitor-test .
docker run --rm janitor-test

# Packaging (needs cargo-deb / cargo-generate-rpm). Use the script, not `cargo deb`
# directly: it regenerates completions and the man page under target/assets/ first.
scripts/package.sh deb          # also: rpm, all, assets-only
```

Three test layers:

- **Unit tests** live in `#[cfg(test)]` modules in a handful of files (`helpers`, `chperm`, `perms`, `access`, `acl`, `locks`, `render`, `seal`, `users`). Most behaviour is proven by the smoke suite, not by unit tests. There are no Rust integration tests.
- **`tests/smoke-test.sh`** is the primary suite: numbered sections built from `pass`/`fail`/`assert`/`refute`/`assert_grep` helpers. It creates users, groups and ACLs, so it only runs as root inside the container.
- **`tests/cross-distro-test.sh`** covers SELinux, XFS/Btrfs, `chattr`, NSS and large trees and needs root on a real host. `tests/distro-test-orchestrator.sh` deploys it over SSH to the hosts listed in git-ignored `tests/hosts.env` (copy `hosts.env.example`). Never commit host addresses. The orchestrator's happy path has not been exercised since its 2026-07 rewrite.

Many commands print narration and tables only when stdout is a TTY. Smoke tests that assert on human-readable wording wrap the call in `tty_run` (uses `script`); do the same for new wording assertions.

**A fix is not done until something proves it** (CONTRIBUTING.md). Before a fix is recorded in the changelog it needs a smoke-test assertion that fails without it, a unit test, or a reproduction run pasted into the PR. A `seal` fix (audit finding H-02) once reached the changelog and a release without ever being run.

## Architecture

Single crate, single binary (`src/main.rs`), no workspace, no library target. Each module starts with a `//!` doc comment describing it; the notes below are the cross-file picture.

**Dispatch:** `main()` installs a panic hook and a Ctrl-C handler, caches the umask (must happen before any file is created), initialises `render` colours and glyphs, then `run(cli)` pattern-matches `Command` and calls one `cmd_*` function per subcommand. The global flags `--dry-run`/`-n` and `--json`/`-j` are threaded through as plain booleans; `--json` is honoured only by the commands whose help says so.

**Every mutating command follows the same sequence** (`chperm::cmd_chmod` is the canonical shape):

1. Resolve targets with `helpers::resolve_path_nofollow` (parents canonicalised, final symlink kept) and expand `-R` / `--exclude` through `matcher::ExcludeSet`. Recursive walks use `follow_root_links(false)` and are fail-closed: a `walkdir` error aborts the command (`chperm::walk_error`) because a subtree that cannot be enumerated cannot be backed up.
2. `locks::ensure_not_locked` on every target. User-created path locks (`janitor lock`) live in `locks.txt` in the backup directory; a directory lock covers all descendants.
3. `locking::with_lock` takes an exclusive `flock` on `.janitor.lock` in the backup directory so concurrent janitor processes cannot interleave. It is taken in dry-run mode too.
4. Unless `--dry-run`: `snapshot::snapshot_with_acl` captures mode, uid, gid, dev/ino and ACLs per path (`types::SnapEntry`), then `backup::save_backup` writes `<YYYYMMDD-HHMMSS-8hex>.mpk` atomically (temp file, fsync, rename) and prints `backup: <id>`. The snapshot is fail-closed: a path that cannot be stat'ed, or a `getfacl` failure on an ACL-capable filesystem, aborts the command with `SnapshotFailed`. Missing `acl` tooling or a filesystem without ACL support is not an error; the entry is flagged `acl_unavailable` and a warning is printed once per run.
5. Apply the change through the low-level primitives in `perms.rs`: `lchown` for ownership and `chmod_nofollow` for modes. The latter opens the path with `O_PATH|O_NOFOLLOW`, re-checks the inode identity the caller inspected, and applies the mode through `/proc/self/fd`, so a path swapped for a symlink after the check cannot redirect the write. Never call `fs::set_permissions` or `libc::chmod` on a path. Apply deepest paths first (`chperm::depth_first`) so a tightened parent does not lock the run out of its children. Print a summary line on stderr via `render::summary_line`.

With `--dry-run` step 4 is skipped and shell-equivalent actions are printed instead. Account changes made by `grant` (creating the managed group, adding the user) happen inside the same transaction, after the backup exists, and are recorded in `types::Operation` (`group_created`, `user_added`) so `restore` can undo them.

**Restore path:** `commands::cmd_restore` / `cmd_undo` load the backup with `backup::load_backup` (the id format is validated; anything janitor did not generate is rejected) and apply it with `perms::apply_restore` and `RestoreOptions { dry_run, skip_missing, allow_replaced }`. Restore refuses entries whose file type or inode changed since the snapshot unless `--allow-replaced`, and fails on missing paths unless `--skip-missing`. Legacy `.json` backups are still readable.

**Module groups:**

- CLI surface: `cli.rs` (clap derive, all help text), `completions.rs` (`janitor completions`, `janitor man`).
- Mutating commands: `commands.rs` (grant, revoke, backup, restore, undo, history, lock/unlock, list-backups), `chperm.rs` (chmod, chown, copy-perms), `aclcmd.rs`, `seal.rs`, `presets.rs`, `policy.rs` (YAML rules), `batch.rs` (many ops, one snapshot), `attr.rs` (chattr/lsattr wrapper), `prune.rs`.
- Read-only commands: `tree.rs`, `info.rs`, `explain.rs`, `whocan.rs`, `compare.rs`, `diffcmd.rs` (diff, export), `audit.rs` (audit, find-orphans; `--fix` turns audit into a mutating command).
- Shared machinery: `snapshot.rs`, `backup.rs`, `types.rs`, `perms.rs`, `locking.rs`, `locks.rs`, `config.rs`, `acl.rs` (`getfacl`/`setfacl` shell-outs), `access.rs` (effective-access evaluator, ACL aware), `users.rs` and `groups.rs` (NSS lookups, managed groups), `helpers.rs`, `matcher.rs`, `errors.rs`, `render.rs`.

**Managed groups:** `grant` without `-g` creates a group named `pm_<slug>_<hash>` (slug from the last two path components, FNV hash of the full path; `helpers::default_group_name`), adds the user to it and makes the parent chain traversable so the target is reachable while siblings stay hidden. `revoke` removes the membership under a backup of its own so `undo` can re-add it; `restore` of a grant removes the membership and deletes the group only if that grant created it.

**Backup storage:** root writes to `/var/lib/janitor/backups/`, everyone else to `~/.local/share/janitor/backups/` (`config::backup_root`, with passwd and temp-dir fallbacks when `$HOME` is unset). The directory is forced to 0700 on every access.

**ACLs:** reads go through the `system.posix_acl_*` extended attributes (`acl.rs`), rendered in `getfacl -c` text form; a file without the attribute has exactly the ACL its mode implies (`base_acl_text`). Reading needs no tooling and no process spawn; writes go through `setfacl`. `has_extended_acl` returns `Option<bool>` and `None` means unknown, which scanners must report, never treat as "no ACL". `access.rs` splits a check into `UserCtx` (resolved once per user) and `InodeFacts` (read once per path, a symlink evaluates its target) combined by the pure `evaluate`; loops over users or paths must use these rather than `effective_for_user_path` per pair.

**Errors and output:** every user-facing failure is an `errors::PmError` variant (`thiserror`), rendered once in `main` through `render::eprint_diag`. Do not print errors directly and do not `unwrap()` on user input. `render.rs` owns colours, glyphs, diagnostic boxes, tables and progress bars; colour follows `NO_COLOR`, `TERM=dumb` and isatty, the glyph set follows `$LANG`. `render.rs` carries a module-scoped `#![allow(dead_code)]` for its wider toolkit; there is deliberately no crate-wide one (it once hid two `SnapEntry` fields that were written and never read). Clippy allowances are crate-wide at the top of `main.rs`.

**Filesystem scanning:** `audit` and `find-orphans` skip pseudo-filesystems (`helpers::is_pseudo_fs`) unless `--include-pseudo`, and exit non-zero on unreadable subtrees unless `--best-effort`. Recursive walks complete before any mutation starts.

## Conventions

- **Snapshot before mutate.** Every command that changes the filesystem, ACLs, attributes or accounts goes through the sequence above.
- **Symlinks are never followed** for ownership changes (`lchown(2)`); snapshots use `symlink_metadata`; a symlink named directly as an operand is changed itself, not its target.
- **`--dry-run` (-n)** must be honoured by every mutating command.
- **Paths are `Path`/`PathBuf`**, never `String`, so non-UTF-8 names round-trip (snapshots store paths as bytes).
- Formatting: `rustfmt.toml` pins `edition = "2021"`, `max_width = 100`.
- Commit messages follow Conventional Commits: `feat(audit):`, `fix(acl):`, `docs:`, `test:`, `chore:`.
- `CHANGELOG.md` follows Keep a Changelog: record user-visible changes under `[Unreleased]` and move them under a version heading at release time.

## Documentation surfaces

There are two man pages. `docs/janitor.1` is hand-written, kept in the repo for reference (CONTRIBUTING points to it) and never packaged; its `.TH` header still says 0.1.0. The man page that ships in packages and tarballs is generated from the clap definitions by `janitor man` (`clap_mangen`) into `target/assets/man/` by `scripts/package.sh` and the release workflow. Help strings in `cli.rs` are therefore user-facing documentation and must stay accurate. Shell completions are generated the same way; `completions.rs::hide_for_completion` only hides aliases and short flags from tab completion, the parser still accepts them.

Every CLI change must update `cli.rs` help text, `docs/janitor.1`, the README command table (and the preset table when relevant) and `CHANGELOG.md`.

## Branch and release model

Two-branch flow: all work lands on `dev`; `main` only accepts merges from `dev`. Before merging, rebase `dev` on `main` (`git fetch && git rebase origin/main`), never amend a merge commit, and run the full suite (unit tests plus Docker smoke) on the merge commit itself, not just on `dev`. CI runs on pushes and PRs to both branches and also builds with Rust 1.85 to guard the MSRV.

Releases are cut by pushing a `v*.*.*` tag. `.github/workflows/release.yml` re-runs fmt, clippy, unit and smoke tests on the tagged tree, then builds glibc and static musl binaries for amd64 and arm64 (`cross`), `.deb` and `.rpm` packages, and publishes a GitHub release whose body is `CHANGELOG.md`. Bump `version` in `Cargo.toml` and finalise the changelog section before tagging.

## Adding a new subcommand

1. Add a variant to `Command` (or `AclCmd`, `PresetCmd`, `PolicyCmd`, `AttrCmd`) in `cli.rs`, with help text.
2. Implement `cmd_*` in a new or existing `src/*.rs` module. If it mutates anything, follow the mutation sequence above (path lock check, `with_lock`, snapshot, `save_backup`, then apply) and honour `--dry-run`.
3. Wire the dispatch in `main.rs::run()`.
4. Add smoke-test assertions in `tests/smoke-test.sh` (at least one; use `tty_run` for wording checks).
5. Document it in `docs/janitor.1`, the README command table and `CHANGELOG.md`.
