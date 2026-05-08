# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is janitor

A single-binary Linux CLI for managing POSIX file permissions and ACLs. Core invariant: every mutation is preceded by a MessagePack snapshot, so any change can be reverted with `janitor restore <id>` or `janitor undo`.

## Build and test commands

```sh
cargo build                     # debug build
cargo build --release           # release build (LTO, stripped)
cargo test --release            # unit tests
cargo fmt --all -- --check      # format check
cargo clippy --all-targets -- -D warnings  # lint

# End-to-end smoke tests (requires Docker, runs as root inside container)
cargo build --release
docker build -f tests/Dockerfile -t janitor-test .
docker run --rm janitor-test

# Package (.deb or .rpm)
scripts/package.sh deb          # also: rpm, all, assets-only
```

The smoke tests in `tests/smoke-test.sh` are the primary integration test suite. They run inside Docker on Debian trixie-slim and require root (they create users, groups, ACLs). There are no Rust integration tests — `cargo test` runs only unit tests.

## Architecture

Single crate, single binary (`src/main.rs`). No workspace, no library target.

**Dispatch chain:** `main.rs::main()` → `Cli::parse()` (clap derive) → `run(cli)` pattern-matches on `Command` enum → delegates to per-module functions.

**Key layers:**

- `cli.rs` — clap `Parser`/`Subcommand` derive structs. All CLI surface is here. New subcommands start here.
- `commands.rs` — high-level mutation entry points: `grant`, `revoke`, `backup`, `restore`, `undo`, `history`, `lock`/`unlock`.
- `chperm.rs` — `chmod`, `chown`, `copy-perms` implementations. Largest module after `commands.rs`.
- `snapshot.rs` + `backup.rs` + `types.rs` — the snapshot/backup system. `SnapEntry` captures mode/uid/gid/ACL per path. Backups are MessagePack (`.mpk`), with legacy JSON fallback for old backups.
- `render.rs` — all terminal output: colors, glyphs, diagnostic boxes, tables, progress bars. Commands should use these primitives, not print directly.
- `errors.rs` — `PmError` enum + `Result<T>` alias. All user-facing errors go through this. No `unwrap()` on user input.
- `acl.rs` + `aclcmd.rs` — POSIX ACL read/write (calls `setfacl`/`getfacl` binaries) and the `acl grant/revoke/show/strip` subcommands.
- `seal.rs` — `seal` command: uniform baseline + surgical ACL pinholes with auto-traverse.
- `audit.rs` — filesystem scanning for world-writable, SUID, orphan UIDs, etc.
- `locking.rs` — advisory file lock (prevents concurrent janitor mutations).
- `locks.rs` — user-facing path locks (prevent accidental mutation of protected paths).
- `config.rs` — backup directory resolution: `/var/lib/janitor/backups` (root) or `~/.local/share/janitor/backups` (user).

**Backup storage:** root stores to `/var/lib/janitor/backups/`, non-root to `~/.local/share/janitor/backups/`. Directory is hardened to 0700.

## Conventions

- **Snapshot before mutate.** Every command that changes the filesystem must snapshot first.
- **Symlinks are never followed** for ownership changes — use `lchown(2)` semantics.
- **`--dry-run` (-n)** must be honored by all mutating commands.
- **Paths are `Path`/`PathBuf`**, never `String`, for non-UTF-8 safety.
- Formatting: `rustfmt.toml` pins `edition = "2021"`, `max_width = 100`.
- Commit messages follow Conventional Commits: `feat(audit):`, `fix(acl):`, `docs:`, etc.

## Branch model

Two-branch flow: `dev` → `main`. All work lands on `dev` first. `main` only accepts merges from `dev`. Rebase `dev` on `main` before merging. Test the merge commit itself, not just `dev`.

## Adding a new subcommand

1. Add variant to `Command` (or sub-enum) in `cli.rs`
2. Implement in a new or existing `src/*.rs` module
3. Wire dispatch in `main.rs::run()`
4. Add smoke-test assertions in `tests/smoke-test.sh`
5. Document in `docs/janitor.1` and the README command table
