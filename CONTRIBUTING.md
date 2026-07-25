# Contributing to janitor

Thanks for your interest in improving `janitor`. This document describes the
development workflow, coding conventions, and how to add new subcommands.

## Development setup

Requirements:

- Rust 1.85+ (install via [rustup](https://rustup.rs)).
- A Linux host or VM (the code is Linux-only; uses `lchown`, `/etc/passwd`, `setfacl`).
- `docker` for the end-to-end test harness.
- `acl` package installed for local ACL testing: `sudo apt install acl`.

```sh
git clone https://github.com/Tristram1337/janitor
cd janitor
cargo build
cargo test
```

## Running the full test suite

```sh
# Unit tests.
cargo test --release

# End-to-end Docker smoke tests.
cargo build --release
docker build -f tests/Dockerfile -t janitor-test .
docker run --rm janitor-test
```

CI runs the same commands on every push and pull request.

## Coding conventions

- **`cargo fmt`** must be clean. `rustfmt.toml` pins the style.
- **`cargo clippy -- -D warnings`** must be clean.
- Every new subcommand MUST:
  1. Take an auto-snapshot before mutation.
  2. Honor the global `--dry-run` flag (print shell-equivalent actions).
  3. Refuse to follow symlinks for ownership changes (use `lchown(2)`).
  4. Have at least one smoke-test assertion in `tests/smoke-test.sh`.
- Errors go through `crate::errors::PmError`. No `unwrap()` on user input.
- All file paths are `Path`/`PathBuf`, never `String`, so non-UTF-8 paths work.

## A fix is not done until something proves it

Do not mark a bug fixed on the strength of having read the diff. Before it
goes in a changelog, one of these must exist:

- an assertion in `tests/smoke-test.sh` that fails without the fix, or
- a unit test covering the decision the fix changed, or
- a reproduction run against the built binary, pasted into the PR.

This is not process for its own sake. During the July 2026 audit review,
`seal`'s pinhole isolation bug (§H-02) was analysed correctly, written up
correctly, and then never actually fixed — the claim reached `CHANGELOG.md`
and a published release because nobody ran the command. It was caught only
by a later inventory. Every other fix in that batch had a test or a
reproduction; that one had neither, and it is the one that got through.

If a fix genuinely cannot be tested in CI (it needs particular hardware, a
filesystem the runner lacks, or a race), say so explicitly in the PR and in
the code comment, rather than leaving the gap implicit.

## Adding a subcommand

1. Add a variant to `Command` (or `AclCmd`) in [`src/cli.rs`](src/cli.rs).
2. Implement the logic in a new module under `src/` (or extend an existing one).
3. Wire the dispatch in [`src/main.rs`](src/main.rs).
4. Add smoke-test assertions in [`tests/smoke-test.sh`](tests/smoke-test.sh).
5. Document it in [`docs/janitor.1`](docs/janitor.1) and the README command table.
6. Run the full Docker test suite before opening the PR.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(audit): add --no-group filter
fix(acl): preserve mask when restoring default ACL
docs: clarify managed-group naming scheme
```

## Branch hygiene: `main` vs `dev`

The project uses a simple two-branch flow. Follow these rules to keep
`dev → main` merges boring:

1. **`main` only accepts merges from `dev`** — never commit or cherry-pick
   fixes directly onto `main`. Any hotfix that needs to ship must first
   land on `dev`, get tested there, then flow to `main` via merge.
2. **Before merging `dev → main`, rebase `dev` on top of `main`.** If `main`
   has moved forward (e.g. a prior hotfix merge), running
   `git fetch && git rebase origin/main` on `dev` makes the merge a
   fast-forward and eliminates conflict resolution that silently drops
   changes. If you cannot rebase (shared `dev`), at minimum merge `main`
   back into `dev` first and resolve conflicts on `dev` where tests run.
3. **Never amend a merge commit.** If conflict resolution went wrong,
   revert the merge and redo it cleanly. Amending hides the real state
   behind a timestamp skew (commit-date drifting from author-date) and
   the result on `main` can end up containing code that was never on
   `dev` and therefore never tested there.
4. **Run the full test suite on the merge commit, not just on `dev`.**
   Even a clean auto-merge can combine unrelated changes in a way
   neither branch exercised. `cargo test --release && docker run ...` on
   the resulting merge commit is the only ground truth.
5. **Protect `main`.** CI must pass on the merge commit before it is
   pushed. Any CI failure on `main` after a merge is a workflow bug,
   not just a code bug — fix it by adjusting the merge, not by piling
   another commit on top.

### Post-mortem: why did `v0.1.1` break on `main` despite passing on `dev`?

`main` had diverged before the merge: it carried several commits
(`audit sweep`, `seal`, `scan skip pseudo-fs`, …) that never landed on
`dev`. When the `dev → main` merge was made, files touched by both
sides (notably `src/tree.rs`, `src/whocan.rs`, `src/render.rs`,
`src/presets.rs`) required hand resolution. The merge commit was then
amended an hour after it was authored, so the tree on `main` differs
from `dev`'s tip in 19 files — code that was never compiled or tested
together shipped under the release tag. The fix for next time is rule
2 above (rebase `dev` first) combined with rule 4 (test the merge
commit itself).



Please include:

- `janitor --version`
- Kernel and distro (`uname -a`, `/etc/os-release`).
- Exact command and output.
- `janitor --json <cmd>` output if applicable.
- A minimal filesystem reproducer.

## Security issues

Security-sensitive reports should not be filed as public issues. Use GitHub's
"Report a vulnerability" feature under the Security tab.

## License

By contributing, you agree your contributions are licensed under the MIT license.
