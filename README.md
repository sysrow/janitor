# janitor

Hierarchical Unix filesystem permissions manager with snapshots, ACLs, and audit.

`janitor` is a single-binary Linux CLI for managing POSIX permissions and ACLs. It is built around four ideas:

- A hierarchical `grant` that walks the parent chain and sets the minimum traverse-only (`--x`) bit on every intermediate directory, so a user can reach a deep file without seeing its siblings.
- An automatic snapshot before every mutation. A MessagePack backup is written to `/var/lib/janitor/backups` (root) or `~/.local/share/janitor/backups` (user) before any change, so any `grant`, `chmod`, `chown`, or `acl` call can be reverted with `janitor restore <id>` (or `janitor undo` for the most recent one).
- POSIX ACL support via `setfacl`/`getfacl`, including default ACLs and recursive application.
- Audit and inspection tooling: `audit`, `find-orphans`, `who-can`, `explain`, `compare`, `diff`, `export`.

Safe defaults: `lchown(2)` is used for symlinks, an advisory file lock prevents concurrent mutations, `SIGINT` aborts cleanly with exit 130, and `--dry-run` prints every planned change without touching disk.

No runtime dependencies beyond a Linux kernel and (for the `acl` subcommand) the `acl` package. A statically linked musl build runs on any Linux distribution from RHEL 8 to Fedora 43.

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Concept: hierarchical grant](#concept-hierarchical-grant)
- [Command reference](#command-reference)
- [Presets](#presets)
- [JSON output](#json-output)
- [Backup & restore](#backup--restore)
- [Security notes](#security-notes)
- [Building from source](#building-from-source)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Installation

Every tagged release publishes prebuilt Debian, Red Hat, and portable tarball
artifacts for `amd64` and `arm64`. Replace `VERSION` with the latest version
from the [releases page](https://github.com/Tristram1337/janitor/releases).

### Debian / Ubuntu

```sh
VERSION=0.1.0
curl -LO https://github.com/Tristram1337/janitor/releases/download/v${VERSION}/janitor_${VERSION}-1_amd64.deb
sudo apt install ./janitor_${VERSION}-1_amd64.deb
```

For `arm64` substitute `arm64` for `amd64`. The package installs the binary to
`/usr/bin/janitor`, the man page to `/usr/share/man/man1/janitor.1`, and pulls
in `acl` and `passwd` as dependencies.

### Red Hat / Fedora / RHEL / Rocky / Alma

```sh
VERSION=0.1.0
sudo dnf install https://github.com/Tristram1337/janitor/releases/download/v${VERSION}/janitor-${VERSION}-1.x86_64.rpm
```

For `aarch64` substitute the matching RPM. Dependencies (`glibc`, `acl`,
`shadow-utils`) are resolved automatically.

### Portable tarball (any glibc 2.35+ distro)

```sh
VERSION=0.1.0
curl -LO https://github.com/Tristram1337/janitor/releases/download/v${VERSION}/janitor-${VERSION}-linux-amd64.tar.gz
tar xzf janitor-${VERSION}-linux-amd64.tar.gz
cd janitor-${VERSION}-linux-amd64
sudo install -m 0755 janitor /usr/local/bin/
sudo install -m 0644 janitor.1 /usr/local/share/man/man1/
janitor completions bash | sudo tee /etc/bash_completion.d/janitor >/dev/null
```

A fully static build (`linux-amd64-static`, `linux-arm64-static`) is also
published for systems without a compatible glibc (Alpine, minimal containers).

### From source

```sh
cargo install --path .
```

### Static binary (recommended — runs everywhere)

```sh
VERSION=0.1.4
curl -LO https://github.com/Tristram1337/janitor/releases/download/v${VERSION}/janitor-linux-amd64-static
sudo install -m 0755 janitor-linux-amd64-static /usr/local/bin/janitor
```

The static (musl) binary has **no glibc requirement** and runs on every
Linux x86_64 system from RHEL 8 / Ubuntu 22.04 to Fedora 43.

### Runtime dependencies

- **glibc build:** requires glibc >= 2.39 (Debian 13+, Ubuntu 24.04+, Fedora 42+).
  The `.deb` and `.rpm` packages use the glibc build.
- **Static (musl) build:** no glibc requirement. Runs on any Linux x86_64 kernel >= 4.18 (RHEL 8+, Debian 12+, Ubuntu 22.04+).
- `acl` package (for `janitor acl` subcommands): `apt install acl` or `dnf install acl`.
- `shadow-utils` (`groupadd`, `gpasswd`) for the automatic managed-group feature of `grant`.
- The Debian and RPM packages declare these as dependencies automatically.

---

## Quick start

```sh
# Give Alice read-only access to a nested file (siblings remain hidden):
sudo janitor grant /srv/docs/secret.txt -u alice -r

# Same, but read + write:
sudo janitor grant /srv/docs/report.txt -u alice -rw

# One-shot summary of any path (type, owner, mode, ACLs, effective rwx):
janitor info /srv/docs/report.txt -U alice

# See the resulting permission tree, colored for a specific user:
janitor tree /srv -U alice

# List every file under /home that Bob can execute (binary / script):
janitor --json tree /home -U bob | jq '.. | select(.x? == true) | .path'

# Audit the whole server for world-writable files and SUID binaries as JSON,
# and print just the paths:
sudo janitor --json audit / -W -s | jq -r '.[].path'

# Who can read /etc/shadow? (checks the parent chain, group memberships,
# and POSIX ACLs; returns three arrays: read / write / exec.)
sudo janitor --json who-can /etc/shadow | jq '.read'

# Give the `devs` group rwx on a project tree via POSIX ACL (new files
# inherit the same ACL thanks to -d):
sudo janitor acl grant /srv/app -g devs -rwx -d -R

# Oops, undo the last change (one-shot revert for permissions):
sudo janitor undo

# Exact rollback of a specific earlier change:
BID=$(sudo janitor ls | awk 'NR==3 {print $1}')
sudo janitor restore "$BID"
```

---

## Concept: hierarchical grant

Running:

```sh
sudo janitor grant /srv/docs/secret.txt -u alice -r
```

performs all of the following, atomically:

1. Snapshots current permissions of `/srv`, `/srv/docs`, and `/srv/docs/secret.txt`.
2. Creates a managed group named `pm_tmp_<owner>_<pathhash>` (unless `-g GROUP` is given).
3. Adds Alice to the group.
4. Sets the group-triad of `/srv` and `/srv/docs` to exactly `--x`, so Alice can pass through but cannot `ls` them.
5. ORs the requested bits (here just `r`) onto the target file's group triad.
6. Prints a `backup: <id>` line for exact rollback.

Sibling files in `/srv/docs` stay invisible to Alice. This is the key difference from `chmod -R` or a blunt `chgrp`.

Access bits are given with `-r` / `-w` / `-x` (e.g. `-rw`, `-rwx`), or as a string with `-a rwx`. If no access flag is given, defaults to read-only.
---

## Command reference

Paths are positional; commands have short aliases and every common flag has a
single-letter equivalent.

| Command (alias) | Purpose |
|---|---|
| `grant` (`g`) `PATH [-u USER\|-g GROUP] [-r] [-w] [-x] [-R]` | Hierarchical grant with auto-snapshot. |
| `revoke` (`rv`) `PATH -u USER` | Remove user from the managed group (all-or-nothing). |
| `restore` (`r`) `ID` | Full rollback of a specific backup. |
| `undo` (`u`) | Restore the most recent backup (one-shot revert of the last change). |
| `tree` (`t`) `PATH [-L DEPTH] [-U USER] [-A] [-c WHEN]` | Colored permission tree. |
| `chmod MODE PATH... [-R] [-F FILE] [-E GLOB] [--from-file FILE] [--stdin0]` | Octal (inc. `4755`/`2755`/`1777`/`6755` special bits) or symbolic (`u+s`, `g+s`, `+t`, `a+X`, ...), with auto-snapshot. Accepts many PATHs in one call (single snapshot) and can stream them from a file or NUL-separated stdin. `--reference FILE` copies the mode from another path. |
| `chown SPEC PATH... [-R] [-F FILE] [-E GLOB] [--from-file FILE] [--stdin0]` | `user`, `user:group`, `:group`, `user:`, numeric `1000:1000`. Symlinks are always `lchown`-ed. Same mass-path / exclude / stdin options as `chmod`. |
| `info` (`i`) `PATH [-U USER]` | One-shot summary: type, owner, group, mode (octal + symbolic), setuid/setgid/sticky, size, mtime, symlink target, ACLs, optional effective access for a user. |
| `history` (`h`) `PATH [--since DUR]` | Every backup whose target contains PATH, newest first. `--since 30m/1h/2d/1w` filters by age. Supports `--json`. |
| `copy-perms` (`cp`) `SRC DST [-R] [-A] [-E GLOB]` | Atomically copy mode + owner + group (+ ACLs with `-A`) from SRC to DST, snapshotting DST first. |
| `audit` (`a`) `PATH [-W] [-r] [-x] [-s] [-S] [-t] [-o USER] [-g GROUP] [-m MODE] [-A] [--no-owner] [--no-group] [-E GLOB] [--fix ACTION]` | Scan filters are AND-combined. `--fix ACTION` applies `chmod MODE` / `chown SPEC` / `preset NAME` / `strip-world-write` / `strip-setuid` / `strip-setgid` / `strip-sticky` to every match under one snapshot. |
| `find-orphans PATH` | Files with UID/GID not in `/etc/passwd` or `/etc/group`. |
| `who-can` (`w`) `PATH` | Reverse query: which users can read / write / exec. |
| `diff ID` / `export ID` | Inspect a backup vs current / dump a backup as text or JSON. |
| `acl grant\|revoke\|show\|strip PATH [-u USER\|-g GROUP] [-r] [-w] [-x] [-d] [-R]` | POSIX ACL management with snapshots. |
| `preset` (`p`) `list` | Show all named modes with their octal values and description. |
| `preset` (`p`) `apply NAME PATH... [-R] [-E GLOB]` | Apply a named mode (`private`, `group-shared`, `setgid-dir`, `ssh-key`, ...). Accepts many PATHs under one snapshot. |
| `seal PATH -B USER:GROUP:MODE [-R] [--allow USER:PERM PATH] [--allow-group GROUP:PERM PATH] [-E GLOB]` | Atomic "uniform baseline + surgical pinholes". Baseline is POSIX-only (chown + chmod), ACLs are written only for the `--allow` pinholes and their parent-chain traversal bits. One snapshot covers everything. |
| `list-backups` (`ls`) `[-p SUBSTR]` / `prune-backups` (`prune`) `[-k N]` | List (optionally filter by target path) / prune snapshots. |
| `backup` (`b`) `PATH [-R] [--no-acl]` | Snapshot without changing anything (ACLs included by default). |
| `explain` (`e`) `PATH [-U USER]` | Human-readable r/w/x verdict walking the parent chain. |
| `compare A B [-R]` | Diff mode / owner / group / ACL. Exit 1 on drift. |
| `lock PATH [-r REASON]` / `unlock PATH` / `locks` | Block all janitor mutations on PATH (and descendants if PATH is a directory). |
| `policy apply\|verify FILE` | Declarative YAML policy: `rules: [{path, mode?, owner?, group?, preset?, recursive?, exclude?}]`. `verify` exits 1 on drift. |
| `batch FILE` | Run many `chmod` / `chown` / `preset` ops in one transaction (one snapshot, one undo). Use `-` for stdin. |
| `attr show\|set-immutable\|clear-immutable\|set-append-only\|clear-append-only PATH` | Wrapper around `chattr` / `lsattr`. |
| `completions SHELL` | bash / zsh / fish / powershell / elvish. |

**Global flags:** `-n, --dry-run`, `-j, --json` (where supported), `-h, --help`, `-V, --version`.

See `man janitor` (or `janitor(1)`) for the full manual with workflows and more examples.

---

## Presets

| Name | Mode | Description |
|---|---|---|
| `private` | 700 | owner only |
| `private-dir` | 700 | directory visible to owner only |
| `private-file` | 600 | file readable/writable by owner only |
| `group-shared` | 770 | rwx for owner and group, none for other |
| `group-read` | 750 | rwx owner, rx group, none other |
| `public-read` | 755 | rwx owner, rx group, rx other |
| `public-file` | 644 | rw owner, r group, r other |
| `sticky-dir` | 1777 | world-writable with sticky bit (`/tmp` style) |
| `setgid-dir` | 2775 | group-shared dir with setgid (children inherit group) |
| `secret` | 400 | read-only for owner, nobody else |
| `secret-dir` | 500 | directory readable/traversable by owner only |
| `exec-only` | 711 | owner rwx; others may traverse but not list |
| `ssh-key` | 600 | private SSH key (what `sshd` demands) |
| `ssh-dir` | 700 | `~/.ssh` directory |
| `config` | 640 | config file readable by owner's group |
| `log-file` | 640 | log file readable by owner + group |
| `systemd-unit` | 644 | systemd unit file (`/etc/systemd/system/*.service`) |
| `read-only` | 444 | read for everyone, writable by no one |
| `no-access` | 000 | no permissions at all (panic-button quarantine) |

```sh
sudo janitor preset apply setgid-dir /srv/project --recursive
```

---

## JSON output

`--json` is supported on `audit`, `find-orphans`, `who-can`, `diff`, `export`, and `list-backups`, producing machine-readable output suitable for `jq`, Ansible, or monitoring pipelines:

```sh
# Paths of every world-writable file under /:
janitor --json audit / --world-writable | jq -r '.[].path'

# who-can returns an object { "read": [users], "write": [users], "exec": [users] };
# `.read` prints only the list of usernames who can read the target:
janitor --json who-can /etc/shadow | jq '.read'

# Count how many backups exist for a given subtree:
janitor --json ls -p /srv/app | jq 'length'
```

---

## Recipes

All recipes assume `sudo` where needed. Every mutating command snapshots first,
so any of these can be undone with `janitor undo` or `janitor restore <id>`.

### grant / revoke
```sh
sudo janitor grant /srv/docs/secret.txt -u alice -r         # grant read-only access to one file
sudo janitor grant /srv/project -u alice -r -w -R           # grant read/write recursively
sudo janitor grant /srv/project -g devs -a rw -R            # grant read/write to a group recursively
sudo janitor grant /srv/docs -u alice -x                    # grant traverse only on parent directory
sudo janitor -n grant /srv/project -u alice -rw -R          # dry-run (show planned changes)
sudo janitor    grant /srv/project -u alice -rw -R          # apply changes
sudo janitor revoke /srv/project -u alice                   # revoke access granted by janitor
```

### chmod (auto-snapshot)
```sh
sudo janitor chmod 644           /etc/nginx/nginx.conf            # typical config file mode
sudo janitor chmod 755           /usr/local/bin/tool              # executable file
sudo janitor chmod 4755          /usr/local/bin/suid-helper       # setuid
sudo janitor chmod 2755          /srv/shared                      # setgid directory
sudo janitor chmod 1777          /srv/tmp                         # sticky directory
sudo janitor chmod 6755          /usr/local/bin/suid-sgid         # setuid + setgid
sudo janitor chmod u+rwx,g=rx,o= /srv/private                     # symbolic mode example
sudo janitor chmod a+X           /srv/project -R                  # recursive +X
sudo janitor chmod -F /etc/ssh/sshd_config /etc/ssh/sshd_config.bak   # copy mode from reference
```

### chown (auto-snapshot)
```sh
sudo janitor chown alice              /srv/alice                  # change owner only
sudo janitor chown alice:devs         /srv/project -R             # change owner and group recursively
sudo janitor chown :devs              /srv/project                # change group only
sudo janitor chown alice:             /srv/alice                  # user and primary group
sudo janitor chown 1000:1000          /srv/legacy                 # numeric uid:gid
sudo janitor chown -F /etc/passwd     /srv/new-file               # copy owner/group from reference
```

### info
```sh
janitor info /etc/shadow                      # show metadata and permissions
janitor info /etc/shadow -U alice             # check effective access for user
janitor -j info /srv/project | jq             # JSON output
```

### audit
```sh
janitor audit /  -W                         # world-writable paths
janitor audit /  -r                         # world-readable paths
janitor audit /  -x                         # world-executable paths
janitor audit /  -s                         # setuid files
janitor audit /  -S                         # setgid files
janitor audit /  -t                         # sticky directories
janitor audit /  -A                         # paths with POSIX ACLs
janitor audit /  -m 777                     # exact mode 0777
janitor audit /  -o alice                   # owner = alice
janitor audit /  -g devs                    # group = devs
janitor audit /  --no-owner                 # unknown UID
janitor audit /  --no-group                 # unknown GID
janitor audit /srv -W -s                    # combine filters (world-writable + setuid)
janitor --json audit / -W | jq -r '.[].path'   # paths only (for scripts)
```

### find-orphans / who-can
```sh
janitor find-orphans /home                         # files with unknown UID/GID
janitor who-can /etc/shadow                        # users who can read/write/exec
janitor -j who-can /etc/shadow | jq '.write'       # users with write access (JSON)
```

### acl
```sh
sudo janitor acl grant  /srv/project -u alice -rw -R         # add user ACL recursively
sudo janitor acl grant  /srv/project -g devs  -rwx -d        # add group default ACL
sudo janitor acl revoke /srv/project -u alice                # remove user ACL
sudo janitor acl show   /srv/project                         # show access and default ACL
sudo janitor acl strip  /srv/project -R                      # remove all ACLs recursively
```

### tree
```sh
janitor tree /srv/project                        # show permission tree
janitor tree /srv/project -L 3                   # limit depth to 3
janitor tree /srv/project -U alice               # evaluate access for user
janitor tree /srv/project -A                     # show ACL markers
janitor tree /srv/project -H /srv/project/secret.txt   # highlight one target path
janitor tree /srv/project -P                     # include parent chain
```

### preset
```sh
janitor preset list                                                            # show every preset with its mode

sudo janitor preset apply private       ~/.gnupg -R                            # mode 700 recursively
sudo janitor preset apply private-dir   ~/.config                              # mode 700 directory
sudo janitor preset apply private-file  ~/.netrc                               # mode 600 file
sudo janitor preset apply group-shared  /srv/team  -R                          # mode 770 recursively
sudo janitor preset apply group-read    /srv/docs  -R                          # mode 750 recursively
sudo janitor preset apply public-read   /srv/www   -R                          # mode 755 recursively
sudo janitor preset apply public-file   /var/www/index.html                    # mode 644 file
sudo janitor preset apply sticky-dir    /srv/tmp                               # mode 1777 directory
sudo janitor preset apply setgid-dir    /srv/project -R                        # mode 2775 recursively
sudo janitor preset apply secret        /etc/secret.key                        # mode 400 file
sudo janitor preset apply secret-dir    /root/secrets                          # mode 500 directory
sudo janitor preset apply exec-only     /srv/drop                              # mode 711 directory
sudo janitor preset apply ssh-key       ~/.ssh/id_ed25519                      # mode 600 private key
sudo janitor preset apply ssh-dir       ~/.ssh                                 # mode 700 .ssh directory
sudo janitor preset apply config        /etc/myapp.conf                        # mode 640 config file
sudo janitor preset apply log-file      /var/log/myapp.log                     # mode 640 log file
sudo janitor preset apply systemd-unit  /etc/systemd/system/myapp.service      # mode 644 unit file
sudo janitor preset apply read-only     /srv/release.tar.gz                    # mode 444 file
sudo janitor preset apply no-access     /srv/quarantine -R                     # mode 000 recursively
```

### seal (atomic baseline + pinholes)
```sh
# Uniform tree: root:root 0700 everywhere, no ACLs written.
sudo janitor seal /srv/secrets -B root:root:700 -R

# Same baseline, but let alice read two specific files. Seal adds the
# minimal u:alice:--x ACL entries on every parent directory so she can
# actually reach them, and the final rwx entry on the leaf. One
# snapshot covers the whole operation.
sudo janitor seal /srv/secrets \
  -B root:root:700 -R \
  --allow alice:r  /srv/secrets/company/.env \
  --allow alice:rw /srv/secrets/shared/config.yaml
```

> **Why pinholes require ACLs.** Once the baseline is `root:root 0700`,
> no non-root user has `x` on the parent directories, so plain chmod/
> chown on a single leaf file can't grant access — the EACCES happens
> before the kernel ever looks at the leaf. The only POSIX-bit options
> would be `o+x` on every parent (breaks the uniform baseline for
> everyone) or chgrp'ing the whole chain to a group containing the
> pinhole user (same problem). A per-user `u:alice:--x` ACL on each
> parent is the only *surgical* way to give exactly one user traversal
> while preserving `700` for everybody else. That's why `seal` without
> `--allow` is pure POSIX, and `seal --allow ...` requires a
> filesystem with ACL support.

### copy-perms
```sh
sudo janitor copy-perms /etc/ssh/sshd_config /etc/ssh/sshd_config.bak   # copy mode/owner/group from source
sudo janitor copy-perms /srv/template /srv/new -R                        # copy mode/owner/group recursively
sudo janitor copy-perms /srv/template /srv/new -R -A                     # copy mode/owner/group/ACL recursively
```

### Snapshots, history, undo, restore
```sh
sudo janitor backup /srv/project -R              # create manual snapshot (ACLs included)
sudo janitor list-backups                       # list snapshots (newest first)
sudo janitor list-backups -p /srv/project       # list snapshots touching /srv/project
sudo janitor history /srv/project               # show history for one path
sudo janitor -j history /srv/project | jq       # history as JSON
sudo janitor diff   <id>                        # preview restore changes
sudo janitor export <id>                        # export snapshot as text
sudo janitor -j export <id>                     # export snapshot as JSON
sudo janitor restore <id>                       # restore one snapshot
sudo janitor undo                               # restore most recent snapshot
sudo janitor prune-backups -k 20                # keep last 20 snapshots
```

### Shell completions
```sh
janitor completions bash       | sudo tee /etc/bash_completion.d/janitor     # bash completion (system-wide)
janitor completions zsh        > ~/.zsh/completions/_janitor                 # zsh completion file
janitor completions fish       > ~/.config/fish/completions/janitor.fish     # fish completion file
janitor completions powershell > janitor.ps1                                 # PowerShell completion script
janitor completions elvish     > janitor.elv                                 # elvish completion file
```

---

## Backup & restore

Every mutating command writes a MessagePack (`.mpk`) snapshot before it touches anything:

```
/var/lib/janitor/backups/            # when run as root, mode 0700
~/.local/share/janitor/backups/      # when run as a normal user
```

Each snapshot contains mode, uid, gid, symlink-ness, and optionally ACLs for every path it intends to modify (parents + target + recursive children). Restore is atomic per path:

```sh
janitor list-backups                 # list available snapshots
janitor diff <id>                    # preview restore changes
janitor restore <id>                 # restore snapshot
janitor prune-backups --keep 50      # keep last 50 snapshots
```

Backups are never touched by `restore` itself, so you can re-apply or re-revert.

---

## Security notes

- Parent directories receive only `--x` (traverse); they are never made world-readable.
- Symlinks are never followed for ownership or mode changes; `lchown(2)` is used.
- Granting access to a world-readable file emits a warning, since in that state the grant is purely advisory.
- The backup directory is `0700` to prevent snapshot leakage.
- An advisory `flock` in the backup directory prevents concurrent mutations.
- `SIGINT` aborts with exit 130 and prints a recovery hint pointing at `list-backups`.

---

## Why `chmod` and `chown` as subcommands?

`janitor chmod` and `janitor chown` accept the same argument syntax as the coreutils tools: octal (`0644`, `4755`, `1777`), full symbolic (`u+s`, `g-w`, `a+X`, `+t`), `-R`, and `--reference`. They are not wrappers around `/bin/chmod` or `/bin/chown`; they call `chmod(2)` and `lchown(2)` directly. The behavior is a strict superset:

1. Snapshot-wrapped. Every invocation first records the prior mode, uid, gid (and optionally ACLs) to `<backup>/*.mpk`. A single `janitor undo` reverts the whole call, including recursive walks and variadic `PATH...` lists.
2. Variadic plus stream input. `chmod 0644 a b c`, `chmod 0644 --from-file list.txt`, and `audit ... --format paths0 | janitor chmod --stdin0 0644` all produce one snapshot covering every path.
3. `-E` / `--exclude GLOB` lets mass operations skip paths by full-path or basename match.
4. Lock-aware. If a path (or an ancestor) has been `janitor lock`ed, the operation fails with a clear message instead of silently mutating protected state.

Scripts written against coreutils work unchanged; they just gain a backup and a working `janitor undo`. The one operational note: snapshots accumulate in the backup directory. Run `janitor prune-backups --keep N` periodically (or wire it into logrotate / systemd-tmpfiles) when using `janitor` for high-volume scripted operations.

`janitor` does not modify shell dotfiles, PAM config, sudoers, or SELinux/AppArmor contexts.

---

## Building from source

Requirements: Rust 1.85 or newer, a GNU toolchain, `pkg-config`.

```sh
git clone https://github.com/Tristram1337/janitor
cd janitor
cargo build --release
# Binary at target/release/janitor (glibc, ~3.4 MB stripped).
```

For a fully static binary that runs on any Linux (RHEL 8+, Debian 12+, Ubuntu 22.04+, Alpine):

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools   # or: dnf install musl-gcc
cargo build --release --target x86_64-unknown-linux-musl
# Binary at target/x86_64-unknown-linux-musl/release/janitor (~3.6 MB, static-pie).
```

Reproducible release profile (configured in `Cargo.toml`):

```toml
[profile.release]
lto = true
strip = true
codegen-units = 1
```

---

## Testing

The test suite consists of three layers:

```sh
# Unit tests (59 tests).
cargo test --release

# End-to-end smoke tests in Docker (263 assertions).
cargo build --release
docker build -f tests/Dockerfile -t janitor-test .
docker run --rm janitor-test

# Cross-distro tests (138 assertions, requires root on target host).
bash tests/cross-distro-test.sh

# Multi-host orchestrator (deploys + runs on N hosts via SSH).
bash tests/distro-test-orchestrator.sh
```

CI runs unit + Docker smoke tests on every push.

### Tested distributions

The v0.1.4 release passes **4,400+ assertions across 11 distributions** with zero failures:

| Distribution | Version | Kernel | Filesystem | SELinux | Smoke (263) | Cross-distro (138) |
|---|---|---|---|---|---|---|
| Rocky Linux | 8.8 | 4.18 | XFS | Enforcing | 263/0 | 138/0 |
| Rocky Linux | 9.2 | 5.14 | XFS | Enforcing | 263/0 | 138/0 |
| AlmaLinux | 8.10 | 4.18 | XFS | Enforcing | 263/0 | 138/0 |
| AlmaLinux | 9.7 | 5.14 | XFS | Enforcing | 263/0 | 138/0 |
| CentOS Stream | 9 | 5.14 | XFS | Enforcing | 263/0 | 138/0 |
| Fedora | 42 | 6.14 | Btrfs | Enforcing | 262/0 | 138/0 |
| Fedora | 43 | 6.17 | Btrfs | Enforcing | 262/0 | 138/0 |
| Debian | 12 (bookworm) | 6.1 | ext4 | — | 263/0 | 138/0 |
| Debian | 13 (trixie) | 6.12 | ext4 | — | 263/0 | 138/0 |
| Ubuntu | 22.04 LTS | 5.15 | ext4 | — | 263/0 | 138/0 |
| Ubuntu | 24.04 LTS | 6.8 | ext4 | — | 263/0 | 138/0 |

Filesystems tested: **XFS, Btrfs, ext4**. SELinux enforcing on 7 of 11 hosts with zero AVC denials. Kernel range: 4.18 (RHEL 8) through 6.17 (Fedora 43). Static musl binary used on all hosts.

---

## Contributing

Pull requests welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, coding conventions, and how to add a new subcommand.

Bug reports: please include `janitor --version`, kernel version, a minimal reproducer, and the output of `janitor --json <cmd>` if relevant.

---

## License

[MIT](LICENSE). Copyright (c) 2026 Tristram1337.
