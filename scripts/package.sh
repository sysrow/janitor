#!/usr/bin/env bash
# package.sh — build janitor and create distributable packages.
#
# Generates shell completions + man page from the freshly built binary,
# drops them under target/assets/, then invokes cargo-deb / generate-rpm.
# This gives Debian/Ubuntu users the standard experience: after
# `apt install janitor`, tab-completion on `janitor <TAB>` just works,
# and `man janitor` resolves without any manual setup.
#
# Paths follow Debian policy:
#   /usr/share/bash-completion/completions/janitor     (bash)
#   /usr/share/zsh/vendor-completions/_janitor         (zsh)
#   /usr/share/fish/vendor_completions.d/janitor.fish  (fish)
#   /usr/share/man/man1/janitor.1.gz                   (man)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"
# Cargo.toml's packaging metadata hardcodes target/assets/..., so the assets
# must land there even when CARGO_TARGET_DIR points the build elsewhere.
ASSETS="$ROOT/target/assets"

echo "==> cargo build --release"
cargo build --release --locked

BIN="$TARGET/release/janitor"
if [[ ! -x $BIN ]]; then
    echo "error: $BIN not found after build" >&2
    exit 1
fi

echo "==> generating completions + man page"
mkdir -p "$ASSETS/completions" "$ASSETS/man"
"$BIN" completions bash > "$ASSETS/completions/janitor"
"$BIN" completions zsh  > "$ASSETS/completions/_janitor"
"$BIN" completions fish > "$ASSETS/completions/janitor.fish"
"$BIN" man              > "$ASSETS/man/janitor.1"

case "${1:-deb}" in
    deb)
        echo "==> cargo deb --no-build"
        cargo deb --no-build
        echo "==> built: $TARGET/debian/*.deb"
        ;;
    rpm)
        echo "==> cargo generate-rpm"
        cargo generate-rpm
        echo "==> built: $TARGET/generate-rpm/*.rpm"
        ;;
    all)
        cargo deb --no-build
        cargo generate-rpm
        ;;
    assets-only)
        echo "==> assets staged under $ASSETS"
        ;;
    *)
        echo "usage: $0 [deb|rpm|all|assets-only]" >&2
        exit 2
        ;;
esac
