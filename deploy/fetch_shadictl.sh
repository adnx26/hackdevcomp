#!/bin/sh
# Download the pinned SHADI launcher into .tools/bin (git-ignored) for the optional "shadi" backend.
# Usage: deploy/fetch_shadictl.sh [expected-sha256]
# Only the macOS arm64 archive has a checksum recorded here; other platforms must pass one explicitly.
set -eu
VERSION="0.2.0"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TARGET="aarch64-apple-darwin"; PINNED="1532af503a0d183acf81fabd03c3bd6401401a231f8eb69f0b08188feeb32caf" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin"; PINNED="" ;;
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu"; PINNED="" ;;
  Linux-aarch64) TARGET="aarch64-unknown-linux-gnu"; PINNED="" ;;
  *) echo "unsupported platform" >&2; exit 1 ;;
esac
EXPECTED="${1:-$PINNED}"
if [ -z "$EXPECTED" ]; then
  echo "no pinned checksum for $TARGET: pass the expected sha256 as the first argument" >&2
  exit 1
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="shadictl-v${VERSION}-${TARGET}"
mkdir -p "$ROOT/.tools/dl" "$ROOT/.tools/bin"
curl -fsSL -o "$ROOT/.tools/dl/$NAME.tar.gz" "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v${VERSION}/$NAME.tar.gz"
ACTUAL="$(shasum -a 256 "$ROOT/.tools/dl/$NAME.tar.gz" | cut -d' ' -f1)"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "checksum mismatch for $NAME.tar.gz" >&2
  exit 1
fi
tar -xzf "$ROOT/.tools/dl/$NAME.tar.gz" -C "$ROOT/.tools/dl"
cp "$ROOT/.tools/dl/$NAME/shadictl" "$ROOT/.tools/bin/shadictl"
echo "installed $ROOT/.tools/bin/shadictl"
