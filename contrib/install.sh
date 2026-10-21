#!/bin/sh
# Install the fssh release binary (universal: Apple Silicon + Intel).
#
#   curl -fsSL https://raw.githubusercontent.com/Mister-leo/fssh/main/contrib/install.sh | sh
#
# FSSH_VERSION=v0.2.0 selects a release (default: latest),
# FSSH_BIN_DIR=/path the install directory (default: /usr/local/bin).
set -eu

REPO="Mister-leo/fssh"
VERSION="${FSSH_VERSION:-latest}"
BIN_DIR="${FSSH_BIN_DIR:-/usr/local/bin}"
ASSET="fssh-macos-universal.tar.gz"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "fssh only supports macOS" >&2
  exit 1
fi

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $ASSET ($VERSION)..."
curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -fsSL -o "$TMP/$ASSET.sha256" "$BASE/$ASSET.sha256"

expected=$(awk '{print $1}' "$TMP/$ASSET.sha256")
actual=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
# The binary is not signed by Apple; drop the download quarantine flag so
# Gatekeeper does not block it.
xattr -d com.apple.quarantine "$TMP/fssh" 2>/dev/null || true

mkdir -p "$BIN_DIR" 2>/dev/null || sudo mkdir -p "$BIN_DIR"
if [ -w "$BIN_DIR" ]; then
  install -m 755 "$TMP/fssh" "$BIN_DIR/fssh"
else
  echo "Installing to $BIN_DIR (requires sudo)..."
  sudo install -m 755 "$TMP/fssh" "$BIN_DIR/fssh"
fi

"$BIN_DIR/fssh" version
echo
echo "Next: run 'fssh init' to set up fssh."
