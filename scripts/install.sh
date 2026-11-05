#!/bin/sh
# Installs a kennel release after verifying it. Usage:
#   scripts/install.sh [--version vX.Y.Z] [--dir ~/.local/bin]
#
# Verification: the archive's SHA-256 must match checksums.txt, and checksums.txt must carry a valid
# Sigstore signature from this repository's release workflow (needs `cosign` on PATH). Without
# cosign the script stops rather than installing something it could not verify; pass
# --insecure-skip-signature to accept the checksum alone (not recommended).
set -eu

REPO="middle-systems/kennel"
VERSION=""
DIR="${HOME}/.local/bin"
SKIP_SIG=0

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="$2"; shift 2 ;;
	--dir) DIR="$2"; shift 2 ;;
	--insecure-skip-signature) SKIP_SIG=1; shift ;;
	-h | --help) sed -n '2,10p' "$0"; exit 0 ;;
	*) echo "install.sh: unknown option $1" >&2; exit 2 ;;
	esac
done

fail() { echo "install.sh: $*" >&2; exit 1; }

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) fail "unsupported OS $(uname -s); on Windows use the zip from the releases page or Scoop" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) fail "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
	VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
	[ -n "$VERSION" ] || fail "could not find the latest release; pass --version vX.Y.Z"
fi
case "$VERSION" in v[0-9]*) ;; *) fail "version must look like v1.2.3, got $VERSION" ;; esac

if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else fail "need sha256sum or shasum"; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/download/$VERSION"
archive="kennel_${VERSION#v}_${os}_${arch}.tar.gz"

curl -fsSL -o "$tmp/$archive" "$base/$archive" || fail "could not download $base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "could not download checksums.txt"

if [ "$SKIP_SIG" -eq 0 ]; then
	command -v cosign >/dev/null 2>&1 || fail "cosign is not installed, so the signature cannot be checked
  next: install cosign (https://docs.sigstore.dev/cosign/installation/) and re-run, or pass --insecure-skip-signature"
	curl -fsSL -o "$tmp/checksums.txt.sigstore.json" "$base/checksums.txt.sigstore.json" || fail "could not download the signature bundle"
	cosign verify-blob \
		--bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity-regexp "^https://github.com/$REPO/\\.github/workflows/release\\.yml@refs/tags/v" \
		--certificate-oidc-issuer https://token.actions.githubusercontent.com \
		"$tmp/checksums.txt" >/dev/null || fail "the signature on checksums.txt is not valid; not installing"
fi

want=$(grep "  $archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$want" ] || fail "$archive is not listed in checksums.txt"
[ "$(sha "$tmp/$archive")" = "$want" ] || fail "checksum mismatch for $archive; not installing"

tar -xzf "$tmp/$archive" -C "$tmp" kennel
mkdir -p "$DIR"
install -m 0755 "$tmp/kennel" "$DIR/kennel"
echo "installed kennel $VERSION to $DIR/kennel"
case ":$PATH:" in *":$DIR:"*) ;; *) echo "note: $DIR is not on your PATH" ;; esac
