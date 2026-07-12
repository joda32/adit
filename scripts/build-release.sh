#!/usr/bin/env bash
# Cross-compile adit release binaries and package them.
#
#   VERSION=0.1.0 scripts/build-release.sh
#
# Produces, under dist/:
#   - one static binary per platform, archived (.tar.gz for unix, .zip for windows)
#   - SHA256SUMS covering every archive
#
# The tool is pure Go (no cgo), so CGO_ENABLED=0 gives fully static binaries.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-dev}"
OUT="dist"
LDFLAGS="-s -w -X main.version=${VERSION}"

PLATFORMS=(
  linux/amd64
  linux/arm64
  windows/amd64
  windows/arm64
  darwin/amd64
  darwin/arm64
)

rm -rf "$OUT"
mkdir -p "$OUT"

echo "building adit ${VERSION}"
for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"
  arch="${platform#*/}"
  name="adit_${VERSION}_${os}_${arch}"

  bin="adit"
  [ "$os" = "windows" ] && bin="adit.exe"

  stage="${OUT}/${name}"
  mkdir -p "$stage"

  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "${stage}/${bin}" ./cmd/adit

  cp README.md "$stage/" 2>/dev/null || true

  if [ "$os" = "windows" ]; then
    ( cd "$OUT" && zip -qr "${name}.zip" "$name" )
  else
    ( cd "$OUT" && tar -czf "${name}.tar.gz" "$name" )
  fi
  rm -rf "$stage"

  size=$(stat -c%s "${OUT}/${name}".* 2>/dev/null | head -1)
  printf "  %-28s %s bytes\n" "$platform" "$size"
done

( cd "$OUT" && sha256sum adit_* > SHA256SUMS )

echo
echo "artifacts in ${OUT}/:"
ls -1 "$OUT"
