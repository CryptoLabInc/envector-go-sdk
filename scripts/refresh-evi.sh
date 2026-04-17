#!/usr/bin/env bash
# refresh-evi.sh -- rebuild libevi_crypto from a local CryptoLabInc/evi-crypto
# checkout and copy the artifacts into third_party/evi/ per Pattern C layout.
#
# Usage:
#   scripts/refresh-evi.sh <path-to-evi-crypto-checkout>
#
# Produces:
#   third_party/evi/include/             (shared C++ headers)
#   third_party/evi/<goos>_<goarch>/lib/ (libevi_crypto.{a,dylib,so})
#
# The script only refreshes the *current* host's (GOOS, GOARCH). Multi-platform
# refresh is done by running it on each target host (or in CI).

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <path-to-evi-crypto-checkout>" >&2
  exit 2
fi

EVI_SRC="$(cd "$1" && pwd)"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_ROOT="$REPO_ROOT/third_party/evi"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   GOOS=darwin; GOARCH=arm64; LIB_EXT=dylib ;;
  Darwin-x86_64)  GOOS=darwin; GOARCH=amd64; LIB_EXT=dylib ;;
  Linux-x86_64)   GOOS=linux;  GOARCH=amd64; LIB_EXT=so ;;
  Linux-aarch64)  GOOS=linux;  GOARCH=arm64; LIB_EXT=so ;;
  *) echo "unsupported host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

TARGET_DIR="$DEST_ROOT/${GOOS}_${GOARCH}/lib"
INCLUDE_DIR="$DEST_ROOT/include"

echo ">> evi-crypto source : $EVI_SRC"
echo ">> target platform   : $GOOS/$GOARCH"
echo ">> installing into   : $TARGET_DIR"

# 1. Build. Adjust cmake flags once the upstream build system is finalised.
BUILD_DIR="$EVI_SRC/build"
cmake -S "$EVI_SRC" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=ON
cmake --build "$BUILD_DIR" --parallel

# 2. Install libs. Prefer static .a when available so downstream Go binaries
#    can link self-contained; fall back to the shared .dylib/.so otherwise.
mkdir -p "$TARGET_DIR" "$INCLUDE_DIR"
shopt -s nullglob
copied=0
for lib in \
  "$BUILD_DIR"/lib/libevi_crypto.a \
  "$BUILD_DIR"/lib/libevi_crypto.$LIB_EXT \
  "$BUILD_DIR"/libevi_crypto.a \
  "$BUILD_DIR"/libevi_crypto.$LIB_EXT; do
  if [[ -f "$lib" ]]; then
    cp "$lib" "$TARGET_DIR/"
    echo ">> copied $(basename "$lib")"
    copied=$((copied+1))
  fi
done
if [[ "$copied" -eq 0 ]]; then
  echo "ERROR: could not find libevi_crypto in $BUILD_DIR" >&2
  exit 1
fi

# 3. Install headers.
if [[ -d "$EVI_SRC/include" ]]; then
  rsync -a --delete "$EVI_SRC/include/" "$INCLUDE_DIR/"
  echo ">> copied headers from $EVI_SRC/include/"
fi

# 4. Record provenance hint.
(
  cd "$EVI_SRC"
  COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo ">> evi-crypto commit : $COMMIT"
  echo ">> (update PROVENANCE manually before committing)"
)
