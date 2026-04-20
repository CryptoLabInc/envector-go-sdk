#!/usr/bin/env bash
# refresh-evi.sh -- rebuild libevi_crypto from a local CryptoLabInc/evi-crypto
# checkout and copy the artifacts into third_party/evi/ per Pattern C layout.
#
# Usage:
#   scripts/refresh-evi.sh <path-to-evi-crypto-checkout>
#
# Produces:
#   third_party/evi/include/             (shared C/C++ headers)
#   third_party/evi/<goos>_<goarch>/lib/ (libevi_c_api.a, libevi_crypto.a,
#                                         libdeb.a, libalea.a)
#
# The script only refreshes the *current* host's (GOOS, GOARCH). Multi-platform
# refresh is done via the upstream .github/workflows/release.yml (see
# PROVENANCE "Multi-platform refresh via CI" for the artifact download path).

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <path-to-evi-crypto-checkout>" >&2
  exit 2
fi

EVI_SRC="$(cd "$1" && pwd)"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST_ROOT="$REPO_ROOT/third_party/evi"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   GOOS=darwin; GOARCH=arm64 ;;
  Darwin-x86_64)  GOOS=darwin; GOARCH=amd64 ;;
  Linux-x86_64)   GOOS=linux;  GOARCH=amd64 ;;
  Linux-aarch64)  GOOS=linux;  GOARCH=arm64 ;;
  *) echo "unsupported host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

TARGET_DIR="$DEST_ROOT/${GOOS}_${GOARCH}/lib"
INCLUDE_DIR="$DEST_ROOT/include"

echo ">> evi-crypto source : $EVI_SRC"
echo ">> target platform   : $GOOS/$GOARCH"
echo ">> installing into   : $TARGET_DIR"

# 1. Build. Flags mirror the upstream release workflow (release.yml) so the
#    locally-refreshed artifact matches what CI would produce.
BUILD_DIR="$EVI_SRC/build-static"
cmake -S "$EVI_SRC" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TEST=OFF \
  -DBUILD_EXAMPLE=OFF \
  -DBUILD_WITH_VALGRIND=OFF \
  -DBUILD_C_API=ON \
  -DBUILD_KEY_MANAGEMENT=ON \
  -DEVI_KM_PREFER_AWS_SDK=OFF \
  -DEVI_KM_PREFER_GCP_SDK=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_AS_STATIC=ON
cmake --build "$BUILD_DIR" --parallel

# 2. Install static archives. All four (libevi_c_api + libevi_crypto + libdeb
#    + libalea) are required: libevi_crypto leaves deb::* / _alea_* symbols
#    unresolved which the two CPM-sourced archives resolve at link time.
mkdir -p "$TARGET_DIR" "$INCLUDE_DIR"
find_one() {
  local pattern="$1" dir="$2"
  local hit
  hit="$(find "${dir}" -maxdepth 6 -type f -name "${pattern}" | head -n 1)"
  if [[ -z "${hit}" ]]; then
    echo "ERROR: could not find ${pattern} under ${dir}" >&2
    find "${dir}" -maxdepth 6 -type f \
      \( -name 'libevi*' -o -name 'libdeb*' -o -name 'libalea*' \) >&2 || true
    exit 1
  fi
  echo "${hit}"
}

for lib in libevi_c_api.a libevi_crypto.a libdeb.a libalea.a; do
  src="$(find_one "$lib" "$BUILD_DIR")"
  cp "$src" "$TARGET_DIR/"
  echo ">> copied $lib from ${src#$BUILD_DIR/}"
done

# 3. Install headers (C++ API under include/, C ABI wrapper under c_api/include/).
rsync -a --delete "$EVI_SRC/include/" "$INCLUDE_DIR/"
if [[ -d "$EVI_SRC/c_api/include" ]]; then
  rsync -a "$EVI_SRC/c_api/include/" "$INCLUDE_DIR/"
fi
echo ">> copied headers into $INCLUDE_DIR"

# 4. Record provenance hint.
(
  cd "$EVI_SRC"
  COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo ">> evi-crypto commit : $COMMIT"
  echo ">> (update PROVENANCE pinned commit + SHA256 tables manually before committing)"
)
