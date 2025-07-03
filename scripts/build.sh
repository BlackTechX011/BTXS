#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/build.sh <version> [suffix]
VERSION="$1"
# The suffix is optional. If provided, it's added to filenames.
SUFFIX="${2:-}" # Default to empty string if not provided

ARTIFACTS="artifacts"
PLATFORMS=(windows/amd64 linux/amd64 darwin/amd64 darwin/arm64)

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version> [suffix]"
  exit 1
fi

echo "▶ Building btxs v${VERSION} with suffix '${SUFFIX}'"
rm -rf "${ARTIFACTS}"
mkdir -p "${ARTIFACTS}"

# Move into the btxs/ dir where go.mod lives
cd "$(dirname "$0")/../btxs"

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"

  # Add a dash only if the suffix is not empty
  SUFFIX_DASH=""
  if [[ -n "$SUFFIX" ]]; then
    SUFFIX_DASH="-$SUFFIX"
  fi

  BIN="../${ARTIFACTS}/btxs-${GOOS}-${GOARCH}${SUFFIX_DASH}"
  [[ "$GOOS" == windows ]] && BIN+=".exe"

  echo "  • $GOOS/$GOARCH → $(basename "$BIN")"
  env GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -v -o "$BIN" .
done

echo "✅ Done — artifacts in ${ARTIFACTS}/"
