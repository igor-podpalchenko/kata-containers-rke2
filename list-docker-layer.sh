#!/usr/bin/env bash
set -euo pipefail

IMG="${1:?Usage: $0 <image> [path-in-image] }"
TARGET="${2:-opt/kata-artifacts/scripts/kata-deploy.sh}"   # tar paths have no leading /

tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

echo "[*] Saving image to temp dir..."
docker save "$IMG" -o "$tmp/image.tar"
mkdir -p "$tmp/unpacked"
tar -xf "$tmp/image.tar" -C "$tmp/unpacked"

# Helper: list a layer blob (handles both tar and tar.gz)
list_blob() {
  local blob="$1"
  if tar -tf "$blob" >/dev/null 2>&1; then
    tar -tf "$blob"
    return
  fi
  if tar -tzf "$blob" >/dev/null 2>&1; then
    tar -tzf "$blob"
    return
  fi
  echo "ERROR: don't know how to list blob: $blob" >&2
  return 1
}

echo "[*] Searching for layer blob containing: $TARGET"
found_blob=""
# Docker save format: blobs/sha256/<digest> for both config + layers.
# Layer blobs are the big ones; we'll just iterate all blobs and test membership.
while IFS= read -r blob; do
  # quick skip tiny blobs (usually config)
  sz=$(stat -c '%s' "$blob" 2>/dev/null || stat -f '%z' "$blob")
  if [ "$sz" -lt 1024 ]; then
    continue
  fi

  if list_blob "$blob" | grep -qx "$TARGET"; then
    found_blob="$blob"
    break
  fi
done < <(find "$tmp/unpacked/blobs/sha256" -type f | sort)

if [ -z "$found_blob" ]; then
  echo "ERROR: Could not find $TARGET in any layer blob from docker save." >&2
  echo "       (Either the path differs inside the layer tar, or the image is in a non-standard layout.)" >&2
  exit 1
fi

echo "[+] Found in blob: $found_blob"
echo
echo "[*] Listing ALL entries in that layer:"
list_blob "$found_blob"
