#!/usr/bin/env bash

# build-and-push.sh
#
# Build kata-deploy artifacts (local-build), merge them into kata-static.tar.zst,
# then build & push a kata-deploy container image to GHCR.
#
# Usage:
#   export GHCR_USER="igor-podpalchenko"
#   export IMAGE="ghcr.io/${GHCR_USER}/kata-deploy"   # optional (auto-derived if missing)
#   export TAG="$(git rev-parse --short HEAD)"        # optional
#   ./build-and-push.sh
#
# Optional auth:
#   export GHCR_TOKEN="..."   # if you want the script to docker login

die() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "[info] $*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

# Resolve repo root
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
[ -n "${REPO_ROOT}" ] || die "not in a git repo (git rev-parse --show-toplevel failed)"
cd "${REPO_ROOT}" || die "cannot cd to repo root: ${REPO_ROOT}"

need_cmd git
need_cmd make
need_cmd docker
need_cmd tar
need_cmd zstd

LOCAL_BUILD_DIR="${REPO_ROOT}/tools/packaging/kata-deploy/local-build"
KATA_DEPLOY_DIR="${REPO_ROOT}/tools/packaging/kata-deploy"
VERSIONS_YAML_REL="../../../../versions.yaml"
VERSIONS_YAML_ABS="${REPO_ROOT}/versions.yaml"

[ -d "${LOCAL_BUILD_DIR}" ] || die "missing: ${LOCAL_BUILD_DIR}"
[ -d "${KATA_DEPLOY_DIR}" ] || die "missing: ${KATA_DEPLOY_DIR}"
[ -f "${VERSIONS_YAML_ABS}" ] || die "missing: ${VERSIONS_YAML_ABS}"

# IMAGE default
if [ -z "${IMAGE:-}" ]; then
  if [ -n "${GHCR_USER:-}" ]; then
    IMAGE="ghcr.io/${GHCR_USER}/kata-deploy"
  else
    # Try to derive owner from origin URL (best-effort)
    ORIGIN_URL="$(git config --get remote.origin.url 2>/dev/null || true)"
    if echo "${ORIGIN_URL}" | grep -qE 'github\.com[:/].+/.+(\.git)?$'; then
      # Extract "owner" from either git@github.com:owner/repo.git or https://github.com/owner/repo.git
      OWNER="$(echo "${ORIGIN_URL}" | sed -E 's#.*github\.com[:/]+([^/]+)/.*#\1#')"
      [ -n "${OWNER}" ] || die "could not derive owner from origin URL; set GHCR_USER or IMAGE"
      IMAGE="ghcr.io/${OWNER}/kata-deploy"
    else
      die "IMAGE not set and could not infer GHCR owner; set GHCR_USER or IMAGE"
    fi
  fi
fi

# TAG default
if [ -z "${TAG:-}" ]; then
  TAG="$(git rev-parse --short HEAD 2>/dev/null || true)"
  [ -n "${TAG}" ] || die "could not determine TAG; set TAG explicitly"
fi

info "repo:  ${REPO_ROOT}"
info "image: ${IMAGE}"
info "tag:   ${TAG}"

# Optional GHCR login
if [ -n "${GHCR_TOKEN:-}" ] && [ -n "${GHCR_USER:-}" ]; then
  info "logging into ghcr.io as ${GHCR_USER}"
  echo "${GHCR_TOKEN}" | docker login ghcr.io -u "${GHCR_USER}" --password-stdin >/dev/null 2>&1 \
    || die "docker login to ghcr.io failed"
fi

# Ensure buildx builder exists
docker buildx create --use >/dev/null 2>&1 || true

# If git describe fails in your environment, create a local annotated tag (no global config needed)
# This helps scripts that call `git describe` without --always.
if ! git describe >/dev/null 2>&1; then
  TS="$(date +%Y%m%d%H%M%S)"
  TMP_TAG="v0.0.0-local-${TS}"
  info "git describe fails; creating local annotated tag: ${TMP_TAG}"

  GIT_AUTHOR_NAME="kata-builder" \
  GIT_AUTHOR_EMAIL="kata-builder@local" \
  GIT_COMMITTER_NAME="kata-builder" \
  GIT_COMMITTER_EMAIL="kata-builder@local" \
  git tag -a "${TMP_TAG}" -m "local kata-deploy build tag" >/dev/null 2>&1 \
    || die "failed to create local annotated tag"
fi

# Build all component tarballs (parallel)
info "building kata-deploy tarballs (local-build/all-parallel)"
if ! make -C "${LOCAL_BUILD_DIR}" all-parallel; then
  die "local-build all-parallel failed"
fi

# Merge builds into kata-static.tar.zst (IMPORTANT: use relative versions.yaml path)
info "merging builds into kata-static.tar.zst"
(
  cd "${LOCAL_BUILD_DIR}" || exit 1
  ./kata-deploy-merge-builds.sh build "${VERSIONS_YAML_REL}"
)
[ $? -eq 0 ] || die "merge-builds failed"

MERGED_TARBALL="${LOCAL_BUILD_DIR}/kata-static.tar.zst"
[ -f "${MERGED_TARBALL}" ] || die "merged tarball not found: ${MERGED_TARBALL}"

# Basic sanity: ensure it isn't the tiny 'nydus-only' tarball.
MERGED_BYTES="$(wc -c < "${MERGED_TARBALL}" 2>/dev/null || echo 0)"
if [ "${MERGED_BYTES}" -lt 200000000 ]; then
  die "merged tarball is suspiciously small (${MERGED_BYTES} bytes). Something went wrong."
fi

info "merged tarball: ${MERGED_TARBALL}"
ls -lh "${MERGED_TARBALL}" || true

# Stage tarball into the Docker build context
DEST_TARBALL="${KATA_DEPLOY_DIR}/kata-static.tar.zst"
info "staging tarball into docker context: ${DEST_TARBALL}"
cp -f "${MERGED_TARBALL}" "${DEST_TARBALL}" || die "failed to copy merged tarball into kata-deploy dir"

# Quick content sanity
info "sanity-check tarball contents (first hits)"
tar --zstd -tf "${DEST_TARBALL}" | egrep -i \
'opt/kata/bin/kata-runtime|containerd-shim-kata|qemu|cloud-hypervisor|firecracker|virtiofsd|share/defaults' \
| head -n 30 || true

# Build & push image (context MUST be tools/packaging/kata-deploy)
info "building & pushing image via buildx"
(
  cd "${KATA_DEPLOY_DIR}" || exit 1
  docker buildx build \
    --platform linux/amd64 \
    -f Dockerfile \
    -t "${IMAGE}:${TAG}" \
    -t "${IMAGE}:latest" \
    --push \
    .
)
[ $? -eq 0 ] || die "docker buildx build failed"

info "pushed: ${IMAGE}:${TAG}"

# Optional: show the manifest summary
docker buildx imagetools inspect "${IMAGE}:${TAG}" || true

info "done"
