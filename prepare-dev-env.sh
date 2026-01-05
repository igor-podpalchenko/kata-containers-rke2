#!/usr/bin/env bash
#
# prepare-dev-env.sh
#
# Idempotent dev/build bootstrap for kata-containers (Ubuntu/Debian).
# Optimized to *skip rebuilding libseccomp for musl* if:
#   /opt/libseccomp-musl/lib/libseccomp.a exists
#   AND (if available) its pkg-config version matches LIBSECCOMP_VERSION
#
# Usage:
#   sudo ./prepare-dev-env.sh
#
# Optional env knobs:
#   LIBSECCOMP_VERSION=2.6.0         # default
#   FORCE_LIBSECCOMP_REBUILD=1       # rebuild even if libseccomp.a exists
#   SKIP_APT=1                       # skip apt install (assume deps already installed)
#   SKIP_RUSTUP=1                    # skip rustup setup (assume rust/cargo already installed)
#

set -o errexit
set -o nounset
set -o pipefail

# ---------------- config ----------------

LIBSECCOMP_VERSION="${LIBSECCOMP_VERSION:-2.6.0}"
FORCE_LIBSECCOMP_REBUILD="${FORCE_LIBSECCOMP_REBUILD:-0}"

SKIP_APT="${SKIP_APT:-0}"
SKIP_RUSTUP="${SKIP_RUSTUP:-0}"

UAPI_ROOT="${UAPI_ROOT:-/opt/musl-uapi}"
UAPI_INC="${UAPI_ROOT}/include"

LIBSECCOMP_PREFIX="${LIBSECCOMP_PREFIX:-/opt/libseccomp-musl}"
LIBSECCOMP_A="${LIBSECCOMP_PREFIX}/lib/libseccomp.a"
LIBSECCOMP_PC="${LIBSECCOMP_PREFIX}/lib/pkgconfig/libseccomp.pc"

RUSTUP_PROFILE="${RUSTUP_PROFILE:-minimal}"
RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-stable}"

ENV_SNIPPET="/etc/profile.d/kata-musl-env.sh"

# ---------------- helpers ----------------

log() { echo "[*] $*"; }
warn() { echo "[WARN] $*" >&2; }
die() { echo "[ERROR] $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
need_file() { [ -e "$1" ] || die "Missing required path: $1"; }
need_dir() { [ -d "$1" ] || die "Missing required directory: $1"; }

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    need_cmd sudo
    sudo "$@"
  fi
}

# Some environments have musl-gcc but no musl-g++.
ensure_musl_gpp() {
  if command -v musl-g++ >/dev/null 2>&1; then
    return 0
  fi

  log "musl-g++ not found; installing wrapper at /usr/local/bin/musl-g++"
  as_root tee /usr/local/bin/musl-g++ >/dev/null <<'EOF'
#!/usr/bin/env sh
# Minimal musl-g++ wrapper for build systems expecting a C++ compiler name.
exec musl-gcc -x c++ "$@"
EOF
  as_root chmod +x /usr/local/bin/musl-g++
  command -v musl-g++ >/dev/null 2>&1 || die "Failed to create musl-g++ wrapper"
}

current_libseccomp_version() {
  if [ -f "$LIBSECCOMP_PC" ]; then
    # libseccomp.pc typically contains: Version: X.Y.Z
    awk -F': *' '$1=="Version"{print $2; exit}' "$LIBSECCOMP_PC" || true
  else
    echo ""
  fi
}

libseccomp_is_usable() {
  if [ ! -f "$LIBSECCOMP_A" ]; then
    return 1
  fi

  # quick sanity: file signature + ar listing
  if ! command -v file >/dev/null 2>&1; then
    return 0
  fi

  # If 'file' says "current ar archive" it's a good sign.
  if ! file "$LIBSECCOMP_A" | grep -qiE 'ar archive|current ar archive'; then
    warn "Found $LIBSECCOMP_A but it doesn't look like an ar archive"
    return 1
  fi

  if command -v ar >/dev/null 2>&1; then
    if ! ar t "$LIBSECCOMP_A" >/dev/null 2>&1; then
      warn "Found $LIBSECCOMP_A but 'ar t' failed"
      return 1
    fi
  fi

  return 0
}

# ---------------- steps ----------------

install_packages() {
  if [ "$SKIP_APT" = "1" ]; then
    log "SKIP_APT=1; skipping apt install"
    return 0
  fi

  need_cmd apt-get
  log "Installing system prerequisites via apt..."

  as_root apt-get update

  # Includes:
  # - musl toolchain + headers
  # - kernel UAPI headers
  # - autotools + gperf for libseccomp
  # - cmake/ninja for libz-sys (zlib-ng) builds
  # - clang/lld often needed for Rust crates/bindgen
  as_root apt-get install -y \
    ca-certificates curl wget git \
    build-essential make pkg-config \
    autoconf automake libtool \
    gperf \
    musl musl-dev musl-tools \
    linux-libc-dev libc6-dev \
    cmake ninja-build \
    clang lld \
    zstd xz-utils unzip file \
    jq

  ensure_musl_gpp
}

install_rust() {
  if [ "$SKIP_RUSTUP" = "1" ]; then
    log "SKIP_RUSTUP=1; skipping rustup setup"
    return 0
  fi

  log "Ensuring rustup + cargo are installed..."
  if ! command -v rustup >/dev/null 2>&1; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile "$RUSTUP_PROFILE" --default-toolchain "$RUST_TOOLCHAIN"
  fi

  if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "${HOME}/.cargo/env"
  fi

  need_cmd rustup
  need_cmd cargo
  need_cmd rustc

  log "Rust toolchain: $(rustc -V)"
  log "Cargo: $(cargo -V)"

  log "Installing Rust target: x86_64-unknown-linux-musl"
  rustup target add x86_64-unknown-linux-musl
}

ensure_ubuntu_asm_layout() {
  log "Ensuring /usr/include/asm exists (Ubuntu multiarch layout)..."
  if [ ! -e /usr/include/asm ]; then
    if [ -d /usr/include/x86_64-linux-gnu/asm ]; then
      as_root ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
    else
      die "/usr/include/x86_64-linux-gnu/asm not found; install linux-libc-dev"
    fi
  fi
}

build_uapi_tree() {
  log "Building UAPI-only include tree at: ${UAPI_INC}"

  ensure_ubuntu_asm_layout

  need_dir /usr/include/linux
  need_dir /usr/include/asm
  need_dir /usr/include/asm-generic

  as_root rm -rf "${UAPI_ROOT}"
  as_root mkdir -p "${UAPI_INC}"

  as_root cp -a /usr/include/linux "${UAPI_INC}/"
  as_root cp -a /usr/include/asm "${UAPI_INC}/"
  as_root cp -a /usr/include/asm-generic "${UAPI_INC}/"

  # Sanity headers we know we need
  need_file "${UAPI_INC}/linux/filter.h"
  need_file "${UAPI_INC}/linux/audit.h"
  need_file "${UAPI_INC}/asm/unistd.h"
  need_file "${UAPI_INC}/asm/bitsperlong.h"
  need_file "${UAPI_INC}/asm-generic/types.h"
  need_file "${UAPI_INC}/asm-generic/bitsperlong.h"
}

build_libseccomp_musl() {
  if [ "$FORCE_LIBSECCOMP_REBUILD" != "1" ] && libseccomp_is_usable; then
    local have_ver=""
    have_ver="$(current_libseccomp_version || true)"

    if [ -n "$have_ver" ]; then
      if [ "$have_ver" = "$LIBSECCOMP_VERSION" ]; then
        log "libseccomp.a already present and version matches (${have_ver}); skipping rebuild"
        return 0
      fi
      warn "libseccomp.a present but version mismatch (have ${have_ver}, want ${LIBSECCOMP_VERSION}); rebuilding"
    else
      # No pc file: still treat as usable and skip unless forced.
      log "libseccomp.a already present (version unknown); skipping rebuild (set FORCE_LIBSECCOMP_REBUILD=1 to rebuild)"
      return 0
    fi
  fi

  log "Building libseccomp v${LIBSECCOMP_VERSION} (static) for musl into: ${LIBSECCOMP_PREFIX}"

  need_cmd musl-gcc
  need_cmd make
  need_cmd tar
  need_cmd curl

  # UAPI include tree is required to avoid glibc/musl header mixing
  if [ ! -d "$UAPI_INC/linux" ] || [ ! -d "$UAPI_INC/asm" ] || [ ! -d "$UAPI_INC/asm-generic" ]; then
    build_uapi_tree
  fi

  local tmpdir="/tmp"
  local tarball="${tmpdir}/libseccomp.tar.gz"
  local srcdir="${tmpdir}/libseccomp-${LIBSECCOMP_VERSION}"

  as_root rm -rf "${srcdir}" "${tarball}" "${LIBSECCOMP_PREFIX}"

  curl -fsSL -o "${tarball}" \
    "https://github.com/seccomp/libseccomp/releases/download/v${LIBSECCOMP_VERSION}/libseccomp-${LIBSECCOMP_VERSION}.tar.gz"

  tar -C "${tmpdir}" -xzf "${tarball}"
  cd "${srcdir}"

  # Clean if present
  make distclean >/dev/null 2>&1 || true

  # Critical: ONLY point at UAPI headers (avoid glibc headers entirely)
  unset CFLAGS CPPFLAGS CXXFLAGS LDFLAGS

  CC=musl-gcc \
  CPPFLAGS="-I${UAPI_INC}" \
  ./configure \
    --build="$(gcc -dumpmachine)" \
    --host="x86_64-linux-musl" \
    --prefix="${LIBSECCOMP_PREFIX}" \
    --disable-shared \
    --enable-static

  make -j"$(nproc)"
  make install

  need_file "${LIBSECCOMP_A}"
  log "Built: ${LIBSECCOMP_A}"

  local v=""
  v="$(current_libseccomp_version || true)"
  if [ -n "$v" ]; then
    log "Installed libseccomp version: ${v}"
  fi
}

write_env_snippet() {
  log "Writing environment snippet: ${ENV_SNIPPET}"

  as_root tee "${ENV_SNIPPET}" >/dev/null <<EOF
# Generated by prepare-dev-env.sh for kata-containers (musl builds)

# Ensure cargo/rustup are available (adjust path if needed)
if [ -f "\$HOME/.cargo/env" ]; then
  . "\$HOME/.cargo/env"
fi

# Link libseccomp statically for musl target
export LIBSECCOMP_LINK_TYPE=static
export LIBSECCOMP_LIB_PATH=${LIBSECCOMP_PREFIX}/lib

# Cross-ish build helpers
export PKG_CONFIG_ALLOW_CROSS=1

# Rust musl linker
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

# Help crates that consult CC/CXX per-target
export CC_x86_64_unknown_linux_musl=musl-gcc
export CXX_x86_64_unknown_linux_musl=musl-g++

# Many build scripts also consult these generics
export CC=musl-gcc
export CXX=musl-g++

# Optional: UAPI-only headers (kernel headers only)
export KATA_MUSL_UAPI_INCLUDE=${UAPI_INC}
EOF
}

# ---------------- main ----------------

install_packages
install_rust

# Always ensure wrapper exists even if apt was skipped
ensure_musl_gpp

# Build/skip libseccomp (optimized for libseccomp.a existence)
build_libseccomp_musl

# Write env snippet (cheap, always)
write_env_snippet

log "Done."
echo
echo "Verify libseccomp:"
echo "  ls -la ${LIBSECCOMP_A}"
echo
echo "Use env in current shell:"
echo "  source ${ENV_SNIPPET}"
echo
echo "Then continue your build (example):"
echo "  make -C src/dragonball clean || true"
echo "  make dragonball"
