#!/usr/bin/env bash
# Install AetherScope + Proteus from the latest GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/darkstardevx/aetherscope/main/install.sh | sh
#
# Supported: Linux (x86_64, aarch64) and macOS (x86_64, aarch64).
set -eu

REPO="darkstardevx/aetherscope"
INSTALL_DIR="${AETHERSCOPE_INSTALL_DIR:-$HOME/.local/bin}"

die() {
  echo "error: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH"
}

need curl
need tar

if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
  die "need either 'shasum' or 'sha256sum' on PATH"
fi

sha256_check() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$1"
  else
    shasum -a 256 -c "$1"
  fi
}

os="$(uname -s)"
case "$os" in
  Linux) platform="unknown-linux-gnu" ;;
  Darwin) platform="apple-darwin" ;;
  *) die "unsupported OS: $os (AetherScope supports Linux and macOS)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

target="${arch}-${platform}"
archive="aetherscope-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/latest/download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "Downloading ${archive}..."
curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
curl -fsSL "${base_url}/${archive}.sha256" -o "${tmp_dir}/${archive}.sha256"

echo "Verifying checksum..."
(cd "$tmp_dir" && sha256_check "${archive}.sha256")

echo "Installing to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
install -m 755 "${tmp_dir}/aetherscope" "${INSTALL_DIR}/aetherscope"
install -m 755 "${tmp_dir}/proteus" "${INSTALL_DIR}/proteus"

# AetherScope/Proteus link against the system's libpcap at runtime (same
# as tcpdump/Wireshark) -- it's not bundled. Catch a missing/mismatched
# libpcap here with an actionable message instead of leaving the user to
# decode a raw "error while loading shared libraries" later.
if ! "${INSTALL_DIR}/aetherscope" --list-interfaces >/dev/null 2>"${tmp_dir}/runcheck.err"; then
  if grep -q "libpcap" "${tmp_dir}/runcheck.err" 2>/dev/null; then
    echo ""
    echo "Warning: installed, but libpcap isn't available at runtime on this system."
    echo "AetherScope/Proteus link against libpcap the same way tcpdump/Wireshark do."
    echo ""
    echo "This prebuilt binary needs libpcap's legacy \"libpcap.so.0.8\" name"
    echo "(from how it's built on Ubuntu). On Debian/Ubuntu that's one command:"
    echo "  sudo apt install libpcap0.8"
    echo ""
    echo "On distros that only ship the modern \"libpcap.so.1\" name (Arch,"
    echo "Fedora, and others), the safest fix is building from source instead"
    echo "-- it links against whatever libpcap you actually have:"
    echo "  git clone https://github.com/darkstardevx/aetherscope && cd aetherscope"
    echo "  cargo build --release   # binaries land in target/release/"
    echo "(macOS ships libpcap in the base system -- this shouldn't happen there.)"
  fi
fi

echo ""
echo "AetherScope + Proteus installed to ${INSTALL_DIR}"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Note: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:" ;
     echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
echo "Run 'aetherscope --list-interfaces' or 'proteus --list-interfaces' to get started."
echo "Root or CAP_NET_RAW is needed to actually capture (sudo resets PATH -- see README)."
