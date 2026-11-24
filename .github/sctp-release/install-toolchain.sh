#!/usr/bin/env bash
# Installs a Rust+SCTP toolchain release next to this script and, when
# rustup is present, links it as a rustup toolchain.
#
#   ./install-rust-1.100.0-sctp.1.sh [prefix]
#
# Run it in a directory holding the release's .tar.xz files for this
# machine (x86_64 Linux or Apple Silicon macOS). The default
# prefix is ~/.local/share/rust-sctp/<release>.
set -euo pipefail
release=$(basename "$0" .sh); release=${release#install-}
prefix="${1:-$HOME/.local/share/rust-sctp/$release}"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$(dirname "$0")"
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) host=x86_64-unknown-linux-gnu ;;
  Darwin/arm64) host=aarch64-apple-darwin ;;
  *) echo "no prebuilt toolchain for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
files=(rustc-*-"$host".tar.xz rust-std-*-"$host".tar.xz cargo-*-"$host".tar.xz rust-src-*.tar.xz)
for t in "${files[@]}"; do
  [[ -f "$t" ]] || { echo "missing $t" >&2; exit 1; }
done
if [[ -f SHA256SUMS ]]; then
  # Check only the files this host installs; the release holds every host's.
  grep -F -e "${files[0]}" -e "${files[1]}" -e "${files[2]}" -e "${files[3]}" SHA256SUMS >"$work/sums"
  if command -v sha256sum >/dev/null; then sha256sum -c --quiet "$work/sums"; else shasum -a 256 -c --quiet "$work/sums"; fi
fi
for t in "${files[@]}"; do
  tar -C "$work" -xJf "$t"
  "$work/$(basename "$t" .tar.xz)/install.sh" --prefix="$prefix" --disable-ldconfig >/dev/null
done
echo "Installed $("$prefix/bin/rustc" --version) to $prefix"
if command -v rustup >/dev/null; then
  name="sctp-${release#rust-}"
  rustup toolchain link "$name" "$prefix"
  echo "Linked as rustup toolchain '$name': cargo +$name build"
else
  echo "Add $prefix/bin to PATH to use it."
fi
