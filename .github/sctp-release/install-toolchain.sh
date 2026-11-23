#!/usr/bin/env bash
# Installs a Rust+SCTP toolchain release next to this script and, when
# rustup is present, links it as a rustup toolchain.
#
#   ./install-rust-1.100.0-sctp.1.sh [prefix]
#
# Run it in a directory holding the release's .tar.xz files. The default
# prefix is ~/.local/share/rust-sctp/<release>.
set -euo pipefail
release=$(basename "$0" .sh); release=${release#install-}
prefix="${1:-$HOME/.local/share/rust-sctp/$release}"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$(dirname "$0")"
if [[ -f SHA256SUMS ]]; then
  grep '\.tar\.xz$' SHA256SUMS | sha256sum -c --quiet
fi
for t in rustc-*.tar.xz rust-std-*.tar.xz cargo-*.tar.xz rust-src-*.tar.xz; do
  [[ -f "$t" ]] || { echo "missing $t" >&2; exit 1; }
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
