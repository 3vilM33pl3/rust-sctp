#!/usr/bin/env bash
# Cross-builds the checked-out release tag for aarch64-unknown-linux-gnu
# (64-bit Raspberry Pi OS and other ARM64 Linux) on an x86_64 Linux runner
# with Docker, then leaves rustc, rust-std and cargo tarballs in
# $OUT_DIR/dist for attach.sh.
#
#   build-aarch64-linux.sh rust-1.100.0-sctp.1
#
# The toolchain is linked against glibc 2.17 by a crosstool-ng compiler in
# the image from aarch64-linux/, so it runs on any 64-bit Raspberry Pi OS.
# It is checked by running it under qemu-user (binfmt_misc must have
# qemu-aarch64 registered with the F flag). The std tests are not run here:
# the x86_64 Linux release job runs them on the same sources.
#
# Needs: docker usable by the runner user, and about 60 GB free for
# build-aarch64/ (kept between runs, like build/).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

target=aarch64-unknown-linux-gnu
image=sctp-rust-dist-aarch64-linux

if [[ "${1:-}" != --inside ]]; then
  version="${1:?usage: build-aarch64-linux.sh <release tag>}"
  root=$(git rev-parse --show-toplevel)
  cd "$root"
  . "$OUT_DIR/state.env"
  export UPSTREAM_TAG
  [[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]] ||
    die "qemu-aarch64 is not registered with binfmt_misc; the cross-built toolchain cannot be checked"

  echo "::group::Submodules"
  git submodule update --init --force --depth 1 --jobs 8
  echo "::endgroup::"

  echo "::group::Cross toolchain image"
  ctx="$OUT_DIR/docker-ctx"
  rm -rf "$ctx"; mkdir -p "$ctx"
  cp -R src/ci/docker/scripts "$ctx/scripts"
  cp "$here/aarch64-linux/Dockerfile" "$here/aarch64-linux/aarch64-linux-gnu.defconfig" "$ctx/"
  docker build -t "$image" "$ctx"
  echo "::endgroup::"

  mkdir -p build-aarch64/home
  docker run --rm --network host \
    -u "$(id -u):$(id -g)" \
    -e HOME=/checkout/build-aarch64/home \
    -e UPSTREAM_TAG -e SCTP_RELEASE_JOBS \
    -v "$root:/checkout" -v "$here:/tools:ro" -v "$OUT_DIR:/out" \
    -w /checkout "$image" \
    bash /tools/build-aarch64-linux.sh --inside "$version"
  exit 0
fi

# Inside the container.
version="$2"
OUT_DIR=/out
step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }
jobs="${SCTP_RELEASE_JOBS:-$(getconf _NPROCESSORS_ONLN)}"

cat >bootstrap-aarch64.toml <<TOML
# Written by .github/sctp-release/build-aarch64-linux.sh
change-id = "ignore"
profile = "dist"

[build]
build-dir = "build-aarch64"
host = ["$target"]
target = ["$target"]
description = "SCTP $version"
extended = true
tools = ["cargo", "rustdoc"]
jobs = $jobs
# Link cargo's OpenSSL, curl and libgit2 statically from vendored sources,
# as upstream's dist builds do: the cross sysroot has no target libssl.
cargo-native-static = true

[llvm]
download-ci-llvm = false
ninja = true

[rust]
channel = "dev"
download-rustc = false

[target.$target]
cc = "$target-gcc"
cxx = "$target-g++"
ar = "$target-ar"
linker = "$target-gcc"

[dist]
compression-formats = ["xz"]
TOML

step "Dist for $target: rustc, rust-std, cargo"
rm -rf build-aarch64/dist
python3 x.py dist rustc rust-std cargo --config bootstrap-aarch64.toml
end

pv="$UPSTREAM_TAG-dev"
tarballs=(
  "build-aarch64/dist/rustc-$pv-$target.tar.xz"
  "build-aarch64/dist/rust-std-$pv-$target.tar.xz"
  "build-aarch64/dist/cargo-$pv-$target.tar.xz"
)
for t in "${tarballs[@]}"; do [[ -f "$t" ]] || die "x.py dist did not produce $t"; done

step "Check the toolchain needs at most glibc 2.17"
smoke="$OUT_DIR/smoke-$target"
rm -rf "$smoke"; mkdir -p "$smoke/prefix"
for t in "${tarballs[@]}"; do
  tar -C "$smoke" -xJf "$t"
  "$smoke/$(basename "$t" .tar.xz)/install.sh" --prefix="$smoke/prefix" --disable-ldconfig >/dev/null
done
# objdump fails on the shell scripts in bin/; only the ELF files matter.
newest=$({ find "$smoke/prefix/bin" "$smoke/prefix/lib" -maxdepth 1 -type f \( -perm -u+x -o -name '*.so' \) \
  -exec "$target-objdump" -T {} + 2>/dev/null || true; } |
  { grep -o 'GLIBC_2\.[0-9]*' || true; } | sort -t. -k2 -n -u | tail -1)
echo "newest glibc symbol version: $newest"
[[ -n "$newest" ]] || die "found no glibc symbol versions"
(( ${newest#GLIBC_2.} <= 17 )) || die "the toolchain needs $newest, newer than glibc 2.17"
end

step "Smoke-test the toolchain under qemu"
"$smoke/prefix/bin/rustc" --version | tee "$OUT_DIR/rustc-version-$target.txt"
"$smoke/prefix/bin/cargo" --version
cat >"$smoke/sctp.rs" <<'RS'
#![feature(sctp)]
use std::net::{SctpListener, SctpTransportConfig, SctpTransportPolicy};
fn main() {
    // qemu-user does not translate SCTP socket options, so check the
    // UDP backend here; the x86_64 job covers native SCTP.
    let config = SctpTransportConfig { policy: SctpTransportPolicy::UdpOnly, udp: None };
    let l = SctpListener::bind_with_config("127.0.0.1:0", config).expect("bind");
    println!("SCTP listener on {}", l.local_addr().expect("local_addr"));
}
RS
"$smoke/prefix/bin/rustc" --edition 2024 -C linker="$target-gcc" -o "$smoke/sctp" "$smoke/sctp.rs"
"$smoke/sctp"
end

step "Package"
rm -rf "$OUT_DIR/dist"; mkdir -p "$OUT_DIR/dist"
cp "${tarballs[@]}" "$OUT_DIR/dist/"
(cd "$OUT_DIR/dist" && sha256 ./* | sed 's# \./# #' >SHA256SUMS)
ls -l "$OUT_DIR/dist"
end
