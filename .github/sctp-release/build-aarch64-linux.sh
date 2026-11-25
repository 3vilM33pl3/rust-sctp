#!/usr/bin/env bash
# Cross-builds the checked-out release tag for aarch64-unknown-linux-gnu
# (64-bit Raspberry Pi OS and other ARM64 Linux) on an x86_64 Linux runner,
# then leaves rustc, rust-std and cargo tarballs in $OUT_DIR/dist for
# attach.sh.
#
#   build-aarch64-linux.sh rust-1.100.0-sctp.1
#
# The toolchain is linked against glibc 2.17 by a crosstool-ng compiler that
# aarch64-linux/toolchain.sh builds once, as the runner user, so it runs on
# any 64-bit Raspberry Pi OS. Nothing here needs root or Docker. It is
# checked by running it under qemu-user (binfmt_misc must have qemu-aarch64
# registered with the F flag). The std tests are not run here: the x86_64
# Linux release job runs them on the same sources.
#
# Needs: the host packages listed in aarch64-linux/toolchain.sh, about 5 GB
# for the cross compiler and about 60 GB free for build-aarch64/ (kept
# between runs, like build/).
set -euo pipefail
. "$(dirname "$0")/lib.sh"

target=aarch64-unknown-linux-gnu
version="${1:?usage: build-aarch64-linux.sh <release tag>}"
root=$(git rev-parse --show-toplevel)
cd "$root"
. "$OUT_DIR/state.env"
[[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ]] ||
  die "qemu-aarch64 is not registered with binfmt_misc; the cross-built toolchain cannot be checked"
step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }
jobs="${SCTP_RELEASE_JOBS:-$(getconf _NPROCESSORS_ONLN)}"

step "Submodules"
git submodule update --init --force --depth 1 --jobs 8
end

xtools=$("$here/aarch64-linux/toolchain.sh" "$root/src/ci/docker/scripts")
export PATH="$xtools/bin:$PATH"
export CC_aarch64_unknown_linux_gnu=$target-gcc \
  CXX_aarch64_unknown_linux_gnu=$target-g++ \
  AR_aarch64_unknown_linux_gnu=$target-ar \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$target-gcc \
  QEMU_LD_PREFIX="$xtools/$target/sysroot"
"$target-gcc" --version | head -1
# build-aarch64/ caches paths into the compiler (LLVM's CMake cache among
# them), so start it afresh when the cross compiler changes.
if [[ "$(cat build-aarch64/.sctp-xtools 2>/dev/null)" != "$(cat "$xtools/.sctp-stamp") $xtools" ]]; then
  rm -rf build-aarch64
  mkdir -p build-aarch64
  echo "$(cat "$xtools/.sctp-stamp") $xtools" >build-aarch64/.sctp-xtools
fi

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
