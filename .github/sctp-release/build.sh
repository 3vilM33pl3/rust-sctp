#!/usr/bin/env bash
# Builds, tests and packages the checked-out release branch as an
# installable Rust toolchain named after the release tag.
#
#   build.sh rust-1.100.0-sctp.1
#
# The toolchain is built on the "dev" channel so that #![feature(sctp)]
# is usable: rustc reports "1.N.M-dev", and the tarballs are named
# <component>-1.N.M-dev-x86_64-unknown-linux-gnu.tar.xz.
#
# Needs: python3, a C/C++ toolchain, cmake, ninja, SCTP kernel support
# (/proc/net/sctp) and roughly 60 GB free for build/. Upstream does not
# publish CI LLVM for release tags, so LLVM is built from source; keep
# build/ between runs to reuse it.
# Leaves the tarballs in $OUT_DIR/dist.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

version="${1:?usage: build.sh <release tag>}"
root=$(git rev-parse --show-toplevel)
cd "$root"
. "$OUT_DIR/state.env"

[[ -e /proc/net/sctp/assocs ]] || die "SCTP kernel support is not active (try: sudo modprobe sctp)"

host=x86_64-unknown-linux-gnu
jobs="${SCTP_RELEASE_JOBS:-$(nproc)}"

cat >bootstrap.toml <<TOML
# Written by .github/sctp-release/build.sh
change-id = "ignore"
profile = "dist"

[build]
description = "SCTP $version"
extended = true
tools = ["cargo", "rustdoc"]
jobs = $jobs

[llvm]
download-ci-llvm = false
ninja = true

[rust]
channel = "dev"
download-rustc = false

[dist]
compression-formats = ["xz"]
TOML

step() { echo "::group::$*"; }
end() { echo "::endgroup::"; }

step "Tidy"
python3 x.py test tidy --set rust.channel=stable
end

step "SCTP std tests (stage 1)"
python3 x.py test library/std --stage 1 --test-args net::sctp 2>&1 | tee "$OUT_DIR/sctp-tests.log"
python3 x.py test library/std --stage 1 --doc --test-args sctp
end

step "Vendored sctp-proto tests"
cargo="$root/build/$host/stage0/bin/cargo"
"$cargo" test --manifest-path library/vendor-std/sctp-proto/Cargo.toml
end

step "Dist: rustc, rust-std, cargo, rust-src"
# build/ is kept between runs; drop tarballs from earlier versions so only
# this build's files are tested and published.
rm -rf build/dist
python3 x.py dist rustc rust-std cargo rust-src
end

pv="$UPSTREAM_TAG-dev"   # package version on the dev channel
tarballs=(
  "build/dist/rustc-$pv-$host.tar.xz"
  "build/dist/rust-std-$pv-$host.tar.xz"
  "build/dist/cargo-$pv-$host.tar.xz"
  "build/dist/rust-src-$pv.tar.xz"
)
for t in "${tarballs[@]}"; do [[ -f "$t" ]] || die "x.py dist did not produce $t"; done

step "Smoke-test the installed toolchain"
smoke="$OUT_DIR/smoke"
rm -rf "$smoke"; mkdir -p "$smoke/prefix"
for t in "${tarballs[@]}"; do
  d="$smoke/$(basename "$t" .tar.xz)"
  tar -C "$smoke" -xJf "$t"
  "$d/install.sh" --prefix="$smoke/prefix" --disable-ldconfig >/dev/null
done
"$smoke/prefix/bin/rustc" --version | tee "$OUT_DIR/rustc-version.txt"
cat >"$smoke/sctp.rs" <<'RS'
#![feature(sctp)]
use std::net::SctpListener;
fn main() {
    let l = SctpListener::bind("127.0.0.1:0").expect("bind");
    println!("SCTP listener on {}", l.local_addr().expect("local_addr"));
}
RS
"$smoke/prefix/bin/rustc" --edition 2024 -o "$smoke/sctp" "$smoke/sctp.rs"
"$smoke/sctp"
"$smoke/prefix/bin/rustdoc" --version
"$smoke/prefix/bin/rustdoc" --edition 2024 -o "$smoke/doc" "$smoke/sctp.rs"
end

step "Package"
rm -rf "$OUT_DIR/dist"; mkdir -p "$OUT_DIR/dist"
cp "${tarballs[@]}" "$OUT_DIR/dist/"
cp "$here/install-toolchain.sh" "$OUT_DIR/dist/install-$version.sh"
(cd "$OUT_DIR/dist" && sha256sum ./* | sed 's# \./# #' >SHA256SUMS)
ls -l "$OUT_DIR/dist"
end
