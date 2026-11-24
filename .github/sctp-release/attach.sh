#!/usr/bin/env bash
# Adds this host's toolchain tarballs from build.sh to an existing GitHub
# Release, which publish.sh created from the Linux build.
#
#   attach.sh rust-1.100.0-sctp.1
#
# Merges SHA256SUMS, replaces the installer with this checkout's version
# (which knows every host), and adds an install section to the notes once.
# Needs GH_TOKEN with write access to releases.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

version="${1:?usage: attach.sh <release tag>}"
dist="$OUT_DIR/dist"
host=$(ls "$dist"/rustc-*.tar.xz | sed 's#.*/rustc-[^-]*-dev-##; s#\.tar\.xz$##')
[[ -n "$host" ]] || die "no rustc tarball in $dist"
work="$OUT_DIR/attach"; rm -rf "$work"; mkdir -p "$work"

new=()
for f in "$dist"/*-"$host".tar.xz; do new+=("$f"); done

# Keep the other hosts' sums, replace this host's.
gh release download "$version" -p SHA256SUMS -D "$work"
grep -v -F -e "-$host.tar.xz" "$work/SHA256SUMS" >"$work/SHA256SUMS.new" || true
(cd "$dist" && sha256 $(for f in "${new[@]}"; do basename "$f"; done)) >>"$work/SHA256SUMS.new"
cp "$here/install-toolchain.sh" "$work/install-$version.sh"
(cd "$work" && sha256 "install-$version.sh") >"$work/inst.sum"
grep -v -F "install-$version.sh" "$work/SHA256SUMS.new" >"$work/SHA256SUMS" || true
cat "$work/inst.sum" >>"$work/SHA256SUMS"
sort -k2 -o "$work/SHA256SUMS" "$work/SHA256SUMS"
cat "$work/SHA256SUMS"

gh release upload "$version" --clobber "${new[@]}" "$work/install-$version.sh" "$work/SHA256SUMS"

case "$host" in
  aarch64-apple-darwin) title="macOS, Apple Silicon" ;;
  aarch64-unknown-linux-gnu) title="64-bit Raspberry Pi OS and other ARM64 Linux" ;;
  *) title="$host" ;;
esac
gh release view "$version" --json body --jq .body >"$work/notes.md"
if ! grep -q "^## Install ($title)" "$work/notes.md"; then
  {
    echo
    echo "## Install ($title)"
    echo
    echo "Built for \`$host\`; \`rustc --version\` prints \`$(cat "$OUT_DIR/rustc-version-$host.txt")\`."
    if [[ "$host" == *-apple-darwin ]]; then
      echo "macOS has no kernel SCTP, so std uses its SCTP-over-UDP backend there. Needs macOS 11 or later."
    fi
    if [[ "$host" == aarch64-unknown-linux-gnu ]]; then
      echo "Cross-built against glibc 2.17, so it runs on Raspberry Pi OS (64-bit) and any ARM64 Linux from that era on. Native SCTP needs \`sudo modprobe sctp\`."
    fi
    echo
    echo '```sh'
    echo "mkdir $version && cd $version"
    echo "gh release download $version -R $GITHUB_REPOSITORY -p '*$host*' -p 'rust-src-*' -p 'install-*' -p SHA256SUMS"
    echo "bash install-$version.sh"
    echo '```'
  } >>"$work/notes.md"
  gh release edit "$version" --notes-file "$work/notes.md"
fi
