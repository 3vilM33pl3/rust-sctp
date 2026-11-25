#!/usr/bin/env bash
# Builds, once, the glibc 2.17 aarch64 cross compiler that
# build-aarch64-linux.sh uses, and prints its prefix.
#
#   toolchain.sh <checkout>/src/ci/docker/scripts
#
# It takes the crosstool-ng version and checksum patches from the release
# checkout's own crosstool-ng.sh, as upstream's dist image does. It runs as the runner
# user, without root or Docker: crosstool-ng is built and used in place
# (--enable-local), and the toolchain goes under $SCTP_XTOOLS (default
# ~/x-tools). A stamp holds the hash of the defconfig and crosstool-ng
# version and patches, so the toolchain is rebuilt only when one changes.
#
# Host packages it needs (Arch names): base-devel, help2man, gperf, unzip,
# rsync, python, curl, ncurses, xz, bzip2.
set -euo pipefail

scripts="$(cd "${1:?usage: toolchain.sh <checkout>/src/ci/docker/scripts}" && pwd)"
CT_NG=$(sed -n 's/^CT_NG=//p' "$scripts/crosstool-ng.sh")
[[ -n "$CT_NG" ]] || { echo "error: no CT_NG= in $scripts/crosstool-ng.sh" >&2; exit 1; }
shopt -s nullglob
patches=("$scripts"/crosstool-ng-sha256-*.diff)
shopt -u nullglob
target=aarch64-unknown-linux-gnu
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
defconfig="$here/aarch64-linux-gnu.defconfig"
root="${SCTP_XTOOLS:-$HOME/x-tools}"
prefix="$root/$target"
stamp="$prefix/.sctp-stamp"
want="$( { echo "ct-ng $CT_NG"; cat "$defconfig" "${patches[@]}"; } | sha256sum | cut -d' ' -f1)"

if [[ -f "$stamp" && "$(cat "$stamp")" == "$want" && -x "$prefix/bin/$target-gcc" ]]; then
  echo "$prefix"
  exit 0
fi

{
  echo "::group::Build the $target cross compiler (crosstool-ng $CT_NG)"
  work="$root/.work"
  rm -rf "$work" "$prefix"
  mkdir -p "$work"
  cd "$work"

  curl -Lf "https://github.com/crosstool-ng/crosstool-ng/archive/crosstool-ng-$CT_NG.tar.gz" | tar xzf -
  cd "crosstool-ng-crosstool-ng-$CT_NG"
  # Same fix as upstream's src/ci/docker/scripts/crosstool-ng.sh.
  sed -e "s|zlib.net/'|zlib.net/fossils'|" -i packages/zlib/package.desc
  for p in "${patches[@]}"; do patch -p1 <"$p"; done
  ./bootstrap
  ./configure --enable-local
  make -j"$(getconf _NPROCESSORS_ONLN)"

  mkdir ../build
  cd ../build
  sed "s|^CT_PREFIX_DIR=.*|CT_PREFIX_DIR=\"$prefix\"|" "$defconfig" >.config
  cat >>.config <<CONFIG
CT_LOCAL_TARBALLS_DIR="$root/.tarballs"
CT_SAVE_TARBALLS=y
CT_LOG_PROGRESS_BAR=n
CONFIG
  # A newer host compiler defaults to C23, which the GCC 8 and binutils 2.32
  # era host code (and its companion libraries) does not build as.
  if [[ "$(gcc -dumpversion | cut -d. -f1)" -ge 15 ]]; then
    echo 'CT_EXTRA_CFLAGS_FOR_BUILD="-std=gnu17"' >>.config
    echo 'CT_EXTRA_CFLAGS_FOR_HOST="-std=gnu17"' >>.config
  fi
  ../crosstool-ng-crosstool-ng-$CT_NG/ct-ng olddefconfig
  # crosstool-ng refuses to run with these set.
  unset LD_LIBRARY_PATH LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
  if ! ../crosstool-ng-crosstool-ng-$CT_NG/ct-ng build >"$root/ct-ng-build.log" 2>&1; then
    tail -n 200 "$root/ct-ng-build.log"
    echo "error: crosstool-ng build failed; full log in $root/ct-ng-build.log" >&2
    exit 1
  fi
  chmod -R u+w "$prefix"
  echo "$want" >"$stamp"
  cd "$root"
  rm -rf "$work"
  echo "::endgroup::"
} >&2

echo "$prefix"
