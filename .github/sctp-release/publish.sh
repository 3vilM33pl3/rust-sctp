#!/usr/bin/env bash
# Tags the tested release branch, pushes branch and tag, and publishes a
# GitHub Release with the toolchain tarballs from build.sh.
#
#   publish.sh rust-1.100.0-sctp.1
#
# Needs GH_TOKEN, and push access for "origin" that may write workflow files
# (upstream commits on the release branch change .github/workflows).
set -euo pipefail
. "$(dirname "$0")/lib.sh"
. "$OUT_DIR/state.env"

version="${1:?usage: publish.sh <release tag>}"
cd "$(git rev-parse --show-toplevel)"

git tag -a "$version" -m "SCTP release $version on Rust $UPSTREAM_TAG"
# The lease makes the push fail if someone moved the release branch since
# port.sh read it, instead of silently overwriting their work.
git push --force-with-lease="refs/heads/$RELEASE_BRANCH:$OLD_RELEASE_HEAD" \
  origin "HEAD:refs/heads/$RELEASE_BRANCH" "refs/tags/$version"

dl="https://github.com/$GITHUB_REPOSITORY/releases/download/$version"
notes="$OUT_DIR/notes.md"
{
  echo "Rust $UPSTREAM_TAG with \`std::net::{SctpStream, SctpListener, SctpSocket}\` behind \`#![feature(sctp)]\`:"
  echo "native Linux and FreeBSD backends plus an SCTP-over-UDP fallback."
  echo
  echo "Built on the \`dev\` channel so the feature gate works; \`rustc --version\` prints:"
  echo
  echo '```'
  cat "$OUT_DIR/rustc-version.txt"
  echo '```'
  echo
  echo "## Install (x86_64 Linux)"
  echo
  echo '```sh'
  echo "mkdir $version && cd $version"
  echo "gh release download $version -R $GITHUB_REPOSITORY   # or curl -LO each asset from $dl/"
  echo "bash install-$version.sh            # installs to ~/.local/share/rust-sctp/$version"
  echo "cargo +sctp-${version#rust-} build   # rustup toolchain linked by the installer"
  echo '```'
  echo
  echo "Native SCTP needs the kernel module: \`sudo modprobe sctp\`. Without it, the UDP fallback is used."
  echo
  echo "## SCTP commits on top of $UPSTREAM_TAG"
  echo
  git log --reverse --format='- %s' "$UPSTREAM_TAG..HEAD"
  echo
  echo "## Tested"
  echo
  echo "- \`x.py test tidy\`"
  echo "- \`std\` SCTP unit and doc tests (native Linux SCTP and UDP fallback)"
  echo "- vendored \`sctp-proto\` test suite"
  echo "- the installed toolchain compiles and runs a \`#![feature(sctp)]\` program"
  echo
  echo "Built by [run $GITHUB_RUN_ID]($GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID) from \`$SOURCE\`."
} >"$notes"

gh release create "$version" --verify-tag --title "$version" --notes-file "$notes" \
  "$OUT_DIR"/dist/*
