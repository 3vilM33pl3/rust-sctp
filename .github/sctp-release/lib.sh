# Shared helpers for the SCTP release scripts. Source, do not execute.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release.conf
. "$here/release.conf"

die() { echo "error: $*" >&2; exit 1; }

# 1.100.0 -> 1.100
release_line() {
  local t="$1"
  [[ "$t" =~ ^1\.([0-9]+)\.[0-9]+$ ]] || die "not a Rust release tag: $t"
  echo "1.${BASH_REMATCH[1]}"
}

release_branch() { echo "${RELEASE_BRANCH_PREFIX}$(release_line "$1")"; }

# Next SCTP release tag for an upstream tag: 1.100.0 -> rust-1.100.0-sctp.N
next_release_tag() {
  local t="$1" n
  n=$(git ls-remote --tags --refs origin "${TAG_PREFIX}$t-sctp.*" | sed 's#.*refs/tags/##' |
      sed -n "s/^${TAG_PREFIX}$t-sctp\.\([0-9][0-9]*\)$/\1/p" | sort -n | tail -1)
  echo "${TAG_PREFIX}$t-sctp.$(( ${n:-0} + 1 ))"
}

# Directory for logs and outputs shared between steps.
OUT_DIR="${SCTP_RELEASE_OUT:-${RUNNER_TEMP:-/tmp}/sctp-release}"
mkdir -p "$OUT_DIR"
