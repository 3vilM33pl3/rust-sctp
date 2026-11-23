# Automated Rust+SCTP releases

`.github/workflows/sctp-release.yml` cuts a Rust toolchain release with
`std::net` SCTP support every time upstream Rust ships a stable release.

## What a run does

1. **Detect** (GitHub-hosted, daily at 06:47 UTC). Lists upstream `1.N.M`
   tags, keeps the newest patch of every minor version from `MIN_MINOR` on,
   and drops those that already have a `rust-1.N.M-sctp.K` tag here or an
   open `sctp-release-blocked` issue. Betas and nightlies have no such tags.
2. **Port** (`port.sh`). Rebases the SCTP series onto the upstream tag into
   `release/sctp-1.N`:
   - a new minor version is ported from `SCTP_DEV_BRANCH` (everything after
     its merge base with upstream `main`);
   - a point release rebases the existing release branch from the previous
     patch tag onto the new one.
3. **Build and test** (`build.sh`, self-hosted `[self-hosted, linux, sctp]`).
   Writes `bootstrap.toml` (dist profile, `dev` channel so `#![feature(sctp)]`
   works, LLVM from source because upstream has no CI LLVM for release
   tags), then runs `x.py test tidy`, the std SCTP unit and doc tests, the
   vendored `sctp-proto` suite, `x.py dist rustc rust-std cargo rust-src`, and
   compiles and runs a `#![feature(sctp)]` program with the installed result.
4. **Publish** (`publish.sh`). Tags `rust-1.N.M-sctp.K`, pushes the release
   branch and tag, and creates a GitHub Release with the component tarballs,
   `install-rust-1.N.M-sctp.K.sh` and `SHA256SUMS`.

A conflict or a red test opens an issue titled `SCTP release blocked: 1.N.M`
(`report-failure.sh`) and publishes nothing. The daily run skips that version
while the issue is open.

## Installing a release

```sh
mkdir rust-1.100.0-sctp.1 && cd rust-1.100.0-sctp.1
gh release download rust-1.100.0-sctp.1 -R 3vilM33pl3/rust-sctp
bash install-rust-1.100.0-sctp.1.sh      # ~/.local/share/rust-sctp/rust-1.100.0-sctp.1
cargo +sctp-1.100.0-sctp.1 build         # linked with rustup when it is installed
```

`rustc --version` reports `1.100.0-dev` because of the `dev` channel.

## One-time setup

- Repository secret `SCTP_RELEASE_TOKEN`: a fine-grained token for this
  repository with **Contents: read and write** and **Workflows: read and
  write**. Release branches contain upstream commits that change
  `.github/workflows`, which the default `GITHUB_TOKEN` may not push.
- A runner with labels `self-hosted, linux, sctp`, SCTP kernel support,
  `python3`, `cmake`, `ninja`, a C/C++ toolchain, `gh`, and about 80 GB free.
  The first build compiles LLVM; later builds reuse `build/` in the runner's
  workspace. Expect 3 to 6 hours on 8 cores for a new minor version.

## Manual runs

Actions → SCTP release → Run workflow:

- `version`: one upstream tag, e.g. `1.100.0`. A second run for the same tag
  produces `-sctp.2`, `-sctp.3`, ...
- `from_dev`: port from `SCTP_DEV_BRANCH` again, to ship SCTP changes made
  since the last release of that line.
- `dry_run`: build and test without pushing or publishing.

When the SCTP series moves to a newer upstream base (a new `sctp-1.N` branch),
update `SCTP_DEV_BRANCH` in `release.conf`.

## When a port conflicts

```sh
git fetch origin && git fetch https://github.com/rust-lang/rust tag 1.N.M
git checkout -B release/sctp-1.N origin/release/sctp-1.N   # or origin/sctp-1.100 for a new line
git rebase --onto 1.N.M <old base>    # fix conflicts, git rebase --continue
git push -f origin release/sctp-1.N
```

Then close the issue; the next run builds from the fixed branch.
