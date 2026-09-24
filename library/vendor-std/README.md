# `library/vendor-std`

Vendored copies of the crates that the standard library's user-space SCTP-over-UDP
engine (`std::net::Sctp*` with the `UdpOnly`/`NativePreferred` transport policies)
depends on. They live here, not under `src/tools/`, because `library/std` must only
path-depend on crates that ship in the `rust-src` component.

| Crate | Upstream version | Why it is vendored |
| --- | --- | --- |
| `sctp-proto` | 0.9.0 (webrtc-rs) | Sans-I/O SCTP protocol engine. Locally patched: `no_std` `Instant` shim (`src/instant.rs`), injectable random source (`with_random_source`), configurable INIT timeout, `thiserror` removed. See `SYNC-RTC-SCTP.md` for the upstream sync procedure. |
| `bytes` | crates.io | Used throughout `sctp-proto` (`Bytes`/`BytesMut`). |
| `crc` / `crc-catalog` | crates.io | CRC-32C packet checksum. |
| `log` | crates.io | Diagnostics inside `sctp-proto`; compiled out under `rustc-dep-of-std`. |
| `rustc-hash` | crates.io | `FxHashMap` for association lookup. |
| `slab` | crates.io | Association table. |

Each crate's `Cargo.toml` differs from the published one (`Cargo.toml.orig`) only by
the `rustc-dep-of-std` feature, which swaps the crate's `core`/`alloc` dependencies
for `rustc-std-workspace-core`/`-alloc` so it can be built as part of std. This is the
same idiom upstream uses for `hashbrown`, `cfg-if` and `libc`.

`library/Cargo.toml` patches these names to the vendored paths for the `library`
workspace only. Do not add the patches to the root `Cargo.toml`: that would also
rebuild the compiler's own `rustc-hash` and `log` from these copies.

`rustfmt.toml` and `src/tools/tidy/src/walk.rs` exclude this directory, and
`library/Cargo.toml` lists it under `exclude` so that `sctp-proto` can be its own
workspace: `cargo test --manifest-path library/vendor-std/sctp-proto/Cargo.toml`
runs the engine's protocol suite with a plain host toolchain. Its manifest carries
the same `[patch.crates-io]` entries so standalone builds see the std-compatible
copies. (Two of its tests bind fixed UDP ports and can collide under parallel
execution; rerun with `--test-threads=1` if they fail.)
