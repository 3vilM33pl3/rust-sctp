# SCTP transport selection

This experimental fork exposes `std::net::{SctpStream, SctpListener, SctpSocket}`
behind `#![feature(sctp)]`. Ordinary constructors use `NativePreferred`:
try kernel SCTP first, then user-space SCTP over UDP on a protocol-unavailable
or connection-refused/reset/aborted/unreachable/timeout error. Invalid input,
permission failures, local bind failures and resource exhaustion do not trigger
fallback. Native timeouts are not shortened or raced against UDP.

Listeners and one-to-many sockets bind UDP plus native SCTP when available.
They accept either transport. UDP binding is required even on native-capable
hosts: use `NativeOnly` when that is not appropriate. Port zero reserves a
shared numeric SCTP/UDP port with bounded collision retries. The portable UDP
adapter is enabled on Linux, macOS, FreeBSD, OpenBSD, NetBSD and DragonFly;
the current native adapters are Linux and FreeBSD.

## Explicit selection and ports

```rust
#![feature(sctp)]
use std::net::{SctpListener, SctpTransportConfig, SctpTransportPolicy};

fn main() -> std::io::Result<()> {
    let _listener = SctpListener::bind("127.0.0.1:9000")?;
    let native_only = SctpTransportConfig {
        policy: SctpTransportPolicy::NativeOnly,
        udp: None,
    };
    let _native_listener = SctpListener::bind_with_config("127.0.0.1:9001", native_only)?;
    Ok(())
}
```

Use `*_with_config` constructors for `NativeOnly` or `UdpOnly`.
`udp: None` means default UDP settings, not disabled fallback.
`SctpUdpConfig::{local_encap_port,remote_encap_port}` override the carrier
ports; omitted ports reuse the SCTP endpoint port. `reuse_port` requests real
pre-bind `SO_REUSEPORT`; it is not needed for ordinary dual transport binding.
Keep reuse disabled unless deliberately sharing a UDP port.

The remote endpoint must support compatible SCTP-over-UDP encapsulation.
Fallback cannot make an unmodified native-only server listen for UDP.
Firewalls must permit UDP as well as SCTP on the configured ports. This is
not DTLS/WebRTC framing, authentication, encryption or a NAT traversal service.
Use a trusted network or a separately secured tunnel. The user-space protocol
engine remains research code, not a production security boundary.

## Supported behavior and boundaries

The UDP adapter drives handshakes, timers, retransmissions and receive queues
independently of application reads. Clones share the association. Accepted and
peeled-off streams retain the endpoint worker; dropping the listener stops new
acceptance without destroying accepted sessions. Endpoint shutdown has a
bounded five-second background drain once all application handles are gone.

| API behavior | UDP implementation |
| --- | --- |
| Send/receive, vectored I/O, partial record reads | Real SCTP messages; stream, PPID, SSN, TSN and unordered metadata; EOR on the last part |
| PPID | Same opaque network-byte-order convention as the existing native adapter; use `to_be()` / `from_be()` when interpreting a protocol number |
| INIT options and RTO | Negotiated stream counts, handshake retry/timeout limits, configurable retransmission intervals |
| Default send, default PR, receive-next | Stream/PPID/unordered defaults, reliable / TTL / RTX policies, queued next-message metadata |
| Association/shutdown notifications, status | Typed notifications and live protocol counters; platform-style association state values |
| Nonblocking, timeouts, clone, shutdown, autoclose | Shared state and wakeups; zero timeouts rejected |
| Bound connect | Shared pending transport selection; nonblocking connect returns `WouldBlock`, then I/O or `take_error` reports completion/failure |
| One-to-many | Handshake before application send; mixed native/UDP associations use stable facade IDs |
| Peeloff | Transfers the association and prefetched data, preserving facade metadata IDs |
| Local multi-bind | Several same-family local addresses and one SCTP port; no path failover |
| Remote multi-address association / bindx / primary path | `Unsupported`; use native SCTP for true multihoming |
| AUTH, stream reset/add-stream, schedulers, fragment interleave | `Unsupported` |
| Delayed SACK, max burst, max segment controls | `Unsupported` |
| Address/send-failure/peer-error/adaptation/AUTH/partial-delivery/sender-dry/reset event subscriptions | `Unsupported`, not silently ignored |

`set_nodelay(true)` matches the engine's immediate-send behavior; disabling
it is unsupported. INIT options apply before connecting or to future accepted
associations; changing them on an established UDP stream is unsupported.
Connected native streams retain native option handling. Hybrid endpoint-wide
options are checked against UDP capabilities before native application.
The engine's stream-close/reset model does not yet provide socket-API reset
parity, so those controls deliberately remain unavailable.

There are bounded application queues and a 128-association UDP endpoint cap.
Ordinary resolved address candidates are tried as candidates, not interpreted
as a multihoming request. Selection does not migrate an already-established
session to another transport after application data has been sent.

## Build and verify

From this runtime tree:

```sh
python3 x.py build library/std library/proc_macro --stage 1
python3 x.py test library/std --stage 1 --test-args net::sctp::tests
cargo test --manifest-path src/tools/sctp-feature-client/vendor/sctp-proto/Cargo.toml
python3 x.py check library/std --stage 1 --target x86_64-unknown-linux-gnu,x86_64-unknown-freebsd,x86_64-unknown-openbsd,x86_64-unknown-netbsd,x86_64-unknown-dragonfly,x86_64-apple-darwin
```

The protocol suite covers loss, reordering, retransmission, congestion and
partial reliability. Socket tests cover native/UDP selection, mixed endpoints,
IPv4/IPv6, ports, metadata, bound connect, one-to-many and peeloff, cloning,
timeouts and unsupported controls. Cross-target checks establish compilation,
not runtime interoperability on those operating systems. Run native platform
and cross-host conformance separately before making such claims; the shared
FreeBSD oracle is not modified or restarted by this change.

On Linux, `src/tools/sctp-feature-client/no-kernel-sctp.c` is a test-only
socket shim. Compile it to a temporary shared library and set `LD_PRELOAD`
only on the test process to return `EPROTONOSUPPORT` for native SCTP socket
creation. This exercises missing-kernel fallback without changing the host:

```sh
test_dir=$(mktemp -d)
cc -shared -fPIC src/tools/sctp-feature-client/no-kernel-sctp.c -ldl -o "$test_dir/no-kernel-sctp.so"
cd ../distributed-agents-example
LD_PRELOAD="$test_dir/no-kernel-sctp.so" ./scripts/cargo-sctp.sh test --test three_agent_smoke -- --ignored --nocapture
```

The feature client's native conformance contract and native capability probe
explicitly use `NativeOnly`. They must not inherit the application default and
mislabel user-space UDP evidence as native SCTP evidence.
