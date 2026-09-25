# `sctp`

This feature has no tracking issue yet; it is experimental research work.

------------------------

Adds SCTP (Stream Control Transmission Protocol, [RFC 9260]) sockets to
`std::net`: [`SctpStream`] for one-to-one associations, [`SctpListener`] to
accept them, and [`SctpSocket`] for one-to-many sockets, together with the
metadata and option types the protocol needs (streams, payload protocol
identifiers, notifications, multihoming, partial reliability).

Two transports are available. The native backend uses the operating system's
SCTP stack (Linux and FreeBSD). A user-space SCTP-over-UDP engine ([RFC 6951]
encapsulation) is built on Linux, macOS, FreeBSD, OpenBSD, NetBSD and DragonFly.
`SctpTransportPolicy` selects between them; the default `NativePreferred`
uses the native stack and falls back to UDP only when the host has no SCTP
support. Listeners and one-to-many sockets accept both transports on one port.
`SctpStream::transport` reports which one a connected stream uses.

```rust,no_run
#![feature(sctp)]
use std::net::{SctpListener, SctpSendInfo, SctpStream};

fn main() -> std::io::Result<()> {
    let listener = SctpListener::bind("127.0.0.1:9000")?;
    let client = SctpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;

    let info = SctpSendInfo { stream: 3, ppid: 42u32.to_be(), ..Default::default() };
    client.send_with_info(b"hello", Some(&info))?;

    let mut buf = [0u8; 64];
    let received = server.recv_message(&mut buf)?;
    assert_eq!(&buf[..received.len], b"hello");
    assert_eq!(received.info.unwrap().stream, 3);
    Ok(())
}
```

The design, the UDP engine's capability matrix and the verification steps are
described in `SCTP-TRANSPORT.md` at the repository root.

[RFC 9260]: https://www.rfc-editor.org/rfc/rfc9260
[RFC 6951]: https://www.rfc-editor.org/rfc/rfc6951
[`SctpStream`]: ../../std/net/struct.SctpStream.html
[`SctpListener`]: ../../std/net/struct.SctpListener.html
[`SctpSocket`]: ../../std/net/struct.SctpSocket.html
