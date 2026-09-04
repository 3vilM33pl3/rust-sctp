use crate::io::ErrorKind;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
mod udp_transport {
    use super::*;
    use crate::net::{SCTP_UNORDERED, SctpTransportConfig, SctpTransportPolicy, SctpUdpConfig};
    use crate::thread;
    use crate::time::{Duration, Instant};

    fn config() -> SctpTransportConfig {
        SctpTransportConfig {
            policy: SctpTransportPolicy::UdpOnly,
            udp: Some(SctpUdpConfig::default()),
        }
    }

    #[test]
    fn udp_autoclose_and_listener_lifetime() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let client =
            SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
        let server = accept(&listener);
        drop(listener);
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.send_with_info(b"accepted survives", None).unwrap();
        assert_eq!(server.recv_message(&mut [0; 32]).unwrap().len, 17);
        server.set_autoclose(1).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(client.recv_message(&mut [0; 32]).unwrap().len, 0);
    }

    #[test]
    fn udp_failed_many_selection_can_retry_on_the_same_socket() {
        let reservation = crate::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = reservation.local_addr().unwrap();
        let socket = SctpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_init_options(crate::net::SctpInitOptions { max_attempts: 1, max_init_timeout: 25, ..Default::default() }).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let error = socket.send_to_with_info(b"not-delivered", peer, None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
        drop(reservation);
        let listener = SctpListener::bind_with_config(peer, config()).unwrap();
        socket.send_to_with_info(b"retry", peer, None).unwrap();
        let stream = accept(&listener);
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(stream.recv_message(&mut [0; 32]).unwrap().len, 5);
    }

    #[test]
    fn udp_completed_sessions_release_the_association_cap() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        for _ in 0..140 {
            let client =
                SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
            let server = accept(&listener);
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            assert_eq!(server.recv_message(&mut [0; 1]).unwrap().len, 0);
            assert_eq!(client.recv_message(&mut [0; 1]).unwrap().len, 0);
        }
    }

    #[test]
    fn udp_reuse_port_and_unsupported_event_preflight() {
        let reusable = SctpTransportConfig {
            policy: SctpTransportPolicy::UdpOnly,
            udp: Some(SctpUdpConfig { reuse_port: true, ..Default::default() }),
        };
        let first = SctpListener::bind_with_config("127.0.0.1:0", reusable).unwrap();
        let _second =
            SctpListener::bind_with_config(first.local_addr().unwrap(), reusable).unwrap();
        assert_eq!(
            first
                .subscribe_events(SctpEventMask { stream_reset: true, ..Default::default() })
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
        let hybrid = SctpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            hybrid
                .subscribe_events(SctpEventMask { authentication: true, ..Default::default() })
                .unwrap_err()
                .kind(),
            ErrorKind::Unsupported
        );
        assert_eq!(hybrid.set_maxseg(500).unwrap_err().kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn udp_default_policy_and_fallback_error_boundary() {
        assert_eq!(SctpTransportConfig::default().policy, SctpTransportPolicy::NativePreferred);
        assert_eq!(SctpTransportPolicy::default(), SctpTransportPolicy::NativePreferred);
        for kind in [
            ErrorKind::Unsupported,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::TimedOut,
        ] {
            assert!(super::super::should_fallback(&crate::io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied,
            ErrorKind::AddrInUse,
            ErrorKind::AddrNotAvailable,
            ErrorKind::OutOfMemory,
            ErrorKind::WouldBlock,
            ErrorKind::Other,
        ] {
            assert!(!super::super::should_fallback(&crate::io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn udp_plain_client_falls_back_and_clone_io_is_independent() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let client = SctpStream::connect(listener.local_addr().unwrap()).unwrap();
        let server = accept(&listener);
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let reader = client.try_clone().unwrap();
        let reader = thread::spawn(move || reader.recv_message(&mut [0; 8]).unwrap().len);
        client.send_with_info(b"ping", None).unwrap();
        assert_eq!(server.recv_message(&mut [0; 8]).unwrap().len, 4);
        server.send_with_info(b"pong", None).unwrap();
        assert_eq!(reader.join().unwrap(), 4);
    }

    #[test]
    fn udp_ipv6_candidates_and_explicit_encapsulation_ports() {
        let listener = SctpListener::bind_with_config("[::1]:0", config()).unwrap();
        let peer = listener.local_addr().unwrap();
        let candidates = ["127.0.0.1:0".parse().unwrap(), peer];
        // A bad first candidate must not turn an ordinary address list into
        // unsupported multihoming or suppress a usable second candidate.
        let client = SctpStream::connect_with_config(&candidates[..], config()).unwrap();
        let server = accept(&listener);
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.send_with_info(b"ipv6", None).unwrap();
        assert_eq!(server.recv_message(&mut [0; 8]).unwrap().len, 4);

        let probe = crate::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let encap = probe.local_addr().unwrap().port();
        drop(probe);
        let listener = SctpListener::bind_with_config(
            "127.0.0.1:19001",
            SctpTransportConfig {
                policy: SctpTransportPolicy::UdpOnly,
                udp: Some(SctpUdpConfig { local_encap_port: Some(encap), ..Default::default() }),
            },
        )
        .unwrap();
        let _client = SctpStream::connect_with_config(
            listener.local_addr().unwrap(),
            SctpTransportConfig {
                policy: SctpTransportPolicy::UdpOnly,
                udp: Some(SctpUdpConfig { remote_encap_port: Some(encap), ..Default::default() }),
            },
        )
        .unwrap();
        let _server = accept(&listener);
    }

    #[test]
    fn udp_local_multibind_and_remote_multihoming_boundary() {
        let addrs = SctpMultiAddr::new(vec![
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.2:0".parse().unwrap(),
        ])
        .unwrap();
        let listener = SctpListener::bind_multi_with_config(&addrs, config()).unwrap();
        let local = listener.local_addrs().unwrap();
        assert_eq!(local.len(), 2);
        assert_eq!(local[0].port(), local[1].port());
        let _client = SctpStream::connect_with_config(local[1], config()).unwrap();
        let _server = accept(&listener);
        let remotes = SctpMultiAddr::new(local).unwrap();
        assert_eq!(
            SctpStream::connect_multi_with_config(&remotes, config()).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn udp_defaults_rto_partial_reliability_next_info_and_shutdown() {
        use crate::net::{SCTP_PR_RTX, SCTP_PR_TTL, SctpPrInfo, SctpRtoInfo};
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let client =
            SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
        let server = accept(&listener);
        server.set_recv_nxtinfo(true).unwrap();
        server.subscribe_events(SctpEventMask { shutdown: true, ..Default::default() }).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client
            .set_default_send_info(SctpSendInfo {
                stream: 3,
                ppid: 0x11223344,
                ..Default::default()
            })
            .unwrap();
        client
            .set_rto_info(SctpRtoInfo { min: 10, initial: 20, max: 50, ..Default::default() })
            .unwrap();
        client.set_rto_info(SctpRtoInfo { initial: 30, ..Default::default() }).unwrap();
        assert!(client.assoc_status(0).unwrap().primary_rto <= 50);
        assert_eq!(
            client.set_rto_info(SctpRtoInfo { min: 100, ..Default::default() }).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        for policy in [SCTP_PR_RTX, SCTP_PR_TTL] {
            client
                .set_default_prinfo(SctpPrInfo { policy, value: 1000, ..Default::default() })
                .unwrap();
            client.send_with_info(b"record", None).unwrap();
        }
        thread::sleep(Duration::from_millis(50));
        let first = server.recv_message(&mut [0; 16]).unwrap();
        let info = first.info.unwrap();
        assert_eq!(info.stream, 3);
        assert_eq!(info.ppid, 0x11223344);
        assert_eq!(info.next.unwrap().length, 6);
        assert_eq!(server.recv_message(&mut [0; 16]).unwrap().len, 6);
        client.shutdown(Shutdown::Write).unwrap();
        let end = server.recv_message(&mut [0; 16]).unwrap();
        assert!(matches!(end.notification, Some(SctpNotification::Shutdown { .. })));
    }

    #[test]
    fn udp_native_and_udp_clients_share_default_many_socket() {
        let socket = SctpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer = socket.local_addrs().unwrap()[0];
        let udp = SctpStream::connect_with_config(peer, config()).unwrap();
        let preferred = SctpStream::connect(peer).unwrap();
        udp.send_with_info(b"udp", None).unwrap();
        preferred.send_with_info(b"preferred", None).unwrap();
        let mut ids = Vec::new();
        for _ in 0..2 {
            let r = socket.recv_message(&mut [0; 32]).unwrap();
            ids.push(r.receive.info.unwrap().assoc_id);
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(socket.assoc_ids().unwrap().len(), 2);
    }

    #[test]
    fn udp_hybrid_many_falls_back_before_sending() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let peer = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let stream = accept(&listener);
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut data = [0; 32];
            let r = stream.recv_message(&mut data).unwrap();
            assert_eq!(&data[..r.len], b"selected");
            assert_eq!(r.info.unwrap().ppid, 99);
            stream.send_with_info(b"reply", None).unwrap();
        });
        // The server has no native listener: native connection refusal must
        // complete before any application data is submitted to the UDP engine.
        let socket = SctpSocket::bind_with_config(
            "127.0.0.1:0",
            SctpTransportConfig { policy: SctpTransportPolicy::NativePreferred, udp: None },
        )
        .unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket
            .send_to_with_info(
                b"selected",
                peer,
                Some(&SctpSendInfo { ppid: 99, ..Default::default() }),
            )
            .unwrap();
        let mut data = [0; 32];
        let r = socket.recv_message(&mut data).unwrap();
        assert_eq!(&data[..r.receive.len], b"reply");
        server.join().unwrap();
    }

    #[test]
    fn udp_hybrid_many_peeloff_preserves_prefetched_data_and_ids() {
        let socket = SctpSocket::bind_with_config(
            "127.0.0.1:0",
            SctpTransportConfig { policy: SctpTransportPolicy::NativePreferred, udp: None },
        )
        .unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let client =
            SctpStream::connect_with_config(socket.local_addrs().unwrap()[0], config()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.send_with_info(b"first", None).unwrap();
        let mut data = [0; 32];
        let first = socket.recv_message(&mut data).unwrap();
        let id = first.receive.info.unwrap().assoc_id;
        client
            .send_with_info(b"second", Some(&SctpSendInfo { ppid: 23, ..Default::default() }))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        let peeled = socket.peeloff(id).unwrap();
        peeled.set_nonblocking(false).unwrap();
        peeled.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let r = peeled.recv_message(&mut data).unwrap();
        assert_eq!(&data[..r.len], b"second");
        assert_eq!(r.info.unwrap().assoc_id, id);
        assert_eq!(r.info.unwrap().ppid, 23);
        assert_eq!(peeled.assoc_status(id).unwrap().assoc_id, id);
        peeled
            .send_with_info(b"reply", Some(&SctpSendInfo { assoc_id: id, ..Default::default() }))
            .unwrap();
        assert_eq!(client.recv_message(&mut data).unwrap().len, 5);
        assert!(!socket.assoc_ids().unwrap().contains(&id));
    }

    #[test]
    fn udp_bound_nonblocking_connect_preserves_local_endpoint() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let stream =
            SctpStream::bind_with_config("127.0.0.1:0".parse().unwrap(), config()).unwrap();
        let local = stream.local_addr().unwrap();
        stream.set_nonblocking(true).unwrap();
        assert_eq!(
            stream.connect_bound(listener.local_addr().unwrap()).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        let _server = accept(&listener);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match stream.peer_addr() {
                Ok(_) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("bound connect: {e}"),
            }
        }
        assert_eq!(stream.local_addr().unwrap(), local);
        assert!(stream.take_error().unwrap().is_none());
    }

    #[test]
    fn udp_native_preferred_listener_accepts_udp_and_requires_udp_port() {
        let preferred =
            SctpTransportConfig { policy: SctpTransportPolicy::NativePreferred, udp: None };
        let listener = SctpListener::bind_with_config("127.0.0.1:0", preferred).unwrap();
        let _client =
            SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
        let _server = accept(&listener);
        let occupied = crate::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err =
            SctpListener::bind_with_config(occupied.local_addr().unwrap(), preferred).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
    }

    fn accept(listener: &SctpListener) -> SctpStream {
        listener.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((s, _)) => return s,
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < end => {
                    thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("UDP accept failed: {e}"),
            }
        }
    }

    #[test]
    fn udp_listener_roundtrip_metadata_and_partial_records() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let client =
            SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
        let server = accept(&listener);
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let info = SctpSendInfo {
            stream: 7,
            ppid: 0x10203040,
            flags: SCTP_UNORDERED,
            ..Default::default()
        };
        client.send_with_info(b"metadata", Some(&info)).unwrap();
        let mut buf = [0; 4];
        let a = server.recv_message(&mut buf).unwrap();
        assert_eq!(&buf, b"meta");
        assert!(!a.flags.end_of_record);
        assert_eq!(a.info.unwrap().stream, 7);
        assert_eq!(a.info.unwrap().ppid, 0x10203040);
        assert_eq!(a.info.unwrap().flags & SCTP_UNORDERED, SCTP_UNORDERED);
        let b = server.recv_message(&mut buf).unwrap();
        assert_eq!(&buf, b"data");
        assert!(b.flags.end_of_record);
        server.send_with_info(b"reply", None).unwrap();
        let mut response = [0; 32];
        let r = client.recv_message(&mut response).unwrap();
        assert_eq!(&response[..r.len], b"reply");
    }

    #[test]
    fn udp_one_to_many_receive_reply_and_peeloff() {
        let server = SctpSocket::bind_with_config("127.0.0.1:0", config()).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let client =
            SctpStream::connect_with_config(server.local_addrs().unwrap()[0], config()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.send_with_info(b"request", None).unwrap();
        let mut buf = [0; 32];
        let r = server.recv_message(&mut buf).unwrap();
        assert_eq!(&buf[..r.receive.len], b"request");
        let id = r.receive.info.unwrap().assoc_id;
        assert!(server.assoc_ids().unwrap().contains(&id));
        server
            .send_to_with_info(
                b"reply",
                r.peer_addr.unwrap(),
                Some(&SctpSendInfo { assoc_id: id, ..Default::default() }),
            )
            .unwrap();
        let r = client.recv_message(&mut buf).unwrap();
        assert_eq!(&buf[..r.len], b"reply");
        let peeled = server.peeloff(id).unwrap();
        assert!(!server.assoc_ids().unwrap().contains(&id));
        client.send_with_info(b"peeled", None).unwrap();
        let r = peeled.recv_message(&mut buf).unwrap();
        assert_eq!(&buf[..r.len], b"peeled");
    }

    #[test]
    fn udp_nonblocking_timeouts_and_unsupported_controls() {
        let listener = SctpListener::bind_with_config("127.0.0.1:0", config()).unwrap();
        let client =
            SctpStream::connect_with_config(listener.local_addr().unwrap(), config()).unwrap();
        let _server = accept(&listener);
        client.set_nonblocking(true).unwrap();
        assert_eq!(client.recv_message(&mut [0; 8]).unwrap_err().kind(), ErrorKind::WouldBlock);
        client.set_nonblocking(false).unwrap();
        client.set_read_timeout(Some(Duration::from_millis(25))).unwrap();
        assert_eq!(client.recv_message(&mut [0; 8]).unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(
            client.set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(client.set_auth_chunks(&[0]).unwrap_err().kind(), ErrorKind::Unsupported);
        assert_eq!(client.set_maxseg(512).unwrap_err().kind(), ErrorKind::Unsupported);
        assert_eq!(
            client.bindx_add(&["127.0.0.2:0".parse().unwrap()]).unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }
}
use crate::net::{
    Ipv4Addr, Ipv6Addr, SctpEventMask, SctpListener, SctpMultiAddr, SctpNotification, SctpSendInfo,
    SctpSocket, SctpStream, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6,
};
#[cfg(target_os = "linux")]
use crate::thread;
#[cfg(target_os = "linux")]
use crate::time::Duration;

#[test]
fn multi_addr_rejects_empty() {
    let err = SctpMultiAddr::new(Vec::new()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn multi_addr_rejects_mixed_families() {
    let addrs = vec![
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7777)),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7777, 0, 0)),
    ];
    let err = SctpMultiAddr::new(addrs).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn multi_addr_rejects_mixed_ports() {
    let addrs = vec![
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7777)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8888)),
    ];
    let err = SctpMultiAddr::new(addrs).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}

#[test]
fn multi_addr_accepts_valid_ipv4_set() {
    let addrs = vec![
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7777)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 7777)),
    ];
    let m = SctpMultiAddr::new(addrs.clone()).unwrap();
    assert_eq!(m.addrs(), addrs.as_slice());
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
#[test]
fn unsupported_platform_returns_unsupported_error() {
    let err = SctpListener::bind("127.0.0.1:0").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[cfg(target_os = "linux")]
fn localhost_listener() -> (SctpListener, SocketAddr) {
    let listener = SctpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[cfg(target_os = "linux")]
#[test]
fn recv_nxtinfo_reports_next_message_metadata() {
    let (listener, addr) = localhost_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let first = SctpSendInfo { stream: 7, ppid: 701, ..SctpSendInfo::default() };
        let second = SctpSendInfo { stream: 8, ppid: 702, ..SctpSendInfo::default() };
        stream.send_with_info(b"first", Some(&first)).unwrap();
        stream.send_with_info(b"second", Some(&second)).unwrap();
    });

    let stream = SctpStream::connect(addr).unwrap();
    stream.set_recv_nxtinfo(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    thread::sleep(Duration::from_millis(100));

    let mut buf = [0u8; 1024];
    let received = stream.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"first");
    let info = received.info.expect("first receive metadata");
    let next = info.next.expect("next receive metadata");
    assert_eq!(next.stream, 8);
    assert_eq!(next.ppid, 702);
    assert_eq!(next.length, 6);

    let received = stream.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"second");
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn plain_connect_reports_receive_metadata_and_record_flags() {
    let (listener, addr) = localhost_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let info = SctpSendInfo { stream: 4, ppid: 404, ..SctpSendInfo::default() };
        stream.send_with_info(b"metadata", Some(&info)).unwrap();
    });

    let stream = SctpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut buf = [0u8; 1024];
    let received = stream.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"metadata");
    assert!(received.flags.end_of_record);
    assert!(!received.flags.truncated);
    assert!(!received.flags.control_truncated);
    let info = received.info.expect("receive metadata");
    assert_eq!(info.stream, 4);
    assert_eq!(info.ppid, 404);
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn one_to_many_socket_receives_message_and_peer_address() {
    let socket = SctpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addrs().unwrap()[0];
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let client = thread::spawn(move || {
        let stream = SctpStream::connect(addr).unwrap();
        let info = SctpSendInfo { stream: 6, ppid: 606, ..SctpSendInfo::default() };
        stream.send_with_info(b"one-to-many", Some(&info)).unwrap();
    });

    let mut buf = [0u8; 1024];
    let received = socket.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.receive.len], b"one-to-many");
    assert!(received.peer_addr.is_some());
    let info = received.receive.info.expect("receive metadata");
    assert_eq!(info.stream, 6);
    assert_eq!(info.ppid, 606);
    client.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn one_to_many_socket_can_still_send_to_stream_listener() {
    let (listener, addr) = localhost_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let received = stream.recv_message(&mut buf).unwrap();
        assert_eq!(&buf[..received.len], b"send-to");
    });

    let socket = SctpSocket::bind("127.0.0.1:0").unwrap();
    let info = SctpSendInfo { stream: 2, ppid: 202, ..SctpSendInfo::default() };
    socket.send_to_with_info(b"send-to", addr, Some(&info)).unwrap();
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn recv_message_reports_shutdown_notifications() {
    let (listener, addr) = localhost_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let info = SctpSendInfo { stream: 3, ppid: 301, ..SctpSendInfo::default() };
        stream.send_with_info(b"hello", Some(&info)).unwrap();
        thread::sleep(Duration::from_millis(100));
        stream.shutdown(Shutdown::Write).unwrap();
    });

    let stream = SctpStream::connect(addr).unwrap();
    stream
        .subscribe_events(SctpEventMask {
            association: true,
            shutdown: true,
            data_io: true,
            ..SctpEventMask::default()
        })
        .unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut buf = [0u8; 1024];
    let received = stream.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"hello");

    let mut saw_shutdown = false;
    for _ in 0..8 {
        let received = stream.recv_message(&mut buf).unwrap();
        if matches!(received.notification, Some(SctpNotification::Shutdown { .. })) {
            saw_shutdown = true;
            break;
        }
    }
    assert!(saw_shutdown, "expected SCTP shutdown notification");
    server.join().unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn fragment_interleave_can_be_enabled_without_breaking_traffic() {
    let (listener, addr) = localhost_listener();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let info = SctpSendInfo { stream: 9, ppid: 901, ..SctpSendInfo::default() };
        stream.send_with_info(b"interleave-ok", Some(&info)).unwrap();
    });

    let stream = SctpStream::connect(addr).unwrap();
    stream.set_fragment_interleave(2).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let mut buf = [0u8; 1024];
    let received = stream.recv_message(&mut buf).unwrap();
    assert_eq!(&buf[..received.len], b"interleave-ok");
    server.join().unwrap();
}
