use crate::io::ErrorKind;
use crate::net::{
    Ipv4Addr, Ipv6Addr, SctpEventMask, SctpListener, SctpMultiAddr, SctpNotification, SctpSendInfo,
    SctpStream, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6,
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

#[cfg(not(target_os = "linux"))]
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
