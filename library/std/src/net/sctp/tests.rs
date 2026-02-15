use crate::io::ErrorKind;
#[cfg(not(target_os = "linux"))]
use crate::net::SctpListener;
use crate::net::{Ipv4Addr, Ipv6Addr, SctpMultiAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
