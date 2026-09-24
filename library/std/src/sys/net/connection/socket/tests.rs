use super::*;
use crate::collections::HashMap;
#[cfg(target_os = "linux")]
use crate::mem::size_of;
#[cfg(target_os = "linux")]
use crate::net::{SctpNotification, SocketAddr, SocketAddrV4};
#[cfg(target_os = "linux")]
use crate::vec;

#[test]
fn no_lookup_host_duplicates() {
    let mut addrs = HashMap::new();
    let lh = match lookup_host("localhost", 0) {
        Ok(lh) => lh,
        Err(e) => panic!("couldn't resolve `localhost`: {e}"),
    };
    for sa in lh {
        *addrs.entry(sa).or_insert(0) += 1;
    }
    assert_eq!(
        addrs.iter().filter(|&(_, &v)| v > 1).collect::<Vec<_>>(),
        vec![],
        "There should be no duplicate localhost entries"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn parse_assoc_change_notification() {
    let mut payload = vec![0u8; 20];
    payload[0..2].copy_from_slice(&SCTP_EVENT_ASSOCIATION.to_ne_bytes());
    payload[8..10].copy_from_slice(&1u16.to_ne_bytes());
    payload[10..12].copy_from_slice(&2u16.to_ne_bytes());
    payload[12..14].copy_from_slice(&3u16.to_ne_bytes());
    payload[14..16].copy_from_slice(&4u16.to_ne_bytes());
    payload[16..20].copy_from_slice(&55i32.to_ne_bytes());

    let notification = parse_sctp_notification(&payload).unwrap();
    assert_eq!(
        notification,
        SctpNotification::AssociationChange {
            assoc_id: 55,
            state: 1,
            error: 2,
            outbound_streams: 3,
            inbound_streams: 4,
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn parse_peer_addr_change_notification() {
    let addr = SocketAddrV4::new(crate::net::Ipv4Addr::LOCALHOST, 4242);
    let sockaddr = socket_addr_v4_to_c(&addr);
    let mut payload = vec![0u8; 8 + size_of::<c::sockaddr_storage>() + 12];
    payload[0..2].copy_from_slice(&SCTP_EVENT_ADDRESS.to_ne_bytes());
    // SAFETY: both regions are valid for the size of sockaddr_in and do not overlap.
    unsafe {
        crate::ptr::copy_nonoverlapping(
            (&raw const sockaddr).cast::<u8>(),
            payload[8..].as_mut_ptr(),
            size_of::<c::sockaddr_in>(),
        );
    }
    let offset = 8 + size_of::<c::sockaddr_storage>();
    payload[offset..offset + 4].copy_from_slice(&7u32.to_ne_bytes());
    payload[offset + 4..offset + 8].copy_from_slice(&8u32.to_ne_bytes());
    payload[offset + 8..offset + 12].copy_from_slice(&99i32.to_ne_bytes());

    let notification = parse_sctp_notification(&payload).unwrap();
    assert_eq!(
        notification,
        SctpNotification::PeerAddressChange {
            assoc_id: 99,
            address: SocketAddr::V4(addr),
            state: 7,
            error: 8,
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn parse_shutdown_and_partial_delivery_notifications() {
    let mut shutdown = vec![0u8; 12];
    shutdown[0..2].copy_from_slice(&SCTP_EVENT_SHUTDOWN.to_ne_bytes());
    shutdown[8..12].copy_from_slice(&123i32.to_ne_bytes());
    assert_eq!(
        parse_sctp_notification(&shutdown).unwrap(),
        SctpNotification::Shutdown { assoc_id: 123 }
    );

    let mut partial = vec![0u8; 16];
    partial[0..2].copy_from_slice(&SCTP_EVENT_PARTIAL_DELIVERY.to_ne_bytes());
    partial[8..12].copy_from_slice(&4u32.to_ne_bytes());
    partial[12..16].copy_from_slice(&321i32.to_ne_bytes());
    assert_eq!(
        parse_sctp_notification(&partial).unwrap(),
        SctpNotification::PartialDelivery { assoc_id: 321, indication: 4 }
    );
}

// #115325: on Apple, `send` rejects a length > `c_int::MAX` with `EINVAL`, so
// the clamp must not regress to the unbounded `wrlen_t::MAX`.
#[test]
fn max_send_len_within_platform_limit() {
    if cfg!(target_vendor = "apple") {
        assert_eq!(MAX_SEND_LEN, c_int::MAX as usize);
    } else {
        assert_eq!(MAX_SEND_LEN, <wrlen_t>::MAX as usize);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn parse_send_failed_event_uses_sndinfo_layout() {
    // struct sctp_send_failed_event: type(2) flags(2) length(4) error(4)
    // sctp_sndinfo{stream(2) flags(2) ppid(4) context(4) assoc_id(4)} assoc_id(4) data[]
    let data = b"payload";
    let mut payload = vec![0u8; 32 + data.len()];
    payload[0..2].copy_from_slice(&SCTP_EVENT_SEND_FAILURE.to_ne_bytes());
    payload[2..4].copy_from_slice(&0x0002u16.to_ne_bytes()); // SCTP_DATA_SENT
    let total = payload.len() as u32;
    payload[4..8].copy_from_slice(&total.to_ne_bytes());
    payload[8..12].copy_from_slice(&5u32.to_ne_bytes());
    payload[12..14].copy_from_slice(&3u16.to_ne_bytes());
    payload[14..16].copy_from_slice(&SCTP_UNORDERED.to_ne_bytes());
    payload[16..20].copy_from_slice(&0x1234u32.to_ne_bytes());
    payload[20..24].copy_from_slice(&77u32.to_ne_bytes());
    payload[24..28].copy_from_slice(&9i32.to_ne_bytes());
    payload[28..32].copy_from_slice(&9i32.to_ne_bytes());
    payload[32..].copy_from_slice(data);

    assert_eq!(
        parse_sctp_notification(&payload).unwrap(),
        SctpNotification::SendFailure {
            assoc_id: 9,
            flags: 0x0002,
            error: 5,
            info: Some(crate::net::SctpSendInfo {
                stream: 3,
                flags: SCTP_UNORDERED,
                ppid: 0x1234,
                context: 77,
                assoc_id: 9,
            }),
            data: data.to_vec(),
        }
    );

    // The legacy SCTP_SEND_FAILED (sctp_sndrcvinfo layout) is not subscribed
    // to and must surface as an unknown notification rather than be misread.
    let mut legacy = vec![0u8; 48];
    legacy[0..2].copy_from_slice(&0x8003u16.to_ne_bytes());
    legacy[4..8].copy_from_slice(&48u32.to_ne_bytes());
    legacy[44..48].copy_from_slice(&9i32.to_ne_bytes());
    assert!(matches!(
        parse_sctp_notification(&legacy).unwrap(),
        SctpNotification::Unknown { notification_type: 0x8003, .. }
    ));
}
