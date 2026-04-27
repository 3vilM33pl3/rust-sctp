use super::*;
use crate::cmp;
use crate::ffi::c_int;
use crate::io::{self, BorrowedCursor, ErrorKind, IoSlice, IoSliceMut};
use crate::mem::MaybeUninit;
use crate::net::{Shutdown, SocketAddr, ToSocketAddrs};
use crate::os::fd::FromRawFd;
use crate::time::Duration;
use crate::{fmt, mem, ptr};

unsafe extern "C" {
    fn sctp_peeloff(sd: c_int, assoc_id: u32) -> c_int;
}

const IPPROTO_SCTP_FREEBSD: c_int = c::IPPROTO_SCTP;
const SCTP_SOCKOPT_RTOINFO: c_int = 0x00000001;
const SCTP_SOCKOPT_INITMSG: c_int = 0x00000003;
const SCTP_SOCKOPT_NODELAY: c_int = 0x00000004;
const SCTP_SOCKOPT_AUTOCLOSE: c_int = 0x00000005;
const SCTP_SOCKOPT_SET_PEER_PRIMARY: c_int = 0x00000006;
const SCTP_SOCKOPT_PRIMARY_ADDR: c_int = 0x00000007;
const SCTP_SOCKOPT_MAXSEG: c_int = 0x0000000e;
const SCTP_SOCKOPT_DELAYED_SACK: c_int = 0x0000000f;
const SCTP_SOCKOPT_FRAGMENT_INTERLEAVE: c_int = 0x00000010;
const SCTP_SOCKOPT_AUTH_CHUNK: c_int = 0x00000012;
const SCTP_SOCKOPT_AUTH_KEY: c_int = 0x00000013;
const SCTP_SOCKOPT_AUTH_ACTIVE_KEY: c_int = 0x00000015;
const SCTP_SOCKOPT_AUTH_DELETE_KEY: c_int = 0x00000016;
const SCTP_SOCKOPT_MAX_BURST: c_int = 0x00000019;
const SCTP_SOCKOPT_EVENTS_COMPAT: c_int = 0x0000000c;
const SCTP_SOCKOPT_EVENT: c_int = 0x0000001e;
const SCTP_SOCKOPT_RECVRCVINFO: c_int = 0x0000001f;
const SCTP_SOCKOPT_RECVNXTINFO: c_int = 0x00000020;
const SCTP_SOCKOPT_DEFAULT_SNDINFO: c_int = 0x00000021;
const SCTP_SOCKOPT_DEFAULT_PRINFO: c_int = 0x00000022;
const SCTP_SOCKOPT_STATUS: c_int = 0x00000100;
const SCTP_SOCKOPT_ASSOC_ID_LIST: c_int = 0x00000105;
const SCTP_BINDX_ADD: c_int = 0x00008001;
const SCTP_BINDX_REMOVE: c_int = 0x00008002;
const SCTP_GET_PEER_ADDRS: c_int = 0x00008003;
const SCTP_GET_LOCAL_ADDRS: c_int = 0x00008004;
const SCTP_GET_LOCAL_ADDR_SIZE: c_int = 0x00008005;
const SCTP_GET_REMOTE_ADDR_SIZE: c_int = 0x00008006;
const SCTP_SOCKOPT_CONNECTX: c_int = 0x00008007;
const SCTP_SOCKOPT_ENABLE_STREAM_RESET: c_int = 0x00000900;
const SCTP_SOCKOPT_RESET_STREAMS: c_int = 0x00000901;
const SCTP_SOCKOPT_ADD_STREAMS: c_int = 0x00000903;
const SCTP_SOCKOPT_STREAM_SCHEDULER: c_int = 0x00001203;
const SCTP_SOCKOPT_STREAM_SCHEDULER_VALUE: c_int = 0x00001204;
const SCTP_CMSG_SNDINFO: c_int = 0x0004;
const SCTP_CMSG_RCVINFO: c_int = 0x0005;
const SCTP_CMSG_NXTINFO: c_int = 0x0006;
const SCTP_MSG_NOTIFICATION: c_int = 0x2000;

const SCTP_EVENT_DATA_IO: u16 = 0x0000;
const SCTP_EVENT_ASSOCIATION: u16 = 0x0001;
const SCTP_EVENT_ADDRESS: u16 = 0x0002;
const SCTP_EVENT_PEER_ERROR: u16 = 0x0003;
const SCTP_EVENT_SHUTDOWN: u16 = 0x0005;
const SCTP_EVENT_ADAPTATION: u16 = 0x0006;
const SCTP_EVENT_PARTIAL_DELIVERY: u16 = 0x0007;
const SCTP_EVENT_AUTHENTICATION: u16 = 0x0008;
const SCTP_EVENT_STREAM_RESET: u16 = 0x0009;
const SCTP_EVENT_SENDER_DRY: u16 = 0x000a;
const SCTP_EVENT_SEND_FAILURE: u16 = 0x000e;

#[repr(C)]
struct SctpInitMsgFreeBSD {
    num_ostreams: u16,
    max_instreams: u16,
    max_attempts: u16,
    max_init_timeout: u16,
}

#[repr(C)]
struct SctpSndInfoFreeBSD {
    stream: u16,
    flags: u16,
    ppid: u32,
    context: u32,
    assoc_id: i32,
}

#[repr(C)]
struct SctpRtoInfoFreeBSD {
    assoc_id: i32,
    initial: u32,
    max: u32,
    min: u32,
}

#[repr(C)]
struct SctpDelayedSackInfoFreeBSD {
    assoc_id: i32,
    delay: u32,
    frequency: u32,
}

#[repr(C)]
struct SctpPrInfoFreeBSD {
    policy: u16,
    _pad: u16,
    value: u32,
    assoc_id: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SctpRcvInfoFreeBSD {
    stream: u16,
    ssn: u16,
    flags: u16,
    _pad: u16,
    ppid: u32,
    tsn: u32,
    cumtsn: u32,
    context: u32,
    assoc_id: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SctpNxtInfoFreeBSD {
    stream: u16,
    flags: u16,
    ppid: u32,
    length: u32,
    assoc_id: i32,
}

#[repr(C)]
struct SctpEventFreeBSD {
    assoc_id: i32,
    event_type: u16,
    on: u8,
    _pad: u8,
}

#[repr(C)]
struct SctpEventSubscribeFreeBSD {
    data_io: u8,
    association: u8,
    address: u8,
    send_failure: u8,
    peer_error: u8,
    shutdown: u8,
    partial_delivery: u8,
    adaptation: u8,
    authentication: u8,
    sender_dry: u8,
    stream_reset: u8,
}

#[repr(C)]
struct SctpAssocIdListHeaderFreeBSD {
    count: u32,
}

#[repr(C)]
struct SctpAuthChunkFreeBSD {
    chunk: u8,
}

#[repr(C)]
struct SctpAuthKeyIdFreeBSD {
    assoc_id: i32,
    key_id: u16,
    _pad: u16,
}

#[repr(C)]
struct SctpAuthKeyHeaderFreeBSD {
    assoc_id: i32,
    key_id: u16,
    key_length: u16,
}

#[repr(C)]
struct SctpAssocValueFreeBSD {
    assoc_id: i32,
    value: u32,
}

#[repr(C)]
struct SctpStreamValueFreeBSD {
    assoc_id: i32,
    stream: u16,
    value: u16,
}

#[repr(C)]
struct SctpPrimaryAddrFreeBSD {
    addr: [u8; mem::size_of::<c::sockaddr_storage>()],
    assoc_id: i32,
    _padding: [u8; 4],
}

#[repr(C)]
struct SctpPeerAddrInfoFreeBSD {
    addr: [u8; mem::size_of::<c::sockaddr_storage>()],
    assoc_id: i32,
    state: i32,
    cwnd: u32,
    srtt: u32,
    rto: u32,
    mtu: u32,
}

#[repr(C)]
struct SctpStatusFreeBSD {
    assoc_id: i32,
    state: i32,
    rwnd: u32,
    unacked_data: u16,
    pending_data: u16,
    inbound_streams: u16,
    outbound_streams: u16,
    fragmentation_point: u32,
    primary: SctpPeerAddrInfoFreeBSD,
}

#[repr(C)]
struct SctpResetStreamsHeaderFreeBSD {
    assoc_id: i32,
    flags: u16,
    number_streams: u16,
}

#[repr(C)]
struct SctpAddStreamsFreeBSD {
    assoc_id: i32,
    inbound_streams: u16,
    outbound_streams: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct RawSockaddrInet4FreeBSD {
    len: u8,
    family: u8,
    port: u16,
    addr: c::in_addr,
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct RawSockaddrInet6FreeBSD {
    len: u8,
    family: u8,
    port: u16,
    flowinfo: u32,
    addr: c::in6_addr,
    scope_id: u32,
}

fn sctp_socket(family: c_int, ty: c_int) -> io::Result<Socket> {
    let fd = cvt(unsafe { c::socket(family, ty | c::SOCK_CLOEXEC, IPPROTO_SCTP_FREEBSD) })?;
    Ok(unsafe { Socket::from_raw_fd(fd) })
}

fn normalize_bound_addrs(addrs: &[SocketAddr], actual_port: u16) -> Vec<SocketAddr> {
    addrs
        .iter()
        .copied()
        .map(|mut a| {
            if a.port() == 0 {
                a.set_port(actual_port);
            }
            a
        })
        .collect()
}

fn read_u16_ne(payload: &[u8], offset: usize) -> Option<u16> {
    let bytes = payload.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

fn read_u32_ne(payload: &[u8], offset: usize) -> Option<u32> {
    let bytes = payload.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i32_ne(payload: &[u8], offset: usize) -> Option<i32> {
    let bytes = payload.get(offset..offset + 4)?;
    Some(i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn notification_payload_len(payload: &[u8]) -> usize {
    read_u32_ne(payload, 4)
        .map(|len| cmp::min(len as usize, payload.len()))
        .unwrap_or(payload.len())
}

fn read_send_info_freebsd(payload: &[u8], offset: usize) -> Option<crate::net::SctpSendInfo> {
    let bytes = payload.get(offset..offset + mem::size_of::<SctpSndInfoFreeBSD>())?;
    let raw = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<SctpSndInfoFreeBSD>()) };
    Some(crate::net::SctpSendInfo {
        stream: raw.stream,
        flags: raw.flags,
        ppid: raw.ppid,
        context: raw.context,
        assoc_id: raw.assoc_id,
    })
}

fn read_u16_list(payload: &[u8], offset: usize) -> Vec<u16> {
    payload
        .get(offset..notification_payload_len(payload))
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
        .collect()
}

fn sockaddr_span(data: &[u8]) -> io::Result<(usize, c_int, usize)> {
    if data.len() < 2 {
        return Err(io::const_error!(ErrorKind::InvalidData, "short SCTP sockaddr"));
    }
    let mut addr_len = data[0] as usize;
    let family = data[1] as c_int;
    let size = match family {
        c::AF_INET => mem::size_of::<RawSockaddrInet4FreeBSD>(),
        c::AF_INET6 => mem::size_of::<RawSockaddrInet6FreeBSD>(),
        _ => {
            return Err(io::const_error!(
                ErrorKind::InvalidData,
                "unsupported SCTP sockaddr family",
            ));
        }
    };
    if addr_len == 0 {
        addr_len = size;
    }
    Ok((addr_len, family, size))
}

fn parse_sockaddr_storage(bytes: &[u8]) -> io::Result<Option<SocketAddr>> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let (_, family, size) = sockaddr_span(bytes)?;
    if bytes.len() < size {
        return Err(io::const_error!(ErrorKind::InvalidData, "short SCTP sockaddr storage"));
    }
    match family {
        c::AF_INET => {
            let raw =
                unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawSockaddrInet4FreeBSD>()) };
            Ok(Some(SocketAddr::V4(crate::net::SocketAddrV4::new(
                ip_v4_addr_from_c(raw.addr),
                u16::from_be(raw.port),
            ))))
        }
        c::AF_INET6 => {
            let raw =
                unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawSockaddrInet6FreeBSD>()) };
            Ok(Some(SocketAddr::V6(crate::net::SocketAddrV6::new(
                ip_v6_addr_from_c(raw.addr),
                u16::from_be(raw.port),
                raw.flowinfo,
                raw.scope_id,
            ))))
        }
        _ => Ok(None),
    }
}

fn parse_raw_sockaddrs_sctp(mut bytes: &[u8]) -> io::Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    while bytes.len() >= 2 {
        let (addr_len, _, size) = sockaddr_span(bytes)?;
        if bytes.len() < size {
            return Err(io::const_error!(ErrorKind::InvalidData, "truncated SCTP sockaddr list"));
        }
        if let Some(addr) = parse_sockaddr_storage(&bytes[..size])? {
            addrs.push(addr);
        }
        let consume = cmp::max(addr_len, size);
        if consume > bytes.len() {
            return Err(io::const_error!(ErrorKind::InvalidData, "invalid SCTP sockaddr length"));
        }
        bytes = &bytes[consume..];
    }
    Ok(addrs)
}

fn marshal_raw_sockaddrs_sctp(addrs: &[SocketAddr]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(addrs.len() * mem::size_of::<RawSockaddrInet6FreeBSD>());
    for addr in addrs {
        match addr {
            SocketAddr::V4(addr) => {
                let raw = RawSockaddrInet4FreeBSD {
                    len: mem::size_of::<RawSockaddrInet4FreeBSD>() as u8,
                    family: c::AF_INET as u8,
                    port: addr.port().to_be(),
                    addr: ip_v4_addr_to_c(addr.ip()),
                    zero: [0; 8],
                };
                let bytes = unsafe {
                    crate::slice::from_raw_parts(
                        (&raw as *const RawSockaddrInet4FreeBSD).cast::<u8>(),
                        mem::size_of::<RawSockaddrInet4FreeBSD>(),
                    )
                };
                packed.extend_from_slice(bytes);
            }
            SocketAddr::V6(addr) => {
                let raw = RawSockaddrInet6FreeBSD {
                    len: mem::size_of::<RawSockaddrInet6FreeBSD>() as u8,
                    family: c::AF_INET6 as u8,
                    port: addr.port().to_be(),
                    flowinfo: addr.flowinfo(),
                    addr: ip_v6_addr_to_c(addr.ip()),
                    scope_id: addr.scope_id(),
                };
                let bytes = unsafe {
                    crate::slice::from_raw_parts(
                        (&raw as *const RawSockaddrInet6FreeBSD).cast::<u8>(),
                        mem::size_of::<RawSockaddrInet6FreeBSD>(),
                    )
                };
                packed.extend_from_slice(bytes);
            }
        }
    }
    packed
}

fn marshal_sockaddr_storage(
    addr: &SocketAddr,
) -> io::Result<[u8; mem::size_of::<c::sockaddr_storage>()]> {
    let mut storage = [0u8; mem::size_of::<c::sockaddr_storage>()];
    match addr {
        SocketAddr::V4(addr) => {
            let raw = RawSockaddrInet4FreeBSD {
                len: mem::size_of::<RawSockaddrInet4FreeBSD>() as u8,
                family: c::AF_INET as u8,
                port: addr.port().to_be(),
                addr: ip_v4_addr_to_c(addr.ip()),
                zero: [0; 8],
            };
            let bytes = unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const RawSockaddrInet4FreeBSD).cast::<u8>(),
                    mem::size_of::<RawSockaddrInet4FreeBSD>(),
                )
            };
            storage[..bytes.len()].copy_from_slice(bytes);
        }
        SocketAddr::V6(addr) => {
            let raw = RawSockaddrInet6FreeBSD {
                len: mem::size_of::<RawSockaddrInet6FreeBSD>() as u8,
                family: c::AF_INET6 as u8,
                port: addr.port().to_be(),
                flowinfo: addr.flowinfo(),
                addr: ip_v6_addr_to_c(addr.ip()),
                scope_id: addr.scope_id(),
            };
            let bytes = unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const RawSockaddrInet6FreeBSD).cast::<u8>(),
                    mem::size_of::<RawSockaddrInet6FreeBSD>(),
                )
            };
            storage[..bytes.len()].copy_from_slice(bytes);
        }
    }
    Ok(storage)
}

fn set_sockopt_bytes(
    sock: &Socket,
    level: c_int,
    option_name: c_int,
    bytes: &[u8],
) -> io::Result<()> {
    let ptr = if bytes.is_empty() { ptr::null() } else { bytes.as_ptr().cast::<c::c_void>() };
    cvt(unsafe {
        c::setsockopt(sock.as_raw(), level, option_name, ptr, bytes.len() as c::socklen_t)
    })?;
    Ok(())
}

fn get_sockopt_bytes(
    sock: &Socket,
    level: c_int,
    option_name: c_int,
    bytes: &mut [u8],
) -> io::Result<usize> {
    let mut len = bytes.len() as c::socklen_t;
    let ptr =
        if bytes.is_empty() { ptr::null_mut() } else { bytes.as_mut_ptr().cast::<c::c_void>() };
    cvt(unsafe { c::getsockopt(sock.as_raw(), level, option_name, ptr, &mut len) })?;
    Ok(len as usize)
}

fn bind_addrs_sctp(sock: &Socket, addrs: &[SocketAddr]) -> io::Result<()> {
    if addrs.is_empty() {
        return Ok(());
    }
    let packed = marshal_raw_sockaddrs_sctp(addrs);
    set_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_BINDX_ADD, &packed)
}

fn unbind_addrs_sctp(sock: &Socket, addrs: &[SocketAddr]) -> io::Result<()> {
    if addrs.is_empty() {
        return Ok(());
    }
    let packed = marshal_raw_sockaddrs_sctp(addrs);
    set_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_BINDX_REMOVE, &packed)
}

fn connect_addrs_sctp(sock: &Socket, addrs: &[SocketAddr]) -> io::Result<i32> {
    if addrs.is_empty() {
        return Err(io::const_error!(ErrorKind::InvalidInput, "empty SCTP address set"));
    }
    let packed = marshal_raw_sockaddrs_sctp(addrs);
    let mut buffer = vec![0u8; packed.len() + mem::size_of::<i32>()];
    buffer[..packed.len()].copy_from_slice(&packed);
    set_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_CONNECTX, &buffer)?;
    Ok(i32::from_ne_bytes(buffer[packed.len()..packed.len() + 4].try_into().unwrap()))
}

fn assoc_ids_sctp(sock: &Socket) -> io::Result<Vec<i32>> {
    let mut bytes = vec![0u8; 4096];
    let n = get_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_ASSOC_ID_LIST, &mut bytes)?;
    if n < mem::size_of::<SctpAssocIdListHeaderFreeBSD>() {
        return Err(io::const_error!(ErrorKind::InvalidData, "short SCTP assoc id list response",));
    }
    let hdr = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<SctpAssocIdListHeaderFreeBSD>()) };
    let mut ids = Vec::with_capacity(hdr.count as usize);
    let mut offset = mem::size_of::<SctpAssocIdListHeaderFreeBSD>();
    for _ in 0..hdr.count {
        if offset + 4 > n {
            return Err(io::const_error!(
                ErrorKind::InvalidData,
                "truncated SCTP assoc id list response",
            ));
        }
        ids.push(i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()));
        offset += 4;
    }
    Ok(ids)
}

fn resolve_assoc_id(sock: &Socket, current: i32) -> io::Result<i32> {
    if current != 0 {
        return Ok(current);
    }
    let ids = assoc_ids_sctp(sock)?;
    match ids.as_slice() {
        [id] => Ok(*id),
        [] => Err(io::const_error!(
            ErrorKind::WouldBlock,
            "SCTP association id is not available yet",
        )),
        _ => Err(io::const_error!(
            ErrorKind::InvalidInput,
            "multiple SCTP associations are present; specify an association id explicitly",
        )),
    }
}

fn assoc_status_sctp(sock: &Socket, assoc_id: i32) -> io::Result<crate::net::SctpAssocStatus> {
    let mut raw = SctpStatusFreeBSD {
        assoc_id,
        state: 0,
        rwnd: 0,
        unacked_data: 0,
        pending_data: 0,
        inbound_streams: 0,
        outbound_streams: 0,
        fragmentation_point: 0,
        primary: SctpPeerAddrInfoFreeBSD {
            addr: [0; mem::size_of::<c::sockaddr_storage>()],
            assoc_id: 0,
            state: 0,
            cwnd: 0,
            srtt: 0,
            rto: 0,
            mtu: 0,
        },
    };
    let buf = unsafe {
        crate::slice::from_raw_parts_mut(
            (&mut raw as *mut SctpStatusFreeBSD).cast::<u8>(),
            mem::size_of::<SctpStatusFreeBSD>(),
        )
    };
    get_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_STATUS, buf)?;
    Ok(crate::net::SctpAssocStatus {
        assoc_id: raw.assoc_id,
        state: raw.state,
        rwnd: raw.rwnd,
        unacked_data: raw.unacked_data,
        pending_data: raw.pending_data,
        inbound_streams: raw.inbound_streams,
        outbound_streams: raw.outbound_streams,
        fragmentation_point: raw.fragmentation_point,
        primary_addr: parse_sockaddr_storage(&raw.primary.addr).unwrap_or(None),
        primary_state: raw.primary.state,
        primary_cwnd: raw.primary.cwnd,
        primary_srtt: raw.primary.srtt,
        primary_rto: raw.primary.rto,
        primary_mtu: raw.primary.mtu,
    })
}

fn subscribe_events_sctp(sock: &Socket, mask: crate::net::SctpEventMask) -> io::Result<()> {
    let compat = SctpEventSubscribeFreeBSD {
        data_io: mask.data_io as u8,
        association: mask.association as u8,
        address: mask.address as u8,
        send_failure: mask.send_failure as u8,
        peer_error: mask.peer_error as u8,
        shutdown: mask.shutdown as u8,
        partial_delivery: mask.partial_delivery as u8,
        adaptation: mask.adaptation as u8,
        authentication: mask.authentication as u8,
        sender_dry: mask.sender_dry as u8,
        stream_reset: mask.stream_reset as u8,
    };
    set_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_EVENTS_COMPAT, unsafe {
        crate::slice::from_raw_parts(
            (&compat as *const SctpEventSubscribeFreeBSD).cast::<u8>(),
            mem::size_of::<SctpEventSubscribeFreeBSD>(),
        )
    })?;
    if mask.data_io {
        unsafe { setsockopt(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
    }
    let events = [
        (SCTP_EVENT_DATA_IO, mask.data_io),
        (SCTP_EVENT_ASSOCIATION, mask.association),
        (SCTP_EVENT_ADDRESS, mask.address),
        (SCTP_EVENT_SEND_FAILURE, mask.send_failure),
        (SCTP_EVENT_PEER_ERROR, mask.peer_error),
        (SCTP_EVENT_SHUTDOWN, mask.shutdown),
        (SCTP_EVENT_PARTIAL_DELIVERY, mask.partial_delivery),
        (SCTP_EVENT_ADAPTATION, mask.adaptation),
        (SCTP_EVENT_AUTHENTICATION, mask.authentication),
        (SCTP_EVENT_SENDER_DRY, mask.sender_dry),
        (SCTP_EVENT_STREAM_RESET, mask.stream_reset),
    ];
    for (event_type, on) in events {
        let evt = SctpEventFreeBSD { assoc_id: 0, event_type, on: on as u8, _pad: 0 };
        unsafe { setsockopt(sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_EVENT, evt) }?;
    }
    Ok(())
}

fn get_addrs_sctp(
    sock: &Socket,
    size_opt: c_int,
    addrs_opt: c_int,
    assoc_id: i32,
) -> io::Result<Vec<SocketAddr>> {
    let mut size_buf = assoc_id.to_ne_bytes();
    let n = get_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, size_opt, &mut size_buf)?;
    if n < 4 {
        return Err(io::const_error!(ErrorKind::InvalidData, "short SCTP getaddrs size response"));
    }
    let size = u32::from_ne_bytes(size_buf) as usize;
    if size < 4 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; size];
    buffer[..4].copy_from_slice(&assoc_id.to_ne_bytes());
    let n = get_sockopt_bytes(sock, IPPROTO_SCTP_FREEBSD, addrs_opt, &mut buffer)?;
    if n < 4 {
        return Err(io::const_error!(ErrorKind::InvalidData, "short SCTP getaddrs response"));
    }
    parse_raw_sockaddrs_sctp(&buffer[4..n])
}

fn local_addrs_sctp(sock: &Socket, assoc_id: i32) -> io::Result<Vec<SocketAddr>> {
    get_addrs_sctp(sock, SCTP_GET_LOCAL_ADDR_SIZE, SCTP_GET_LOCAL_ADDRS, assoc_id)
}

fn peer_addrs_sctp(sock: &Socket, assoc_id: i32) -> io::Result<Vec<SocketAddr>> {
    get_addrs_sctp(sock, SCTP_GET_REMOTE_ADDR_SIZE, SCTP_GET_PEER_ADDRS, assoc_id)
}

fn parse_sctp_notification(payload: &[u8]) -> Option<crate::net::SctpNotification> {
    let notification_type = read_u16_ne(payload, 0)?;
    match notification_type {
        SCTP_EVENT_ASSOCIATION => Some(crate::net::SctpNotification::AssociationChange {
            assoc_id: read_i32_ne(payload, 16)?,
            state: read_u16_ne(payload, 8)?,
            error: read_u16_ne(payload, 10)?,
            outbound_streams: read_u16_ne(payload, 12)?,
            inbound_streams: read_u16_ne(payload, 14)?,
        }),
        SCTP_EVENT_ADDRESS => {
            let address =
                parse_sockaddr_storage(payload.get(8..8 + mem::size_of::<c::sockaddr_storage>())?)
                    .ok()??;
            Some(crate::net::SctpNotification::PeerAddressChange {
                address,
                state: read_u32_ne(payload, 8 + mem::size_of::<c::sockaddr_storage>())?,
                error: read_u32_ne(payload, 12 + mem::size_of::<c::sockaddr_storage>())?,
                assoc_id: read_i32_ne(payload, 16 + mem::size_of::<c::sockaddr_storage>())?,
            })
        }
        SCTP_EVENT_SHUTDOWN => {
            Some(crate::net::SctpNotification::Shutdown { assoc_id: read_i32_ne(payload, 8)? })
        }
        SCTP_EVENT_PARTIAL_DELIVERY => Some(crate::net::SctpNotification::PartialDelivery {
            indication: read_u32_ne(payload, 8)?,
            assoc_id: read_i32_ne(payload, 12)?,
        }),
        SCTP_EVENT_SEND_FAILURE => {
            let end = notification_payload_len(payload);
            let data_offset = 12 + mem::size_of::<SctpSndInfoFreeBSD>() + 4;
            Some(crate::net::SctpNotification::SendFailure {
                flags: read_u16_ne(payload, 2)?,
                error: read_u32_ne(payload, 8)?,
                info: read_send_info_freebsd(payload, 12),
                assoc_id: read_i32_ne(payload, 12 + mem::size_of::<SctpSndInfoFreeBSD>())?,
                data: payload.get(data_offset..end).unwrap_or_default().to_vec(),
            })
        }
        SCTP_EVENT_PEER_ERROR => {
            let end = notification_payload_len(payload);
            Some(crate::net::SctpNotification::PeerError {
                error: read_u16_ne(payload, 8)?,
                assoc_id: read_i32_ne(payload, 12)?,
                data: payload.get(16..end).unwrap_or_default().to_vec(),
            })
        }
        SCTP_EVENT_ADAPTATION => Some(crate::net::SctpNotification::Adaptation {
            indication: read_u32_ne(payload, 8)?,
            assoc_id: read_i32_ne(payload, 12)?,
        }),
        SCTP_EVENT_AUTHENTICATION => Some(crate::net::SctpNotification::Authentication {
            key_id: read_u16_ne(payload, 8)?,
            alt_key_id: read_u16_ne(payload, 10)?,
            indication: read_u32_ne(payload, 12)?,
            assoc_id: read_i32_ne(payload, 16)?,
        }),
        SCTP_EVENT_SENDER_DRY => {
            Some(crate::net::SctpNotification::SenderDry { assoc_id: read_i32_ne(payload, 8)? })
        }
        SCTP_EVENT_STREAM_RESET => Some(crate::net::SctpNotification::StreamReset {
            flags: read_u16_ne(payload, 2)?,
            assoc_id: read_i32_ne(payload, 8)?,
            streams: read_u16_list(payload, 12),
        }),
        _ => Some(crate::net::SctpNotification::Unknown {
            notification_type,
            assoc_id: read_i32_ne(payload, 8),
            payload: payload.to_vec(),
        }),
    }
}

pub struct SctpStream {
    inner: Socket,
    local_addrs: Vec<SocketAddr>,
    peer_addrs: Vec<SocketAddr>,
    assoc_id: i32,
}

impl SctpStream {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<SctpStream> {
        init();
        each_addr(addr, |addr| {
            let sock = sctp_socket(addr_family(addr), c::SOCK_STREAM)?;
            unsafe {
                setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int)
            }?;
            sock.connect(addr)?;
            let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
            Ok(SctpStream {
                inner: sock,
                local_addrs: vec![local],
                peer_addrs: vec![*addr],
                assoc_id: 0,
            })
        })
    }

    pub fn connect_with_init_options<A: ToSocketAddrs>(
        addr: A,
        opts: crate::net::SctpInitOptions,
    ) -> io::Result<SctpStream> {
        init();
        each_addr(addr, |addr| {
            let sock = sctp_socket(addr_family(addr), c::SOCK_STREAM)?;
            let raw = SctpInitMsgFreeBSD {
                num_ostreams: opts.num_ostreams,
                max_instreams: opts.max_instreams,
                max_attempts: opts.max_attempts,
                max_init_timeout: opts.max_init_timeout,
            };
            unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_INITMSG, raw) }?;
            unsafe {
                setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int)
            }?;
            sock.connect(addr)?;
            let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
            Ok(SctpStream {
                inner: sock,
                local_addrs: vec![local],
                peer_addrs: vec![*addr],
                assoc_id: 0,
            })
        })
    }

    pub fn connect_multi(addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        init();
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let sock = sctp_socket(addr_family(&addrs[0]), c::SOCK_STREAM)?;
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let assoc_id = connect_addrs_sctp(&sock, addrs)?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpStream {
            inner: sock,
            local_addrs: vec![local],
            peer_addrs: addrs.to_vec(),
            assoc_id,
        })
    }

    pub fn connect_multi_with_init_options(
        addrs: &[SocketAddr],
        opts: crate::net::SctpInitOptions,
    ) -> io::Result<SctpStream> {
        init();
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let sock = sctp_socket(addr_family(&addrs[0]), c::SOCK_STREAM)?;
        let raw = SctpInitMsgFreeBSD {
            num_ostreams: opts.num_ostreams,
            max_instreams: opts.max_instreams,
            max_attempts: opts.max_attempts,
            max_init_timeout: opts.max_init_timeout,
        };
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_INITMSG, raw) }?;
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let assoc_id = connect_addrs_sctp(&sock, addrs)?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpStream {
            inner: sock,
            local_addrs: vec![local],
            peer_addrs: addrs.to_vec(),
            assoc_id,
        })
    }

    pub fn bind(addr: SocketAddr) -> io::Result<SctpStream> {
        init();
        let sock = sctp_socket(addr_family(&addr), c::SOCK_STREAM)?;
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let (raw, len) = socket_addr_to_c(&addr);
        cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpStream {
            inner: sock,
            local_addrs: vec![local],
            peer_addrs: Vec::new(),
            assoc_id: 0,
        })
    }

    pub fn bind_multi(addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        init();
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let sock = sctp_socket(addr_family(&addrs[0]), c::SOCK_STREAM)?;
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let (raw, len) = socket_addr_to_c(&addrs[0]);
        cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
        if addrs.len() > 1 {
            bind_addrs_sctp(&sock, &addrs[1..])?;
        }
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpStream {
            inner: sock,
            local_addrs: normalize_bound_addrs(addrs, local.port()),
            peer_addrs: Vec::new(),
            assoc_id: 0,
        })
    }

    pub fn connect_bound<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        each_addr(addr, |addr| self.inner.connect(addr))
    }

    pub fn connect_bound_multi(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        connect_addrs_sctp(&self.inner, addrs).map(|_| ())
    }

    pub fn duplicate(&self) -> io::Result<SctpStream> {
        self.inner.duplicate().map(|inner| SctpStream {
            inner,
            local_addrs: self.local_addrs.clone(),
            peer_addrs: self.peer_addrs.clone(),
            assoc_id: self.assoc_id,
        })
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_SNDTIMEO)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn read_buf(&self, buf: BorrowedCursor<'_>) -> io::Result<()> {
        self.inner.read_buf(buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.inner.is_read_vectored()
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send_with_flags(buf, MSG_NOSIGNAL)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        unsafe { sockname(|buf, len| c::getpeername(self.inner.as_raw(), buf, len)) }
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        unsafe { sockname(|buf, len| c::getsockname(self.inner.as_raw(), buf, len)) }
    }

    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match resolve_assoc_id(&self.inner, self.assoc_id) {
            Ok(id) => peer_addrs_sctp(&self.inner, id),
            Err(_) if !self.peer_addrs.is_empty() => Ok(self.peer_addrs.clone()),
            Err(_) => self.peer_addr().map(|addr| vec![addr]),
        }
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match resolve_assoc_id(&self.inner, self.assoc_id) {
            Ok(id) => {
                let addrs = local_addrs_sctp(&self.inner, id)?;
                if addrs.is_empty() && !self.local_addrs.is_empty() {
                    Ok(self.local_addrs.clone())
                } else {
                    Ok(addrs)
                }
            }
            Err(_) if !self.local_addrs.is_empty() => Ok(self.local_addrs.clone()),
            Err(_) => self.socket_addr().map(|addr| vec![addr]),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        unsafe {
            setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_NODELAY, nodelay as c_int)
        }
    }

    pub fn set_init_options(&self, opts: crate::net::SctpInitOptions) -> io::Result<()> {
        let raw = SctpInitMsgFreeBSD {
            num_ostreams: opts.num_ostreams,
            max_instreams: opts.max_instreams,
            max_attempts: opts.max_attempts,
            max_init_timeout: opts.max_init_timeout,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_INITMSG, raw) }
    }

    pub fn subscribe_events(&self, mask: crate::net::SctpEventMask) -> io::Result<()> {
        subscribe_events_sctp(&self.inner, mask)
    }

    pub fn set_rto_info(&self, info: crate::net::SctpRtoInfo) -> io::Result<()> {
        let raw = SctpRtoInfoFreeBSD {
            assoc_id: info.assoc_id,
            initial: info.initial,
            max: info.max,
            min: info.min,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RTOINFO, raw) }
    }

    pub fn set_delayed_sack(&self, info: crate::net::SctpDelayedSackInfo) -> io::Result<()> {
        let raw = SctpDelayedSackInfoFreeBSD {
            assoc_id: info.assoc_id,
            delay: info.delay,
            frequency: info.frequency,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_DELAYED_SACK, raw) }
    }

    pub fn set_default_send_info(&self, info: crate::net::SctpSendInfo) -> io::Result<()> {
        let raw = SctpSndInfoFreeBSD {
            stream: info.stream,
            flags: info.flags,
            ppid: info.ppid,
            context: info.context,
            assoc_id: info.assoc_id,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_DEFAULT_SNDINFO, raw) }
    }

    pub fn set_default_prinfo(&self, info: crate::net::SctpPrInfo) -> io::Result<()> {
        let raw = SctpPrInfoFreeBSD {
            policy: info.policy.0,
            _pad: 0,
            value: info.value,
            assoc_id: info.assoc_id,
        };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_DEFAULT_PRINFO, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpPrInfoFreeBSD).cast::<u8>(),
                mem::size_of::<SctpPrInfoFreeBSD>(),
            )
        })
    }

    pub fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        if on {
            unsafe {
                setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int)
            }?;
        }
        unsafe {
            setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVNXTINFO, on as c_int)
        }
    }

    pub fn set_fragment_interleave(&self, level: u32) -> io::Result<()> {
        unsafe {
            setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_FRAGMENT_INTERLEAVE, level)
        }
    }

    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_AUTOCLOSE, seconds) }
    }

    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: self.assoc_id, value };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_MAX_BURST, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAssocValueFreeBSD>(),
            )
        })
    }

    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: 0, value };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_MAXSEG, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAssocValueFreeBSD>(),
            )
        })
    }

    pub fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        bind_addrs_sctp(&self.inner, addrs)
    }

    pub fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        unbind_addrs_sctp(&self.inner, addrs)
    }

    pub fn set_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        let raw = SctpPrimaryAddrFreeBSD {
            addr: marshal_sockaddr_storage(&addr)?,
            assoc_id: resolve_assoc_id(&self.inner, self.assoc_id)?,
            _padding: [0; 4],
        };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_PRIMARY_ADDR, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpPrimaryAddrFreeBSD).cast::<u8>(),
                mem::size_of::<SctpPrimaryAddrFreeBSD>(),
            )
        })
    }

    pub fn set_peer_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        let raw = SctpPrimaryAddrFreeBSD {
            addr: marshal_sockaddr_storage(&addr)?,
            assoc_id: resolve_assoc_id(&self.inner, self.assoc_id)?,
            _padding: [0; 4],
        };
        set_sockopt_bytes(
            &self.inner,
            IPPROTO_SCTP_FREEBSD,
            SCTP_SOCKOPT_SET_PEER_PRIMARY,
            unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const SctpPrimaryAddrFreeBSD).cast::<u8>(),
                    mem::size_of::<SctpPrimaryAddrFreeBSD>(),
                )
            },
        )
    }

    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        assoc_ids_sctp(&self.inner)
    }

    pub fn assoc_status(&self, assoc_id: i32) -> io::Result<crate::net::SctpAssocStatus> {
        assoc_status_sctp(
            &self.inner,
            if assoc_id == 0 { resolve_assoc_id(&self.inner, self.assoc_id)? } else { assoc_id },
        )
    }

    pub fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStream> {
        let resolved =
            if assoc_id == 0 { resolve_assoc_id(&self.inner, self.assoc_id)? } else { assoc_id };
        let fd = cvt(unsafe { sctp_peeloff(self.inner.as_raw(), resolved as u32) })? as c_int;
        let sock = unsafe { Socket::from_raw_fd(fd) };
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        let peer = unsafe { sockname(|buf, len| c::getpeername(sock.as_raw(), buf, len)) }?;
        Ok(SctpStream {
            inner: sock,
            local_addrs: vec![local],
            peer_addrs: vec![peer],
            assoc_id: resolved,
        })
    }

    pub fn enable_stream_reset(&self, flags: u16) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: self.assoc_id, value: flags as u32 };
        set_sockopt_bytes(
            &self.inner,
            IPPROTO_SCTP_FREEBSD,
            SCTP_SOCKOPT_ENABLE_STREAM_RESET,
            unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                    mem::size_of::<SctpAssocValueFreeBSD>(),
                )
            },
        )
    }

    pub fn reset_streams(&self, flags: u16, streams: &[u16]) -> io::Result<()> {
        if streams.len() > u16::MAX as usize {
            return Err(io::const_error!(ErrorKind::InvalidInput, "too many SCTP streams"));
        }
        let assoc_id = resolve_assoc_id(&self.inner, self.assoc_id)?;
        let mut bytes =
            vec![0u8; mem::size_of::<SctpResetStreamsHeaderFreeBSD>() + streams.len() * 2];
        let hdr =
            SctpResetStreamsHeaderFreeBSD { assoc_id, flags, number_streams: streams.len() as u16 };
        bytes[..mem::size_of::<SctpResetStreamsHeaderFreeBSD>()].copy_from_slice(unsafe {
            crate::slice::from_raw_parts(
                (&hdr as *const SctpResetStreamsHeaderFreeBSD).cast::<u8>(),
                mem::size_of::<SctpResetStreamsHeaderFreeBSD>(),
            )
        });
        let mut offset = mem::size_of::<SctpResetStreamsHeaderFreeBSD>();
        for stream in streams {
            bytes[offset..offset + 2].copy_from_slice(&stream.to_ne_bytes());
            offset += 2;
        }
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RESET_STREAMS, &bytes)
    }

    pub fn add_streams(&self, inbound: u16, outbound: u16) -> io::Result<()> {
        let raw = SctpAddStreamsFreeBSD {
            assoc_id: resolve_assoc_id(&self.inner, self.assoc_id)?,
            inbound_streams: inbound,
            outbound_streams: outbound,
        };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_ADD_STREAMS, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAddStreamsFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAddStreamsFreeBSD>(),
            )
        })
    }

    pub fn set_auth_chunks(&self, chunks: &[u8]) -> io::Result<()> {
        for chunk in chunks {
            let raw = SctpAuthChunkFreeBSD { chunk: *chunk };
            set_sockopt_bytes(
                &self.inner,
                IPPROTO_SCTP_FREEBSD,
                SCTP_SOCKOPT_AUTH_CHUNK,
                unsafe {
                    crate::slice::from_raw_parts(
                        (&raw as *const SctpAuthChunkFreeBSD).cast::<u8>(),
                        mem::size_of::<SctpAuthChunkFreeBSD>(),
                    )
                },
            )?;
        }
        Ok(())
    }

    pub fn set_auth_key(&self, key: &crate::net::SctpAuthKey) -> io::Result<()> {
        if key.secret.len() > u16::MAX as usize {
            return Err(io::const_error!(ErrorKind::InvalidInput, "SCTP AUTH key is too large"));
        }
        let mut bytes = vec![0u8; mem::size_of::<SctpAuthKeyHeaderFreeBSD>() + key.secret.len()];
        let hdr = SctpAuthKeyHeaderFreeBSD {
            assoc_id: key.assoc_id,
            key_id: key.key_id,
            key_length: key.secret.len() as u16,
        };
        bytes[..mem::size_of::<SctpAuthKeyHeaderFreeBSD>()].copy_from_slice(unsafe {
            crate::slice::from_raw_parts(
                (&hdr as *const SctpAuthKeyHeaderFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAuthKeyHeaderFreeBSD>(),
            )
        });
        bytes[mem::size_of::<SctpAuthKeyHeaderFreeBSD>()..].copy_from_slice(&key.secret);
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_AUTH_KEY, &bytes)
    }

    pub fn activate_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        let raw = SctpAuthKeyIdFreeBSD { assoc_id, key_id, _pad: 0 };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_AUTH_ACTIVE_KEY, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAuthKeyIdFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAuthKeyIdFreeBSD>(),
            )
        })
    }

    pub fn delete_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        let raw = SctpAuthKeyIdFreeBSD { assoc_id, key_id, _pad: 0 };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_AUTH_DELETE_KEY, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAuthKeyIdFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAuthKeyIdFreeBSD>(),
            )
        })
    }

    pub fn set_stream_scheduler(&self, scheduler: crate::net::SctpScheduler) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: self.assoc_id, value: scheduler.0 as u32 };
        set_sockopt_bytes(
            &self.inner,
            IPPROTO_SCTP_FREEBSD,
            SCTP_SOCKOPT_STREAM_SCHEDULER,
            unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                    mem::size_of::<SctpAssocValueFreeBSD>(),
                )
            },
        )
    }

    pub fn set_stream_scheduler_value(&self, stream: u16, value: u16) -> io::Result<()> {
        let raw = SctpStreamValueFreeBSD { assoc_id: self.assoc_id, stream, value };
        set_sockopt_bytes(
            &self.inner,
            IPPROTO_SCTP_FREEBSD,
            SCTP_SOCKOPT_STREAM_SCHEDULER_VALUE,
            unsafe {
                crate::slice::from_raw_parts(
                    (&raw as *const SctpStreamValueFreeBSD).cast::<u8>(),
                    mem::size_of::<SctpStreamValueFreeBSD>(),
                )
            },
        )
    }

    pub fn send_with_info(
        &self,
        buf: &[u8],
        info: Option<&crate::net::SctpSendInfo>,
    ) -> io::Result<usize> {
        use libc::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE};

        let mut iov =
            [libc::iovec { iov_base: buf.as_ptr().cast_mut().cast(), iov_len: buf.len() }];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = (&raw mut iov) as *mut _;
        msg.msg_iovlen = 1;

        #[repr(C)]
        union Cmsg {
            buf: [u8; unsafe { CMSG_SPACE(mem::size_of::<SctpSndInfoFreeBSD>() as u32) as usize }],
            _align: libc::cmsghdr,
        }
        let mut cmsg: Cmsg = unsafe { mem::zeroed() };
        if let Some(info) = info {
            msg.msg_control = (&raw mut cmsg.buf).cast();
            msg.msg_controllen = mem::size_of_val(unsafe { &cmsg.buf }) as _;
            unsafe {
                let hdr = CMSG_FIRSTHDR((&raw mut msg) as *mut _);
                if !hdr.is_null() {
                    (*hdr).cmsg_level = IPPROTO_SCTP_FREEBSD;
                    (*hdr).cmsg_type = SCTP_CMSG_SNDINFO;
                    (*hdr).cmsg_len = CMSG_LEN(mem::size_of::<SctpSndInfoFreeBSD>() as u32) as _;
                    let data = CMSG_DATA(hdr).cast::<SctpSndInfoFreeBSD>();
                    *data = SctpSndInfoFreeBSD {
                        stream: info.stream,
                        flags: info.flags,
                        ppid: info.ppid,
                        context: info.context,
                        assoc_id: info.assoc_id,
                    };
                }
            }
        }
        self.inner.send_msg(&mut msg)
    }

    fn recv_message_inner(
        &self,
        buf: &mut [u8],
        want_peer_addr: bool,
    ) -> io::Result<(crate::net::SctpReceive, Option<SocketAddr>)> {
        use libc::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE};

        let mut iov = [libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() }];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = (&raw mut iov) as *mut _;
        msg.msg_iovlen = 1;
        let mut peer_storage = MaybeUninit::<c::sockaddr_storage>::zeroed();
        if want_peer_addr {
            msg.msg_name = peer_storage.as_mut_ptr().cast();
            msg.msg_namelen = mem::size_of::<c::sockaddr_storage>() as c::socklen_t;
        }

        #[repr(C)]
        union Cmsg {
            buf: [u8; unsafe {
                (CMSG_SPACE(mem::size_of::<SctpRcvInfoFreeBSD>() as u32) as usize)
                    + (CMSG_SPACE(mem::size_of::<SctpNxtInfoFreeBSD>() as u32) as usize)
            }],
            _align: libc::cmsghdr,
        }
        let mut cmsg: Cmsg = unsafe { mem::zeroed() };
        msg.msg_control = (&raw mut cmsg.buf).cast();
        msg.msg_controllen = mem::size_of_val(unsafe { &cmsg.buf }) as _;

        let n = self.inner.recv_msg(&mut msg)?;
        let mut recv_info = None;
        let mut next_info = None;
        unsafe {
            let mut hdr = CMSG_FIRSTHDR((&raw mut msg) as *mut _);
            while !hdr.is_null() {
                if (*hdr).cmsg_level == IPPROTO_SCTP_FREEBSD {
                    if (*hdr).cmsg_type == SCTP_CMSG_RCVINFO
                        && ((*hdr).cmsg_len as usize)
                            >= CMSG_LEN(mem::size_of::<SctpRcvInfoFreeBSD>() as u32) as usize
                    {
                        let data = CMSG_DATA(hdr).cast::<SctpRcvInfoFreeBSD>();
                        let d = *data;
                        recv_info = Some(crate::net::SctpRecvInfo {
                            stream: d.stream,
                            ssn: d.ssn,
                            flags: d.flags,
                            ppid: d.ppid,
                            tsn: d.tsn,
                            cumtsn: d.cumtsn,
                            context: d.context,
                            assoc_id: d.assoc_id,
                            next: None,
                        });
                    } else if (*hdr).cmsg_type == SCTP_CMSG_NXTINFO
                        && ((*hdr).cmsg_len as usize)
                            >= CMSG_LEN(mem::size_of::<SctpNxtInfoFreeBSD>() as u32) as usize
                    {
                        let data = CMSG_DATA(hdr).cast::<SctpNxtInfoFreeBSD>();
                        let d = *data;
                        next_info = Some(crate::net::SctpNextInfo {
                            stream: d.stream,
                            flags: d.flags,
                            ppid: d.ppid,
                            length: d.length,
                            assoc_id: d.assoc_id,
                        });
                    }
                }
                hdr = CMSG_NXTHDR((&raw mut msg) as *mut _, hdr);
            }
        }
        if let Some(info) = recv_info.as_mut() {
            info.next = next_info;
        }
        let notification = if (msg.msg_flags & SCTP_MSG_NOTIFICATION) != 0 {
            parse_sctp_notification(&buf[..n])
        } else {
            None
        };
        let flags = crate::net::SctpReceiveFlags {
            end_of_record: (msg.msg_flags & libc::MSG_EOR) != 0,
            truncated: (msg.msg_flags & libc::MSG_TRUNC) != 0,
            control_truncated: (msg.msg_flags & libc::MSG_CTRUNC) != 0,
        };
        let peer_addr = if want_peer_addr && msg.msg_namelen > 0 {
            unsafe { socket_addr_from_c(peer_storage.as_ptr(), msg.msg_namelen as usize).ok() }
        } else {
            None
        };
        Ok((crate::net::SctpReceive { len: n, info: recv_info, notification, flags }, peer_addr))
    }

    pub fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<crate::net::SctpRecvInfo>)> {
        let (received, _) = self.recv_message_inner(buf, false)?;
        Ok((received.len, received.info))
    }

    pub fn recv_message(&self, buf: &mut [u8]) -> io::Result<crate::net::SctpReceive> {
        self.recv_message_inner(buf, false).map(|(received, _)| received)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl AsInner<Socket> for SctpStream {
    #[inline]
    fn as_inner(&self) -> &Socket {
        &self.inner
    }
}

impl FromInner<Socket> for SctpStream {
    fn from_inner(socket: Socket) -> SctpStream {
        SctpStream { inner: socket, local_addrs: Vec::new(), peer_addrs: Vec::new(), assoc_id: 0 }
    }
}

impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("SctpStream");
        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }
        if let Ok(peer) = self.peer_addr() {
            res.field("peer", &peer);
        }
        res.field("fd", &self.inner.as_raw()).finish()
    }
}

pub struct SctpListener {
    inner: Socket,
    local_addrs: Vec<SocketAddr>,
}

impl SctpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpListener> {
        init();
        each_addr(addr, |addr| {
            let sock = sctp_socket(addr_family(addr), c::SOCK_STREAM)?;
            unsafe { setsockopt(&sock, c::SOL_SOCKET, c::SO_REUSEADDR, 1 as c_int)? };
            unsafe {
                setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int)
            }?;
            let (raw, len) = socket_addr_to_c(addr);
            cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
            cvt(unsafe { c::listen(sock.as_raw(), 128) })?;
            let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
            Ok(SctpListener { inner: sock, local_addrs: vec![local] })
        })
    }

    pub fn bind_multi(addrs: &[SocketAddr]) -> io::Result<SctpListener> {
        init();
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let sock = sctp_socket(addr_family(&addrs[0]), c::SOCK_STREAM)?;
        unsafe { setsockopt(&sock, c::SOL_SOCKET, c::SO_REUSEADDR, 1 as c_int)? };
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let (raw, len) = socket_addr_to_c(&addrs[0]);
        cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
        if addrs.len() > 1 {
            bind_addrs_sctp(&sock, &addrs[1..])?;
        }
        cvt(unsafe { c::listen(sock.as_raw(), 128) })?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpListener { inner: sock, local_addrs: normalize_bound_addrs(addrs, local.port()) })
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        unsafe { sockname(|buf, len| c::getsockname(self.inner.as_raw(), buf, len)) }
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        if self.local_addrs.is_empty() {
            self.socket_addr().map(|addr| vec![addr])
        } else {
            Ok(self.local_addrs.clone())
        }
    }

    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        let mut storage = MaybeUninit::<c::sockaddr_storage>::uninit();
        let mut len = mem::size_of::<c::sockaddr_storage>() as c::socklen_t;
        let sock = self.inner.accept(storage.as_mut_ptr() as *mut _, &mut len)?;
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let addr = unsafe { socket_addr_from_c(storage.as_ptr(), len as usize)? };
        Ok((
            SctpStream {
                inner: sock,
                local_addrs: self.local_addrs.clone(),
                peer_addrs: vec![addr],
                assoc_id: 0,
            },
            addr,
        ))
    }

    pub fn duplicate(&self) -> io::Result<SctpListener> {
        self.inner
            .duplicate()
            .map(|inner| SctpListener { inner, local_addrs: self.local_addrs.clone() })
    }

    pub fn set_init_options(&self, opts: crate::net::SctpInitOptions) -> io::Result<()> {
        let raw = SctpInitMsgFreeBSD {
            num_ostreams: opts.num_ostreams,
            max_instreams: opts.max_instreams,
            max_attempts: opts.max_attempts,
            max_init_timeout: opts.max_init_timeout,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_INITMSG, raw) }
    }

    pub fn subscribe_events(&self, mask: crate::net::SctpEventMask) -> io::Result<()> {
        subscribe_events_sctp(&self.inner, mask)
    }

    pub fn set_rto_info(&self, info: crate::net::SctpRtoInfo) -> io::Result<()> {
        let raw = SctpRtoInfoFreeBSD {
            assoc_id: info.assoc_id,
            initial: info.initial,
            max: info.max,
            min: info.min,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RTOINFO, raw) }
    }

    pub fn set_delayed_sack(&self, info: crate::net::SctpDelayedSackInfo) -> io::Result<()> {
        let raw = SctpDelayedSackInfoFreeBSD {
            assoc_id: info.assoc_id,
            delay: info.delay,
            frequency: info.frequency,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_DELAYED_SACK, raw) }
    }

    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: 0, value };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_MAX_BURST, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAssocValueFreeBSD>(),
            )
        })
    }

    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        let raw = SctpAssocValueFreeBSD { assoc_id: 0, value };
        set_sockopt_bytes(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_MAXSEG, unsafe {
            crate::slice::from_raw_parts(
                (&raw as *const SctpAssocValueFreeBSD).cast::<u8>(),
                mem::size_of::<SctpAssocValueFreeBSD>(),
            )
        })
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl FromInner<Socket> for SctpListener {
    fn from_inner(socket: Socket) -> SctpListener {
        SctpListener { inner: socket, local_addrs: Vec::new() }
    }
}

impl fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("SctpListener");
        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }
        res.field("fd", &self.inner.as_raw()).finish()
    }
}

pub struct SctpSocket {
    inner: Socket,
    local_addrs: Vec<SocketAddr>,
}

impl SctpSocket {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpSocket> {
        init();
        each_addr(addr, |addr| {
            let sock = sctp_socket(addr_family(addr), c::SOCK_SEQPACKET)?;
            unsafe { setsockopt(&sock, c::SOL_SOCKET, c::SO_REUSEADDR, 1 as c_int)? };
            unsafe {
                setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int)
            }?;
            let (raw, len) = socket_addr_to_c(addr);
            cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
            cvt(unsafe { c::listen(sock.as_raw(), 128) })?;
            let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
            Ok(SctpSocket { inner: sock, local_addrs: vec![local] })
        })
    }

    pub fn bind_multi(addrs: &[SocketAddr]) -> io::Result<SctpSocket> {
        init();
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let sock = sctp_socket(addr_family(&addrs[0]), c::SOCK_SEQPACKET)?;
        unsafe { setsockopt(&sock, c::SOL_SOCKET, c::SO_REUSEADDR, 1 as c_int)? };
        unsafe { setsockopt(&sock, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_RECVRCVINFO, 1 as c_int) }?;
        let (raw, len) = socket_addr_to_c(&addrs[0]);
        cvt(unsafe { c::bind(sock.as_raw(), raw.as_ptr(), len as _) })?;
        if addrs.len() > 1 {
            bind_addrs_sctp(&sock, &addrs[1..])?;
        }
        cvt(unsafe { c::listen(sock.as_raw(), 128) })?;
        let local = unsafe { sockname(|buf, len| c::getsockname(sock.as_raw(), buf, len)) }?;
        Ok(SctpSocket { inner: sock, local_addrs: normalize_bound_addrs(addrs, local.port()) })
    }

    pub fn duplicate(&self) -> io::Result<SctpSocket> {
        self.inner
            .duplicate()
            .map(|inner| SctpSocket { inner, local_addrs: self.local_addrs.clone() })
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        if self.local_addrs.is_empty() {
            unsafe { sockname(|buf, len| c::getsockname(self.inner.as_raw(), buf, len)) }
                .map(|addr| vec![addr])
        } else {
            Ok(self.local_addrs.clone())
        }
    }

    pub fn set_init_options(&self, opts: crate::net::SctpInitOptions) -> io::Result<()> {
        let raw = SctpInitMsgFreeBSD {
            num_ostreams: opts.num_ostreams,
            max_instreams: opts.max_instreams,
            max_attempts: opts.max_attempts,
            max_init_timeout: opts.max_init_timeout,
        };
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_INITMSG, raw) }
    }

    pub fn subscribe_events(&self, mask: crate::net::SctpEventMask) -> io::Result<()> {
        subscribe_events_sctp(&self.inner, mask)
    }

    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        unsafe { setsockopt(&self.inner, IPPROTO_SCTP_FREEBSD, SCTP_SOCKOPT_AUTOCLOSE, seconds) }
    }

    pub fn send_to_with_info(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        info: Option<&crate::net::SctpSendInfo>,
    ) -> io::Result<usize> {
        use libc::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE};

        let mut iov =
            [libc::iovec { iov_base: buf.as_ptr().cast_mut().cast(), iov_len: buf.len() }];
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = (&raw mut iov) as *mut _;
        msg.msg_iovlen = 1;

        let (raw_addr, addr_len) = socket_addr_to_c(&addr);
        msg.msg_name = (&raw const raw_addr).cast_mut().cast();
        msg.msg_namelen = addr_len;

        #[repr(C)]
        union Cmsg {
            buf: [u8; unsafe { CMSG_SPACE(mem::size_of::<SctpSndInfoFreeBSD>() as u32) as usize }],
            _align: libc::cmsghdr,
        }
        let mut cmsg: Cmsg = unsafe { mem::zeroed() };
        if let Some(info) = info {
            msg.msg_control = (&raw mut cmsg.buf).cast();
            msg.msg_controllen = mem::size_of_val(unsafe { &cmsg.buf }) as _;
            unsafe {
                let hdr = CMSG_FIRSTHDR((&raw mut msg) as *mut _);
                if !hdr.is_null() {
                    (*hdr).cmsg_level = IPPROTO_SCTP_FREEBSD;
                    (*hdr).cmsg_type = SCTP_CMSG_SNDINFO;
                    (*hdr).cmsg_len = CMSG_LEN(mem::size_of::<SctpSndInfoFreeBSD>() as u32) as _;
                    let data = CMSG_DATA(hdr).cast::<SctpSndInfoFreeBSD>();
                    *data = SctpSndInfoFreeBSD {
                        stream: info.stream,
                        flags: info.flags,
                        ppid: info.ppid,
                        context: info.context,
                        assoc_id: info.assoc_id,
                    };
                }
            }
        }
        self.inner.send_msg(&mut msg)
    }

    pub fn recv_message(&self, buf: &mut [u8]) -> io::Result<crate::net::SctpReceiveFrom> {
        let stream = SctpStream {
            inner: self.inner.duplicate()?,
            local_addrs: self.local_addrs.clone(),
            peer_addrs: Vec::new(),
            assoc_id: 0,
        };
        let (receive, peer_addr) = stream.recv_message_inner(buf, true)?;
        Ok(crate::net::SctpReceiveFrom { receive, peer_addr })
    }

    pub fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<crate::net::SctpRecvInfo>, Option<SocketAddr>)> {
        let received = self.recv_message(buf)?;
        Ok((received.receive.len, received.receive.info, received.peer_addr))
    }

    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        assoc_ids_sctp(&self.inner)
    }

    pub fn assoc_status(&self, assoc_id: i32) -> io::Result<crate::net::SctpAssocStatus> {
        assoc_status_sctp(&self.inner, assoc_id)
    }

    pub fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStream> {
        let stream = SctpStream {
            inner: self.inner.duplicate()?,
            local_addrs: self.local_addrs.clone(),
            peer_addrs: Vec::new(),
            assoc_id,
        };
        stream.peeloff(assoc_id)
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, c::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(c::SO_SNDTIMEO)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl fmt::Debug for SctpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("SctpSocket");
        if let Ok(addrs) = self.local_addrs() {
            res.field("local_addrs", &addrs);
        }
        res.field("fd", &self.inner.as_raw()).finish()
    }
}
