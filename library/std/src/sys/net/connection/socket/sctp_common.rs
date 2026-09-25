//! Helpers shared by the Linux and FreeBSD native SCTP backends: little
//! byte readers for kernel-filled buffers, bound-address normalisation and
//! the "kernel has no SCTP" errno probe. Everything platform-specific stays
//! in the owning backend.

use super::*;

pub(super) fn read_u16_ne(payload: &[u8], offset: usize) -> Option<u16> {
    let bytes = payload.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u32_ne(payload: &[u8], offset: usize) -> Option<u32> {
    let bytes = payload.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn read_i32_ne(payload: &[u8], offset: usize) -> Option<i32> {
    let bytes = payload.get(offset..offset + 4)?;
    Some(i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn notification_payload_len(payload: &[u8]) -> usize {
    read_u32_ne(payload, 4)
        .map(|len| cmp::min(len as usize, payload.len()))
        .unwrap_or(payload.len())
}

pub(super) fn read_u16_list(payload: &[u8], offset: usize) -> Vec<u16> {
    payload
        .get(offset..notification_payload_len(payload))
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
        .collect()
}

pub(super) fn normalize_bound_addrs(addrs: &[SocketAddr], actual_port: u16) -> Vec<SocketAddr> {
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

/// Whether an error from a native SCTP socket call means the kernel has no
/// SCTP support at all (as opposed to a per-connection failure).
pub fn sctp_error_means_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(c::EPROTONOSUPPORT | c::EAFNOSUPPORT | c::ESOCKTNOSUPPORT | c::ENOPROTOOPT)
    )
}
