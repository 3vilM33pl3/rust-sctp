//! `Unsupported` implementations of the SCTP socket types for targets without a
//! native SCTP adapter. Used by every `sys::net::connection` backend except the
//! Linux and FreeBSD arms of `socket`, so `std::net::Sctp*` exists on all targets.

use crate::fmt;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::net::{Shutdown, SocketAddr, ToSocketAddrs};
use crate::time::Duration;

// Platform values behind the `std::net` SCTP constants and the association
// states reported by `SctpAssocStatus` / `SctpNotification::AssociationChange`.
// No native stack: the Linux numbering is used for the user-space fallback.
pub const SCTP_UNORDERED: u16 = 1;
pub const SCTP_PR_TTL: u16 = 0x0010;
pub const SCTP_PR_RTX: u16 = 0x0020;
pub const SCTP_PR_PRIORITY: u16 = 0x0030;
#[allow(dead_code)] // read by the UDP fallback, absent on some targets
pub const SCTP_STATE_CLOSED: i32 = 1;
#[allow(dead_code)] // read by the UDP fallback, absent on some targets
pub const SCTP_STATE_ESTABLISHED: i32 = 4;
#[allow(dead_code)] // read by the UDP fallback, absent on some targets
pub const SCTP_COMM_UP: u16 = 0;
#[allow(dead_code)] // read by the UDP fallback, absent on some targets
pub const SCTP_CANT_STR_ASSOC: u16 = 4;

/// Whether an error from a native SCTP socket call means the kernel has no
/// SCTP support at all (as opposed to a per-connection failure).
pub fn sctp_error_means_unsupported(err: &io::Error) -> bool {
    let _ = err;
    false
}

#[inline]
fn sctp_unsupported<T>() -> io::Result<T> {
    Err(io::const_error!(io::ErrorKind::Unsupported, "SCTP is not supported on this platform"))
}

pub struct SctpStream;

impl SctpStream {
    #[allow(dead_code)]
    pub fn connect<A: ToSocketAddrs>(_addr: A) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn connect_with_init_options<A: ToSocketAddrs>(
        _addr: A,
        _opts: crate::net::SctpInitOptions,
    ) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    #[allow(dead_code)]
    pub fn connect_multi(_addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn connect_multi_with_init_options(
        _addrs: &[SocketAddr],
        _opts: crate::net::SctpInitOptions,
    ) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn bind(_addr: SocketAddr) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn bind_multi(_addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn connect_bound<A: ToSocketAddrs>(&self, _addr: A) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn connect_bound_multi(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn duplicate(&self) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        sctp_unsupported()
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        sctp_unsupported()
    }

    pub fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        sctp_unsupported()
    }

    pub fn read_buf(&self, _buf: BorrowedCursor<'_, u8>) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn read_vectored(&self, _bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        sctp_unsupported()
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn write(&self, _buf: &[u8]) -> io::Result<usize> {
        sctp_unsupported()
    }

    pub fn write_vectored(&self, _bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        sctp_unsupported()
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        false
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        sctp_unsupported()
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sctp_unsupported()
    }

    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        sctp_unsupported()
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        sctp_unsupported()
    }

    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_init_options(&self, _opts: crate::net::SctpInitOptions) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn subscribe_events(&self, _mask: crate::net::SctpEventMask) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_rto_info(&self, _info: crate::net::SctpRtoInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_delayed_sack(&self, _info: crate::net::SctpDelayedSackInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_default_send_info(&self, _info: crate::net::SctpSendInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_default_prinfo(&self, _info: crate::net::SctpPrInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_recv_nxtinfo(&self, _on: bool) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_fragment_interleave(&self, _level: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_autoclose(&self, _seconds: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn bindx_add(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn bindx_remove(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_primary_addr(&self, _addr: SocketAddr) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_peer_primary_addr(&self, _addr: SocketAddr) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        sctp_unsupported()
    }

    pub fn assoc_status(&self, _assoc_id: i32) -> io::Result<crate::net::SctpAssocStatus> {
        sctp_unsupported()
    }

    pub fn peeloff(&self, _assoc_id: i32) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn enable_stream_reset(&self, _flags: u16) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn reset_streams(&self, _flags: u16, _streams: &[u16]) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn add_streams(&self, _inbound: u16, _outbound: u16) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_auth_chunks(&self, _chunks: &[u8]) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_auth_key(&self, _key: &crate::net::SctpAuthKey) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn activate_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn delete_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_stream_scheduler(&self, _scheduler: crate::net::SctpScheduler) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_stream_scheduler_value(&self, _stream: u16, _value: u16) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn send_with_info(
        &self,
        _buf: &[u8],
        _info: Option<&crate::net::SctpSendInfo>,
    ) -> io::Result<usize> {
        sctp_unsupported()
    }

    pub fn recv_with_info(
        &self,
        _buf: &mut [u8],
    ) -> io::Result<(usize, Option<crate::net::SctpRecvInfo>)> {
        sctp_unsupported()
    }

    pub fn recv_message(&self, _buf: &mut [u8]) -> io::Result<crate::net::SctpReceive> {
        sctp_unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        sctp_unsupported()
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        sctp_unsupported()
    }
}

impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpStream").finish_non_exhaustive()
    }
}

pub struct SctpListener;

impl SctpListener {
    pub fn bind<A: ToSocketAddrs>(_addr: A) -> io::Result<SctpListener> {
        sctp_unsupported()
    }

    pub fn bind_multi(_addrs: &[SocketAddr]) -> io::Result<SctpListener> {
        sctp_unsupported()
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sctp_unsupported()
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        sctp_unsupported()
    }

    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        sctp_unsupported()
    }

    pub fn duplicate(&self) -> io::Result<SctpListener> {
        sctp_unsupported()
    }

    pub fn set_init_options(&self, _opts: crate::net::SctpInitOptions) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn subscribe_events(&self, _mask: crate::net::SctpEventMask) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_rto_info(&self, _info: crate::net::SctpRtoInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_delayed_sack(&self, _info: crate::net::SctpDelayedSackInfo) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        sctp_unsupported()
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        sctp_unsupported()
    }
}

impl fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpListener").finish_non_exhaustive()
    }
}

pub struct SctpSocket;

impl SctpSocket {
    // Only the hybrid one-to-many endpoint calls this.
    #[allow(dead_code)]
    pub fn begin_association(&self, _peer: SocketAddr) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn bind<A: ToSocketAddrs>(_addr: A) -> io::Result<SctpSocket> {
        sctp_unsupported()
    }

    pub fn bind_multi(_addrs: &[SocketAddr]) -> io::Result<SctpSocket> {
        sctp_unsupported()
    }

    pub fn duplicate(&self) -> io::Result<SctpSocket> {
        sctp_unsupported()
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        sctp_unsupported()
    }

    pub fn set_init_options(&self, _opts: crate::net::SctpInitOptions) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn subscribe_events(&self, _mask: crate::net::SctpEventMask) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_autoclose(&self, _seconds: u32) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn send_to_with_info(
        &self,
        _buf: &[u8],
        _addr: SocketAddr,
        _info: Option<&crate::net::SctpSendInfo>,
    ) -> io::Result<usize> {
        sctp_unsupported()
    }

    pub fn recv_message(&self, _buf: &mut [u8]) -> io::Result<crate::net::SctpReceiveFrom> {
        sctp_unsupported()
    }

    pub fn recv_with_info(
        &self,
        _buf: &mut [u8],
    ) -> io::Result<(usize, Option<crate::net::SctpRecvInfo>, Option<SocketAddr>)> {
        sctp_unsupported()
    }

    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        sctp_unsupported()
    }

    pub fn assoc_status(&self, _assoc_id: i32) -> io::Result<crate::net::SctpAssocStatus> {
        sctp_unsupported()
    }

    pub fn peeloff(&self, _assoc_id: i32) -> io::Result<SctpStream> {
        sctp_unsupported()
    }

    pub fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        sctp_unsupported()
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        sctp_unsupported()
    }

    pub fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        sctp_unsupported()
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        sctp_unsupported()
    }
}

impl fmt::Debug for SctpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpSocket").finish_non_exhaustive()
    }
}
