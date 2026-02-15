#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(all(
    test,
    not(any(
        target_os = "emscripten",
        all(target_os = "wasi", target_env = "p1"),
        target_os = "xous",
        target_os = "trusty",
    ))
))]
mod tests;

use crate::fmt;
use crate::io::prelude::*;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::iter::FusedIterator;
use crate::net::{SocketAddr, ToSocketAddrs};
use crate::sys::{AsInner, FromInner, IntoInner, net as net_imp};
use crate::time::Duration;

/// SCTP association setup options.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpInitOptions {
    /// Requested number of outbound streams for a new association.
    pub num_ostreams: u16,
    /// Maximum number of inbound streams accepted for a new association.
    pub max_instreams: u16,
    /// Maximum number of `INIT` retransmission attempts.
    pub max_attempts: u16,
    /// Maximum `INIT` retransmission timeout in milliseconds.
    pub max_init_timeout: u16,
}

/// Per-message SCTP send metadata.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpSendInfo {
    /// Stream identifier used for this user message.
    pub stream: u16,
    /// Per-message send flags (`SCTP_*` send flags from the platform API).
    pub flags: u16,
    /// Upper-layer payload protocol identifier.
    pub ppid: u32,
    /// Application-defined message context value.
    pub context: u32,
    /// Target association identifier (0 for current association).
    pub assoc_id: i32,
}

/// Per-message SCTP receive metadata.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpRecvInfo {
    /// Stream identifier on which the message was received.
    pub stream: u16,
    /// Stream sequence number.
    pub ssn: u16,
    /// Per-message receive flags (`SCTP_*` receive flags from the platform API).
    pub flags: u16,
    /// Upper-layer payload protocol identifier.
    pub ppid: u32,
    /// Transmission sequence number.
    pub tsn: u32,
    /// Cumulative transmission sequence number acknowledged by the peer.
    pub cumtsn: u32,
    /// Application-defined message context value.
    pub context: u32,
    /// Association identifier for the received message.
    pub assoc_id: i32,
}

/// SCTP event subscription mask.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpEventMask {
    /// Subscribe to per-message data I/O notifications.
    pub data_io: bool,
    /// Subscribe to association state notifications.
    pub association: bool,
    /// Subscribe to peer/local address change notifications.
    pub address: bool,
    /// Subscribe to send-failure notifications.
    pub send_failure: bool,
    /// Subscribe to peer-error notifications.
    pub peer_error: bool,
    /// Subscribe to shutdown notifications.
    pub shutdown: bool,
    /// Subscribe to partial-delivery notifications.
    pub partial_delivery: bool,
    /// Subscribe to adaptation-layer indications.
    pub adaptation: bool,
    /// Subscribe to authentication notifications.
    pub authentication: bool,
    /// Subscribe to sender-dry notifications.
    pub sender_dry: bool,
    /// Subscribe to stream-reset notifications.
    pub stream_reset: bool,
}

/// A validated SCTP multi-address endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpMultiAddr {
    addrs: Vec<SocketAddr>,
}

#[unstable(feature = "sctp", issue = "none")]
impl SctpMultiAddr {
    /// Builds a validated SCTP multi-address endpoint.
    ///
    /// The input must be non-empty, all addresses must be from the same address family,
    /// and all addresses must use the same port.
    pub fn new(addrs: Vec<SocketAddr>) -> io::Result<Self> {
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty SCTP address set"));
        }
        let family = addrs[0].is_ipv4();
        let port = addrs[0].port();
        for a in &addrs[1..] {
            if a.is_ipv4() != family {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mixed IPv4/IPv6 SCTP address families",
                ));
            }
            if a.port() != port {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "all SCTP addresses must use the same port",
                ));
            }
        }
        Ok(Self { addrs })
    }

    /// Returns the addresses in this endpoint.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

/// An SCTP stream between a local and remote endpoint.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpStream(net_imp::SctpStream);

/// An SCTP listener socket.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpListener(net_imp::SctpListener);

/// Iterator over incoming SCTP streams.
#[must_use = "iterators are lazy and do nothing unless consumed"]
#[derive(Debug)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpIncoming<'a> {
    listener: &'a SctpListener,
}

#[unstable(feature = "sctp", issue = "none")]
impl SctpStream {
    /// Connects to a single remote SCTP endpoint.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<SctpStream> {
        net_imp::SctpStream::connect(addr).map(SctpStream)
    }

    /// Connects to a remote SCTP endpoint represented by multiple peer addresses.
    pub fn connect_multi(remote: &SctpMultiAddr) -> io::Result<SctpStream> {
        net_imp::SctpStream::connect_multi(remote.addrs()).map(SctpStream)
    }

    /// Creates an SCTP socket bound to a single local address.
    pub fn bind(local: SocketAddr) -> io::Result<SctpStream> {
        net_imp::SctpStream::bind(local).map(SctpStream)
    }

    /// Creates an SCTP socket bound to multiple local addresses.
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpStream> {
        net_imp::SctpStream::bind_multi(local.addrs()).map(SctpStream)
    }

    /// Returns the primary remote address of this association.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Returns one local address currently used by this socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.socket_addr()
    }

    /// Returns all remote addresses configured for this association.
    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.peer_addrs()
    }

    /// Returns all local addresses configured for this socket.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Enables or disables the SCTP Nagle-style bundling algorithm.
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.0.set_nodelay(on)
    }

    /// Configures association setup options applied to future handshakes.
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Sends one user message and optional SCTP per-message metadata.
    pub fn send_with_info(&self, buf: &[u8], info: Option<&SctpSendInfo>) -> io::Result<usize> {
        self.0.send_with_info(buf, info)
    }

    /// Receives one user message and optional SCTP receive metadata.
    pub fn recv_with_info(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        self.0.recv_with_info(buf)
    }

    /// Sets the read timeout.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    /// Sets the write timeout.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    /// Returns the read timeout.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.read_timeout()
    }

    /// Returns the write timeout.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.write_timeout()
    }

    /// Shuts down the read, write, or both halves of this SCTP socket.
    pub fn shutdown(&self, how: super::Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    /// Moves this socket into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Returns the pending socket error, if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Creates a new independently owned handle to the same SCTP socket.
    pub fn try_clone(&self) -> io::Result<SctpStream> {
        self.0.duplicate().map(SctpStream)
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl Read for SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn read_buf(&mut self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        self.0.read_buf(cursor)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_vectored(bufs)
    }

    fn is_read_vectored(&self) -> bool {
        self.0.is_read_vectored()
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl Write for SctpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl SctpListener {
    /// Creates an SCTP listener bound to a local address.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpListener> {
        net_imp::SctpListener::bind(addr).map(SctpListener)
    }

    /// Creates an SCTP listener bound to multiple local addresses.
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpListener> {
        net_imp::SctpListener::bind_multi(local.addrs()).map(SctpListener)
    }

    /// Accepts a new SCTP association.
    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        self.0.accept().map(|(s, a)| (SctpStream(s), a))
    }

    /// Returns one local address currently used by this listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.socket_addr()
    }

    /// Returns all local addresses configured for this listener.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Configures association setup options applied to future accepted sockets.
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Moves this listener into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Returns the pending socket error, if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Creates a new independently owned handle to the same SCTP listener.
    pub fn try_clone(&self) -> io::Result<SctpListener> {
        self.0.duplicate().map(SctpListener)
    }

    /// Returns an iterator over incoming SCTP associations.
    pub fn incoming(&self) -> SctpIncoming<'_> {
        SctpIncoming { listener: self }
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl<'a> Iterator for SctpIncoming<'a> {
    type Item = io::Result<SctpStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept().map(|(s, _)| s))
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl FusedIterator for SctpIncoming<'_> {}

impl AsInner<net_imp::SctpStream> for SctpStream {
    fn as_inner(&self) -> &net_imp::SctpStream {
        &self.0
    }
}

impl FromInner<net_imp::SctpStream> for SctpStream {
    fn from_inner(inner: net_imp::SctpStream) -> Self {
        Self(inner)
    }
}

impl IntoInner<net_imp::SctpStream> for SctpStream {
    fn into_inner(self) -> net_imp::SctpStream {
        self.0
    }
}

impl AsInner<net_imp::SctpListener> for SctpListener {
    fn as_inner(&self) -> &net_imp::SctpListener {
        &self.0
    }
}

impl FromInner<net_imp::SctpListener> for SctpListener {
    fn from_inner(inner: net_imp::SctpListener) -> Self {
        Self(inner)
    }
}

impl IntoInner<net_imp::SctpListener> for SctpListener {
    fn into_inner(self) -> net_imp::SctpListener {
        self.0
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
