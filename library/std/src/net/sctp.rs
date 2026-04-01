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

/// SCTP association retransmission timeout parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpRtoInfo {
    /// Target association identifier (0 for current association).
    pub assoc_id: i32,
    /// Initial retransmission timeout in milliseconds.
    pub initial: u32,
    /// Maximum retransmission timeout in milliseconds.
    pub max: u32,
    /// Minimum retransmission timeout in milliseconds.
    pub min: u32,
}

/// SCTP delayed-SACK parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpDelayedSackInfo {
    /// Target association identifier (0 for current association).
    pub assoc_id: i32,
    /// Delay timer in milliseconds.
    pub delay: u32,
    /// Acknowledge at least every N packets.
    pub frequency: u32,
}

/// SCTP partial-reliability policy identifier.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpPrPolicy(pub u16);

/// SCTP default partial-reliability configuration.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpPrInfo {
    /// Target association identifier (0 for current association).
    pub assoc_id: i32,
    /// Policy-specific value.
    pub value: u32,
    /// Partial-reliability policy selector.
    pub policy: SctpPrPolicy,
}

/// SCTP AUTH shared-key material.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpAuthKey {
    /// Target association identifier (0 for current association).
    pub assoc_id: i32,
    /// SCTP AUTH key identifier.
    pub key_id: u16,
    /// Raw shared-secret bytes for this key.
    pub secret: Vec<u8>,
}

/// SCTP stream scheduler selector.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpScheduler(pub u16);

/// SCTP association status returned by `SCTP_STATUS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpAssocStatus {
    /// Association identifier described by this status.
    pub assoc_id: i32,
    /// Association state returned by the kernel.
    pub state: i32,
    /// Current receiver window.
    pub rwnd: u32,
    /// Number of unacked outbound DATA/I-DATA chunks.
    pub unacked_data: u16,
    /// Number of pending outbound chunks.
    pub pending_data: u16,
    /// Configured inbound stream count.
    pub inbound_streams: u16,
    /// Configured outbound stream count.
    pub outbound_streams: u16,
    /// Current fragmentation point.
    pub fragmentation_point: u32,
    /// Current primary peer address, if the kernel returned one.
    pub primary_addr: Option<SocketAddr>,
    /// Primary-path state.
    pub primary_state: i32,
    /// Primary-path congestion window.
    pub primary_cwnd: u32,
    /// Primary-path smoothed RTT.
    pub primary_srtt: u32,
    /// Primary-path retransmission timeout.
    pub primary_rto: u32,
    /// Primary-path MTU.
    pub primary_mtu: u32,
}

/// SCTP send flag requesting unordered delivery.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_UNORDERED: u16 = 1 << 0;

/// Disable partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_NONE: SctpPrPolicy = SctpPrPolicy(0x0000);

/// Time-based partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_TTL: SctpPrPolicy = SctpPrPolicy(0x0010);

/// Retransmission-limited partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_RTX: SctpPrPolicy = SctpPrPolicy(0x0020);

/// Priority-based partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_PRIORITY: SctpPrPolicy = SctpPrPolicy(0x0030);

/// First-come, first-served stream scheduling.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_SCHEDULER_FCFS: SctpScheduler = SctpScheduler(0);

/// Priority-based stream scheduling.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_SCHEDULER_PRIORITY: SctpScheduler = SctpScheduler(1);

/// Round-robin stream scheduling.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_SCHEDULER_RR: SctpScheduler = SctpScheduler(2);

/// Fair-capacity stream scheduling.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_SCHEDULER_FC: SctpScheduler = SctpScheduler(3);

/// Weighted-fair-queueing stream scheduling.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_SCHEDULER_WFQ: SctpScheduler = SctpScheduler(4);

/// Enable or request incoming stream reset support.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_STREAM_RESET_INCOMING: u16 = 0x01;

/// Enable or request outgoing stream reset support.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_STREAM_RESET_OUTGOING: u16 = 0x02;

/// Metadata describing the next queued SCTP message, if available.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpNextInfo {
    /// Stream identifier of the next message.
    pub stream: u16,
    /// SCTP receive flags for the next message.
    pub flags: u16,
    /// Upper-layer payload protocol identifier of the next message.
    pub ppid: u32,
    /// Byte length of the next message.
    pub length: u32,
    /// Association identifier for the next message.
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
    /// Metadata for the next queued SCTP message, if the stack made it available.
    pub next: Option<SctpNextInfo>,
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

/// A typed SCTP notification delivered via `recvmsg()`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
#[non_exhaustive]
pub enum SctpNotification {
    /// Association state changed.
    AssociationChange {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// New association state reported by the stack.
        state: u16,
        /// Notification-specific error code.
        error: u16,
        /// Outbound stream count currently configured for the association.
        outbound_streams: u16,
        /// Inbound stream count currently configured for the association.
        inbound_streams: u16,
    },
    /// Peer address state changed on a multihomed association.
    PeerAddressChange {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Peer address whose state changed.
        address: SocketAddr,
        /// New peer-address state reported by the stack.
        state: u32,
        /// Notification-specific error code.
        error: u32,
    },
    /// The peer initiated graceful shutdown.
    Shutdown {
        /// Association identifier for the notification.
        assoc_id: i32,
    },
    /// Partial delivery state changed while receiving a large user message.
    PartialDelivery {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Partial-delivery indication value from the stack.
        indication: u32,
    },
    /// A notification the runtime does not parse yet.
    Unknown {
        /// Raw SCTP notification type.
        notification_type: u16,
        /// Association identifier if it could be derived from the payload.
        assoc_id: Option<i32>,
    },
}

/// Result of receiving one SCTP message or notification.
#[derive(Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpReceive {
    /// Number of payload bytes written into the provided buffer.
    pub len: usize,
    /// Per-message receive metadata for user data messages.
    pub info: Option<SctpRecvInfo>,
    /// Typed SCTP notification metadata when the received payload is a notification.
    pub notification: Option<SctpNotification>,
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

/// An unconnected one-to-many SCTP socket.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpSocket(net_imp::SctpSocket);

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

    /// Connects to a single remote SCTP endpoint after applying `SCTP_INITMSG`.
    pub fn connect_with_init_options<A: ToSocketAddrs>(
        addr: A,
        opts: SctpInitOptions,
    ) -> io::Result<SctpStream> {
        net_imp::SctpStream::connect_with_init_options(addr, opts).map(SctpStream)
    }

    /// Connects to a remote SCTP endpoint represented by multiple peer addresses.
    pub fn connect_multi(remote: &SctpMultiAddr) -> io::Result<SctpStream> {
        net_imp::SctpStream::connect_multi(remote.addrs()).map(SctpStream)
    }

    /// Connects to a remote multi-address SCTP endpoint after applying `SCTP_INITMSG`.
    pub fn connect_multi_with_init_options(
        remote: &SctpMultiAddr,
        opts: SctpInitOptions,
    ) -> io::Result<SctpStream> {
        net_imp::SctpStream::connect_multi_with_init_options(remote.addrs(), opts).map(SctpStream)
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

    /// Configures retransmission timeout parameters on this socket or association.
    pub fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.0.set_rto_info(info)
    }

    /// Configures delayed-SACK behavior on this socket or association.
    pub fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        self.0.set_delayed_sack(info)
    }

    /// Configures the default per-message send metadata used by plain writes.
    pub fn set_default_send_info(&self, info: SctpSendInfo) -> io::Result<()> {
        self.0.set_default_send_info(info)
    }

    /// Configures default partial-reliability behavior for future messages.
    pub fn set_default_prinfo(&self, info: SctpPrInfo) -> io::Result<()> {
        self.0.set_default_prinfo(info)
    }

    /// Controls whether the kernel returns metadata for the next queued SCTP message.
    pub fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        self.0.set_recv_nxtinfo(on)
    }

    /// Controls receive-side fragment interleaving behavior.
    pub fn set_fragment_interleave(&self, level: u32) -> io::Result<()> {
        self.0.set_fragment_interleave(level)
    }

    /// Configures the SCTP_AUTOCLOSE timeout in seconds.
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.0.set_autoclose(seconds)
    }

    /// Configures the maximum number of back-to-back packets sent by the stack.
    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        self.0.set_max_burst(value)
    }

    /// Configures the SCTP_MAXSEG send fragmentation threshold.
    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        self.0.set_maxseg(value)
    }

    /// Adds local addresses to the socket or active association.
    pub fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.0.bindx_add(addrs)
    }

    /// Removes local addresses from the socket or active association.
    pub fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.0.bindx_remove(addrs)
    }

    /// Requests a change to the primary destination address.
    pub fn set_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        self.0.set_primary_addr(addr)
    }

    /// Requests that the peer switch its primary path to one of our local addresses.
    pub fn set_peer_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        self.0.set_peer_primary_addr(addr)
    }

    /// Lists association identifiers currently present on this socket.
    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        self.0.assoc_ids()
    }

    /// Retrieves association status for the given association id, or for the current association when 0.
    pub fn assoc_status(&self, assoc_id: i32) -> io::Result<SctpAssocStatus> {
        self.0.assoc_status(assoc_id)
    }

    /// Peels the given association off onto a dedicated SCTP stream.
    pub fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStream> {
        self.0.peeloff(assoc_id).map(SctpStream)
    }

    /// Enables stream-reset support for the active association.
    pub fn enable_stream_reset(&self, flags: u16) -> io::Result<()> {
        self.0.enable_stream_reset(flags)
    }

    /// Requests a reset for the specified streams.
    pub fn reset_streams(&self, flags: u16, streams: &[u16]) -> io::Result<()> {
        self.0.reset_streams(flags, streams)
    }

    /// Requests additional inbound and outbound streams.
    pub fn add_streams(&self, inbound: u16, outbound: u16) -> io::Result<()> {
        self.0.add_streams(inbound, outbound)
    }

    /// Configures SCTP AUTH chunk coverage.
    pub fn set_auth_chunks(&self, chunks: &[u8]) -> io::Result<()> {
        self.0.set_auth_chunks(chunks)
    }

    /// Installs or replaces an SCTP AUTH shared key.
    pub fn set_auth_key(&self, key: &SctpAuthKey) -> io::Result<()> {
        self.0.set_auth_key(key)
    }

    /// Switches the active SCTP AUTH key.
    pub fn activate_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        self.0.activate_auth_key(assoc_id, key_id)
    }

    /// Deletes a previously installed SCTP AUTH key.
    pub fn delete_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        self.0.delete_auth_key(assoc_id, key_id)
    }

    /// Selects the SCTP stream scheduler policy.
    pub fn set_stream_scheduler(&self, scheduler: SctpScheduler) -> io::Result<()> {
        self.0.set_stream_scheduler(scheduler)
    }

    /// Sets a per-stream scheduler value.
    pub fn set_stream_scheduler_value(&self, stream: u16, value: u16) -> io::Result<()> {
        self.0.set_stream_scheduler_value(stream, value)
    }

    /// Receives one user message and optional SCTP receive metadata.
    pub fn recv_with_info(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        self.0.recv_with_info(buf)
    }

    /// Receives one SCTP user message or notification with typed metadata.
    pub fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        self.0.recv_message(buf)
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

    /// Configures association setup options applied to future accepted sockets.
    pub fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.0.set_rto_info(info)
    }

    /// Configures delayed-SACK behavior on this listener socket.
    pub fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        self.0.set_delayed_sack(info)
    }

    /// Configures the maximum number of back-to-back packets sent by the stack.
    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        self.0.set_max_burst(value)
    }

    /// Configures the SCTP_MAXSEG send fragmentation threshold.
    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        self.0.set_maxseg(value)
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
impl SctpSocket {
    /// Creates an unconnected SCTP socket bound to one local address.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpSocket> {
        net_imp::SctpSocket::bind(addr).map(SctpSocket)
    }

    /// Creates an unconnected SCTP socket bound to multiple local addresses.
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpSocket> {
        net_imp::SctpSocket::bind_multi(local.addrs()).map(SctpSocket)
    }

    /// Returns all local addresses configured for this socket.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Configures association setup options applied to future associations.
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Configures the SCTP_AUTOCLOSE timeout in seconds.
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.0.set_autoclose(seconds)
    }

    /// Sends one SCTP user message to a peer address and optional SCTP metadata.
    pub fn send_to_with_info(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.0.send_to_with_info(buf, addr, info)
    }

    /// Lists association identifiers currently present on this socket.
    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        self.0.assoc_ids()
    }

    /// Moves this socket into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Creates a new independently owned handle to the same SCTP socket.
    pub fn try_clone(&self) -> io::Result<SctpSocket> {
        self.0.duplicate().map(SctpSocket)
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

impl AsInner<net_imp::SctpSocket> for SctpSocket {
    fn as_inner(&self) -> &net_imp::SctpSocket {
        &self.0
    }
}

impl FromInner<net_imp::SctpSocket> for SctpSocket {
    fn from_inner(inner: net_imp::SctpSocket) -> Self {
        Self(inner)
    }
}

impl IntoInner<net_imp::SctpSocket> for SctpSocket {
    fn into_inner(self) -> net_imp::SctpSocket {
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

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
