#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(sctp_udp_backend)]
mod auto;
#[cfg(sctp_udp_backend)]
mod many;
#[cfg(test)]
mod tests;
#[cfg(sctp_udp_backend)]
mod udp;

use crate::fmt;
use crate::io::prelude::*;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::iter::FusedIterator;
use crate::net::{SocketAddr, ToSocketAddrs};
use crate::sys::net as net_imp;
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

/// SCTP transport selection policy.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub enum SctpTransportPolicy {
    /// Use the operating system SCTP stack only.
    NativeOnly,
    /// Prefer native SCTP, falling back to UDP encapsulation only when the
    /// operating system has no SCTP support at all (e.g. the protocol is not
    /// available). A native connection that is refused, reset or times out is
    /// reported as-is and is **not** silently moved onto the user-space engine.
    /// Listeners and one-to-many sockets accept both transports on the same port.
    #[default]
    NativePreferred,
    /// Like [`NativePreferred`](Self::NativePreferred), but a one-to-one
    /// `connect` also falls back to UDP when the native attempt fails with a
    /// connection error (refused, reset, aborted, unreachable or timed out).
    /// Opt in only when the peer is known to answer over UDP encapsulation:
    /// this lets a single forged reset move the connection onto the research
    /// -grade user-space stack, which has different security properties.
    NativePreferredWithConnectFallback,
    /// Use SCTP encapsulated in UDP.
    UdpOnly,
}

/// The transport a connected [`SctpStream`] actually uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub enum SctpTransport {
    /// The operating system's native SCTP stack.
    Native,
    /// The user-space SCTP-over-UDP engine.
    Udp,
}

/// UDP encapsulation settings for RFC 6951 SCTP fallback.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpUdpConfig {
    /// Remote UDP encapsulation port. When omitted, the peer SCTP port is reused.
    pub remote_encap_port: Option<u16>,
    /// Local UDP encapsulation port. When omitted, the local SCTP port is reused.
    pub local_encap_port: Option<u16>,
    /// Whether the backend should attempt to reuse the encapsulation port.
    pub reuse_port: bool,
}

/// SCTP transport configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpTransportConfig {
    /// Transport selection policy.
    pub policy: SctpTransportPolicy,
    /// UDP encapsulation settings used by `UdpOnly` and `NativePreferred`.
    /// `None` uses `SctpUdpConfig::default()`; it does not disable fallback.
    pub udp: Option<SctpUdpConfig>,
}

#[unstable(feature = "sctp", issue = "none")]
impl Default for SctpTransportConfig {
    fn default() -> Self {
        Self { policy: SctpTransportPolicy::NativePreferred, udp: None }
    }
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
pub const SCTP_UNORDERED: u16 = net_imp::SCTP_UNORDERED;

/// Disable partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_NONE: SctpPrPolicy = SctpPrPolicy(0x0000);

/// Time-based partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_TTL: SctpPrPolicy = SctpPrPolicy(net_imp::SCTP_PR_TTL);

/// Retransmission-limited partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_RTX: SctpPrPolicy = SctpPrPolicy(net_imp::SCTP_PR_RTX);

/// Priority-based partial reliability.
#[unstable(feature = "sctp", issue = "none")]
pub const SCTP_PR_PRIORITY: SctpPrPolicy = SctpPrPolicy(net_imp::SCTP_PR_PRIORITY);

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
    /// The stack failed to send a user message.
    SendFailure {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Send-failure flags reported by the stack.
        flags: u16,
        /// Notification-specific error code.
        error: u32,
        /// Per-message send metadata associated with the failed message, if available.
        info: Option<SctpSendInfo>,
        /// Returned failed user payload bytes.
        data: Vec<u8>,
    },
    /// The remote peer reported an SCTP operational error.
    PeerError {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Remote SCTP error code.
        error: u16,
        /// Raw remote error TLV payload.
        data: Vec<u8>,
    },
    /// The peer indicated an adaptation-layer value.
    Adaptation {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Adaptation-layer indication value.
        indication: u32,
    },
    /// SCTP AUTH key state changed.
    Authentication {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Key id described by the notification.
        key_id: u16,
        /// Alternate key id, when supplied by the stack.
        alt_key_id: u16,
        /// Authentication notification indication value.
        indication: u32,
    },
    /// The stack has no more data queued for the association.
    SenderDry {
        /// Association identifier for the notification.
        assoc_id: i32,
    },
    /// SCTP stream reset state changed.
    StreamReset {
        /// Association identifier for the notification.
        assoc_id: i32,
        /// Stream-reset flags reported by the stack.
        flags: u16,
        /// Streams affected by the reset notification.
        streams: Vec<u16>,
    },
    /// A notification the runtime does not parse yet.
    Unknown {
        /// Raw SCTP notification type.
        notification_type: u16,
        /// Association identifier if it could be derived from the payload.
        assoc_id: Option<i32>,
        /// Raw notification payload bytes.
        payload: Vec<u8>,
    },
}

/// Message-level state returned by SCTP `recvmsg()`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpReceiveFlags {
    /// The receive completed an SCTP user message record.
    pub end_of_record: bool,
    /// The user payload was larger than the provided buffer.
    pub truncated: bool,
    /// Ancillary SCTP metadata was larger than the runtime control buffer.
    pub control_truncated: bool,
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
    /// Message-level flags returned by `recvmsg()`.
    pub flags: SctpReceiveFlags,
}

/// Result of receiving one SCTP message or notification on a one-to-many socket.
#[derive(Clone, Debug, PartialEq, Eq)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpReceiveFrom {
    /// Received user message or notification metadata.
    pub receive: SctpReceive,
    /// Peer address returned by `recvmsg()`, when supplied by the stack.
    pub peer_addr: Option<SocketAddr>,
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
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `addrs` is empty, mixes IPv4 and IPv6, or uses
    /// more than one port.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// assert_eq!(multi.addrs().len(), 2);
    /// # Ok::<(), std::io::Error>(())
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    /// ])?;
    /// for addr in multi.addrs() {
    ///     println!("{addr}");
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

/// An SCTP stream between a local and remote endpoint.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpStream(SctpStreamBackend);

/// An SCTP listener socket.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpListener(SctpListenerBackend);

/// An unconnected one-to-many SCTP socket.
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpSocket(SctpSocketBackend);

enum SctpStreamBackend {
    Native(net_imp::SctpStream),
    #[cfg(sctp_udp_backend)]
    Udp(udp::UdpSctpStream),
    #[cfg(sctp_udp_backend)]
    Pending(auto::Bound),
}

enum SctpListenerBackend {
    Native(net_imp::SctpListener),
    #[cfg(sctp_udp_backend)]
    Udp(udp::UdpSctpListener),
    #[cfg(sctp_udp_backend)]
    Hybrid(auto::Listener),
}

enum SctpSocketBackend {
    #[cfg(sctp_udp_backend)]
    Hybrid(many::Many),
    Native(net_imp::SctpSocket),
    #[cfg(sctp_udp_backend)]
    Udp(udp::UdpSctpSocket),
}

/// Iterator over incoming SCTP streams.
#[must_use = "iterators are lazy and do nothing unless consumed"]
#[derive(Debug)]
#[unstable(feature = "sctp", issue = "none")]
pub struct SctpIncoming<'a> {
    listener: &'a SctpListener,
}

fn resolve_socket_addrs<A: ToSocketAddrs>(addr: A) -> io::Result<Vec<SocketAddr>> {
    let addrs = addr.to_socket_addrs()?.collect::<Vec<_>>();
    if addrs.is_empty() {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved"))
    } else {
        Ok(addrs)
    }
}

#[cfg(not(sctp_udp_backend))]
fn udp_only_unsupported() -> io::Error {
    io::const_error!(io::ErrorKind::Unsupported, "SCTP over UDP is not available on this target")
}

#[cfg(sctp_udp_backend)]
fn udp_config(config: SctpTransportConfig) -> io::Result<SctpUdpConfig> {
    Ok(config.udp.unwrap_or_default())
}

fn is_native_sctp_unsupported(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Unsupported || net_imp::sctp_error_means_unsupported(err)
}

/// A native connection error that `NativePreferredWithConnectFallback` retries
/// over UDP. Deliberately not part of the default policy: an attacker who can
/// forge one of these would otherwise be able to force the downgrade.
fn is_connect_fallback_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::TimedOut
    )
}

/// Whether a failed native `connect` under `policy` should be retried over UDP.
fn should_fallback(err: &io::Error, policy: SctpTransportPolicy) -> bool {
    is_native_sctp_unsupported(err)
        || (policy == SctpTransportPolicy::NativePreferredWithConnectFallback
            && is_connect_fallback_error(err))
}

impl SctpStreamBackend {
    fn transport(&self) -> SctpTransport {
        match self {
            Self::Native(_) => SctpTransport::Native,
            #[cfg(sctp_udp_backend)]
            Self::Udp(_) => SctpTransport::Udp,
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.transport(),
        }
    }

    fn connect_bound<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.connect(&resolve_socket_addrs(addr)?, false),
            Self::Native(inner) => inner.connect_bound(addr),
            #[cfg(sctp_udp_backend)]
            Self::Udp(_) => {
                Err(io::const_error!(io::ErrorKind::Unsupported, "UDP stream is already connected"))
            }
        }
    }

    fn connect_bound_multi(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.connect(addrs, true),
            Self::Native(inner) => inner.connect_bound_multi(addrs),
            #[cfg(sctp_udp_backend)]
            Self::Udp(_) => Err(io::const_error!(
                io::ErrorKind::Unsupported,
                "UDP multihoming is not supported"
            )),
        }
    }

    fn connect(
        addrs: &[SocketAddr],
        opts: SctpInitOptions,
        config: SctpTransportConfig,
        multi: bool,
    ) -> io::Result<Self> {
        match config.policy {
            SctpTransportPolicy::NativeOnly => {
                if multi {
                    net_imp::SctpStream::connect_multi_with_init_options(addrs, opts)
                        .map(Self::Native)
                } else {
                    net_imp::SctpStream::connect_with_init_options(addrs, opts).map(Self::Native)
                }
            }
            SctpTransportPolicy::NativePreferred
            | SctpTransportPolicy::NativePreferredWithConnectFallback => {
                let native = if multi {
                    net_imp::SctpStream::connect_multi_with_init_options(addrs, opts)
                } else {
                    net_imp::SctpStream::connect_with_init_options(addrs, opts)
                };
                match native {
                    Ok(stream) => Ok(Self::Native(stream)),
                    Err(err) if should_fallback(&err, config.policy) => {
                        #[cfg(sctp_udp_backend)]
                        {
                            {
                                if multi && addrs.len() > 1 {
                                    return Err(udp::unsupported());
                                }
                                udp::UdpSctpStream::connect(addrs, opts, &udp_config(config)?)
                            }
                            .map(Self::Udp)
                        }
                        #[cfg(not(sctp_udp_backend))]
                        {
                            let _ = addrs;
                            let _ = opts;
                            let _ = config;
                            Err(udp_only_unsupported())
                        }
                    }
                    Err(err) => Err(err),
                }
            }
            SctpTransportPolicy::UdpOnly => {
                #[cfg(sctp_udp_backend)]
                {
                    {
                        if multi && addrs.len() > 1 {
                            return Err(udp::unsupported());
                        }
                        udp::UdpSctpStream::connect(addrs, opts, &udp_config(config)?)
                    }
                    .map(Self::Udp)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    let _ = addrs;
                    let _ = opts;
                    let _ = config;
                    Err(udp_only_unsupported())
                }
            }
        }
    }

    fn bind(local: &[SocketAddr], config: SctpTransportConfig, multi: bool) -> io::Result<Self> {
        match config.policy {
            SctpTransportPolicy::NativeOnly => {
                if multi {
                    net_imp::SctpStream::bind_multi(local).map(Self::Native)
                } else {
                    net_imp::SctpStream::bind(local[0]).map(Self::Native)
                }
            }
            SctpTransportPolicy::NativePreferred
            | SctpTransportPolicy::NativePreferredWithConnectFallback
            | SctpTransportPolicy::UdpOnly => {
                #[cfg(sctp_udp_backend)]
                {
                    auto::Bound::bind(local, config, multi).map(Self::Pending)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    Err(udp_only_unsupported())
                }
            }
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.peer_addr()),
            Self::Native(inner) => inner.peer_addr(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.peer_addr(),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.local_addr(),
            Self::Native(inner) => inner.socket_addr(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.local_addr(),
        }
    }

    fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.peer_addrs()),
            Self::Native(inner) => inner.peer_addrs(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.peer_addrs(),
        }
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.local_addrs(),
            Self::Native(inner) => inner.local_addrs(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.local_addrs(),
        }
    }

    fn set_nodelay(&self, on: bool) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_nodelay(on)),
            Self::Native(inner) => inner.set_nodelay(on),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_nodelay(on),
        }
    }

    fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_init_options(opts),
            Self::Native(inner) => inner.set_init_options(opts),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_init_options(opts),
        }
    }

    fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.subscribe_events(mask),
            Self::Native(inner) => inner.subscribe_events(mask),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.subscribe_events(mask),
        }
    }

    fn send_with_info(&self, buf: &[u8], info: Option<&SctpSendInfo>) -> io::Result<usize> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.send_with_info(buf, info),
            Self::Native(inner) => inner.send_with_info(buf, info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.send_with_info(buf, info),
        }
    }

    fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_rto_info(info),
            Self::Native(inner) => inner.set_rto_info(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_rto_info(info),
        }
    }

    fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_delayed_sack(info),
            Self::Native(inner) => inner.set_delayed_sack(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_delayed_sack(info),
        }
    }

    fn set_default_send_info(&self, info: SctpSendInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_default_send_info(info),
            Self::Native(inner) => inner.set_default_send_info(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_default_send_info(info),
        }
    }

    fn set_default_prinfo(&self, info: SctpPrInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_default_prinfo(info),
            Self::Native(inner) => inner.set_default_prinfo(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_default_prinfo(info),
        }
    }

    fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_recv_nxtinfo(on)),
            Self::Native(inner) => inner.set_recv_nxtinfo(on),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_recv_nxtinfo(on),
        }
    }

    fn set_fragment_interleave(&self, level: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_fragment_interleave(level)),
            Self::Native(inner) => inner.set_fragment_interleave(level),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_fragment_interleave(level),
        }
    }

    fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_autoclose(seconds)),
            Self::Native(inner) => inner.set_autoclose(seconds),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_autoclose(seconds),
        }
    }

    fn set_max_burst(&self, value: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_max_burst(value)),
            Self::Native(inner) => inner.set_max_burst(value),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_max_burst(value),
        }
    }

    fn set_maxseg(&self, value: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_maxseg(value)),
            Self::Native(inner) => inner.set_maxseg(value),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_maxseg(value),
        }
    }

    fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.bindx_add(addrs)),
            Self::Native(inner) => inner.bindx_add(addrs),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.bindx_add(addrs),
        }
    }

    fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.bindx_remove(addrs)),
            Self::Native(inner) => inner.bindx_remove(addrs),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.bindx_remove(addrs),
        }
    }

    fn set_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_primary_addr(addr)),
            Self::Native(inner) => inner.set_primary_addr(addr),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_primary_addr(addr),
        }
    }

    fn set_peer_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_peer_primary_addr(addr)),
            Self::Native(inner) => inner.set_peer_primary_addr(addr),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_peer_primary_addr(addr),
        }
    }

    fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.assoc_ids(),
            Self::Native(inner) => inner.assoc_ids(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.assoc_ids(),
        }
    }

    fn assoc_status(&self, assoc_id: i32) -> io::Result<SctpAssocStatus> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.assoc_status(assoc_id),
            Self::Native(inner) => inner.assoc_status(assoc_id),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.assoc_status(assoc_id),
        }
    }

    fn peeloff(&self, assoc_id: i32) -> io::Result<Self> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.peeloff(assoc_id)),
            Self::Native(inner) => inner.peeloff(assoc_id).map(Self::Native),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.peeloff(assoc_id).map(Self::Udp),
        }
    }

    fn enable_stream_reset(&self, flags: u16) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.enable_stream_reset(flags)),
            Self::Native(inner) => inner.enable_stream_reset(flags),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.enable_stream_reset(flags),
        }
    }

    fn reset_streams(&self, flags: u16, streams: &[u16]) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.reset_streams(flags, streams)),
            Self::Native(inner) => inner.reset_streams(flags, streams),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.reset_streams(flags, streams),
        }
    }

    fn add_streams(&self, inbound: u16, outbound: u16) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.add_streams(inbound, outbound)),
            Self::Native(inner) => inner.add_streams(inbound, outbound),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.add_streams(inbound, outbound),
        }
    }

    fn set_auth_chunks(&self, chunks: &[u8]) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_auth_chunks(chunks)),
            Self::Native(inner) => inner.set_auth_chunks(chunks),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_auth_chunks(chunks),
        }
    }

    fn set_auth_key(&self, key: &SctpAuthKey) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_auth_key(key),
            Self::Native(inner) => inner.set_auth_key(key),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_auth_key(key),
        }
    }

    fn activate_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.activate_auth_key(assoc_id, key_id),
            Self::Native(inner) => inner.activate_auth_key(assoc_id, key_id),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.activate_auth_key(assoc_id, key_id),
        }
    }

    fn delete_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.delete_auth_key(assoc_id, key_id),
            Self::Native(inner) => inner.delete_auth_key(assoc_id, key_id),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.delete_auth_key(assoc_id, key_id),
        }
    }

    fn set_stream_scheduler(&self, scheduler: SctpScheduler) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.set_stream_scheduler(scheduler)),
            Self::Native(inner) => inner.set_stream_scheduler(scheduler),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_stream_scheduler(scheduler),
        }
    }

    fn set_stream_scheduler_value(&self, stream: u16, value: u16) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => {
                inner.call(|selected| selected.set_stream_scheduler_value(stream, value))
            }
            Self::Native(inner) => inner.set_stream_scheduler_value(stream, value),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_stream_scheduler_value(stream, value),
        }
    }

    fn recv_with_info(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.recv_with_info(buf),
            Self::Native(inner) => inner.recv_with_info(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.recv_with_info(buf),
        }
    }

    fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.recv_message(buf),
            Self::Native(inner) => inner.recv_message(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.recv_message(buf),
        }
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_read_timeout(dur),
            Self::Native(inner) => inner.set_read_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_read_timeout(dur),
        }
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_write_timeout(dur),
            Self::Native(inner) => inner.set_write_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_write_timeout(dur),
        }
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.read_timeout(),
            Self::Native(inner) => inner.read_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.read_timeout(),
        }
    }

    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.write_timeout(),
            Self::Native(inner) => inner.write_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.write_timeout(),
        }
    }

    fn shutdown(&self, how: super::Shutdown) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.shutdown(how),
            Self::Native(inner) => inner.shutdown(how),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.shutdown(how),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.set_nonblocking(nonblocking),
            Self::Native(inner) => inner.set_nonblocking(nonblocking),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_nonblocking(nonblocking),
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.take_error(),
            Self::Native(inner) => inner.take_error(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.take_error(),
        }
    }

    fn duplicate(&self) -> io::Result<Self> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => Ok(Self::Pending(inner.clone())),
            Self::Native(inner) => inner.duplicate().map(Self::Native),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.try_clone().map(Self::Udp),
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.read(buf),
            Self::Native(inner) => inner.read(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.read(buf),
        }
    }

    fn read_buf(&self, cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.read_buf(cursor),
            Self::Native(inner) => inner.read_buf(cursor),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.read_buf(cursor),
        }
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.read_vectored(bufs),
            Self::Native(inner) => inner.read_vectored(bufs),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.read_vectored(bufs),
        }
    }

    fn is_read_vectored(&self) -> bool {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(_) => false,
            Self::Native(inner) => inner.is_read_vectored(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(_) => true,
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.write(buf)),
            Self::Native(inner) => inner.write(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.write(buf),
        }
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(inner) => inner.call(|selected| selected.write_vectored(bufs)),
            Self::Native(inner) => inner.write_vectored(bufs),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.write_vectored(bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Pending(_) => false,
            Self::Native(inner) => inner.is_write_vectored(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(_) => true,
        }
    }
}

impl SctpListenerBackend {
    fn bind(local: &[SocketAddr], config: SctpTransportConfig, multi: bool) -> io::Result<Self> {
        if !multi && local.len() > 1 {
            let mut error =
                io::const_error!(io::ErrorKind::AddrNotAvailable, "no usable SCTP bind address");
            for addr in local {
                match Self::bind(crate::slice::from_ref(addr), config, false) {
                    Ok(listener) => return Ok(listener),
                    Err(e) => error = e,
                }
            }
            return Err(error);
        }
        match config.policy {
            SctpTransportPolicy::NativeOnly => {
                if multi {
                    net_imp::SctpListener::bind_multi(local).map(Self::Native)
                } else {
                    net_imp::SctpListener::bind(local).map(Self::Native)
                }
            }
            SctpTransportPolicy::NativePreferred
            | SctpTransportPolicy::NativePreferredWithConnectFallback => {
                #[cfg(sctp_udp_backend)]
                {
                    auto::Listener::bind(local, config, multi).map(Self::Hybrid)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    net_imp::SctpListener::bind(local).map(Self::Native)
                }
            }
            SctpTransportPolicy::UdpOnly => {
                #[cfg(sctp_udp_backend)]
                {
                    udp::UdpSctpListener::bind_multi(local, &udp_config(config)?).map(Self::Udp)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    let _ = local;
                    let _ = config;
                    Err(udp_only_unsupported())
                }
            }
        }
    }

    fn accept(&self) -> io::Result<(SctpStreamBackend, SocketAddr)> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.accept(),
            Self::Native(inner) => {
                inner.accept().map(|(stream, addr)| (SctpStreamBackend::Native(stream), addr))
            }
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => {
                inner.accept().map(|(stream, addr)| (SctpStreamBackend::Udp(stream), addr))
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.local_addr(),
            Self::Native(inner) => inner.socket_addr(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.local_addr(),
        }
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.local_addrs(),
            Self::Native(inner) => inner.local_addrs(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.local_addrs(),
        }
    }

    fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_init_options(opts),
            Self::Native(inner) => inner.set_init_options(opts),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_init_options(opts),
        }
    }

    fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.subscribe_events(mask),
            Self::Native(inner) => inner.subscribe_events(mask),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.subscribe_events(mask),
        }
    }

    fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_rto_info(info),
            Self::Native(inner) => inner.set_rto_info(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_rto_info(info),
        }
    }

    fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_delayed_sack(info),
            Self::Native(inner) => inner.set_delayed_sack(info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_delayed_sack(info),
        }
    }

    fn set_max_burst(&self, value: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_max_burst(value),
            Self::Native(inner) => inner.set_max_burst(value),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_max_burst(value),
        }
    }

    fn set_maxseg(&self, value: u32) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_maxseg(value),
            Self::Native(inner) => inner.set_maxseg(value),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_maxseg(value),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_nonblocking(nonblocking),
            Self::Native(inner) => inner.set_nonblocking(nonblocking),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_nonblocking(nonblocking),
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.take_error(),
            Self::Native(inner) => inner.take_error(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.take_error(),
        }
    }

    fn duplicate(&self) -> io::Result<Self> {
        match self {
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.duplicate().map(Self::Hybrid),
            Self::Native(inner) => inner.duplicate().map(Self::Native),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.try_clone().map(Self::Udp),
        }
    }
}

impl SctpSocketBackend {
    fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceiveFrom> {
        match self {
            Self::Native(inner) => inner.recv_message(buf),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.recv_message(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.recv_message(buf),
        }
    }

    fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<SctpRecvInfo>, Option<SocketAddr>)> {
        match self {
            Self::Native(inner) => inner.recv_with_info(buf),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.recv_with_info(buf),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.recv_with_info(buf),
        }
    }

    fn assoc_status(&self, assoc_id: i32) -> io::Result<SctpAssocStatus> {
        match self {
            Self::Native(inner) => inner.assoc_status(assoc_id),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.assoc_status(assoc_id),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.assoc_status(assoc_id),
        }
    }

    fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStreamBackend> {
        match self {
            Self::Native(inner) => inner.peeloff(assoc_id).map(SctpStreamBackend::Native),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.peeloff(assoc_id),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.peeloff(assoc_id).map(SctpStreamBackend::Udp),
        }
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.set_read_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_read_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_read_timeout(dur),
        }
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.set_write_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_write_timeout(dur),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_write_timeout(dur),
        }
    }

    fn read_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Self::Native(inner) => inner.read_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.read_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.read_timeout(),
        }
    }

    fn write_timeout(&self) -> io::Result<Option<Duration>> {
        match self {
            Self::Native(inner) => inner.write_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.write_timeout(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.write_timeout(),
        }
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            Self::Native(inner) => inner.take_error(),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.take_error(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.take_error(),
        }
    }

    fn bind(local: &[SocketAddr], config: SctpTransportConfig, multi: bool) -> io::Result<Self> {
        if !multi && local.len() > 1 {
            let mut error =
                io::const_error!(io::ErrorKind::AddrNotAvailable, "no usable SCTP bind address");
            for addr in local {
                match Self::bind(crate::slice::from_ref(addr), config, false) {
                    Ok(socket) => return Ok(socket),
                    Err(e) => error = e,
                }
            }
            return Err(error);
        }
        match config.policy {
            SctpTransportPolicy::NativeOnly => {
                if multi {
                    net_imp::SctpSocket::bind_multi(local).map(Self::Native)
                } else {
                    net_imp::SctpSocket::bind(local).map(Self::Native)
                }
            }
            SctpTransportPolicy::NativePreferred
            | SctpTransportPolicy::NativePreferredWithConnectFallback => {
                #[cfg(sctp_udp_backend)]
                {
                    many::Many::bind(local, config, multi).map(Self::Hybrid)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    Err(udp_only_unsupported())
                }
            }
            SctpTransportPolicy::UdpOnly => {
                #[cfg(sctp_udp_backend)]
                {
                    udp::UdpSctpSocket::bind_multi(local, &udp_config(config)?, true).map(Self::Udp)
                }
                #[cfg(not(sctp_udp_backend))]
                {
                    let _ = local;
                    let _ = config;
                    Err(udp_only_unsupported())
                }
            }
        }
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            Self::Native(inner) => inner.local_addrs(),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.local_addrs(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.local_addrs(),
        }
    }

    fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.set_init_options(opts),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_init_options(opts),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_init_options(opts),
        }
    }

    fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.subscribe_events(mask),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.subscribe_events(mask),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.subscribe_events(mask),
        }
    }

    fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.set_autoclose(seconds),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_autoclose(seconds),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_autoclose(seconds),
        }
    }

    fn send_to_with_info(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        match self {
            Self::Native(inner) => inner.send_to_with_info(buf, addr, info),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.send_to_with_info(buf, addr, info),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.send_to_with_info(buf, addr, info),
        }
    }

    fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        match self {
            Self::Native(inner) => inner.assoc_ids(),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.assoc_ids(),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.assoc_ids(),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            Self::Native(inner) => inner.set_nonblocking(nonblocking),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.set_nonblocking(nonblocking),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.set_nonblocking(nonblocking),
        }
    }

    fn duplicate(&self) -> io::Result<Self> {
        match self {
            Self::Native(inner) => inner.duplicate().map(Self::Native),
            #[cfg(sctp_udp_backend)]
            Self::Hybrid(inner) => inner.duplicate().map(Self::Hybrid),
            #[cfg(sctp_udp_backend)]
            Self::Udp(inner) => inner.try_clone().map(Self::Udp),
        }
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl SctpStream {
    /// Connects to a single remote SCTP endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.send_with_info(b"hello", None)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<SctpStream> {
        Self::connect_with_config(addr, SctpTransportConfig::default())
    }

    /// Connects to a single remote SCTP endpoint with an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SctpTransportConfig, SctpTransportPolicy};
    ///
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream = SctpStream::connect_with_config("127.0.0.1:9000", config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_with_config<A: ToSocketAddrs>(
        addr: A,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        let addrs = resolve_socket_addrs(addr)?;
        SctpStreamBackend::connect(&addrs, SctpInitOptions::default(), config, false)
            .map(SctpStream)
    }

    /// Connects to a single remote SCTP endpoint after applying `SCTP_INITMSG`.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpStream};
    ///
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// let stream = SctpStream::connect_with_init_options("127.0.0.1:9000", opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_with_init_options<A: ToSocketAddrs>(
        addr: A,
        opts: SctpInitOptions,
    ) -> io::Result<SctpStream> {
        Self::connect_with_init_options_and_config(addr, opts, SctpTransportConfig::default())
    }

    /// Connects to a single remote SCTP endpoint after applying `SCTP_INITMSG`
    /// and an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpStream, SctpTransportConfig, SctpTransportPolicy};
    ///
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream =
    ///     SctpStream::connect_with_init_options_and_config("127.0.0.1:9000", opts, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_with_init_options_and_config<A: ToSocketAddrs>(
        addr: A,
        opts: SctpInitOptions,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        let addrs = resolve_socket_addrs(addr)?;
        SctpStreamBackend::connect(&addrs, opts, config, false).map(SctpStream)
    }

    /// Connects to a remote SCTP endpoint represented by multiple peer addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SctpStream, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let stream = SctpStream::connect_multi(&multi)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_multi(remote: &SctpMultiAddr) -> io::Result<SctpStream> {
        Self::connect_multi_with_config(remote, SctpTransportConfig::default())
    }

    /// Connects to a remote SCTP endpoint represented by multiple peer addresses with an
    /// explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{
    ///     SctpMultiAddr,
    ///     SctpStream,
    ///     SctpTransportConfig,
    ///     SctpTransportPolicy,
    ///     SocketAddr,
    /// };
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream = SctpStream::connect_multi_with_config(&multi, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_multi_with_config(
        remote: &SctpMultiAddr,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        SctpStreamBackend::connect(remote.addrs(), SctpInitOptions::default(), config, true)
            .map(SctpStream)
    }

    /// Connects to a remote multi-address SCTP endpoint after applying `SCTP_INITMSG`.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpMultiAddr, SctpStream, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// let stream = SctpStream::connect_multi_with_init_options(&multi, opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_multi_with_init_options(
        remote: &SctpMultiAddr,
        opts: SctpInitOptions,
    ) -> io::Result<SctpStream> {
        Self::connect_multi_with_init_options_and_config(
            remote,
            opts,
            SctpTransportConfig::default(),
        )
    }

    /// Connects to a remote multi-address SCTP endpoint after applying `SCTP_INITMSG`
    /// and an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be resolved, the peer refuses or does not answer, or
    /// the requested transport is unavailable: `NativeOnly` on a host without kernel SCTP, or
    /// `UdpOnly` on a target without the user-space engine, fail with
    /// [`io::ErrorKind::Unsupported`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{
    ///     SctpInitOptions,
    ///     SctpMultiAddr,
    ///     SctpStream,
    ///     SctpTransportConfig,
    ///     SctpTransportPolicy,
    ///     SocketAddr,
    /// };
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream = SctpStream::connect_multi_with_init_options_and_config(&multi, opts, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_multi_with_init_options_and_config(
        remote: &SctpMultiAddr,
        opts: SctpInitOptions,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        SctpStreamBackend::connect(remote.addrs(), opts, config, true).map(SctpStream)
    }

    /// Creates an SCTP socket bound to a single local address.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::bind(SocketAddr::from(([0, 0, 0, 0], 9000)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind(local: SocketAddr) -> io::Result<SctpStream> {
        Self::bind_with_config(local, SctpTransportConfig::default())
    }

    /// Creates an SCTP socket bound to a single local address with an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SctpTransportConfig, SctpTransportPolicy, SocketAddr};
    ///
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream = SctpStream::bind_with_config(SocketAddr::from(([0, 0, 0, 0], 9000)), config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_with_config(
        local: SocketAddr,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        SctpStreamBackend::bind(&[local], config, false).map(SctpStream)
    }

    /// Creates an SCTP socket bound to multiple local addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SctpStream, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let stream = SctpStream::bind_multi(&multi)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpStream> {
        Self::bind_multi_with_config(local, SctpTransportConfig::default())
    }

    /// Creates an SCTP socket bound to multiple local addresses with an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{
    ///     SctpMultiAddr,
    ///     SctpStream,
    ///     SctpTransportConfig,
    ///     SctpTransportPolicy,
    ///     SocketAddr,
    /// };
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let stream = SctpStream::bind_multi_with_config(&multi, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi_with_config(
        local: &SctpMultiAddr,
        config: SctpTransportConfig,
    ) -> io::Result<SctpStream> {
        SctpStreamBackend::bind(local.addrs(), config, true).map(SctpStream)
    }

    /// Connects this bound SCTP socket to a single remote endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is already connected, the address cannot be resolved, or the
    /// peer cannot be reached. A non-blocking stream returns [`io::ErrorKind::WouldBlock`] while
    /// the transport is still being selected.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::bind(SocketAddr::from(([0, 0, 0, 0], 9000)))?;
    /// stream.connect_bound("127.0.0.1:9001")?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_bound<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        self.0.connect_bound(addr)
    }

    /// Connects this bound SCTP socket to a remote multi-address endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is already connected, the address cannot be resolved, or the
    /// peer cannot be reached. A non-blocking stream returns [`io::ErrorKind::WouldBlock`] while
    /// the transport is still being selected.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::bind(SocketAddr::from(([0, 0, 0, 0], 9000)))?;
    /// let remote = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9001)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9001)),
    /// ])?;
    /// stream.connect_bound_multi(&remote)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn connect_bound_multi(&self, remote: &SctpMultiAddr) -> io::Result<()> {
        self.0.connect_bound_multi(remote.addrs())
    }

    /// Returns the primary remote address of this association.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is not connected.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.peer_addr()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// Returns whether this stream is carried by the operating system's native
    /// SCTP stack or by the user-space SCTP-over-UDP engine.
    ///
    /// With [`SctpTransportPolicy::NativePreferred`] a stream can use either
    /// transport depending on host support; callers that must not run over the
    /// user-space engine can assert on the result.
    ///
    /// While a non-blocking connect is still selecting a transport this reports
    /// [`SctpTransport::Native`]; the choice is final once the connect completes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SctpTransport};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// if stream.transport() != SctpTransport::Native {
    ///     println!("carried by the user-space SCTP-over-UDP engine");
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[unstable(feature = "sctp", issue = "none")]
    #[must_use]
    pub fn transport(&self) -> SctpTransport {
        self.0.transport()
    }

    /// Returns one local address currently used by this socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has been closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.local_addr()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Returns all remote addresses configured for this association.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is not connected.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.peer_addrs()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.peer_addrs()
    }

    /// Returns all local addresses configured for this socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has been closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.local_addrs()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Enables or disables the SCTP Nagle-style bundling algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_nodelay(true)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        self.0.set_nodelay(on)
    }

    /// Configures association setup options applied to future handshakes.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// stream.set_init_options(opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpEventMask, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let mask = SctpEventMask {
    ///     data_io: true,
    ///     association: true,
    ///     shutdown: true,
    ///     ..Default::default()
    /// };
    /// stream.subscribe_events(mask)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Sends one user message and optional SCTP per-message metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the association is closed or has failed ([`io::ErrorKind::BrokenPipe`],
    /// [`io::ErrorKind::ConnectionAborted`]), the stream or flags are invalid
    /// ([`io::ErrorKind::InvalidInput`]), a write timeout elapses ([`io::ErrorKind::TimedOut`]) or,
    /// in non-blocking mode, the send queue is full ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpSendInfo, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let info = SctpSendInfo { stream: 1, ppid: 42u32.to_be(), ..Default::default() };
    /// stream.send_with_info(b"hello", Some(&info))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn send_with_info(&self, buf: &[u8], info: Option<&SctpSendInfo>) -> io::Result<usize> {
        self.0.send_with_info(buf, info)
    }

    /// Configures retransmission timeout parameters on this socket or association.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpRtoInfo, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let info = SctpRtoInfo { initial: 1000, min: 500, max: 4000, ..Default::default() };
    /// stream.set_rto_info(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.0.set_rto_info(info)
    }

    /// Configures delayed-SACK behavior on this socket or association.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpDelayedSackInfo, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let info = SctpDelayedSackInfo { delay: 100, frequency: 2, ..Default::default() };
    /// stream.set_delayed_sack(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        self.0.set_delayed_sack(info)
    }

    /// Configures the default per-message send metadata used by plain writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpSendInfo, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let info = SctpSendInfo { stream: 1, ..Default::default() };
    /// stream.set_default_send_info(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_default_send_info(&self, info: SctpSendInfo) -> io::Result<()> {
        self.0.set_default_send_info(info)
    }

    /// Configures default partial-reliability behavior for future messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SCTP_PR_TTL, SctpPrInfo, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let info = SctpPrInfo { policy: SCTP_PR_TTL, value: 500, ..Default::default() };
    /// stream.set_default_prinfo(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_default_prinfo(&self, info: SctpPrInfo) -> io::Result<()> {
        self.0.set_default_prinfo(info)
    }

    /// Controls whether the kernel returns metadata for the next queued SCTP message.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_recv_nxtinfo(true)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        self.0.set_recv_nxtinfo(on)
    }

    /// Controls receive-side fragment interleaving behavior.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_fragment_interleave(1)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_fragment_interleave(&self, level: u32) -> io::Result<()> {
        self.0.set_fragment_interleave(level)
    }

    /// Configures the SCTP_AUTOCLOSE timeout in seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_autoclose(30)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.0.set_autoclose(seconds)
    }

    /// Configures the maximum number of back-to-back packets sent by the stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_max_burst(4)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        self.0.set_max_burst(value)
    }

    /// Configures the SCTP_MAXSEG send fragmentation threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_maxseg(4)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        self.0.set_maxseg(value)
    }

    /// Adds local addresses to the socket or active association.
    ///
    /// # Errors
    ///
    /// Returns an error if an address is invalid or not local, or [`io::ErrorKind::Unsupported`] on
    /// the UDP transport, which has no multihoming.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.bindx_add(&[SocketAddr::from(([10, 0, 1, 1], 9000))])?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.0.bindx_add(addrs)
    }

    /// Removes local addresses from the socket or active association.
    ///
    /// # Errors
    ///
    /// Returns an error if an address is invalid or not local, or [`io::ErrorKind::Unsupported`] on
    /// the UDP transport, which has no multihoming.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.bindx_remove(&[SocketAddr::from(([10, 0, 1, 1], 9000))])?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.0.bindx_remove(addrs)
    }

    /// Requests a change to the primary destination address.
    ///
    /// # Errors
    ///
    /// Returns an error if an address is invalid or not local, or [`io::ErrorKind::Unsupported`] on
    /// the UDP transport, which has no multihoming.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_primary_addr(SocketAddr::from(([10, 0, 1, 1], 9000)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        self.0.set_primary_addr(addr)
    }

    /// Requests that the peer switch its primary path to one of our local addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if an address is invalid or not local, or [`io::ErrorKind::Unsupported`] on
    /// the UDP transport, which has no multihoming.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, SocketAddr};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_peer_primary_addr(SocketAddr::from(([10, 0, 1, 1], 9000)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_peer_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        self.0.set_peer_primary_addr(addr)
    }

    /// Lists association identifiers currently present on this socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.assoc_ids()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        self.0.assoc_ids()
    }

    /// Retrieves association status for the given association id, or for the current
    /// association when 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let id = stream.assoc_ids()?[0];
    /// stream.assoc_status(id)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn assoc_status(&self, assoc_id: i32) -> io::Result<SctpAssocStatus> {
        self.0.assoc_status(assoc_id)
    }

    /// Peels the given association off onto a dedicated SCTP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let id = stream.assoc_ids()?[0];
    /// let own = stream.peeloff(id)?;
    /// own.send_with_info(b"hello", None)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStream> {
        self.0.peeloff(assoc_id).map(SctpStream)
    }

    /// Enables stream-reset support for the active association.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SCTP_STREAM_RESET_OUTGOING, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.enable_stream_reset(SCTP_STREAM_RESET_OUTGOING)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn enable_stream_reset(&self, flags: u16) -> io::Result<()> {
        self.0.enable_stream_reset(flags)
    }

    /// Requests a reset for the specified streams.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SCTP_STREAM_RESET_OUTGOING, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.reset_streams(SCTP_STREAM_RESET_OUTGOING, &[1, 2])?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn reset_streams(&self, flags: u16, streams: &[u16]) -> io::Result<()> {
        self.0.reset_streams(flags, streams)
    }

    /// Requests additional inbound and outbound streams.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.add_streams(2, 2)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn add_streams(&self, inbound: u16, outbound: u16) -> io::Result<()> {
        self.0.add_streams(inbound, outbound)
    }

    /// Configures SCTP AUTH chunk coverage.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_auth_chunks(&[0x0a])?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_auth_chunks(&self, chunks: &[u8]) -> io::Result<()> {
        self.0.set_auth_chunks(chunks)
    }

    /// Installs or replaces an SCTP AUTH shared key.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpAuthKey, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let key = SctpAuthKey { assoc_id: 0, key_id: 1, secret: b"s3cret".to_vec() };
    /// stream.set_auth_key(&key)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_auth_key(&self, key: &SctpAuthKey) -> io::Result<()> {
        self.0.set_auth_key(key)
    }

    /// Switches the active SCTP AUTH key.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let id = stream.assoc_ids()?[0];
    /// stream.activate_auth_key(id, 1)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn activate_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        self.0.activate_auth_key(assoc_id, key_id)
    }

    /// Deletes a previously installed SCTP AUTH key.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let id = stream.assoc_ids()?[0];
    /// stream.delete_auth_key(id, 1)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn delete_auth_key(&self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        self.0.delete_auth_key(assoc_id, key_id)
    }

    /// Selects the SCTP stream scheduler policy.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SCTP_SCHEDULER_RR, SctpStream};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_stream_scheduler(SCTP_SCHEDULER_RR)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_stream_scheduler(&self, scheduler: SctpScheduler) -> io::Result<()> {
        self.0.set_stream_scheduler(scheduler)
    }

    /// Sets a per-stream scheduler value.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Unsupported`] on the UDP transport, or an error if the operating
    /// system rejects the request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_stream_scheduler_value(1, 10)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_stream_scheduler_value(&self, stream: u16, value: u16) -> io::Result<()> {
        self.0.set_stream_scheduler_value(stream, value)
    }

    /// Receives one user message and optional SCTP receive metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the association has failed, a read timeout elapses
    /// ([`io::ErrorKind::TimedOut`]) or, in non-blocking mode, nothing is available
    /// ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let mut buf = [0u8; 1024];
    /// let (len, info) = stream.recv_with_info(&mut buf)?;
    /// println!("{} bytes on stream {:?}", len, info.map(|i| i.stream));
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn recv_with_info(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        self.0.recv_with_info(buf)
    }

    /// Receives one SCTP user message or notification with typed metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the association has failed, a read timeout elapses
    /// ([`io::ErrorKind::TimedOut`]) or, in non-blocking mode, nothing is available
    /// ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// let mut buf = [0u8; 1024];
    /// let received = stream.recv_message(&mut buf)?;
    /// if let Some(info) = received.info {
    ///     println!("stream {} ppid {}", info.stream, u32::from_be(info.ppid));
    /// }
    /// let payload = &buf[..received.len];
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        self.0.recv_message(buf)
    }

    /// Sets the read timeout.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `dur` is `Some(Duration::ZERO)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    /// use std::time::Duration;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    /// Sets the write timeout.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `dur` is `Some(Duration::ZERO)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    /// use std::time::Duration;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    /// Returns the read timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.read_timeout()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.read_timeout()
    }

    /// Returns the write timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.write_timeout()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.write_timeout()
    }

    /// Shuts down the read, write, or both halves of this SCTP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpStream, Shutdown};
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.shutdown(Shutdown::Write)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn shutdown(&self, how: super::Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    /// Moves this socket into or out of nonblocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.set_nonblocking(true)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Returns the pending socket error, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.take_error()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Creates a new independently owned handle to the same SCTP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpStream;
    ///
    /// let stream = SctpStream::connect("127.0.0.1:9000")?;
    /// stream.try_clone()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn try_clone(&self) -> io::Result<SctpStream> {
        self.0.duplicate().map(SctpStream)
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl Read for SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn read_buf(&mut self, cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
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
impl Read for &SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    fn read_buf(&mut self, cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
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
impl Write for &SctpStream {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpListener> {
        Self::bind_with_config(addr, SctpTransportConfig::default())
    }

    /// Creates an SCTP listener bound to a local address with an explicit transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpListener, SctpTransportConfig, SctpTransportPolicy};
    ///
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let listener = SctpListener::bind_with_config("127.0.0.1:9000", config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_with_config<A: ToSocketAddrs>(
        addr: A,
        config: SctpTransportConfig,
    ) -> io::Result<SctpListener> {
        let addrs = resolve_socket_addrs(addr)?;
        SctpListenerBackend::bind(&addrs, config, false).map(SctpListener)
    }

    /// Creates an SCTP listener bound to multiple local addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpListener, SctpMultiAddr, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let listener = SctpListener::bind_multi(&multi)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpListener> {
        Self::bind_multi_with_config(local, SctpTransportConfig::default())
    }

    /// Creates an SCTP listener bound to multiple local addresses with an explicit transport
    /// policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{
    ///     SctpListener,
    ///     SctpMultiAddr,
    ///     SctpTransportConfig,
    ///     SctpTransportPolicy,
    ///     SocketAddr,
    /// };
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let listener = SctpListener::bind_multi_with_config(&multi, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi_with_config(
        local: &SctpMultiAddr,
        config: SctpTransportConfig,
    ) -> io::Result<SctpListener> {
        SctpListenerBackend::bind(local.addrs(), config, true).map(SctpListener)
    }

    /// Accepts a new SCTP association.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener has failed, or [`io::ErrorKind::WouldBlock`] in
    /// non-blocking mode when no association is pending.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// let (stream, peer) = listener.accept()?;
    /// println!("association from {peer}");
    /// let mut buf = [0u8; 1024];
    /// let received = stream.recv_message(&mut buf)?;
    /// println!("{} bytes", received.len);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        self.0.accept().map(|(s, a)| (SctpStream(s), a))
    }

    /// Returns one local address currently used by this listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has been closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.local_addr()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Returns all local addresses configured for this listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has been closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.local_addrs()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Configures association setup options applied to future accepted sockets.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpListener};
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// listener.set_init_options(opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpEventMask, SctpListener};
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// let mask = SctpEventMask {
    ///     data_io: true,
    ///     association: true,
    ///     shutdown: true,
    ///     ..Default::default()
    /// };
    /// listener.subscribe_events(mask)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Configures association setup options applied to future accepted sockets.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpListener, SctpRtoInfo};
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// let info = SctpRtoInfo { initial: 1000, min: 500, max: 4000, ..Default::default() };
    /// listener.set_rto_info(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.0.set_rto_info(info)
    }

    /// Configures delayed-SACK behavior on this listener socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpDelayedSackInfo, SctpListener};
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// let info = SctpDelayedSackInfo { delay: 100, frequency: 2, ..Default::default() };
    /// listener.set_delayed_sack(info)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_delayed_sack(&self, info: SctpDelayedSackInfo) -> io::Result<()> {
        self.0.set_delayed_sack(info)
    }

    /// Configures the maximum number of back-to-back packets sent by the stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.set_max_burst(4)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_max_burst(&self, value: u32) -> io::Result<()> {
        self.0.set_max_burst(value)
    }

    /// Configures the SCTP_MAXSEG send fragmentation threshold.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.set_maxseg(4)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_maxseg(&self, value: u32) -> io::Result<()> {
        self.0.set_maxseg(value)
    }

    /// Moves this listener into or out of nonblocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.set_nonblocking(true)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Returns the pending socket error, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.take_error()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Creates a new independently owned handle to the same SCTP listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// listener.try_clone()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn try_clone(&self) -> io::Result<SctpListener> {
        self.0.duplicate().map(SctpListener)
    }

    /// Returns an iterator over incoming SCTP associations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpListener;
    ///
    /// let listener = SctpListener::bind("127.0.0.1:9000")?;
    /// for stream in listener.incoming() {
    ///     let stream = stream?;
    ///     println!("association from {}", stream.peer_addr()?);
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn incoming(&self) -> SctpIncoming<'_> {
        SctpIncoming { listener: self }
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl SctpSocket {
    /// Creates an unconnected SCTP socket bound to one local address.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpSocket> {
        Self::bind_with_config(addr, SctpTransportConfig::default())
    }

    /// Creates an unconnected SCTP socket bound to one local address with an explicit
    /// transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpSocket, SctpTransportConfig, SctpTransportPolicy};
    ///
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let socket = SctpSocket::bind_with_config("127.0.0.1:9000", config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_with_config<A: ToSocketAddrs>(
        addr: A,
        config: SctpTransportConfig,
    ) -> io::Result<SctpSocket> {
        let addrs = resolve_socket_addrs(addr)?;
        SctpSocketBackend::bind(&addrs, config, false).map(SctpSocket)
    }

    /// Creates an unconnected SCTP socket bound to multiple local addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpMultiAddr, SctpSocket, SocketAddr};
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let socket = SctpSocket::bind_multi(&multi)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi(local: &SctpMultiAddr) -> io::Result<SctpSocket> {
        Self::bind_multi_with_config(local, SctpTransportConfig::default())
    }

    /// Creates an unconnected SCTP socket bound to multiple local addresses with an explicit
    /// transport policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use or not local, or if the requested
    /// transport is unavailable ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{
    ///     SctpMultiAddr,
    ///     SctpSocket,
    ///     SctpTransportConfig,
    ///     SctpTransportPolicy,
    ///     SocketAddr,
    /// };
    ///
    /// let multi = SctpMultiAddr::new(vec![
    ///     SocketAddr::from(([10, 0, 0, 1], 9000)),
    ///     SocketAddr::from(([10, 0, 1, 1], 9000)),
    /// ])?;
    /// let config = SctpTransportConfig { policy: SctpTransportPolicy::NativeOnly, udp: None };
    /// let socket = SctpSocket::bind_multi_with_config(&multi, config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bind_multi_with_config(
        local: &SctpMultiAddr,
        config: SctpTransportConfig,
    ) -> io::Result<SctpSocket> {
        SctpSocketBackend::bind(local.addrs(), config, true).map(SctpSocket)
    }

    /// Returns all local addresses configured for this socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket has been closed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.local_addrs()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs()
    }

    /// Configures association setup options applied to future associations.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpInitOptions, SctpSocket};
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let opts = SctpInitOptions { num_ostreams: 4, max_instreams: 4, ..Default::default() };
    /// socket.set_init_options(opts)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.0.set_init_options(opts)
    }

    /// Subscribes to SCTP socket events.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpEventMask, SctpSocket};
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let mask = SctpEventMask {
    ///     data_io: true,
    ///     association: true,
    ///     shutdown: true,
    ///     ..Default::default()
    /// };
    /// socket.subscribe_events(mask)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.0.subscribe_events(mask)
    }

    /// Configures the SCTP_AUTOCLOSE timeout in seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.set_autoclose(30)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.0.set_autoclose(seconds)
    }

    /// Sends one SCTP user message to a peer address and optional SCTP metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the association is closed or has failed ([`io::ErrorKind::BrokenPipe`],
    /// [`io::ErrorKind::ConnectionAborted`]), the stream or flags are invalid
    /// ([`io::ErrorKind::InvalidInput`]), a write timeout elapses ([`io::ErrorKind::TimedOut`]) or,
    /// in non-blocking mode, the send queue is full ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::{SctpSendInfo, SctpSocket, SocketAddr};
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let peer = SocketAddr::from(([127, 0, 0, 1], 9000));
    /// let info = SctpSendInfo { stream: 2, ..Default::default() };
    /// socket.send_to_with_info(b"hello", peer, Some(&info))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn send_to_with_info(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.0.send_to_with_info(buf, addr, info)
    }

    /// Receives one SCTP user message or notification with metadata and peer address.
    ///
    /// # Errors
    ///
    /// Returns an error if the association has failed, a read timeout elapses
    /// ([`io::ErrorKind::TimedOut`]) or, in non-blocking mode, nothing is available
    /// ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let mut buf = [0u8; 1024];
    /// let received = socket.recv_message(&mut buf)?;
    /// if let Some(notification) = received.receive.notification {
    ///     println!("notification: {notification:?}");
    /// } else if let Some(peer) = received.peer_addr {
    ///     println!("{} bytes from {peer}", received.receive.len);
    /// }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceiveFrom> {
        self.0.recv_message(buf)
    }

    /// Receives one SCTP user message with optional metadata and peer address.
    ///
    /// # Errors
    ///
    /// Returns an error if the association has failed, a read timeout elapses
    /// ([`io::ErrorKind::TimedOut`]) or, in non-blocking mode, nothing is available
    /// ([`io::ErrorKind::WouldBlock`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let mut buf = [0u8; 1024];
    /// let (len, info, peer) = socket.recv_with_info(&mut buf)?;
    /// println!("{len} bytes from {peer:?} on stream {:?}", info.map(|i| i.stream));
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<SctpRecvInfo>, Option<SocketAddr>)> {
        self.0.recv_with_info(buf)
    }

    /// Lists association identifiers currently present on this socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.assoc_ids()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        self.0.assoc_ids()
    }

    /// Retrieves association status for the given association id.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let id = socket.assoc_ids()?[0];
    /// socket.assoc_status(id)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn assoc_status(&self, assoc_id: i32) -> io::Result<SctpAssocStatus> {
        self.0.assoc_status(assoc_id)
    }

    /// Peels the given association off onto a dedicated SCTP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the association id is unknown ([`io::ErrorKind::InvalidInput`]), the
    /// socket is closed, or the selected transport does not support the operation
    /// ([`io::ErrorKind::Unsupported`]).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// let id = socket.assoc_ids()?[0];
    /// let stream = socket.peeloff(id)?;
    /// stream.send_with_info(b"hello", None)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn peeloff(&self, assoc_id: i32) -> io::Result<SctpStream> {
        self.0.peeloff(assoc_id).map(SctpStream)
    }

    /// Sets the read timeout.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `dur` is `Some(Duration::ZERO)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    /// use std::time::Duration;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    /// Sets the write timeout.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `dur` is `Some(Duration::ZERO)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    /// use std::time::Duration;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    /// Returns the read timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.read_timeout()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.read_timeout()
    }

    /// Returns the write timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.write_timeout()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.write_timeout()
    }

    /// Moves this socket into or out of nonblocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the operating system rejects the value, or
    /// [`io::ErrorKind::Unsupported`] when the selected transport cannot honour this option (see
    /// `SCTP-TRANSPORT.md` for the UDP capability matrix).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.set_nonblocking(true)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Returns the pending socket error, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.take_error()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }

    /// Creates a new independently owned handle to the same SCTP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying socket operation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![feature(sctp)]
    /// use std::net::SctpSocket;
    ///
    /// let socket = SctpSocket::bind("127.0.0.1:9000")?;
    /// socket.try_clone()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
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

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SctpStreamBackend::Native(inner) => inner.fmt(f),
            #[cfg(sctp_udp_backend)]
            SctpStreamBackend::Pending(_) => {
                f.debug_struct("SctpStream").field("transport", &"auto").finish()
            }
            #[cfg(sctp_udp_backend)]
            SctpStreamBackend::Udp(_) => {
                f.debug_struct("SctpStream").field("transport", &"udp").finish()
            }
        }
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SctpListenerBackend::Native(inner) => inner.fmt(f),
            #[cfg(sctp_udp_backend)]
            SctpListenerBackend::Hybrid(_) => {
                f.debug_struct("SctpListener").field("transport", &"native+udp").finish()
            }
            #[cfg(sctp_udp_backend)]
            SctpListenerBackend::Udp(_) => {
                f.debug_struct("SctpListener").field("transport", &"udp").finish()
            }
        }
    }
}

#[unstable(feature = "sctp", issue = "none")]
impl fmt::Debug for SctpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SctpSocketBackend::Native(inner) => inner.fmt(f),
            #[cfg(sctp_udp_backend)]
            SctpSocketBackend::Hybrid(_) => {
                f.debug_struct("SctpSocket").field("transport", &"native+udp").finish()
            }
            #[cfg(sctp_udp_backend)]
            SctpSocketBackend::Udp(_) => {
                f.debug_struct("SctpSocket").field("transport", &"udp").finish()
            }
        }
    }
}
