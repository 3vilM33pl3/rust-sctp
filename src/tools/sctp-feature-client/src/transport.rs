use bytes::Bytes;
use sctp_proto::{
    Association, AssociationHandle, ClientConfig as ProtoClientConfig, DatagramEvent, Endpoint,
    EndpointConfig, Event as ProtoEvent, PayloadProtocolIdentifier, ReliabilityType,
};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{
    SctpAuthKey, SctpDelayedSackInfo, SctpEventMask, SctpInitOptions, SctpPrInfo, SctpScheduler,
    SctpSendInfo, SctpSocket, SctpStream, SocketAddr, UdpSocket,
};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{ScenarioContract, UdpEncapsulationContract};

const CONTRACT_TRANSPORT_NATIVE: &str = "sctp4";
const CONTRACT_TRANSPORT_UDP: &str = "sctp4_udp_encap";
const SCTP_UNORDERED_FLAG: u16 = 1 << 0;
const SCTP_PR_POLICY_NONE: u16 = 0x0000;
const SCTP_PR_POLICY_TTL: u16 = 0x0010;
const SCTP_PR_POLICY_RTX: u16 = 0x0020;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedTransportProfile {
    Auto,
    Native,
    UdpEncap,
}

impl Default for RequestedTransportProfile {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTransportProfile {
    Native,
    UdpEncap,
}

impl RequestedTransportProfile {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "native" => Ok(Self::Native),
            "udp_encap" => Ok(Self::UdpEncap),
            other => Err(format!(
                "unknown transport profile {other:?}; expected auto, native, or udp_encap"
            )),
        }
    }

    pub fn resolve(self) -> RuntimeTransportProfile {
        match self {
            Self::Auto => {
                if native_sctp_supported() {
                    RuntimeTransportProfile::Native
                } else {
                    RuntimeTransportProfile::UdpEncap
                }
            }
            Self::Native => RuntimeTransportProfile::Native,
            Self::UdpEncap => RuntimeTransportProfile::UdpEncap,
        }
    }
}

impl RuntimeTransportProfile {
    pub fn session_value(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::UdpEncap => "udp_encap",
        }
    }
}

pub fn native_sctp_supported() -> bool {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    match SctpSocket::bind(bind_addr) {
        Ok(sock) => {
            drop(sock);
            true
        }
        Err(err) => !is_native_sctp_unsupported(&err),
    }
}

fn is_native_sctp_unsupported(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Unsupported
        || matches!(err.raw_os_error(), Some(92 | 93 | 94 | 97))
}

#[derive(Clone, Debug)]
pub struct FeatureRecvNextInfo {
    pub stream: u16,
    pub ppid: u32,
    pub length: u32,
}

#[derive(Clone, Debug)]
pub struct FeatureRecvInfo {
    pub stream: u16,
    pub ppid: u32,
    pub next: Option<FeatureRecvNextInfo>,
}

#[derive(Clone, Debug)]
pub enum FeatureNotification {
    AssociationChange,
    PeerAddressChange,
    Shutdown,
    PartialDelivery,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct FeatureRecvMessage {
    pub len: usize,
    pub notification: Option<FeatureNotification>,
    pub info: Option<FeatureRecvInfo>,
}

#[derive(Clone, Debug)]
pub struct FeatureAssocStatus {
    pub state: String,
    pub inbound_streams: u16,
    pub outbound_streams: u16,
    pub primary_addr: Option<SocketAddr>,
}

#[derive(Clone, Copy)]
struct StoredSendInfo {
    stream: u16,
    flags: u16,
    ppid: u32,
}

#[derive(Clone, Copy)]
enum StoredPrPolicy {
    Reliable,
    Timed,
    Rexmit,
}

#[derive(Clone, Copy)]
struct StoredPrInfo {
    policy: StoredPrPolicy,
    value: u32,
}

#[derive(Clone)]
struct UdpReceivedMessage {
    data: Vec<u8>,
    stream: u16,
    ppid: u32,
}

pub struct FeatureStream {
    inner: FeatureStreamInner,
}

enum FeatureStreamInner {
    Native(SctpStream),
    Udp(UdpAssociationSocket),
}

impl FeatureStream {
    pub fn connect(contract: &ScenarioContract, targets: &[SocketAddr]) -> io::Result<Self> {
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contract did not include any SCTP connect addresses",
            ));
        }
        match contract.transport.as_str() {
            CONTRACT_TRANSPORT_NATIVE => {
                let init = SctpInitOptions {
                    num_ostreams: 32,
                    max_instreams: 32,
                    ..SctpInitOptions::default()
                };
                let stream = SctpStream::connect_with_init_options(targets[0], init)?;
                Ok(Self { inner: FeatureStreamInner::Native(stream) })
            }
            CONTRACT_TRANSPORT_UDP => Ok(Self {
                inner: FeatureStreamInner::Udp(UdpAssociationSocket::connect(contract, targets)?),
            }),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported contract transport {other}"),
            )),
        }
    }

    pub fn set_nodelay(&mut self, enabled: bool) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_nodelay(enabled),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_init_options(&mut self, options: SctpInitOptions) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_init_options(options),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_rto_info(&mut self, info: std::net::SctpRtoInfo) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_rto_info(info),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_delayed_sack(&mut self, info: SctpDelayedSackInfo) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_delayed_sack(info),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_max_burst(&mut self, value: u32) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_max_burst(value),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_default_send_info(&mut self, info: SctpSendInfo) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_default_send_info(info),
            FeatureStreamInner::Udp(stream) => {
                stream.default_send_info = Some(StoredSendInfo {
                    stream: info.stream,
                    flags: info.flags,
                    ppid: info.ppid,
                });
                Ok(())
            }
        }
    }

    pub fn set_default_prinfo(&mut self, info: SctpPrInfo) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_default_prinfo(info),
            FeatureStreamInner::Udp(stream) => {
                stream.default_prinfo =
                    Some(StoredPrInfo { policy: stored_pr_policy(info.policy), value: info.value });
                Ok(())
            }
        }
    }

    pub fn set_maxseg(&mut self, value: u32) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_maxseg(value),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_read_timeout(timeout),
            FeatureStreamInner::Udp(stream) => {
                stream.read_timeout = timeout;
                Ok(())
            }
        }
    }

    pub fn subscribe_events(&mut self, mask: SctpEventMask) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.subscribe_events(mask),
            FeatureStreamInner::Udp(stream) => {
                stream.subscriptions = mask;
                if stream.connected && mask.association {
                    stream.pending_notifications.push_back(FeatureNotification::AssociationChange);
                }
                Ok(())
            }
        }
    }

    pub fn set_recv_nxtinfo(&mut self, enabled: bool) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_recv_nxtinfo(enabled),
            FeatureStreamInner::Udp(stream) => {
                stream.recv_nxtinfo = enabled;
                Ok(())
            }
        }
    }

    pub fn send_with_info(
        &mut self,
        payload: &[u8],
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.send_with_info(payload, info),
            FeatureStreamInner::Udp(stream) => stream.send(payload, info),
        }
    }

    pub fn recv_message(&mut self, buf: &mut [u8]) -> io::Result<FeatureRecvMessage> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => {
                let received = stream.recv_message(buf)?;
                Ok(FeatureRecvMessage {
                    len: received.len,
                    notification: received.notification.as_ref().map(native_notification),
                    info: received.info.map(|info| FeatureRecvInfo {
                        stream: info.stream,
                        ppid: info.ppid,
                        next: info.next.map(|next| FeatureRecvNextInfo {
                            stream: next.stream,
                            ppid: next.ppid,
                            length: next.length,
                        }),
                    }),
                })
            }
            FeatureStreamInner::Udp(stream) => stream.recv_message(buf),
        }
    }

    pub fn local_addrs(&mut self) -> io::Result<Vec<SocketAddr>> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.local_addrs(),
            FeatureStreamInner::Udp(stream) => stream.local_addrs(),
        }
    }

    pub fn peer_addrs(&mut self) -> io::Result<Vec<SocketAddr>> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.peer_addrs(),
            FeatureStreamInner::Udp(stream) => Ok(stream.peer_addrs.clone()),
        }
    }

    pub fn bindx_add(&mut self, addrs: &[SocketAddr]) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.bindx_add(addrs),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn bindx_remove(&mut self, addrs: &[SocketAddr]) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.bindx_remove(addrs),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_primary_addr(&mut self, addr: SocketAddr) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_primary_addr(addr),
            FeatureStreamInner::Udp(stream) => {
                stream.primary_addr = Some(addr);
                Ok(())
            }
        }
    }

    pub fn set_peer_primary_addr(&mut self, addr: SocketAddr) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_peer_primary_addr(addr),
            FeatureStreamInner::Udp(_) => {
                let _ = addr;
                Ok(())
            }
        }
    }

    pub fn peeloff(&self, assoc_id: i32) -> io::Result<Self> {
        match &self.inner {
            FeatureStreamInner::Native(stream) => {
                let peeled = stream.peeloff(assoc_id)?;
                Ok(Self { inner: FeatureStreamInner::Native(peeled) })
            }
            FeatureStreamInner::Udp(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "peeloff is not supported on the UDP encapsulation backend",
            )),
        }
    }

    pub fn assoc_ids(&mut self) -> io::Result<Vec<i32>> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.assoc_ids(),
            FeatureStreamInner::Udp(_) => Ok(vec![1]),
        }
    }

    pub fn assoc_status(&mut self, assoc_id: i32) -> io::Result<FeatureAssocStatus> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => {
                let status = stream.assoc_status(assoc_id)?;
                Ok(FeatureAssocStatus {
                    state: format!("{}", status.state),
                    inbound_streams: status.inbound_streams,
                    outbound_streams: status.outbound_streams,
                    primary_addr: status.primary_addr,
                })
            }
            FeatureStreamInner::Udp(stream) => Ok(stream.assoc_status()),
        }
    }

    pub fn enable_stream_reset(&mut self, flags: u16) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.enable_stream_reset(flags),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn reset_streams(&mut self, flags: u16, streams: &[u16]) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.reset_streams(flags, streams),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn add_streams(&mut self, outbound: u16, inbound: u16) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.add_streams(outbound, inbound),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_auth_chunks(&mut self, chunks: &[u8]) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_auth_chunks(chunks),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_auth_key(&mut self, key: &SctpAuthKey) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_auth_key(key),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn activate_auth_key(&mut self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.activate_auth_key(assoc_id, key_id),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_fragment_interleave(&mut self, level: u32) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_fragment_interleave(level),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_stream_scheduler(&mut self, scheduler: SctpScheduler) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => stream.set_stream_scheduler(scheduler),
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }

    pub fn set_stream_scheduler_value(&mut self, stream_id: u16, value: u16) -> io::Result<()> {
        match &mut self.inner {
            FeatureStreamInner::Native(stream) => {
                stream.set_stream_scheduler_value(stream_id, value)
            }
            FeatureStreamInner::Udp(_) => Ok(()),
        }
    }
}

pub struct FeatureOneToManySocket {
    inner: FeatureOneToManyInner,
}

enum FeatureOneToManyInner {
    Native(SctpSocket),
    Udp(UdpOneToManySocket),
}

impl FeatureOneToManySocket {
    pub fn bind(bind_addr: SocketAddr, contract: &ScenarioContract) -> io::Result<Self> {
        match contract.transport.as_str() {
            CONTRACT_TRANSPORT_NATIVE => {
                Ok(Self { inner: FeatureOneToManyInner::Native(SctpSocket::bind(bind_addr)?) })
            }
            CONTRACT_TRANSPORT_UDP => Ok(Self {
                inner: FeatureOneToManyInner::Udp(UdpOneToManySocket::bind(bind_addr, contract)?),
            }),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported contract transport {other}"),
            )),
        }
    }

    pub fn set_init_options(&mut self, options: SctpInitOptions) -> io::Result<()> {
        match &mut self.inner {
            FeatureOneToManyInner::Native(socket) => socket.set_init_options(options),
            FeatureOneToManyInner::Udp(_) => Ok(()),
        }
    }

    pub fn send_to_with_info(
        &mut self,
        payload: &[u8],
        target: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        match &mut self.inner {
            FeatureOneToManyInner::Native(socket) => {
                socket.send_to_with_info(payload, target, info)
            }
            FeatureOneToManyInner::Udp(socket) => socket.send_to_with_info(payload, target, info),
        }
    }

    pub fn assoc_ids(&mut self) -> io::Result<Vec<i32>> {
        match &mut self.inner {
            FeatureOneToManyInner::Native(socket) => socket.assoc_ids(),
            FeatureOneToManyInner::Udp(socket) => socket.assoc_ids(),
        }
    }
}

struct UdpAssociationSocket {
    socket: UdpSocket,
    endpoint: Endpoint,
    handle: AssociationHandle,
    association: Association,
    peer_addrs: Vec<SocketAddr>,
    primary_addr: Option<SocketAddr>,
    connected: bool,
    subscriptions: SctpEventMask,
    recv_nxtinfo: bool,
    read_timeout: Option<Duration>,
    pending_notifications: VecDeque<FeatureNotification>,
    pending_messages: VecDeque<UdpReceivedMessage>,
    default_send_info: Option<StoredSendInfo>,
    default_prinfo: Option<StoredPrInfo>,
}

impl UdpAssociationSocket {
    fn connect(contract: &ScenarioContract, targets: &[SocketAddr]) -> io::Result<Self> {
        let udp = udp_contract(contract)?;
        let bind_addr = wildcard_addr_for(targets[0]);
        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(SocketAddr::new(targets[0].ip(), udp.remote_port))?;
        socket.set_nonblocking(true)?;

        let local_sctp_port = socket.local_addr()?.port();
        let endpoint = Endpoint::new(Arc::new(EndpointConfig::new()), None);
        let client_config =
            ProtoClientConfig::new().with_sctp_ports(local_sctp_port, targets[0].port());
        let mut endpoint = endpoint;
        let (handle, association) = endpoint
            .connect(client_config, SocketAddr::new(targets[0].ip(), udp.remote_port))
            .map_err(proto_connect_error)?;

        let mut this = Self {
            socket,
            endpoint,
            handle,
            association,
            peer_addrs: targets.to_vec(),
            primary_addr: targets.first().copied(),
            connected: false,
            subscriptions: SctpEventMask::default(),
            recv_nxtinfo: false,
            read_timeout: None,
            pending_notifications: VecDeque::new(),
            pending_messages: VecDeque::new(),
            default_send_info: None,
            default_prinfo: None,
        };
        let deadline = Instant::now()
            + Duration::from_secs(contract.timeout_seconds.max(1).clamp(1, 10) as u64);
        this.pump_until(deadline, |stream| stream.connected)?;
        Ok(this)
    }

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.socket.local_addr()?])
    }

    fn assoc_status(&self) -> FeatureAssocStatus {
        FeatureAssocStatus {
            state: if self.connected { "ESTABLISHED" } else { "COOKIE_WAIT" }.to_owned(),
            inbound_streams: 32,
            outbound_streams: 32,
            primary_addr: self.primary_addr,
        }
    }

    fn send(&mut self, payload: &[u8], info: Option<&SctpSendInfo>) -> io::Result<usize> {
        let info = info
            .map(stored_send_info)
            .or(self.default_send_info)
            .unwrap_or(StoredSendInfo { stream: 0, flags: 0, ppid: 0 });

        let pr = self
            .default_prinfo
            .unwrap_or(StoredPrInfo { policy: StoredPrPolicy::Reliable, value: 0 });
        let written = {
            let mut stream = match self.association.stream(info.stream) {
                Ok(stream) => stream,
                Err(_) => self
                    .association
                    .open_stream(info.stream, PayloadProtocolIdentifier(info.ppid))
                    .map_err(proto_error)?,
            };
            stream
                .set_reliability_params(
                    info.flags & SCTP_UNORDERED_FLAG != 0,
                    match pr.policy {
                        StoredPrPolicy::Reliable => ReliabilityType::Reliable,
                        StoredPrPolicy::Timed => ReliabilityType::Timed,
                        StoredPrPolicy::Rexmit => ReliabilityType::Rexmit,
                    },
                    pr.value,
                )
                .map_err(proto_error)?;
            stream
                .write_with_ppi(payload, PayloadProtocolIdentifier(info.ppid))
                .map_err(proto_error)?
        };
        self.flush_transmits(Instant::now())?;
        Ok(written)
    }

    fn recv_message(&mut self, buf: &mut [u8]) -> io::Result<FeatureRecvMessage> {
        if let Some(notification) = self.pending_notifications.pop_front() {
            return Ok(FeatureRecvMessage { len: 0, notification: Some(notification), info: None });
        }
        if let Some(message) = self.pending_messages.pop_front() {
            return self.materialize_recv_message(buf, message);
        }

        let deadline = self
            .read_timeout
            .map(|timeout| Instant::now() + timeout)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
        self.pump_until(deadline, |stream| {
            !stream.pending_notifications.is_empty() || !stream.pending_messages.is_empty()
        })?;

        if let Some(notification) = self.pending_notifications.pop_front() {
            return Ok(FeatureRecvMessage { len: 0, notification: Some(notification), info: None });
        }
        if let Some(message) = self.pending_messages.pop_front() {
            return self.materialize_recv_message(buf, message);
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for UDP-encapsulated SCTP data",
        ))
    }

    fn materialize_recv_message(
        &self,
        buf: &mut [u8],
        message: UdpReceivedMessage,
    ) -> io::Result<FeatureRecvMessage> {
        if message.data.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("receive buffer too small: {} < {}", buf.len(), message.data.len()),
            ));
        }
        buf[..message.data.len()].copy_from_slice(&message.data);
        let next = if self.recv_nxtinfo {
            self.pending_messages.front().map(|next| FeatureRecvNextInfo {
                stream: next.stream,
                ppid: next.ppid,
                length: next.data.len() as u32,
            })
        } else {
            None
        };
        Ok(FeatureRecvMessage {
            len: message.data.len(),
            notification: None,
            info: Some(FeatureRecvInfo { stream: message.stream, ppid: message.ppid, next }),
        })
    }

    fn pump_until<F>(&mut self, deadline: Instant, mut ready: F) -> io::Result<()>
    where
        F: FnMut(&Self) -> bool,
    {
        let mut buf = [0u8; 65536];
        loop {
            self.handle_timers(Instant::now())?;
            self.flush_transmits(Instant::now())?;
            self.drain_assoc_events()?;
            if ready(self) {
                return Ok(());
            }

            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    self.handle_datagram(&buf[..n])?;
                    continue;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for UDP-encapsulated SCTP progress",
                ));
            }

            thread::sleep(Duration::from_millis(10));
        }
    }

    fn handle_timers(&mut self, now: Instant) -> io::Result<()> {
        while let Some(timeout) = self.association.poll_timeout() {
            if timeout > now {
                break;
            }
            self.association.handle_timeout(now);
            self.flush_transmits(now)?;
        }
        Ok(())
    }

    fn flush_transmits(&mut self, now: Instant) -> io::Result<()> {
        while let Some(transmit) = self.association.poll_transmit(now) {
            match transmit.payload {
                sctp_proto::Payload::RawEncode(datagrams) => {
                    for datagram in datagrams {
                        self.socket.send(&datagram)?;
                    }
                }
                sctp_proto::Payload::PartialDecode(_) => {}
            }
        }
        while let Some(endpoint_event) = self.association.poll_endpoint_event() {
            let _ = self.endpoint.handle_event(self.handle, endpoint_event);
        }
        Ok(())
    }

    fn handle_datagram(&mut self, data: &[u8]) -> io::Result<()> {
        let now = Instant::now();
        let remote = self.socket.peer_addr()?;
        if let Some((handle, event)) =
            self.endpoint.handle(now, remote, None, None, Bytes::copy_from_slice(data))
        {
            if handle != self.handle {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "received datagram for unexpected association handle",
                ));
            }
            match event {
                DatagramEvent::AssociationEvent(event) => self.association.handle_event(event),
                DatagramEvent::NewAssociation(association) => {
                    self.association = association;
                }
            }
        }
        self.flush_transmits(now)?;
        self.drain_assoc_events()
    }

    fn drain_assoc_events(&mut self) -> io::Result<()> {
        while let Some(event) = self.association.poll() {
            match event {
                ProtoEvent::Connected => {
                    self.connected = true;
                    if self.subscriptions.association {
                        self.pending_notifications
                            .push_back(FeatureNotification::AssociationChange);
                    }
                }
                ProtoEvent::HandshakeFailed { reason } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        reason.to_string(),
                    ));
                }
                ProtoEvent::AssociationLost { .. } => {
                    if self.subscriptions.shutdown {
                        self.pending_notifications.push_back(FeatureNotification::Shutdown);
                    }
                }
                ProtoEvent::DatagramReceived | ProtoEvent::Stream(_) => {}
            }
        }

        let stream_ids = self.association.stream_ids();
        for stream_id in stream_ids {
            let mut drained = Vec::new();
            {
                let mut readable = match self.association.stream(stream_id) {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                while readable.is_readable() {
                    match readable.read_sctp().map_err(proto_error)? {
                        Some(chunks) => {
                            let mut data = vec![0u8; chunks.len()];
                            let len = chunks.read(&mut data).map_err(proto_error)?;
                            data.truncate(len);
                            drained.push(UdpReceivedMessage {
                                data,
                                stream: stream_id,
                                ppid: u32::from(chunks.ppi),
                            });
                        }
                        None => break,
                    }
                }
            }
            self.pending_messages.extend(drained);
        }

        Ok(())
    }
}

struct UdpOneToManySocket {
    socket: UdpSocket,
    endpoint: Endpoint,
    udp_remote_port: u16,
    local_sctp_port: u16,
    associations: HashMap<AssociationHandle, UdpMultiAssociation>,
    targets: HashMap<SocketAddr, AssociationHandle>,
    next_assoc_id: i32,
}

struct UdpMultiAssociation {
    association: Association,
    assoc_id: i32,
    connected: bool,
}

impl UdpOneToManySocket {
    fn bind(bind_addr: SocketAddr, contract: &ScenarioContract) -> io::Result<Self> {
        let udp = udp_contract(contract)?;
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            local_sctp_port: socket.local_addr()?.port(),
            socket,
            endpoint: Endpoint::new(Arc::new(EndpointConfig::new()), None),
            udp_remote_port: udp.remote_port,
            associations: HashMap::new(),
            targets: HashMap::new(),
            next_assoc_id: 1,
        })
    }

    fn send_to_with_info(
        &mut self,
        payload: &[u8],
        target: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        let handle = self.ensure_association(target)?;
        let info =
            info.map(stored_send_info).unwrap_or(StoredSendInfo { stream: 0, flags: 0, ppid: 0 });
        let written = {
            let assoc = self.associations.get_mut(&handle).unwrap();
            let mut stream = match assoc.association.stream(info.stream) {
                Ok(stream) => stream,
                Err(_) => assoc
                    .association
                    .open_stream(info.stream, PayloadProtocolIdentifier(info.ppid))
                    .map_err(proto_error)?,
            };
            stream
                .set_reliability_params(
                    info.flags & SCTP_UNORDERED_FLAG != 0,
                    ReliabilityType::Reliable,
                    0,
                )
                .map_err(proto_error)?;
            stream
                .write_with_ppi(payload, PayloadProtocolIdentifier(info.ppid))
                .map_err(proto_error)?
        };
        self.flush_all(Instant::now())?;
        Ok(written)
    }

    fn assoc_ids(&mut self) -> io::Result<Vec<i32>> {
        self.pump(Duration::from_millis(50))?;
        Ok(self
            .associations
            .values()
            .filter(|assoc| assoc.connected)
            .map(|assoc| assoc.assoc_id)
            .collect())
    }

    fn ensure_association(&mut self, target: SocketAddr) -> io::Result<AssociationHandle> {
        if let Some(handle) = self.targets.get(&target).copied() {
            return Ok(handle);
        }
        let remote_udp = SocketAddr::new(target.ip(), self.udp_remote_port);
        let config = ProtoClientConfig::new().with_sctp_ports(self.local_sctp_port, target.port());
        let (handle, association) =
            self.endpoint.connect(config, remote_udp).map_err(proto_connect_error)?;
        let assoc_id = self.next_assoc_id;
        self.next_assoc_id += 1;
        self.associations
            .insert(handle, UdpMultiAssociation { association, assoc_id, connected: false });
        self.targets.insert(target, handle);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            self.flush_all(Instant::now())?;
            self.pump(Duration::from_millis(50))?;
            if self.associations.get(&handle).is_some_and(|assoc| assoc.connected) {
                return Ok(handle);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("timed out establishing UDP-encapsulated association to {target}"),
        ))
    }

    fn pump(&mut self, wait: Duration) -> io::Result<()> {
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 65536];
        loop {
            self.flush_all(Instant::now())?;
            match self.socket.recv_from(&mut buf) {
                Ok((n, remote)) => {
                    if let Some((handle, event)) = self.endpoint.handle(
                        Instant::now(),
                        remote,
                        None,
                        None,
                        Bytes::copy_from_slice(&buf[..n]),
                    ) {
                        let assoc = self.associations.get_mut(&handle).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected association handle",
                            )
                        })?;
                        match event {
                            DatagramEvent::AssociationEvent(event) => {
                                assoc.association.handle_event(event)
                            }
                            DatagramEvent::NewAssociation(association) => {
                                assoc.association = association
                            }
                        }
                        while let Some(event) = assoc.association.poll() {
                            match event {
                                ProtoEvent::Connected => assoc.connected = true,
                                ProtoEvent::HandshakeFailed { reason } => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        reason.to_string(),
                                    ));
                                }
                                _ => {}
                            }
                        }
                    }
                    continue;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn flush_all(&mut self, now: Instant) -> io::Result<()> {
        let handles = self.associations.keys().copied().collect::<Vec<_>>();
        for handle in handles {
            let assoc = self.associations.get_mut(&handle).unwrap();
            while let Some(timeout) = assoc.association.poll_timeout() {
                if timeout > now {
                    break;
                }
                assoc.association.handle_timeout(now);
            }
            while let Some(transmit) = assoc.association.poll_transmit(now) {
                match transmit.payload {
                    sctp_proto::Payload::RawEncode(datagrams) => {
                        for datagram in datagrams {
                            self.socket.send_to(&datagram, transmit.remote)?;
                        }
                    }
                    sctp_proto::Payload::PartialDecode(_) => {}
                }
            }
            while let Some(endpoint_event) = assoc.association.poll_endpoint_event() {
                let _ = self.endpoint.handle_event(handle, endpoint_event);
            }
        }
        Ok(())
    }
}

fn stored_send_info(info: &SctpSendInfo) -> StoredSendInfo {
    StoredSendInfo { stream: info.stream, flags: info.flags, ppid: info.ppid }
}

fn stored_pr_policy(policy: std::net::SctpPrPolicy) -> StoredPrPolicy {
    if policy.0 == SCTP_PR_POLICY_TTL {
        StoredPrPolicy::Timed
    } else if policy.0 == SCTP_PR_POLICY_RTX {
        StoredPrPolicy::Rexmit
    } else {
        let _ = SCTP_PR_POLICY_NONE;
        StoredPrPolicy::Reliable
    }
}

fn wildcard_addr_for(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
    }
}

fn udp_contract(contract: &ScenarioContract) -> io::Result<&UdpEncapsulationContract> {
    let udp = contract.udp_encapsulation.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP transport contract omitted udp_encapsulation metadata",
        )
    })?;
    if !udp.rfc.is_empty() && udp.rfc != "6951" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported UDP encapsulation RFC {:?}", udp.rfc),
        ));
    }
    if udp.remote_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP transport contract omitted a non-zero remote encapsulation port",
        ));
    }
    Ok(udp)
}

fn proto_error(err: sctp_proto::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn proto_connect_error(err: sctp_proto::ConnectError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn native_notification(notification: &impl std::fmt::Debug) -> FeatureNotification {
    let rendered = format!("{notification:?}");
    if rendered.starts_with("AssociationChange") {
        FeatureNotification::AssociationChange
    } else if rendered.starts_with("PeerAddressChange") {
        FeatureNotification::PeerAddressChange
    } else if rendered.starts_with("Shutdown") {
        FeatureNotification::Shutdown
    } else if rendered.starts_with("PartialDelivery") {
        FeatureNotification::PartialDelivery
    } else {
        FeatureNotification::Unknown
    }
}
