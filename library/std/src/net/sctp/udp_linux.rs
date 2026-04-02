use bytes::Bytes;
use sctp_proto::{
    Association, AssociationHandle, ClientConfig as ProtoClientConfig, DatagramEvent, Endpoint,
    EndpointConfig, Event as ProtoEvent, Instant as ProtoInstant, Payload,
    PayloadProtocolIdentifier, ReliabilityType,
};

use crate::collections::{HashMap, VecDeque};
use crate::io;
use crate::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SctpAssocStatus, SctpDelayedSackInfo, SctpEventMask,
    SctpInitOptions, SctpNextInfo, SctpNotification, SctpPrInfo, SctpPrPolicy, SctpReceive,
    SctpRecvInfo, SctpScheduler, SctpSendInfo, SctpUdpConfig, SocketAddr, UdpSocket,
};
use crate::sync::{Arc, Mutex};
use crate::thread;
use crate::time::{Duration, Instant};

const SCTP_STATE_CLOSED: i32 = 1;
const SCTP_STATE_COOKIE_WAIT: i32 = 2;
const SCTP_STATE_COOKIE_ECHOED: i32 = 3;
const SCTP_STATE_ESTABLISHED: i32 = 4;

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

struct UdpAssociationSocket {
    clock_origin: Instant,
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
    write_timeout: Option<Duration>,
    nonblocking: bool,
    pending_notifications: VecDeque<SctpNotification>,
    pending_messages: VecDeque<UdpReceivedMessage>,
    default_send_info: Option<StoredSendInfo>,
    default_prinfo: Option<StoredPrInfo>,
}

#[derive(Clone)]
pub(super) struct UdpSctpStream {
    inner: Arc<Mutex<UdpAssociationSocket>>,
}

impl UdpSctpStream {
    pub(super) fn connect(
        targets: &[SocketAddr],
        _opts: SctpInitOptions,
        config: &SctpUdpConfig,
    ) -> io::Result<Self> {
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty SCTP address set",
            ));
        }

        let bind_addr = wildcard_addr_for(targets[0], config.local_encap_port);
        let socket = UdpSocket::bind(bind_addr)?;
        let remote = SocketAddr::new(
            targets[0].ip(),
            config.remote_encap_port.unwrap_or(targets[0].port()),
        );
        socket.connect(remote)?;
        socket.set_nonblocking(true)?;

        let local_sctp_port = socket.local_addr()?.port();
        let endpoint = Endpoint::new(Arc::new(EndpointConfig::new()), None);
        let client_config =
            ProtoClientConfig::new().with_sctp_ports(local_sctp_port, targets[0].port());
        let clock_origin = Instant::now();
        let mut endpoint = endpoint;
        let (handle, association) = endpoint
            .connect_at(client_config, remote, proto_instant(clock_origin, clock_origin))
            .map_err(proto_connect_error)?;

        let socket_state = UdpAssociationSocket {
            clock_origin,
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
            write_timeout: None,
            nonblocking: false,
            pending_notifications: VecDeque::new(),
            pending_messages: VecDeque::new(),
            default_send_info: None,
            default_prinfo: None,
        };
        let this = Self { inner: Arc::new(Mutex::new(socket_state)) };
        {
            let mut state = this.lock();
            let deadline = Instant::now() + Duration::from_secs(10);
            state.pump_until(deadline, |stream| stream.connected)?;
        }
        Ok(this)
    }

    pub(super) fn peer_addr(&self) -> io::Result<SocketAddr> {
        let state = self.lock();
        state
            .primary_addr
            .or_else(|| state.peer_addrs.first().copied())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "SCTP association is not connected"))
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.lock().socket.local_addr()
    }

    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.local_addr()?])
    }

    pub(super) fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.lock().peer_addrs.clone())
    }

    pub(super) fn set_nodelay(&self, _on: bool) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_init_options(&self, _opts: SctpInitOptions) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.lock().subscriptions = mask;
        Ok(())
    }

    pub(super) fn send_with_info(
        &self,
        payload: &[u8],
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.lock().send(payload, info)
    }

    pub(super) fn set_rto_info(&self, _info: crate::net::SctpRtoInfo) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_delayed_sack(&self, _info: SctpDelayedSackInfo) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_default_send_info(&self, info: SctpSendInfo) -> io::Result<()> {
        self.lock().default_send_info = Some(stored_send_info(&info));
        Ok(())
    }

    pub(super) fn set_default_prinfo(&self, info: SctpPrInfo) -> io::Result<()> {
        self.lock().default_prinfo =
            Some(StoredPrInfo { policy: stored_pr_policy(info.policy), value: info.value });
        Ok(())
    }

    pub(super) fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        self.lock().recv_nxtinfo = on;
        Ok(())
    }

    pub(super) fn set_fragment_interleave(&self, _level: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_autoclose(&self, _seconds: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn bindx_add(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        let state = &mut *self.lock();
        for addr in addrs {
            if !state.peer_addrs.contains(addr) {
                state.peer_addrs.push(*addr);
            }
        }
        Ok(())
    }

    pub(super) fn bindx_remove(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        let state = &mut *self.lock();
        state.peer_addrs.retain(|addr| !addrs.contains(addr));
        if let Some(primary) = state.primary_addr {
            if addrs.contains(&primary) {
                state.primary_addr = state.peer_addrs.first().copied();
            }
        }
        Ok(())
    }

    pub(super) fn set_primary_addr(&self, addr: SocketAddr) -> io::Result<()> {
        let state = &mut *self.lock();
        if !state.peer_addrs.contains(&addr) {
            state.peer_addrs.push(addr);
        }
        state.primary_addr = Some(addr);
        Ok(())
    }

    pub(super) fn set_peer_primary_addr(&self, _addr: SocketAddr) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        Ok(vec![1])
    }

    pub(super) fn assoc_status(&self, _assoc_id: i32) -> io::Result<SctpAssocStatus> {
        let state = self.lock();
        Ok(SctpAssocStatus {
            assoc_id: 1,
            state: if state.connected {
                SCTP_STATE_ESTABLISHED
            } else if state.primary_addr.is_some() {
                SCTP_STATE_COOKIE_ECHOED
            } else {
                SCTP_STATE_COOKIE_WAIT
            },
            rwnd: 0,
            unacked_data: 0,
            pending_data: state.pending_messages.len() as u16,
            inbound_streams: 32,
            outbound_streams: 32,
            fragmentation_point: 0,
            primary_addr: state.primary_addr,
            primary_state: if state.connected { SCTP_STATE_ESTABLISHED } else { SCTP_STATE_CLOSED },
            primary_cwnd: 0,
            primary_srtt: 0,
            primary_rto: 0,
            primary_mtu: 0,
        })
    }

    pub(super) fn peeloff(&self, _assoc_id: i32) -> io::Result<Self> {
        Ok(self.clone())
    }

    pub(super) fn enable_stream_reset(&self, _flags: u16) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn reset_streams(&self, _flags: u16, _streams: &[u16]) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn add_streams(&self, _inbound: u16, _outbound: u16) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_auth_chunks(&self, _chunks: &[u8]) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_auth_key(&self, _key: &crate::net::SctpAuthKey) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn activate_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn delete_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_stream_scheduler(&self, _scheduler: SctpScheduler) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_stream_scheduler_value(&self, _stream: u16, _value: u16) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn recv_with_info(&self, buf: &mut [u8]) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        let received = self.recv_message(buf)?;
        Ok((received.len, received.info))
    }

    pub(super) fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        self.lock().recv_message(buf)
    }

    pub(super) fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().read_timeout = dur;
        Ok(())
    }

    pub(super) fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().write_timeout = dur;
        Ok(())
    }

    pub(super) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.lock().read_timeout)
    }

    pub(super) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.lock().write_timeout)
    }

    pub(super) fn shutdown(&self, how: crate::net::Shutdown) -> io::Result<()> {
        if matches!(how, crate::net::Shutdown::Read | crate::net::Shutdown::Both) {
            self.lock().connected = false;
        }
        Ok(())
    }

    pub(super) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.lock().nonblocking = nonblocking;
        Ok(())
    }

    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.lock().socket.take_error()
    }

    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    pub(super) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let message = self.recv_message(buf)?;
            if message.notification.is_none() {
                return Ok(message.len);
            }
        }
    }

    pub(super) fn read_buf(&self, cursor: crate::io::BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|buf| self.read(buf), cursor)
    }

    pub(super) fn read_vectored(&self, bufs: &mut [crate::io::IoSliceMut<'_>]) -> io::Result<usize> {
        if let Some(buf) = bufs.first_mut() {
            self.read(buf)
        } else {
            Ok(0)
        }
    }

    pub(super) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_with_info(buf, None)
    }

    pub(super) fn write_vectored(&self, bufs: &[crate::io::IoSlice<'_>]) -> io::Result<usize> {
        if let Some(buf) = bufs.first() {
            self.write(buf)
        } else {
            Ok(0)
        }
    }

    fn lock(&self) -> crate::sync::MutexGuard<'_, UdpAssociationSocket> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl UdpAssociationSocket {
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
                    info.flags & super::SCTP_UNORDERED != 0,
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

    fn recv_message(&mut self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        if let Some(notification) = self.pending_notifications.pop_front() {
            return Ok(SctpReceive { len: 0, info: None, notification: Some(notification) });
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
            return Ok(SctpReceive { len: 0, info: None, notification: Some(notification) });
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
    ) -> io::Result<SctpReceive> {
        if message.data.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer too small",
            ));
        }
        buf[..message.data.len()].copy_from_slice(&message.data);
        let next = if self.recv_nxtinfo {
            self.pending_messages.front().map(|next| SctpNextInfo {
                stream: next.stream,
                flags: 0,
                ppid: next.ppid,
                length: next.data.len() as u32,
                assoc_id: 1,
            })
        } else {
            None
        };
        Ok(SctpReceive {
            len: message.data.len(),
            notification: None,
            info: Some(SctpRecvInfo {
                stream: message.stream,
                ssn: 0,
                flags: 0,
                ppid: message.ppid,
                tsn: 0,
                cumtsn: 0,
                context: 0,
                assoc_id: 1,
                next,
            }),
        })
    }

    fn pump_until<F>(&mut self, deadline: Instant, mut ready: F) -> io::Result<()>
    where
        F: FnMut(&Self) -> bool,
    {
        let mut buf = [0u8; 65536];
        loop {
            let now = Instant::now();
            self.handle_timers(now)?;
            self.flush_transmits(now)?;
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

            if self.nonblocking {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for UDP-encapsulated SCTP progress",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn handle_timers(&mut self, now: Instant) -> io::Result<()> {
        let proto_now = proto_instant(self.clock_origin, now);
        while let Some(timeout) = self.association.poll_timeout() {
            if timeout > proto_now {
                break;
            }
            self.association.handle_timeout(proto_now);
            self.flush_transmits(now)?;
        }
        Ok(())
    }

    fn flush_transmits(&mut self, now: Instant) -> io::Result<()> {
        let proto_now = proto_instant(self.clock_origin, now);
        while let Some(transmit) = self.association.poll_transmit(proto_now) {
            match transmit.payload {
                Payload::RawEncode(datagrams) => {
                    for datagram in datagrams {
                        self.socket.send(&datagram)?;
                    }
                }
                Payload::PartialDecode(_) => {}
            }
        }
        while let Some(endpoint_event) = self.association.poll_endpoint_event() {
            let _ = self.endpoint.handle_event(self.handle, endpoint_event);
        }
        Ok(())
    }

    fn handle_datagram(&mut self, data: &[u8]) -> io::Result<()> {
        let now = Instant::now();
        let proto_now = proto_instant(self.clock_origin, now);
        let remote = self.socket.peer_addr()?;
        if let Some((handle, event)) =
            self.endpoint.handle(proto_now, remote, None, None, Bytes::copy_from_slice(data))
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
                        self.pending_notifications.push_back(SctpNotification::AssociationChange {
                            assoc_id: 1,
                            state: SCTP_STATE_ESTABLISHED as u16,
                            error: 0,
                            outbound_streams: 32,
                            inbound_streams: 32,
                        });
                    }
                }
                ProtoEvent::HandshakeFailed { reason } => {
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason.to_string()));
                }
                ProtoEvent::AssociationLost { .. } => {
                    self.connected = false;
                    if self.subscriptions.shutdown {
                        self.pending_notifications
                            .push_back(SctpNotification::Shutdown { assoc_id: 1 });
                    }
                }
                ProtoEvent::DatagramReceived | ProtoEvent::Stream(_) => {}
                _ => {}
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
    clock_origin: Instant,
    socket: UdpSocket,
    endpoint: Endpoint,
    udp_remote_port: Option<u16>,
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

#[derive(Clone)]
pub(super) struct UdpSctpSocket {
    inner: Arc<Mutex<UdpOneToManySocket>>,
}

impl UdpSctpSocket {
    pub(super) fn bind(bind_addr: SocketAddr, config: &SctpUdpConfig) -> io::Result<Self> {
        let bind_addr = with_port(bind_addr, config.local_encap_port.unwrap_or(bind_addr.port()));
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(UdpOneToManySocket {
                clock_origin: Instant::now(),
                local_sctp_port: socket.local_addr()?.port(),
                socket,
                endpoint: Endpoint::new(Arc::new(EndpointConfig::new()), None),
                udp_remote_port: config.remote_encap_port,
                associations: HashMap::new(),
                targets: HashMap::new(),
                next_assoc_id: 1,
            })),
        })
    }

    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.lock().socket.local_addr()?])
    }

    pub(super) fn set_init_options(&self, _opts: SctpInitOptions) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn subscribe_events(&self, _mask: SctpEventMask) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_autoclose(&self, _seconds: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn send_to_with_info(
        &self,
        payload: &[u8],
        target: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.lock().send_to_with_info(payload, target, info)
    }

    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        self.lock().assoc_ids()
    }

    pub(super) fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    fn lock(&self) -> crate::sync::MutexGuard<'_, UdpOneToManySocket> {
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl UdpOneToManySocket {
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
                    info.flags & super::SCTP_UNORDERED != 0,
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
        let remote_udp_port = self.udp_remote_port.unwrap_or(target.port());
        let remote_udp = SocketAddr::new(target.ip(), remote_udp_port);
        let config = ProtoClientConfig::new().with_sctp_ports(self.local_sctp_port, target.port());
        let now = Instant::now();
        let (handle, association) = self
            .endpoint
            .connect_at(config, remote_udp, proto_instant(self.clock_origin, now))
            .map_err(proto_connect_error)?;
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
            "timed out establishing UDP-encapsulated association",
        ))
    }

    fn pump(&mut self, wait: Duration) -> io::Result<()> {
        let deadline = Instant::now() + wait;
        let mut buf = [0u8; 65536];
        loop {
            self.flush_all(Instant::now())?;
            match self.socket.recv_from(&mut buf) {
                Ok((n, remote)) => {
                    let now = Instant::now();
                    if let Some((handle, event)) = self.endpoint.handle(
                        proto_instant(self.clock_origin, now),
                        remote,
                        None,
                        None,
                        Bytes::copy_from_slice(&buf[..n]),
                    ) {
                        let assoc = self.associations.get_mut(&handle).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "unexpected association handle")
                        })?;
                        match event {
                            DatagramEvent::AssociationEvent(event) => assoc.association.handle_event(event),
                            DatagramEvent::NewAssociation(association) => assoc.association = association,
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
        let proto_now = proto_instant(self.clock_origin, now);
        let handles = self.associations.keys().copied().collect::<Vec<_>>();
        for handle in handles {
            let assoc = self.associations.get_mut(&handle).unwrap();
            while let Some(timeout) = assoc.association.poll_timeout() {
                if timeout > proto_now {
                    break;
                }
                assoc.association.handle_timeout(proto_now);
            }
            while let Some(transmit) = assoc.association.poll_transmit(proto_now) {
                match transmit.payload {
                    Payload::RawEncode(datagrams) => {
                        for datagram in datagrams {
                            self.socket.send_to(&datagram, transmit.remote)?;
                        }
                    }
                    Payload::PartialDecode(_) => {}
                }
            }
            while let Some(endpoint_event) = assoc.association.poll_endpoint_event() {
                let _ = self.endpoint.handle_event(handle, endpoint_event);
            }
        }
        Ok(())
    }
}

pub(super) struct UdpSctpListener {
    socket: UdpSocket,
}

impl UdpSctpListener {
    pub(super) fn bind(bind_addr: SocketAddr, config: &SctpUdpConfig) -> io::Result<Self> {
        let bind_addr = with_port(bind_addr, config.local_encap_port.unwrap_or(bind_addr.port()));
        Ok(Self { socket: UdpSocket::bind(bind_addr)? })
    }

    pub(super) fn accept(&self) -> io::Result<(UdpSctpStream, SocketAddr)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP-encapsulated SCTP listener accept is not implemented",
        ))
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.socket.local_addr()?])
    }

    pub(super) fn set_init_options(&self, _opts: SctpInitOptions) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn subscribe_events(&self, _mask: SctpEventMask) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_rto_info(&self, _info: crate::net::SctpRtoInfo) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_delayed_sack(&self, _info: SctpDelayedSackInfo) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }

    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.socket.take_error()
    }

    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self { socket: self.socket.try_clone()? })
    }
}

fn stored_send_info(info: &SctpSendInfo) -> StoredSendInfo {
    StoredSendInfo { stream: info.stream, flags: info.flags, ppid: info.ppid }
}

fn stored_pr_policy(policy: SctpPrPolicy) -> StoredPrPolicy {
    if policy.0 == super::SCTP_PR_TTL.0 {
        StoredPrPolicy::Timed
    } else if policy.0 == super::SCTP_PR_RTX.0 {
        StoredPrPolicy::Rexmit
    } else {
        StoredPrPolicy::Reliable
    }
}

fn wildcard_addr_for(target: SocketAddr, port: Option<u16>) -> SocketAddr {
    match target.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port.unwrap_or(0))),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, port.unwrap_or(0))),
    }
}

fn with_port(mut addr: SocketAddr, port: u16) -> SocketAddr {
    addr.set_port(port);
    addr
}

fn proto_instant(origin: Instant, now: Instant) -> ProtoInstant {
    ProtoInstant::from_duration(now.duration_since(origin))
}

fn proto_error(err: sctp_proto::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

fn proto_connect_error(err: sctp_proto::ConnectError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}
