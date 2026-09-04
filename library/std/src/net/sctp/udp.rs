//! Shared, synchronous socket adapter for the sans-I/O SCTP engine.
//!
//! One worker drives each endpoint independently of application reads. In particular,
//! an accepted association never takes ownership of or connects the listening UDP socket.

impl UdpSctpStream {
    pub(super) fn set_delayed_sack(&self, _info: SctpDelayedSackInfo) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_fragment_interleave(&self, _level: u32) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn bindx_add(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn bindx_remove(&self, _addrs: &[SocketAddr]) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_primary_addr(&self, _addr: SocketAddr) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_peer_primary_addr(&self, _addr: SocketAddr) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn enable_stream_reset(&self, _flags: u16) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn reset_streams(&self, _flags: u16, _streams: &[u16]) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn add_streams(&self, _inbound: u16, _outbound: u16) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_auth_chunks(&self, _chunks: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_auth_key(&self, _key: &SctpAuthKey) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn activate_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn delete_auth_key(&self, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_stream_scheduler(&self, _scheduler: SctpScheduler) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_stream_scheduler_value(&self, _stream: u16, _value: u16) -> io::Result<()> {
        Err(unsupported())
    }
}
impl UdpSctpListener {
    pub(super) fn set_delayed_sack(&self, _info: SctpDelayedSackInfo) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }
}

use super::*;
use crate::collections::{HashMap, VecDeque};
use crate::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use crate::sync::{Arc, Condvar, Mutex, MutexGuard};
use crate::thread;
use crate::time::Instant;
use bytes::Bytes;
use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ReliabilityType, ServerConfig, TransportConfig,
};

const QUEUE_BYTES: usize = 1024 * 1024;
const MAX_ASSOCIATIONS: usize = 128;
const TICK: Duration = Duration::from_millis(10);

pub(super) fn unsupported() -> io::Error {
    io::const_error!(io::ErrorKind::Unsupported, "operation is not supported by SCTP over UDP")
}

fn proto_error(e: impl fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[derive(Clone)]
struct Failure(io::ErrorKind, String);
impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.0, self.1.clone())
    }
    fn from_error(e: io::Error) -> Self {
        Self(e.kind(), e.to_string())
    }
}

#[derive(Clone, Copy, Default)]
struct Options {
    init: SctpInitOptions,
    rto: SctpRtoInfo,
    events: SctpEventMask,
    send: SctpSendInfo,
    pr: SctpPrInfo,
    next: bool,
    nonblocking: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    autoclose: u32,
}

impl Options {
    fn transport(&self) -> TransportConfig {
        let mut c = TransportConfig::default().with_random_source(crate::sys::random::fill_bytes);
        if self.init.num_ostreams != 0 {
            c = c.with_max_num_outbound_streams(self.init.num_ostreams);
        }
        if self.init.max_instreams != 0 {
            c = c.with_max_num_inbound_streams(self.init.max_instreams);
        }
        if self.init.max_attempts != 0 {
            c = c.with_max_init_retransmits(Some(self.init.max_attempts as usize));
        }
        if self.init.max_init_timeout != 0 {
            c = c.with_max_init_timeout_ms(self.init.max_init_timeout as u64);
        }
        if self.rto.initial != 0 {
            c = c.with_rto_initial_ms(self.rto.initial as u64);
        }
        if self.rto.min != 0 {
            c = c.with_rto_min_ms(self.rto.min as u64);
        }
        if self.rto.max != 0 {
            c = c.with_rto_max_ms(self.rto.max as u64);
        }
        c
    }
}

struct Message {
    data: Vec<u8>,
    offset: usize,
    info: SctpRecvInfo,
}

struct Session {
    protocol: Association,
    handle: AssociationHandle,
    peer: SocketAddr,
    remote_udp: SocketAddr,
    socket_index: usize,
    options: Options,
    connected: bool,
    incoming: bool,
    accepted: bool,
    detached: bool,
    leased: bool,
    endpoint_drained: bool,
    closed: bool,
    read_closed: bool,
    write_closed: bool,
    messages: VecDeque<Message>,
    notifications: VecDeque<SctpNotification>,
    queued_bytes: usize,
    failure: Option<Failure>,
    pending_error: Option<Failure>,
    last_activity: Instant,
}

struct State {
    sockets: Vec<UdpSocket>,
    local: Vec<SocketAddr>,
    config: SctpUdpConfig,
    options: Options,
    endpoint: Endpoint,
    server: bool,
    origin: Instant,
    sessions: HashMap<i32, Session>,
    handles: HashMap<AssociationHandle, i32>,
    incoming: VecDeque<i32>,
    transmits: VecDeque<(usize, SocketAddr, Bytes)>,
    next_id: i32,
    error: Option<Failure>,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Clone)]
pub(super) struct UdpSctpSocket {
    shared: Arc<Shared>,
}

pub(super) struct UdpSctpListener {
    socket: UdpSctpSocket,
    lease: Arc<ListenerLease>,
}

struct ListenerLease(UdpSctpSocket);
impl Drop for ListenerLease {
    fn drop(&mut self) {
        self.0.stop_accepting();
    }
}

struct StreamLease {
    socket: UdpSctpSocket,
    id: i32,
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        let mut state = self.socket.lock();
        if let Some(s) = state.sessions.get_mut(&self.id) {
            s.leased = false;
            s.write_closed = true;
            s.read_closed = true;
            s.messages.clear();
            s.queued_bytes = 0;
            let _ = s.protocol.shutdown();
        }
        self.socket.shared.changed.notify_all();
    }
}

#[derive(Clone)]
pub(super) struct UdpSctpStream {
    lease: Arc<StreamLease>,
}

pub(super) fn validate_timeout(d: Option<Duration>) -> io::Result<()> {
    if d == Some(Duration::ZERO) {
        Err(io::const_error!(io::ErrorKind::InvalidInput, "zero timeout is not allowed"))
    } else {
        Ok(())
    }
}

pub(super) fn validate_events(mask: SctpEventMask) -> io::Result<()> {
    // These events cannot be synthesized from this engine. Never promise delivery.
    if mask.address
        || mask.send_failure
        || mask.peer_error
        || mask.adaptation
        || mask.authentication
        || mask.partial_delivery
        || mask.sender_dry
        || mask.stream_reset
    {
        return Err(unsupported());
    }
    Ok(())
}

pub(super) fn validate_rto(info: SctpRtoInfo) -> io::Result<()> {
    let min = if info.min == 0 { 1000 } else { info.min };
    let max = if info.max == 0 { 60000 } else { info.max };
    if min > max || (info.initial != 0 && !(min..=max).contains(&info.initial)) {
        Err(io::const_error!(io::ErrorKind::InvalidInput, "invalid SCTP RTO interval"))
    } else {
        Ok(())
    }
}

fn merge_rto(old: SctpRtoInfo, new: SctpRtoInfo) -> io::Result<SctpRtoInfo> {
    let info = SctpRtoInfo {
        assoc_id: new.assoc_id,
        initial: if new.initial != 0 {
            new.initial
        } else if old.initial != 0 {
            old.initial
        } else {
            3000
        },
        min: if new.min != 0 {
            new.min
        } else if old.min != 0 {
            old.min
        } else {
            1000
        },
        max: if new.max != 0 {
            new.max
        } else if old.max != 0 {
            old.max
        } else {
            60000
        },
    };
    validate_rto(info)?;
    Ok(info)
}

impl UdpSctpSocket {
    pub(super) fn bind_multi(
        addrs: &[SocketAddr],
        config: &SctpUdpConfig,
        server: bool,
    ) -> io::Result<Self> {
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty address set"));
        }
        let mut sockets = Vec::new();
        let mut local = Vec::new();
        let mut port = config.local_encap_port.unwrap_or(addrs[0].port());
        for addr in addrs {
            let udp_addr = SocketAddr::new(addr.ip(), port);
            let socket = net_imp::UdpSocket::bind_sctp_encapsulation(udp_addr, config.reuse_port)?;
            let socket = UdpSocket::from_inner(socket);
            socket.set_nonblocking(true)?;
            port = socket.local_addr()?.port();
            local.push(SocketAddr::new(
                addr.ip(),
                if addr.port() == 0 { port } else { addr.port() },
            ));
            sockets.push(socket);
        }
        let options = Options::default();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                sockets,
                local,
                config: *config,
                options,
                endpoint: Endpoint::new(
                    Arc::new(
                        EndpointConfig::new().with_random_source(crate::sys::random::fill_bytes),
                    ),
                    if server {
                        let mut s = ServerConfig::new();
                        s.transport = Arc::new(options.transport());
                        Some(Arc::new(s))
                    } else {
                        None
                    },
                ),
                server,
                origin: Instant::now(),
                sessions: HashMap::new(),
                handles: HashMap::new(),
                incoming: VecDeque::new(),
                transmits: VecDeque::new(),
                next_id: 1,
                error: None,
            }),
            changed: Condvar::new(),
        });
        let worker = shared.clone();
        thread::Builder::new().name("sctp-udp".into()).spawn(move || {
            let shared = worker;
            let mut orphaned = None;
            loop {
                let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
                if Arc::strong_count(&shared) == 1 {
                    let since = *orphaned.get_or_insert_with(Instant::now);
                    if state.sessions.values().all(|s| s.closed)
                        || since.elapsed() >= Duration::from_secs(5)
                    {
                        break;
                    }
                    for s in state.sessions.values_mut() {
                        if s.connected && !s.write_closed {
                            let _ = s.protocol.shutdown();
                            s.write_closed = true;
                        }
                    }
                }
                if let Err(e) = state.pump() {
                    state.error = Some(Failure::from_error(e));
                }
                shared.changed.notify_all();
                let (guard, _) =
                    shared.changed.wait_timeout(state, TICK).unwrap_or_else(|e| e.into_inner());
                drop(guard);
            }
        })?;
        Ok(Self { shared })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.shared.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn stop_accepting(&self) {
        let mut state = self.lock();
        state.server = false;
        state.endpoint.set_server_config(None);
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, State>,
        deadline: Option<Instant>,
    ) -> io::Result<MutexGuard<'a, State>> {
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::const_error!(io::ErrorKind::TimedOut, "SCTP operation timed out"));
            }
            Ok(self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0)
        } else {
            Ok(self.shared.changed.wait(state).unwrap_or_else(|e| e.into_inner()))
        }
    }

    fn update_options(&self, f: impl FnOnce(&mut Options) -> io::Result<()>) -> io::Result<()> {
        let mut state = self.lock();
        f(&mut state.options)?;
        if state.server {
            let mut config = ServerConfig::new();
            config.transport = Arc::new(state.options.transport());
            state.endpoint.set_server_config(Some(Arc::new(config)));
        }
        self.shared.changed.notify_all();
        Ok(())
    }

    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.lock().local.clone())
    }
    pub(super) fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.update_options(|o| {
            o.init = opts;
            Ok(())
        })
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        validate_events(mask)?;
        let mut state = self.lock();
        state.options.events = mask;
        for s in state.sessions.values_mut() {
            s.options.events = mask;
        }
        Ok(())
    }
    pub(super) fn check_rto(&self, info: SctpRtoInfo) -> io::Result<()> {
        let state = self.lock();
        if info.assoc_id != 0 {
            state.session(info.assoc_id)?;
        }
        merge_rto(state.options.rto, info)?;
        for (id, s) in &state.sessions {
            if info.assoc_id == 0 || info.assoc_id == *id {
                merge_rto(s.options.rto, info)?;
            }
        }
        Ok(())
    }

    pub(super) fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        let mut state = self.lock();
        if info.assoc_id != 0 {
            state.session(info.assoc_id)?;
        }
        let endpoint_rto = merge_rto(state.options.rto, info)?;
        for (id, s) in &state.sessions {
            if info.assoc_id == 0 || info.assoc_id == *id {
                merge_rto(s.options.rto, info)?;
            }
        }
        if info.assoc_id == 0 {
            state.options.rto = endpoint_rto;
        }
        for (id, s) in &mut state.sessions {
            if info.assoc_id == 0 || info.assoc_id == *id {
                let rto = merge_rto(s.options.rto, info)?;
                s.options.rto = rto;
                s.protocol.configure_rto(rto.initial as u64, rto.min as u64, rto.max as u64);
            }
        }
        drop(state);
        self.update_options(|_| Ok(()))?;
        Ok(())
    }
    pub(super) fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        let mut state = self.lock();
        state.options.autoclose = seconds;
        for s in state.sessions.values_mut() {
            s.options.autoclose = seconds;
        }
        Ok(())
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.update_options(|o| {
            o.nonblocking = on;
            Ok(())
        })
    }
    pub(super) fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        validate_timeout(d)?;
        self.update_options(|o| {
            o.read_timeout = d;
            Ok(())
        })
    }
    pub(super) fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        validate_timeout(d)?;
        self.update_options(|o| {
            o.write_timeout = d;
            Ok(())
        })
    }
    pub(super) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.lock().options.read_timeout)
    }
    pub(super) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.lock().options.write_timeout)
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(self.lock().error.take().map(|e| e.error()))
    }
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }

    pub(super) fn start_connect(&self, peer: SocketAddr) -> io::Result<i32> {
        let mut state = self.lock();
        if let Some((id, _)) =
            state.sessions.iter().find(|(_, s)| s.peer == peer && !s.closed && !s.detached)
        {
            return Ok(*id);
        }
        if state.sessions.len() >= MAX_ASSOCIATIONS {
            return Err(io::const_error!(
                io::ErrorKind::OutOfMemory,
                "SCTP association limit reached"
            ));
        }
        let remote =
            SocketAddr::new(peer.ip(), state.config.remote_encap_port.unwrap_or(peer.port()));
        let mut config = ClientConfig::new().with_sctp_ports(state.local[0].port(), peer.port());
        config.transport = Arc::new(state.options.transport());
        let now = state.now();
        let (handle, protocol) =
            state.endpoint.connect_at(config, remote, now).map_err(proto_error)?;
        let id = state.insert(protocol, handle, peer, remote, 0, false)?;
        self.shared.changed.notify_all();
        Ok(id)
    }

    pub(super) fn connection_state(&self, id: i32) -> io::Result<bool> {
        let state = self.lock();
        if let Some(e) = &state.error {
            return Err(e.error());
        }
        let s = state.session(id)?;
        if let Some(e) = &s.failure { Err(e.error()) } else { Ok(s.connected && !s.closed) }
    }

    pub(super) fn discard_failed(&self, id: i32) {
        let mut state = self.lock();
        if !state.sessions.get(&id).is_some_and(|s| s.closed && !s.leased) {
            return;
        }
        if let Some(mut s) = state.sessions.remove(&id) {
            if !s.endpoint_drained {
                s.protocol.drain_endpoint();
                if let Some(event) = s.protocol.poll_endpoint_event() {
                    state.endpoint.handle_event(s.handle, event);
                }
            }
            state.handles.remove(&s.handle);
            state.incoming.retain(|incoming| *incoming != id);
        }
    }

    fn wait_connected(&self, id: i32, nonblocking: bool) -> io::Result<()> {
        let mut state = self.lock();
        loop {
            let s = state.session(id)?;
            if let Some(e) = &state.error {
                return Err(e.error());
            }
            if let Some(e) = &s.failure {
                return Err(e.error());
            }
            if s.connected {
                return Ok(());
            }
            if nonblocking {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "SCTP association is connecting"
                ));
            }
            state = self.wait(state, None)?;
        }
    }

    fn stream(&self, id: i32) -> UdpSctpStream {
        let mut state = self.lock();
        if let Some(s) = state.sessions.get_mut(&id) {
            s.leased = true;
            s.detached = true;
        }
        drop(state);
        UdpSctpStream { lease: Arc::new(StreamLease { socket: self.clone(), id }) }
    }

    pub(super) fn connect_stream(&self, targets: &[SocketAddr]) -> io::Result<UdpSctpStream> {
        let mut error = io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set");
        for &peer in targets {
            let id = self.start_connect(peer)?;
            match self.wait_connected(id, false) {
                Ok(()) => return Ok(self.stream(id)),
                Err(e) => {
                    self.discard_failed(id);
                    error = e;
                }
            }
        }
        Err(error)
    }

    pub(super) fn send_to_with_info(
        &self,
        data: &[u8],
        peer: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        let id = if let Some(info) = info.filter(|i| i.assoc_id != 0) {
            let state = self.lock();
            let s = state.session(info.assoc_id)?;
            if s.peer != peer || s.detached {
                return Err(io::const_error!(
                    io::ErrorKind::InvalidInput,
                    "association does not belong to this peer/socket"
                ));
            }
            info.assoc_id
        } else {
            self.start_connect(peer)?
        };
        let options = self.lock().options;
        if let Err(error) = self.wait_connected(id, options.nonblocking) {
            if error.kind() != io::ErrorKind::WouldBlock { self.discard_failed(id); }
            return Err(error);
        }
        self.send(id, data, info, options)
    }

    fn send(
        &self,
        id: i32,
        data: &[u8],
        info: Option<&SctpSendInfo>,
        options: Options,
    ) -> io::Result<usize> {
        let deadline = options.write_timeout.map(|d| Instant::now() + d);
        let mut state = self.lock();
        loop {
            let s = state.session_mut(id)?;
            if let Some(e) = &s.failure {
                return Err(e.error());
            }
            if s.write_closed || s.closed {
                return Err(io::const_error!(
                    io::ErrorKind::BrokenPipe,
                    "SCTP write side is closed"
                ));
            }
            if !s.connected {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "SCTP association is connecting"
                ));
            }
            let info = info.copied().unwrap_or(s.options.send);
            if info.flags & !SCTP_UNORDERED != 0 {
                return Err(unsupported());
            }
            if info.assoc_id != 0 && info.assoc_id != id {
                return Err(io::const_error!(io::ErrorKind::InvalidInput, "wrong association id"));
            }
            let pr = s.options.pr;
            let reliability = match pr.policy {
                SCTP_PR_NONE => ReliabilityType::Reliable,
                SCTP_PR_TTL => ReliabilityType::Timed,
                SCTP_PR_RTX => ReliabilityType::Rexmit,
                _ => return Err(unsupported()),
            };
            if s.protocol.stream(info.stream).is_err() {
                s.protocol
                    .open_stream(info.stream, PayloadProtocolIdentifier(u32::from_be(info.ppid)))
                    .map_err(proto_error)?;
            }
            let mut stream = s.protocol.stream(info.stream).map_err(proto_error)?;
            if stream.buffered_amount().map_err(proto_error)? < QUEUE_BYTES {
                stream
                    .set_reliability_params(info.flags & SCTP_UNORDERED != 0, reliability, pr.value)
                    .map_err(proto_error)?;
                // Preserve the native socket API's opaque, network-byte-order PPID.
                let n = stream
                    .write_with_ppi(data, PayloadProtocolIdentifier(u32::from_be(info.ppid)))
                    .map_err(proto_error)?;
                s.last_activity = Instant::now();
                self.shared.changed.notify_all();
                return Ok(n);
            }
            if options.nonblocking {
                return Err(io::const_error!(io::ErrorKind::WouldBlock, "SCTP send queue is full"));
            }
            state = self.wait(state, deadline)?;
        }
    }

    fn receive(
        &self,
        id: Option<i32>,
        buf: &mut [u8],
        options: Options,
    ) -> io::Result<SctpReceiveFrom> {
        let deadline = options.read_timeout.map(|d| Instant::now() + d);
        let mut state = self.lock();
        loop {
            let selected = id.or_else(|| {
                state
                    .sessions
                    .iter()
                    .filter(|(_, s)| !s.detached)
                    .find(|(_, s)| {
                        !s.messages.is_empty() || !s.notifications.is_empty() || (s.connected && s.failure.is_some())
                    })
                    .map(|(id, _)| *id)
            });
            if let Some(id) = selected {
                let s = state.session_mut(id)?;
                let peer = s.peer;
                if let Some(notification) = s.notifications.pop_front() {
                    return Ok(SctpReceiveFrom {
                        peer_addr: Some(peer),
                        receive: SctpReceive {
                            len: 0,
                            info: None,
                            notification: Some(notification),
                            flags: Default::default(),
                        },
                    });
                }
                if let Some(m) = s.messages.front_mut() {
                    let n = buf.len().min(m.data.len() - m.offset);
                    buf[..n].copy_from_slice(&m.data[m.offset..m.offset + n]);
                    m.offset += n;
                    let done = m.offset == m.data.len();
                    let mut info = m.info;
                    s.queued_bytes -= n;
                    if done {
                        s.messages.pop_front();
                    }
                    if s.options.next {
                        info.next = s.messages.front().map(|m| SctpNextInfo {
                            stream: m.info.stream,
                            flags: m.info.flags,
                            ppid: m.info.ppid,
                            length: (m.data.len() - m.offset) as u32,
                            assoc_id: id,
                        });
                    }
                    s.last_activity = Instant::now();
                    self.shared.changed.notify_all();
                    return Ok(SctpReceiveFrom {
                        peer_addr: Some(peer),
                        receive: SctpReceive {
                            len: n,
                            info: Some(info),
                            notification: None,
                            flags: SctpReceiveFlags { end_of_record: done, ..Default::default() },
                        },
                    });
                }
                if let Some(e) = &s.failure {
                    let error = e.error();
                    if !s.leased {
                        s.failure = None;
                    }
                    return Err(error);
                }
                if s.closed || s.read_closed {
                    return Ok(SctpReceiveFrom {
                        peer_addr: Some(peer),
                        receive: SctpReceive {
                            len: 0,
                            info: None,
                            notification: None,
                            flags: Default::default(),
                        },
                    });
                }
            }
            if let Some(e) = &state.error {
                return Err(e.error());
            }
            if options.nonblocking {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "no SCTP message available"
                ));
            }
            state = self.wait(state, deadline)?;
        }
    }

    pub(super) fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceiveFrom> {
        let o = self.lock().options;
        self.receive(None, buf, o)
    }
    pub(super) fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<SctpRecvInfo>, Option<SocketAddr>)> {
        let r = self.recv_message(buf)?;
        Ok((r.receive.len, r.receive.info, r.peer_addr))
    }
    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        Ok(self
            .lock()
            .sessions
            .iter()
            .filter(|(_, s)| s.connected && !s.closed && !s.detached)
            .map(|(id, _)| *id)
            .collect())
    }
    pub(super) fn assoc_status(&self, id: i32) -> io::Result<SctpAssocStatus> {
        let state = self.lock();
        let id = if id == 0 && state.sessions.len() == 1 {
            *state.sessions.keys().next().unwrap()
        } else {
            id
        };
        let s = state.session(id)?;
        let p = s.protocol.socket_status();
        Ok(SctpAssocStatus {
            assoc_id: id,
            state: if s.closed {
                if cfg!(target_os = "freebsd") { 0 } else { 1 }
            } else if s.connected {
                if cfg!(target_os = "freebsd") { 8 } else { 4 }
            } else {
                2
            },
            rwnd: p.0,
            unacked_data: p.1,
            pending_data: p.2,
            inbound_streams: p.3,
            outbound_streams: p.4,
            fragmentation_point: p.5,
            primary_addr: Some(s.peer),
            primary_state: if s.closed { 0 } else { 1 },
            primary_cwnd: p.6,
            primary_srtt: p.7,
            primary_rto: p.8,
            primary_mtu: p.9,
        })
    }
    pub(super) fn peeloff(&self, id: i32) -> io::Result<UdpSctpStream> {
        let mut state = self.lock();
        let s = state.session_mut(id)?;
        if s.detached {
            return Err(io::const_error!(
                io::ErrorKind::NotFound,
                "association already peeled off"
            ));
        }
        s.detached = true;
        drop(state);
        Ok(self.stream(id))
    }
}

impl State {
    fn now(&self) -> sctp_proto::Instant {
        sctp_proto::Instant::from_duration(self.origin.elapsed())
    }
    fn session(&self, id: i32) -> io::Result<&Session> {
        self.sessions.get(&id).ok_or_else(|| {
            io::const_error!(io::ErrorKind::NotConnected, "unknown SCTP association")
        })
    }
    fn session_mut(&mut self, id: i32) -> io::Result<&mut Session> {
        self.sessions.get_mut(&id).ok_or_else(|| {
            io::const_error!(io::ErrorKind::NotConnected, "unknown SCTP association")
        })
    }
    fn insert(
        &mut self,
        protocol: Association,
        handle: AssociationHandle,
        peer: SocketAddr,
        remote_udp: SocketAddr,
        socket_index: usize,
        incoming: bool,
    ) -> io::Result<i32> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or_else(|| {
            io::const_error!(io::ErrorKind::OutOfMemory, "SCTP association ids exhausted")
        })?;
        self.handles.insert(handle, id);
        self.sessions.insert(
            id,
            Session {
                protocol,
                handle,
                peer,
                remote_udp,
                socket_index,
                options: self.options,
                connected: false,
                incoming,
                accepted: false,
                detached: false,
                leased: false,
                endpoint_drained: false,
                closed: false,
                read_closed: false,
                write_closed: false,
                messages: VecDeque::new(),
                notifications: VecDeque::new(),
                queued_bytes: 0,
                failure: None,
                pending_error: None,
                last_activity: Instant::now(),
            },
        );
        Ok(id)
    }

    fn pump(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 65536];
        for index in 0..self.sockets.len() {
            for _ in 0..64 {
                let (n, remote) = match self.sockets[index].recv_from(&mut buf) {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if n < 12 || u16::from_be_bytes([buf[2], buf[3]]) != self.local[index].port() {
                    continue;
                }
                let peer = SocketAddr::new(remote.ip(), u16::from_be_bytes([buf[0], buf[1]]));
                if self.sessions.len() >= MAX_ASSOCIATIONS && buf[4..8] == [0, 0, 0, 0] {
                    continue;
                }
                if let Some((handle, event)) = self.endpoint.handle(
                    self.now(),
                    remote,
                    Some(self.local[index].ip()),
                    None,
                    Bytes::copy_from_slice(&buf[..n]),
                ) {
                    match event {
                        DatagramEvent::NewAssociation(protocol) => {
                            self.insert(protocol, handle, peer, remote, index, true)?;
                        }
                        DatagramEvent::AssociationEvent(event) => {
                            if let Some(id) = self.handles.get(&handle) {
                                if let Some(s) = self.sessions.get_mut(id) {
                                    if s.remote_udp == remote && s.peer == peer {
                                        s.protocol.handle_event(event);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let now = self.now();
        for (&id, s) in &mut self.sessions {
            if s.options.autoclose != 0
                && s.connected
                && !s.write_closed
                && s.last_activity.elapsed() >= Duration::from_secs(s.options.autoclose as u64)
            {
                s.write_closed = true;
                let _ = s.protocol.shutdown();
            }
            while s.protocol.poll_timeout().is_some_and(|t| t <= now) {
                s.protocol.handle_timeout(now);
            }
            while let Some(event) = s.protocol.poll() {
                match event {
                    Event::Connected => {
                        s.connected = true;
                        if s.incoming && !s.accepted {
                            s.accepted = true;
                            self.incoming.push_back(id);
                        }
                        if s.options.events.association {
                            let p = s.protocol.socket_status();
                            // SCTP_COMM_UP is a notification state, not SCTP_ESTABLISHED.
                            s.notifications.push_back(SctpNotification::AssociationChange {
                                assoc_id: id,
                                state: if cfg!(target_os = "freebsd") { 1 } else { 0 },
                                error: 0,
                                outbound_streams: p.4,
                                inbound_streams: p.3,
                            });
                        }
                    }
                    Event::HandshakeFailed { reason } => {
                        let failure = Failure(io::ErrorKind::ConnectionAborted, reason.to_string());
                        s.pending_error = Some(failure.clone());
                        s.failure = Some(failure);
                        s.closed = true;
                        let _ = s.protocol.close();
                        // A failed unsolicited handshake is not an endpoint-wide
                        // receive error and must not poison unrelated peers.
                        if s.incoming && !s.connected {
                            s.failure = None;
                        }
                    }
                    _ => {}
                }
            }
            for stream_id in s.protocol.stream_ids() {
                if s.queued_bytes >= QUEUE_BYTES || s.read_closed {
                    break;
                }
                let mut stream = s.protocol.stream(stream_id).map_err(proto_error)?;
                while s.queued_bytes < QUEUE_BYTES && stream.is_readable() {
                    let Some(chunks) = stream.read_sctp().map_err(proto_error)? else {
                        break;
                    };
                    let mut data = vec![0; chunks.len()];
                    chunks.read(&mut data).map_err(proto_error)?;
                    let (ssn, tsn, unordered) = chunks.receive_metadata();
                    let info = SctpRecvInfo {
                        stream: stream_id,
                        ppid: chunks.ppi.0.to_be(),
                        assoc_id: id,
                        ssn,
                        tsn,
                        flags: if unordered { SCTP_UNORDERED } else { 0 },
                        ..Default::default()
                    };
                    s.queued_bytes += data.len();
                    s.last_activity = Instant::now();
                    s.messages.push_back(Message { data, offset: 0, info });
                }
            }
            while self.transmits.len() < 1024 {
                let Some(tx) = s.protocol.poll_transmit(now) else {
                    break;
                };
                if let Payload::RawEncode(datagrams) = tx.payload {
                    for bytes in datagrams {
                        self.transmits.push_back((s.socket_index, tx.remote, bytes));
                    }
                }
            }
            if s.connected && s.protocol.is_closed() && !s.closed {
                s.closed = true;
                if s.options.events.shutdown {
                    s.notifications.push_back(SctpNotification::Shutdown { assoc_id: id });
                }
            }
            while s.closed && !s.endpoint_drained {
                // The engine may mark an endpoint drained when shutdown starts. Keep
                // routing until the association has finished its wire shutdown.
                s.protocol.drain_endpoint();
                let Some(event) = s.protocol.poll_endpoint_event() else {
                    break;
                };
                let _ = self.endpoint.handle_event(s.handle, event);
                s.endpoint_drained = true;
                self.handles.remove(&s.handle);
            }
        }
        while self.transmits.len() < 1024 {
            let Some(tx) = self.endpoint.poll_transmit() else {
                break;
            };
            let index =
                self.local.iter().position(|a| a.is_ipv4() == tx.remote.is_ipv4()).unwrap_or(0);
            if let Payload::RawEncode(datagrams) = tx.payload {
                for bytes in datagrams {
                    self.transmits.push_back((index, tx.remote, bytes));
                }
            }
        }
        while let Some((index, remote, bytes)) = self.transmits.front() {
            match self.sockets[*index].send_to(bytes, *remote) {
                Ok(_) => {
                    self.transmits.pop_front();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.transmits.pop_front();
                    return Err(e);
                }
            }
        }
        // Keep live stream leases and unread evidence, but reclaim completed
        // one-to-many associations so reconnects do not exhaust the endpoint.
        self.sessions.retain(|_, s| {
            !(s.closed
                && s.endpoint_drained
                && !s.leased
                && s.messages.is_empty()
                && s.notifications.is_empty()
                && s.failure.is_none())
        });
        self.incoming.retain(|id| self.sessions.contains_key(id));
        Ok(())
    }
}

impl UdpSctpListener {
    pub(super) fn bind_multi(addrs: &[SocketAddr], config: &SctpUdpConfig) -> io::Result<Self> {
        let socket = UdpSctpSocket::bind_multi(addrs, config, true)?;
        Ok(Self { lease: Arc::new(ListenerLease(socket.clone())), socket })
    }
    pub(super) fn accept(&self) -> io::Result<(UdpSctpStream, SocketAddr)> {
        let mut state = self.socket.lock();
        loop {
            if let Some(id) = state.incoming.pop_front() {
                let s = state.session_mut(id)?;
                s.detached = true;
                s.options.nonblocking = false;
                let peer = s.peer;
                drop(state);
                return Ok((self.socket.stream(id), peer));
            }
            if let Some(e) = &state.error {
                return Err(e.error());
            }
            if state.options.nonblocking {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "no incoming SCTP association"
                ));
            }
            state = self.socket.wait(state, None)?;
        }
    }
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket.local_addrs()?[0])
    }
    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.socket.local_addrs()
    }
    pub(super) fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        self.socket.set_init_options(opts)
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        self.socket.subscribe_events(mask)
    }
    pub(super) fn check_rto(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.socket.check_rto(info)
    }
    pub(super) fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.socket.set_rto_info(info)
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.socket.set_nonblocking(on)
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.socket.take_error()
    }
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self { socket: self.socket.clone(), lease: self.lease.clone() })
    }
}

impl UdpSctpStream {
    pub(super) fn connect(
        targets: &[SocketAddr],
        opts: SctpInitOptions,
        config: &SctpUdpConfig,
    ) -> io::Result<Self> {
        let mut error = io::const_error!(io::ErrorKind::InvalidInput, "empty SCTP address set");
        for &peer in targets {
            let local = SocketAddr::new(
                match peer.ip() {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                },
                0,
            );
            let result = (|| {
                let socket = UdpSctpSocket::bind_multi(&[local], config, false)?;
                socket.set_init_options(opts)?;
                let id = socket.start_connect(peer)?;
                socket.wait_connected(id, false)?;
                Ok(socket.stream(id))
            })();
            match result {
                Ok(s) => return Ok(s),
                Err(e) => error = e,
            }
        }
        Err(error)
    }
    fn options(&self) -> io::Result<Options> {
        Ok(self.lease.socket.lock().session(self.lease.id)?.options)
    }
    fn update(&self, f: impl FnOnce(&mut Session) -> io::Result<()>) -> io::Result<()> {
        let mut state = self.lease.socket.lock();
        f(state.session_mut(self.lease.id)?)?;
        self.lease.socket.shared.changed.notify_all();
        Ok(())
    }
    pub(super) fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.lease.socket.lock().session(self.lease.id)?.peer)
    }
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        let s = self.lease.socket.lock();
        Ok(s.local[s.session(self.lease.id)?.socket_index])
    }
    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.local_addr()?])
    }
    pub(super) fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.peer_addr()?])
    }
    pub(super) fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
    pub(super) fn set_nodelay(&self, on: bool) -> io::Result<()> {
        if on { Ok(()) } else { Err(unsupported()) }
    }
    pub(super) fn set_init_options(&self, _opts: SctpInitOptions) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        validate_events(mask)?;
        self.update(|s| {
            s.options.events = mask;
            Ok(())
        })
    }
    fn check_id(&self, id: i32) -> io::Result<()> {
        if id == 0 || id == self.lease.id {
            Ok(())
        } else {
            Err(io::const_error!(io::ErrorKind::InvalidInput, "wrong association id"))
        }
    }
    pub(super) fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.check_id(info.assoc_id)?;
        self.update(|s| {
            let rto = merge_rto(s.options.rto, info)?;
            s.protocol.configure_rto(rto.initial as u64, rto.min as u64, rto.max as u64);
            s.options.rto = rto;
            Ok(())
        })
    }
    pub(super) fn set_default_send_info(&self, info: SctpSendInfo) -> io::Result<()> {
        self.check_id(info.assoc_id)?;
        if info.flags & !SCTP_UNORDERED != 0 {
            return Err(unsupported());
        }
        self.update(|s| {
            s.options.send = info;
            Ok(())
        })
    }
    pub(super) fn set_default_prinfo(&self, info: SctpPrInfo) -> io::Result<()> {
        self.check_id(info.assoc_id)?;
        if !matches!(info.policy, SCTP_PR_NONE | SCTP_PR_TTL | SCTP_PR_RTX) {
            return Err(unsupported());
        }
        self.update(|s| {
            s.options.pr = info;
            Ok(())
        })
    }
    pub(super) fn set_recv_nxtinfo(&self, on: bool) -> io::Result<()> {
        self.update(|s| {
            s.options.next = on;
            Ok(())
        })
    }
    pub(super) fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.update(|s| {
            s.options.autoclose = seconds;
            Ok(())
        })
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.update(|s| {
            s.options.nonblocking = on;
            Ok(())
        })
    }
    pub(super) fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        validate_timeout(d)?;
        self.update(|s| {
            s.options.read_timeout = d;
            Ok(())
        })
    }
    pub(super) fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        validate_timeout(d)?;
        self.update(|s| {
            s.options.write_timeout = d;
            Ok(())
        })
    }
    pub(super) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.options()?.read_timeout)
    }
    pub(super) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.options()?.write_timeout)
    }
    pub(super) fn shutdown(&self, how: crate::net::Shutdown) -> io::Result<()> {
        self.update(|s| {
            if matches!(how, crate::net::Shutdown::Read | crate::net::Shutdown::Both) {
                s.read_closed = true;
                s.messages.clear();
                s.queued_bytes = 0;
            }
            if matches!(how, crate::net::Shutdown::Write | crate::net::Shutdown::Both)
                && !s.write_closed
            {
                s.protocol.shutdown().map_err(proto_error)?;
                s.write_closed = true;
            }
            Ok(())
        })
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(self
            .lease
            .socket
            .lock()
            .session_mut(self.lease.id)?
            .pending_error
            .take()
            .map(|e| e.error()))
    }
    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        Ok(vec![self.lease.id])
    }
    pub(super) fn assoc_status(&self, id: i32) -> io::Result<SctpAssocStatus> {
        if id != 0 && id != self.lease.id {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "wrong association id"));
        }
        self.lease.socket.assoc_status(self.lease.id)
    }
    pub(super) fn peeloff(&self, _id: i32) -> io::Result<Self> {
        Err(unsupported())
    }
    pub(super) fn send_with_info(
        &self,
        buf: &[u8],
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.lease.socket.send(self.lease.id, buf, info, self.options()?)
    }
    pub(super) fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        Ok(self.lease.socket.receive(Some(self.lease.id), buf, self.options()?)?.receive)
    }
    pub(super) fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<SctpRecvInfo>)> {
        let r = self.recv_message(buf)?;
        Ok((r.len, r.info))
    }
    pub(super) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let r = self.recv_message(buf)?;
            if r.notification.is_none() {
                return Ok(r.len);
            }
        }
    }
    pub(super) fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        crate::io::default_read_buf(|b| self.read(b), cursor)
    }
    pub(super) fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match bufs.iter_mut().find(|b| !b.is_empty()) {
            Some(b) => self.read(b),
            None => Ok(0),
        }
    }
    pub(super) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_with_info(buf, None)
    }
    pub(super) fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let data: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
        self.write(&data)
    }
}
