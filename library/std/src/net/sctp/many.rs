//! Native/UDP association selection for one-to-many sockets.
use super::*;
use crate::collections::{HashMap, VecDeque};
use crate::sync::{Arc, Condvar, Mutex};
use crate::thread;
use crate::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum Route {
    Native(i32),
    Udp(i32),
}

enum Connecting {
    Native(bool),
    Udp(i32),
    Failed(io::ErrorKind, String),
}

pub(super) struct Queued {
    pub(super) received: SctpReceiveFrom,
    pub(super) data: Vec<u8>,
    pub(super) offset: usize,
}

struct State {
    native: Option<Arc<net_imp::SctpSocket>>,
    udp: udp::UdpSctpSocket,
    routes: HashMap<i32, Route>,
    reverse: HashMap<Route, i32>,
    peers: HashMap<SocketAddr, i32>,
    connecting: HashMap<SocketAddr, Connecting>,
    native_pending: Option<SocketAddr>,
    next_id: i32,
    queue: VecDeque<Queued>,
    queued_bytes: usize,
    events: SctpEventMask,
    nonblocking: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    error: Option<(io::ErrorKind, String)>,
}

#[derive(Clone)]
pub(super) struct Many {
    shared: Arc<(Mutex<State>, Condvar)>,
}

impl Many {
    pub(super) fn bind(
        local: &[SocketAddr],
        config: SctpTransportConfig,
        multi: bool,
    ) -> io::Result<Self> {
        let config = udp_config(config)?;
        let mut error =
            io::const_error!(io::ErrorKind::AddrInUse, "unable to reserve SCTP/UDP port pair");
        for _ in 0..8 {
            let udp = udp::UdpSctpSocket::bind_multi(local, &config, true)?;
            let bound = udp.local_addrs()?;
            let native = if multi {
                net_imp::SctpSocket::bind_multi(&bound)
            } else {
                net_imp::SctpSocket::bind(&bound[..])
            };
            let native = match native {
                Ok(n) => {
                    n.set_nonblocking(true)?;
                    n.subscribe_events(SctpEventMask {
                        data_io: true,
                        association: true,
                        ..Default::default()
                    })?;
                    Some(Arc::new(n))
                }
                Err(e) if is_native_sctp_unsupported(&e) => None,
                Err(e)
                    if e.kind() == io::ErrorKind::AddrInUse
                        && local[0].port() == 0
                        && config.local_encap_port.is_none() =>
                {
                    error = e;
                    continue;
                }
                Err(e) => return Err(e),
            };
            udp.set_nonblocking(true)?;
            let shared = Arc::new((
                Mutex::new(State {
                    native,
                    udp,
                    routes: HashMap::new(),
                    reverse: HashMap::new(),
                    peers: HashMap::new(),
                    connecting: HashMap::new(),
                    native_pending: None,
                    next_id: 1,
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                    events: Default::default(),
                    nonblocking: false,
                    read_timeout: None,
                    write_timeout: None,
                    error: None,
                }),
                Condvar::new(),
            ));
            let worker = shared.clone();
            thread::Builder::new().name("sctp-many".into()).spawn(move || {
                while Arc::strong_count(&worker) > 1 {
                    let mut state = worker.0.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = state.pump() {
                        state.error = Some((e.kind(), e.to_string()));
                    }
                    worker.1.notify_all();
                    let (guard, _) = worker
                        .1
                        .wait_timeout(state, Duration::from_millis(10))
                        .unwrap_or_else(|e| e.into_inner());
                    drop(guard);
                }
                worker.0.lock().unwrap_or_else(|e| e.into_inner()).udp.stop_accepting();
            })?;
            return Ok(Self { shared });
        }
        Err(error)
    }

    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).udp.local_addrs()
    }
    pub(super) fn duplicate(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).nonblocking = on;
        Ok(())
    }
    pub(super) fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        udp::validate_timeout(d)?;
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).read_timeout = d;
        Ok(())
    }
    pub(super) fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        udp::validate_timeout(d)?;
        self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).write_timeout = d;
        Ok(())
    }
    pub(super) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).read_timeout)
    }
    pub(super) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(self.shared.0.lock().unwrap_or_else(|e| e.into_inner()).write_timeout)
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        Ok(self
            .shared
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .error
            .take()
            .map(|(k, m)| io::Error::new(k, m)))
    }
    pub(super) fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        let state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = &state.native {
            n.set_init_options(opts)?;
        }
        state.udp.set_init_options(opts)
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        udp::validate_events(mask)?;
        let mut state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = &state.native {
            n.subscribe_events(SctpEventMask { association: true, data_io: true, ..mask })?;
        }
        state.udp.subscribe_events(mask)?;
        state.events = mask;
        Ok(())
    }
    pub(super) fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        let state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = &state.native {
            n.set_autoclose(seconds)?;
        }
        state.udp.set_autoclose(seconds)
    }

    pub(super) fn send_to_with_info(
        &self,
        data: &[u8],
        peer: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        let mut state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = state.write_timeout.map(|d| Instant::now() + d);
        loop {
            let id = info
                .filter(|i| i.assoc_id != 0)
                .map(|i| i.assoc_id)
                .or_else(|| state.peers.get(&peer).copied());
            if let Some(id) = id {
                let route = *state.routes.get(&id).ok_or_else(|| {
                    io::const_error!(io::ErrorKind::NotConnected, "unknown SCTP association")
                })?;
                if state.peers.get(&peer) != Some(&id) {
                    return Err(io::const_error!(
                        io::ErrorKind::InvalidInput,
                        "association and peer do not match"
                    ));
                }
                let mut info = info.copied().unwrap_or_default();
                let result = match route {
                    Route::Native(native_id) => {
                        info.assoc_id = native_id;
                        state.native.as_ref().unwrap().send_to_with_info(data, peer, Some(&info))
                    }
                    Route::Udp(udp_id) => {
                        info.assoc_id = udp_id;
                        state.udp.send_to_with_info(data, peer, Some(&info))
                    }
                };
                match result {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock && !state.nonblocking => {}
                    result => return result,
                }
            } else {
                if let Some(Connecting::Failed(k, m)) = state.connecting.get(&peer) {
                    let error = io::Error::new(*k, m.clone());
                    state.connecting.remove(&peer);
                    return Err(error);
                }
                if state.connecting.len() >= 128 && !state.connecting.contains_key(&peer) {
                    return Err(io::const_error!(
                        io::ErrorKind::OutOfMemory,
                        "too many pending SCTP associations"
                    ));
                }
                state.connecting.entry(peer).or_insert(Connecting::Native(false));
                self.shared.1.notify_all();
            }
            if state.nonblocking {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "SCTP association selection or send in progress"
                ));
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    return Err(io::const_error!(io::ErrorKind::TimedOut, "SCTP send timed out"));
                }
                state = self
                    .shared
                    .1
                    .wait_timeout(state, d.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            } else {
                state = self.shared.1.wait(state).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    pub(super) fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceiveFrom> {
        let mut state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = state.read_timeout.map(|d| Instant::now() + d);
        loop {
            if let Some(front) = state.queue.front_mut() {
                let result = front.read(buf);
                let finished = front.offset == front.data.len();
                state.queued_bytes -= result.receive.len;
                if finished {
                    state.queue.pop_front();
                }
                self.shared.1.notify_all();
                return Ok(result);
            }
            if let Some((k, m)) = state.error.take() {
                return Err(io::Error::new(k, m));
            }
            if state.nonblocking {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "no SCTP message available"
                ));
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    return Err(io::const_error!(
                        io::ErrorKind::TimedOut,
                        "SCTP receive timed out"
                    ));
                }
                state = self
                    .shared
                    .1
                    .wait_timeout(state, d.saturating_duration_since(Instant::now()))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            } else {
                state = self.shared.1.wait(state).unwrap_or_else(|e| e.into_inner());
            }
        }
    }
    pub(super) fn recv_with_info(
        &self,
        buf: &mut [u8],
    ) -> io::Result<(usize, Option<SctpRecvInfo>, Option<SocketAddr>)> {
        let r = self.recv_message(buf)?;
        Ok((r.receive.len, r.receive.info, r.peer_addr))
    }
    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        let state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut routes = state.udp.assoc_ids()?.into_iter().map(Route::Udp).collect::<Vec<_>>();
        if let Some(n) = &state.native {
            routes.extend(n.assoc_ids()?.into_iter().map(Route::Native));
        }
        Ok(routes.iter().filter_map(|r| state.reverse.get(r).copied()).collect())
    }
    pub(super) fn assoc_status(&self, id: i32) -> io::Result<SctpAssocStatus> {
        let state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let route = state.routes.get(&id).ok_or_else(|| {
            io::const_error!(io::ErrorKind::NotConnected, "unknown SCTP association")
        })?;
        let mut status = match route {
            Route::Native(n) => state.native.as_ref().unwrap().assoc_status(*n)?,
            Route::Udp(u) => state.udp.assoc_status(*u)?,
        };
        status.assoc_id = id;
        Ok(status)
    }
    pub(super) fn peeloff(&self, id: i32) -> io::Result<SctpStreamBackend> {
        let mut state = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let route = *state.routes.get(&id).ok_or_else(|| {
            io::const_error!(io::ErrorKind::NotConnected, "unknown SCTP association")
        })?;
        let stream = match route {
            Route::Native(n) => {
                SctpStreamBackend::Native(state.native.as_ref().unwrap().peeloff(n)?)
            }
            Route::Udp(u) => SctpStreamBackend::Udp(state.udp.peeloff(u)?),
        };
        stream.set_nonblocking(state.nonblocking)?;
        stream.set_read_timeout(state.read_timeout)?;
        stream.set_write_timeout(state.write_timeout)?;
        let mut queued = VecDeque::new();
        let mut keep = VecDeque::new();
        while let Some(message) = state.queue.pop_front() {
            if received_id(&message.received.receive) == Some(id) {
                state.queued_bytes -= message.data.len() - message.offset;
                queued.push_back(message);
            } else {
                keep.push_back(message);
            }
        }
        state.queue = keep;
        state.routes.remove(&id);
        state.reverse.remove(&route);
        state.peers.retain(|_, v| *v != id);
        let native_id = match route {
            Route::Native(n) | Route::Udp(n) => n,
        };
        Ok(SctpStreamBackend::Pending(auto::Bound::from_selected(stream, queued, id, native_id)))
    }
}

impl Queued {
    pub(super) fn read(&mut self, buf: &mut [u8]) -> SctpReceiveFrom {
        let mut received = self.received.clone();
        let n = buf.len().min(self.data.len() - self.offset);
        buf[..n].copy_from_slice(&self.data[self.offset..self.offset + n]);
        self.offset += n;
        received.receive.len = n;
        received.receive.flags.end_of_record &= self.offset == self.data.len();
        received
    }
}

fn received_id(r: &SctpReceive) -> Option<i32> {
    r.info.map(|i| i.assoc_id).or_else(|| {
        r.notification.as_ref().and_then(|n| match n {
            SctpNotification::AssociationChange { assoc_id, .. }
            | SctpNotification::PeerAddressChange { assoc_id, .. }
            | SctpNotification::Shutdown { assoc_id }
            | SctpNotification::PartialDelivery { assoc_id, .. }
            | SctpNotification::SendFailure { assoc_id, .. }
            | SctpNotification::PeerError { assoc_id, .. }
            | SctpNotification::Adaptation { assoc_id, .. }
            | SctpNotification::Authentication { assoc_id, .. }
            | SctpNotification::SenderDry { assoc_id }
            | SctpNotification::StreamReset { assoc_id, .. } => Some(*assoc_id),
            SctpNotification::Unknown { assoc_id, .. } => *assoc_id,
        })
    })
}

pub(super) fn remap_received(r: &mut SctpReceive, id: i32) {
    if let Some(info) = &mut r.info {
        info.assoc_id = id;
        if let Some(next) = &mut info.next {
            next.assoc_id = id;
        }
    }
    if let Some(n) = &mut r.notification {
        match n {
            SctpNotification::AssociationChange { assoc_id, .. }
            | SctpNotification::PeerAddressChange { assoc_id, .. }
            | SctpNotification::Shutdown { assoc_id }
            | SctpNotification::PartialDelivery { assoc_id, .. }
            | SctpNotification::SendFailure { assoc_id, .. }
            | SctpNotification::PeerError { assoc_id, .. }
            | SctpNotification::Adaptation { assoc_id, .. }
            | SctpNotification::Authentication { assoc_id, .. }
            | SctpNotification::SenderDry { assoc_id }
            | SctpNotification::StreamReset { assoc_id, .. } => *assoc_id = id,
            SctpNotification::Unknown { assoc_id, .. } => *assoc_id = Some(id),
        }
    }
    if let Some(SctpNotification::SendFailure { info: Some(info), .. }) = &mut r.notification {
        info.assoc_id = id;
    }
}

impl State {
    fn register(&mut self, route: Route, peer: Option<SocketAddr>) -> io::Result<i32> {
        let id = if let Some(id) = self.reverse.get(&route) {
            *id
        } else {
            let id = self.next_id;
            self.next_id = id.checked_add(1).ok_or_else(|| {
                io::const_error!(io::ErrorKind::OutOfMemory, "SCTP association ids exhausted")
            })?;
            self.reverse.insert(route, id);
            self.routes.insert(id, route);
            id
        };
        if let Some(peer) = peer {
            self.peers.insert(peer, id);
            self.connecting.remove(&peer);
            if self.native_pending == Some(peer) {
                self.native_pending = None;
            }
        }
        Ok(id)
    }
    fn fallback(&mut self, peer: SocketAddr, error: io::Error) {
        if self.native_pending == Some(peer) {
            self.native_pending = None;
        }
        let pending = if should_fallback(&error) {
            match self.udp.start_connect(peer) {
                Ok(id) => Connecting::Udp(id),
                Err(e) => Connecting::Failed(e.kind(), e.to_string()),
            }
        } else {
            Connecting::Failed(error.kind(), error.to_string())
        };
        self.connecting.insert(peer, pending);
    }
    fn pump(&mut self) -> io::Result<()> {
        let native = self.native.clone();
        let udp = self.udp.clone();
        let mut buf = [0; 65536];
        for use_udp in [false, true] {
            for _ in 0..32 {
                if self.queued_bytes >= 1024 * 1024 || self.queue.len() >= 1024 {
                    break;
                }
                let result = if use_udp {
                    udp.recv_message(&mut buf)
                } else if let Some(n) = &native {
                    n.recv_message(&mut buf)
                } else {
                    break;
                };
                let mut received = match result {
                    Ok(r) => r,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        if !use_udp {
                            if let Some(peer) = self.native_pending {
                                self.fallback(peer, e);
                                break;
                            }
                        }
                        return Err(e);
                    }
                };
                if !use_udp {
                    if let Some(SctpNotification::AssociationChange { state, .. }) =
                        &received.receive.notification
                    {
                        // FreeBSD's notification state enumeration is one-based.
                        let failed = if cfg!(target_os = "freebsd") { 5 } else { 4 };
                        if *state == failed {
                            if let Some(peer) = self.native_pending {
                                self.fallback(
                                    peer,
                                    io::const_error!(
                                        io::ErrorKind::ConnectionAborted,
                                        "native SCTP association failed"
                                    ),
                                );
                            }
                            continue;
                        }
                    }
                }
                if let Some(raw_id) = received_id(&received.receive) {
                    let route = if use_udp { Route::Udp(raw_id) } else { Route::Native(raw_id) };
                    let up = matches!(received.receive.notification, Some(SctpNotification::AssociationChange { state, .. })
                        if state == if cfg!(target_os = "freebsd") { 1 } else { 0 });
                    if received.receive.info.is_none() && !up && !self.reverse.contains_key(&route)
                    {
                        continue;
                    }
                    let next = received.receive.info.and_then(|i| i.next).and_then(|next| {
                        let route = if use_udp {
                            Route::Udp(next.assoc_id)
                        } else {
                            Route::Native(next.assoc_id)
                        };
                        self.reverse
                            .get(&route)
                            .copied()
                            .map(|id| SctpNextInfo { assoc_id: id, ..next })
                    });
                    let id = self.register(route, received.peer_addr)?;
                    remap_received(&mut received.receive, id);
                    if let Some(info) = &mut received.receive.info {
                        info.next = next;
                    }
                }
                if matches!(
                    received.receive.notification,
                    Some(SctpNotification::AssociationChange { .. })
                ) && !self.events.association
                {
                    continue;
                }
                let n =
                    if received.receive.notification.is_some() { 0 } else { received.receive.len };
                self.queued_bytes += n;
                self.queue.push_back(Queued { received, data: buf[..n].to_vec(), offset: 0 });
            }
        }
        if let Some(native) = &native {
            for id in native.assoc_ids()? {
                if let Ok(status) = native.assoc_status(id) {
                    if status.state == if cfg!(target_os = "freebsd") { 8 } else { 4 } {
                        self.register(Route::Native(id), status.primary_addr)?;
                    }
                }
            }
            if let Some(peer) = self.native_pending {
                if let Some(e) = native.take_error()? {
                    self.fallback(peer, e);
                }
            }
        }
        let peers = self.connecting.keys().copied().collect::<Vec<_>>();
        for peer in peers {
            match self.connecting.get(&peer) {
                Some(Connecting::Native(false)) if self.native_pending.is_none() => {
                    if let Some(native) = &native {
                        self.native_pending = Some(peer);
                        self.connecting.insert(peer, Connecting::Native(true));
                        match native.begin_association(peer) {
                            Ok(()) => {}
                            Err(e)
                                if e.kind() == io::ErrorKind::WouldBlock
                                    || matches!(
                                        e.raw_os_error(),
                                        Some(libc::EINPROGRESS | libc::EALREADY)
                                    ) => {}
                            Err(e) => self.fallback(peer, e),
                        }
                    } else {
                        self.fallback(peer, udp::unsupported());
                    }
                }
                Some(Connecting::Udp(id)) => {
                    let id = *id;
                    match udp.connection_state(id) {
                        Ok(true) => {
                            self.register(Route::Udp(id), Some(peer))?;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            udp.discard_failed(id);
                            self.connecting
                                .insert(peer, Connecting::Failed(e.kind(), e.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
        // Inbound UDP associations need IDs even before their first data message.
        for id in udp.assoc_ids()? {
            if let Ok(s) = udp.assoc_status(id) {
                self.register(Route::Udp(id), s.primary_addr)?;
            }
        }
        let mut live = udp.assoc_ids()?.into_iter().map(Route::Udp).collect::<Vec<_>>();
        if let Some(n) = &native {
            live.extend(n.assoc_ids()?.into_iter().map(Route::Native));
        }
        // A new send to a disconnected peer must select a new association.
        // Retain old IDs only while their final queued evidence is unread.
        self.peers.retain(|_, id| self.routes.get(id).is_some_and(|r| live.contains(r)));
        let queued_ids =
            self.queue.iter().filter_map(|q| received_id(&q.received.receive)).collect::<Vec<_>>();
        self.routes.retain(|id, route| live.contains(route) || queued_ids.contains(id));
        self.reverse.retain(|_, id| self.routes.contains_key(id));
        Ok(())
    }
}
