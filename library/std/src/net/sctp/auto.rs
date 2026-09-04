//! Native-preferred endpoints. UDP is bound before native so the two transports
//! advertise a single port, including for ephemeral binds.

impl Bound {
    pub(super) fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.set_read_timeout(d);
        }
        if s.connecting {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        if let Some(n) = &s.native {
            n.set_read_timeout(d)?;
        }
        s.udp.as_ref().unwrap().set_read_timeout(d)
    }
    pub(super) fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.set_write_timeout(d);
        }
        if s.connecting {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        if let Some(n) = &s.native {
            n.set_write_timeout(d)?;
        }
        s.udp.as_ref().unwrap().set_write_timeout(d)
    }
    pub(super) fn read_timeout(&self) -> io::Result<Option<Duration>> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.read_timeout();
        }
        s.udp.as_ref().unwrap().read_timeout()
    }
    pub(super) fn write_timeout(&self) -> io::Result<Option<Duration>> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.write_timeout();
        }
        s.udp.as_ref().unwrap().write_timeout()
    }
    pub(super) fn set_rto_info(&self, mut info: SctpRtoInfo) -> io::Result<()> {
        info.assoc_id = self.raw_id(info.assoc_id)?;
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.set_rto_info(info);
        }
        s.udp.as_ref().unwrap().check_rto(info)?;
        if s.connecting {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        if let Some(n) = &s.native {
            n.set_rto_info(info)?;
        }
        s.udp.as_ref().unwrap().set_rto_info(info)
    }
}

use super::*;
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::{Condvar, Mutex};
use crate::thread;

struct BoundState {
    native: Option<net_imp::SctpStream>,
    udp: Option<udp::UdpSctpSocket>,
    prefetched: crate::collections::VecDeque<many::Queued>,
    ids: Option<(i32, i32)>,
    selected: Option<Arc<SctpStreamBackend>>,
    connecting: bool,
    nonblocking: bool,
    failure: Option<(io::ErrorKind, String)>,
    pending_error: Option<(io::ErrorKind, String)>,
}

#[derive(Clone)]
pub(super) struct Bound {
    state: Arc<(Mutex<BoundState>, Condvar)>,
}

impl Bound {
    pub(super) fn bind(
        local: &[SocketAddr],
        config: SctpTransportConfig,
        multi: bool,
    ) -> io::Result<Self> {
        let udp_config = udp_config(config)?;
        let mut error =
            io::const_error!(io::ErrorKind::AddrInUse, "unable to reserve SCTP/UDP port pair");
        for _ in 0..8 {
            let udp = udp::UdpSctpSocket::bind_multi(local, &udp_config, false)?;
            let addrs = udp.local_addrs()?;
            let native = if config.policy == SctpTransportPolicy::UdpOnly {
                None
            } else {
                let n = if multi {
                    net_imp::SctpStream::bind_multi(&addrs)
                } else {
                    net_imp::SctpStream::bind(addrs[0])
                };
                match n {
                    Ok(n) => Some(n),
                    Err(e) if is_native_sctp_unsupported(&e) => None,
                    Err(e)
                        if e.kind() == io::ErrorKind::AddrInUse
                            && local[0].port() == 0
                            && udp_config.local_encap_port.is_none() =>
                    {
                        error = e;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            };
            return Ok(Self {
                state: Arc::new((
                    Mutex::new(BoundState {
                        native,
                        udp: Some(udp),
                        prefetched: Default::default(),
                        ids: None,
                        selected: None,
                        connecting: false,
                        nonblocking: false,
                        failure: None,
                        pending_error: None,
                    }),
                    Condvar::new(),
                )),
            });
        }
        Err(error)
    }

    pub(super) fn call<T>(
        &self,
        f: impl FnOnce(&SctpStreamBackend) -> io::Result<T>,
    ) -> io::Result<T> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = s.selected.clone() {
            drop(s);
            return f(&selected);
        }
        if let Some((kind, message)) = &s.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        Err(io::Error::new(
            if s.connecting { io::ErrorKind::WouldBlock } else { io::ErrorKind::NotConnected },
            "SCTP stream is not connected",
        ))
    }

    pub(super) fn connect(&self, addrs: &[SocketAddr], multi: bool) -> io::Result<()> {
        if addrs.is_empty() {
            return Err(io::const_error!(io::ErrorKind::InvalidInput, "empty address set"));
        }
        let mut state = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((kind, message)) = &state.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        if state.selected.is_some() {
            return Err(io::const_error!(
                io::ErrorKind::AlreadyExists,
                "SCTP stream already connected"
            ));
        }
        if !state.connecting {
            let native = state.native.take();
            let udp = state.udp.as_ref().unwrap().clone();
            let targets = addrs.to_vec();
            let shared = self.state.clone();
            state.connecting = true;
            let spawn = thread::Builder::new().name("sctp-connect".into()).spawn(move || {
                let result = (|| {
                    if let Some(native) = native {
                        let result = if multi {
                            native.connect_bound_multi(&targets)
                        } else {
                            native.connect_bound(&targets[..])
                        };
                        match result {
                            Ok(()) => return Ok(SctpStreamBackend::Native(native)),
                            Err(e) if should_fallback(&e) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    if multi && targets.len() > 1 {
                        return Err(udp::unsupported());
                    }
                    udp.connect_stream(&targets).map(SctpStreamBackend::Udp)
                })();
                let mut state = shared.0.lock().unwrap_or_else(|e| e.into_inner());
                state.connecting = false;
                match result.and_then(|s| {
                    s.set_nonblocking(state.nonblocking)?;
                    Ok(s)
                }) {
                    Ok(s) => state.selected = Some(Arc::new(s)),
                    Err(e) => {
                        let failure = (e.kind(), e.to_string());
                        state.pending_error = Some(failure.clone());
                        state.failure = Some(failure);
                    }
                }
                shared.1.notify_all();
            });
            if let Err(e) = spawn {
                state.connecting = false;
                state.failure = Some((e.kind(), e.to_string()));
                return Err(e);
            }
        }
        if state.nonblocking {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        while state.connecting {
            state = self.state.1.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        if let Some((kind, message)) = &state.failure {
            Err(io::Error::new(*kind, message.clone()))
        } else {
            Ok(())
        }
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addrs()?[0])
    }
    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            selected.local_addrs()
        } else {
            s.udp.as_ref().unwrap().local_addrs()
        }
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        let mut s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            selected.set_nonblocking(on)?;
        }
        s.nonblocking = on;
        Ok(())
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        let mut s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.take_error();
        }
        Ok(s.pending_error.take().map(|(kind, message)| io::Error::new(kind, message)))
    }
    pub(super) fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.set_init_options(opts);
        }
        if s.connecting {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        if let Some(n) = &s.native {
            n.set_init_options(opts)?;
        }
        s.udp.as_ref().unwrap().set_init_options(opts)
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(selected) = &s.selected {
            return selected.subscribe_events(mask);
        }
        udp::validate_events(mask)?;
        if s.connecting {
            return Err(io::const_error!(
                io::ErrorKind::WouldBlock,
                "SCTP transport selection in progress"
            ));
        }
        if let Some(n) = &s.native {
            n.subscribe_events(mask)?;
        }
        s.udp.as_ref().unwrap().subscribe_events(mask)
    }
}

pub(super) struct Listener {
    native: Option<net_imp::SctpListener>,
    udp: udp::UdpSctpListener,
    nonblocking: Arc<AtomicBool>,
    udp_first: Arc<AtomicBool>,
}

impl Listener {
    pub(super) fn bind(
        local: &[SocketAddr],
        config: SctpTransportConfig,
        multi: bool,
    ) -> io::Result<Self> {
        let udp_config = udp_config(config)?;
        let mut error =
            io::const_error!(io::ErrorKind::AddrInUse, "unable to reserve an SCTP/UDP port pair");
        for _ in 0..8 {
            let udp = udp::UdpSctpListener::bind_multi(local, &udp_config)?;
            let bound = udp.local_addrs()?;
            let native = if multi {
                net_imp::SctpListener::bind_multi(&bound)
            } else {
                net_imp::SctpListener::bind(&bound[..])
            };
            let native = match native {
                Ok(n) => {
                    n.set_nonblocking(true)?;
                    Some(n)
                }
                Err(e) if is_native_sctp_unsupported(&e) => None,
                Err(e)
                    if e.kind() == io::ErrorKind::AddrInUse
                        && local[0].port() == 0
                        && udp_config.local_encap_port.is_none() =>
                {
                    error = e;
                    continue;
                }
                Err(e) => return Err(e),
            };
            udp.set_nonblocking(true)?;
            return Ok(Self {
                native,
                udp,
                nonblocking: Arc::new(AtomicBool::new(false)),
                udp_first: Arc::new(AtomicBool::new(false)),
            });
        }
        Err(error)
    }

    fn try_accept(&self, udp_first: bool) -> io::Result<Option<(SctpStreamBackend, SocketAddr)>> {
        for udp in [udp_first, !udp_first] {
            let result = if udp {
                self.udp.accept().map(|(s, p)| (SctpStreamBackend::Udp(s), p))
            } else if let Some(n) = &self.native {
                n.accept().map(|(s, p)| (SctpStreamBackend::Native(s), p))
            } else {
                continue;
            };
            match result {
                Ok((s, p)) => {
                    // Internal nonblocking readiness is not inherited by callers.
                    s.set_nonblocking(false)?;
                    return Ok(Some((s, p)));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    pub(super) fn accept(&self) -> io::Result<(SctpStreamBackend, SocketAddr)> {
        loop {
            if let Some(pair) =
                self.try_accept(self.udp_first.fetch_xor(true, Ordering::Relaxed))?
            {
                return Ok(pair);
            }
            if self.nonblocking.load(Ordering::Relaxed) {
                return Err(io::const_error!(
                    io::ErrorKind::WouldBlock,
                    "no incoming SCTP association"
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
    pub(super) fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.udp.local_addrs()
    }
    pub(super) fn set_init_options(&self, opts: SctpInitOptions) -> io::Result<()> {
        if let Some(n) = &self.native {
            n.set_init_options(opts)?;
        }
        self.udp.set_init_options(opts)
    }
    pub(super) fn subscribe_events(&self, mask: SctpEventMask) -> io::Result<()> {
        udp::validate_events(mask)?;
        if let Some(n) = &self.native {
            n.subscribe_events(mask)?;
        }
        self.udp.subscribe_events(mask)
    }
    pub(super) fn set_rto_info(&self, info: SctpRtoInfo) -> io::Result<()> {
        self.udp.check_rto(info)?;
        if info.assoc_id != 0 {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "listener RTO applies to future associations"
            ));
        }
        if let Some(n) = &self.native {
            n.set_rto_info(info)?;
        }
        self.udp.set_rto_info(info)
    }
    pub(super) fn set_delayed_sack(&self, _info: SctpDelayedSackInfo) -> io::Result<()> {
        Err(udp::unsupported())
    }
    pub(super) fn set_max_burst(&self, _value: u32) -> io::Result<()> {
        Err(udp::unsupported())
    }
    pub(super) fn set_maxseg(&self, _value: u32) -> io::Result<()> {
        Err(udp::unsupported())
    }
    pub(super) fn set_nonblocking(&self, on: bool) -> io::Result<()> {
        self.nonblocking.store(on, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn take_error(&self) -> io::Result<Option<io::Error>> {
        if let Some(n) = &self.native {
            if let Some(e) = n.take_error()? {
                return Ok(Some(e));
            }
        }
        self.udp.take_error()
    }
    pub(super) fn duplicate(&self) -> io::Result<Self> {
        Ok(Self {
            native: self.native.as_ref().map(|n| n.duplicate()).transpose()?,
            udp: self.udp.try_clone()?,
            nonblocking: self.nonblocking.clone(),
            udp_first: self.udp_first.clone(),
        })
    }
}

impl Bound {
    pub(super) fn set_delayed_sack(&self, mut info: SctpDelayedSackInfo) -> io::Result<()> {
        info.assoc_id = self.raw_id(info.assoc_id)?;
        self.call(|s| s.set_delayed_sack(info))
    }

    pub(super) fn shutdown(&self, how: crate::net::Shutdown) -> io::Result<()> {
        if matches!(how, crate::net::Shutdown::Read | crate::net::Shutdown::Both) {
            self.state.0.lock().unwrap_or_else(|e| e.into_inner()).prefetched.clear();
        }
        self.call(|s| s.shutdown(how))
    }

    pub(super) fn from_selected(
        selected: SctpStreamBackend,
        prefetched: crate::collections::VecDeque<many::Queued>,
        facade: i32,
        raw: i32,
    ) -> Self {
        Self {
            state: Arc::new((
                Mutex::new(BoundState {
                    native: None,
                    udp: None,
                    selected: Some(Arc::new(selected)),
                    prefetched,
                    ids: Some((facade, raw)),
                    connecting: false,
                    nonblocking: false,
                    failure: None,
                    pending_error: None,
                }),
                Condvar::new(),
            )),
        }
    }

    fn raw_id(&self, id: i32) -> io::Result<i32> {
        let s = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        match s.ids {
            Some((facade, raw)) if id == facade => Ok(raw),
            Some(_) if id != 0 => Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "association does not belong to this stream"
            )),
            _ => Ok(id),
        }
    }
    pub(super) fn send_with_info(
        &self,
        buf: &[u8],
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        let info = info
            .map(|i| {
                let mut i = *i;
                i.assoc_id = self.raw_id(i.assoc_id)?;
                Ok::<_, io::Error>(i)
            })
            .transpose()?;
        self.call(|s| s.send_with_info(buf, info.as_ref()))
    }
    pub(super) fn set_default_send_info(&self, mut info: SctpSendInfo) -> io::Result<()> {
        info.assoc_id = self.raw_id(info.assoc_id)?;
        self.call(|s| s.set_default_send_info(info))
    }
    pub(super) fn set_default_prinfo(&self, mut info: SctpPrInfo) -> io::Result<()> {
        info.assoc_id = self.raw_id(info.assoc_id)?;
        self.call(|s| s.set_default_prinfo(info))
    }
    pub(super) fn set_auth_key(&self, key: &SctpAuthKey) -> io::Result<()> {
        let mut key = key.clone();
        key.assoc_id = self.raw_id(key.assoc_id)?;
        self.call(|s| s.set_auth_key(&key))
    }
    pub(super) fn activate_auth_key(&self, id: i32, key: u16) -> io::Result<()> {
        let id = self.raw_id(id)?;
        self.call(|s| s.activate_auth_key(id, key))
    }
    pub(super) fn delete_auth_key(&self, id: i32, key: u16) -> io::Result<()> {
        let id = self.raw_id(id)?;
        self.call(|s| s.delete_auth_key(id, key))
    }
    pub(super) fn assoc_ids(&self) -> io::Result<Vec<i32>> {
        let ids = self.state.0.lock().unwrap_or_else(|e| e.into_inner()).ids;
        self.call(|s| s.assoc_ids()).map(|raw| {
            raw.into_iter().map(|id| ids.filter(|(_, r)| *r == id).map_or(id, |(f, _)| f)).collect()
        })
    }
    pub(super) fn assoc_status(&self, id: i32) -> io::Result<SctpAssocStatus> {
        let raw = self.raw_id(id)?;
        let mut status = self.call(|s| s.assoc_status(raw))?;
        if let Some((facade, _)) = self.state.0.lock().unwrap_or_else(|e| e.into_inner()).ids {
            status.assoc_id = facade;
        }
        Ok(status)
    }
    pub(super) fn recv_message(&self, buf: &mut [u8]) -> io::Result<SctpReceive> {
        let mut state = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(front) = state.prefetched.front_mut() {
            let received = front.read(buf).receive;
            if front.offset == front.data.len() {
                state.prefetched.pop_front();
            }
            return Ok(received);
        }
        let ids = state.ids;
        drop(state);
        let mut received = self.call(|s| s.recv_message(buf))?;
        if let Some((facade, _)) = ids {
            many::remap_received(&mut received, facade);
        }
        Ok(received)
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
}
