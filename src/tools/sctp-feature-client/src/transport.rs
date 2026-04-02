use std::io;
use std::net::{
    SctpAuthKey, SctpDelayedSackInfo, SctpEventMask, SctpInitOptions, SctpMultiAddr, SctpPrInfo,
    SctpScheduler, SctpSendInfo, SctpSocket, SctpStream, SctpTransportConfig,
    SctpTransportPolicy, SctpUdpConfig, SocketAddr,
};
use std::time::Duration;

use crate::{ScenarioContract, UdpEncapsulationContract};

const CONTRACT_TRANSPORT_NATIVE: &str = "sctp4";
const CONTRACT_TRANSPORT_UDP: &str = "sctp4_udp_encap";

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

pub fn transport_config_for_contract(contract: &ScenarioContract) -> io::Result<SctpTransportConfig> {
    match contract.transport.as_str() {
        CONTRACT_TRANSPORT_NATIVE => Ok(SctpTransportConfig::default()),
        CONTRACT_TRANSPORT_UDP => {
            let udp = udp_contract(contract)?;
            Ok(SctpTransportConfig {
                policy: SctpTransportPolicy::UdpOnly,
                udp: Some(SctpUdpConfig {
                    remote_encap_port: Some(udp.remote_port),
                    local_encap_port: None,
                    reuse_port: false,
                }),
            })
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported contract transport {other}"),
        )),
    }
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

pub struct FeatureStream {
    inner: SctpStream,
}

impl FeatureStream {
    pub fn connect(contract: &ScenarioContract, targets: &[SocketAddr]) -> io::Result<Self> {
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "contract did not include any SCTP connect addresses",
            ));
        }

        let init = SctpInitOptions {
            num_ostreams: 32,
            max_instreams: 32,
            ..SctpInitOptions::default()
        };
        let remote = SctpMultiAddr::new(targets.to_vec())?;
        let stream = SctpStream::connect_multi_with_init_options_and_config(
            &remote,
            init,
            transport_config_for_contract(contract)?,
        )?;
        Ok(Self { inner: stream })
    }

    pub fn set_nodelay(&mut self, enabled: bool) -> io::Result<()> {
        self.inner.set_nodelay(enabled)
    }

    pub fn set_init_options(&mut self, options: SctpInitOptions) -> io::Result<()> {
        self.inner.set_init_options(options)
    }

    pub fn set_rto_info(&mut self, info: std::net::SctpRtoInfo) -> io::Result<()> {
        self.inner.set_rto_info(info)
    }

    pub fn set_delayed_sack(&mut self, info: SctpDelayedSackInfo) -> io::Result<()> {
        self.inner.set_delayed_sack(info)
    }

    pub fn set_max_burst(&mut self, value: u32) -> io::Result<()> {
        self.inner.set_max_burst(value)
    }

    pub fn set_default_send_info(&mut self, info: SctpSendInfo) -> io::Result<()> {
        self.inner.set_default_send_info(info)
    }

    pub fn set_default_prinfo(&mut self, info: SctpPrInfo) -> io::Result<()> {
        self.inner.set_default_prinfo(info)
    }

    pub fn set_maxseg(&mut self, value: u32) -> io::Result<()> {
        self.inner.set_maxseg(value)
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    pub fn subscribe_events(&mut self, mask: SctpEventMask) -> io::Result<()> {
        self.inner.subscribe_events(mask)
    }

    pub fn set_recv_nxtinfo(&mut self, enabled: bool) -> io::Result<()> {
        self.inner.set_recv_nxtinfo(enabled)
    }

    pub fn send_with_info(
        &mut self,
        payload: &[u8],
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.inner.send_with_info(payload, info)
    }

    pub fn recv_message(&mut self, buf: &mut [u8]) -> io::Result<FeatureRecvMessage> {
        let received = self.inner.recv_message(buf)?;
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

    pub fn local_addrs(&mut self) -> io::Result<Vec<SocketAddr>> {
        self.inner.local_addrs()
    }

    pub fn peer_addrs(&mut self) -> io::Result<Vec<SocketAddr>> {
        self.inner.peer_addrs()
    }

    pub fn bindx_add(&mut self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx_add(addrs)
    }

    pub fn bindx_remove(&mut self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx_remove(addrs)
    }

    pub fn set_primary_addr(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.inner.set_primary_addr(addr)
    }

    pub fn set_peer_primary_addr(&mut self, addr: SocketAddr) -> io::Result<()> {
        self.inner.set_peer_primary_addr(addr)
    }

    pub fn peeloff(&self, assoc_id: i32) -> io::Result<Self> {
        Ok(Self { inner: self.inner.peeloff(assoc_id)? })
    }

    pub fn assoc_ids(&mut self) -> io::Result<Vec<i32>> {
        self.inner.assoc_ids()
    }

    pub fn assoc_status(&mut self, assoc_id: i32) -> io::Result<FeatureAssocStatus> {
        let status = self.inner.assoc_status(assoc_id)?;
        Ok(FeatureAssocStatus {
            state: format!("{}", status.state),
            inbound_streams: status.inbound_streams,
            outbound_streams: status.outbound_streams,
            primary_addr: status.primary_addr,
        })
    }

    pub fn enable_stream_reset(&mut self, flags: u16) -> io::Result<()> {
        self.inner.enable_stream_reset(flags)
    }

    pub fn reset_streams(&mut self, flags: u16, streams: &[u16]) -> io::Result<()> {
        self.inner.reset_streams(flags, streams)
    }

    pub fn add_streams(&mut self, outbound: u16, inbound: u16) -> io::Result<()> {
        self.inner.add_streams(outbound, inbound)
    }

    pub fn set_auth_chunks(&mut self, chunks: &[u8]) -> io::Result<()> {
        self.inner.set_auth_chunks(chunks)
    }

    pub fn set_auth_key(&mut self, key: &SctpAuthKey) -> io::Result<()> {
        self.inner.set_auth_key(key)
    }

    pub fn activate_auth_key(&mut self, assoc_id: i32, key_id: u16) -> io::Result<()> {
        self.inner.activate_auth_key(assoc_id, key_id)
    }

    pub fn set_fragment_interleave(&mut self, level: u32) -> io::Result<()> {
        self.inner.set_fragment_interleave(level)
    }

    pub fn set_stream_scheduler(&mut self, scheduler: SctpScheduler) -> io::Result<()> {
        self.inner.set_stream_scheduler(scheduler)
    }

    pub fn set_stream_scheduler_value(&mut self, stream_id: u16, value: u16) -> io::Result<()> {
        self.inner.set_stream_scheduler_value(stream_id, value)
    }
}

pub struct FeatureOneToManySocket {
    inner: SctpSocket,
}

impl FeatureOneToManySocket {
    pub fn bind(bind_addr: SocketAddr, contract: &ScenarioContract) -> io::Result<Self> {
        Ok(Self {
            inner: SctpSocket::bind_with_config(
                bind_addr,
                transport_config_for_contract(contract)?,
            )?,
        })
    }

    pub fn set_init_options(&mut self, options: SctpInitOptions) -> io::Result<()> {
        self.inner.set_init_options(options)
    }

    pub fn send_to_with_info(
        &mut self,
        payload: &[u8],
        target: SocketAddr,
        info: Option<&SctpSendInfo>,
    ) -> io::Result<usize> {
        self.inner.send_to_with_info(payload, target, info)
    }

    pub fn assoc_ids(&mut self) -> io::Result<Vec<i32>> {
        self.inner.assoc_ids()
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
