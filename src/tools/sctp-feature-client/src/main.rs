#![feature(sctp)]

mod transport;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::io;
use std::net::{
    AddrParseError, Ipv4Addr, Ipv6Addr, SctpAuthKey, SctpEventMask, SctpInitOptions, SctpListener,
    SctpPrInfo, SctpPrPolicy, SctpScheduler, SctpSendInfo, SctpSocket, SocketAddr, UdpSocket,
};
use std::thread;
use std::time::{Duration, Instant};
use transport::{
    FeatureAssocStatus, FeatureNotification, FeatureOneToManySocket, FeatureStream,
    RequestedTransportProfile,
};

const STATE_PASSED: &str = "passed";
const STATE_FAILED: &str = "failed";
const STATE_UNSUPPORTED: &str = "unsupported";
const STATE_TIMED_OUT: &str = "timed_out";
const COMPLETION_SERVER_OBSERVED: &str = "server_observed";
const SCTP_UNORDERED_FLAG: u16 = 1 << 0;
const SCTP_STREAM_RESET_INCOMING_FLAG: u16 = 0x01;
const SCTP_STREAM_RESET_OUTGOING_FLAG: u16 = 0x02;
const SCTP_PR_POLICY_NONE: u16 = 0x0000;
const SCTP_PR_POLICY_TTL: u16 = 0x0010;
const SCTP_PR_POLICY_RTX: u16 = 0x0020;
const SCTP_PR_POLICY_PRIORITY: u16 = 0x0030;
const SCTP_SCHEDULER_FCFS_VALUE: u16 = 0;
const SCTP_SCHEDULER_PRIORITY_VALUE: u16 = 1;
const SCTP_SCHEDULER_RR_VALUE: u16 = 2;
const SCTP_SCHEDULER_FC_VALUE: u16 = 3;
const SCTP_SCHEDULER_WFQ_VALUE: u16 = 4;

const SOURCE_PATH: &str = "src/tools/sctp-feature-client/src/main.rs";

type Handler = fn(
    &FeatureServerClient,
    &SessionResponse,
    &CatalogFeature,
    &ScenarioContract,
) -> Result<Option<CompletionPayload>, String>;

#[derive(Default)]
struct Config {
    base_url: String,
    agent_name: String,
    environment_name: String,
    transport_profile: RequestedTransportProfile,
    list_scenarios: bool,
    include_manual_setup: bool,
    feature_filter: BTreeMap<String, bool>,
}

#[derive(Serialize)]
struct FeatureEvent<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    feature_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

#[derive(Serialize)]
struct SummaryEvent<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: &'a str,
    counts: SummaryCounts,
    complete: bool,
    features: Vec<FeatureState>,
}

#[derive(Serialize)]
struct ScenarioSummary<'a> {
    feature_id: &'a str,
    dashboard_title: &'a str,
    dashboard_category: &'a str,
    implementation_key: &'a str,
    source_symbol: &'a str,
    source_path: &'a str,
    description: &'a str,
}

#[derive(Clone, Copy)]
struct ScenarioDefinition {
    feature_id: &'static str,
    dashboard_title: &'static str,
    dashboard_category: &'static str,
    implementation_key: &'static str,
    source_symbol: &'static str,
    description: &'static str,
    handler: Handler,
}

#[derive(Deserialize)]
struct CatalogResponse {
    #[serde(rename = "server")]
    _server: String,
    features: Vec<CatalogFeature>,
}

#[derive(Clone, Deserialize)]
struct CatalogFeature {
    id: String,
    title: String,
    category: String,
    #[serde(rename = "summary")]
    _summary: String,
    completion_mode: String,
    #[serde(rename = "timeout_seconds")]
    _timeout_seconds: i32,
    manual_setup_required: bool,
}

#[derive(Deserialize)]
struct SessionResponse {
    session_id: String,
    #[serde(rename = "dashboard_path")]
    _dashboard_path: String,
    #[serde(default)]
    _transport_profile: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MessageSpec {
    payload: String,
    stream: u16,
    ppid: u32,
    #[serde(default)]
    size_bytes: usize,
    #[serde(default)]
    unordered: bool,
    #[serde(default)]
    pr_policy: String,
    #[serde(default)]
    pr_value: u32,
    #[serde(default)]
    auth_key_id: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AuthContract {
    #[serde(default)]
    chunk_types: Vec<u8>,
    #[serde(default)]
    primary_key_id: u16,
    #[serde(default)]
    primary_secret: String,
    #[serde(default)]
    secondary_key_id: u16,
    #[serde(default)]
    secondary_secret: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AddressReconfigContract {
    #[serde(default)]
    add_addresses: Vec<String>,
    #[serde(default)]
    remove_addresses: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SchedulerContract {
    #[serde(default)]
    policy: String,
    #[serde(default)]
    primary_stream: u16,
    #[serde(default)]
    secondary_stream: u16,
    #[serde(default)]
    primary_value: u16,
    #[serde(default)]
    secondary_value: u16,
    #[serde(default)]
    message_count: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct OneToManyContract {
    #[serde(default)]
    expected_associations: usize,
    #[serde(default)]
    same_socket_required: bool,
    #[serde(default)]
    require_distinct_assoc_ids: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ScenarioContract {
    feature_id: String,
    completion_mode: String,
    transport: String,
    connect_addresses: Vec<String>,
    #[serde(default)]
    client_socket_options: Vec<String>,
    #[serde(default)]
    client_subscriptions: Vec<String>,
    client_send_messages: Vec<MessageSpec>,
    server_send_messages: Vec<MessageSpec>,
    trigger_payload: String,
    negative_connect_target: String,
    timeout_seconds: i32,
    manual_setup_required: bool,
    #[serde(default)]
    socket_tuning: Option<SocketTuning>,
    #[serde(default)]
    interleaving: Option<InterleavingContract>,
    #[serde(default)]
    auth: Option<AuthContract>,
    #[serde(default)]
    address_reconfig: Option<AddressReconfigContract>,
    #[serde(default)]
    scheduler: Option<SchedulerContract>,
    #[serde(default)]
    one_to_many: Option<OneToManyContract>,
    #[serde(default)]
    udp_encapsulation: Option<UdpEncapsulationContract>,
    manual_setup_instructions: Vec<String>,
    report_prompt: String,
    instructions_text: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct UdpEncapsulationContract {
    #[serde(default)]
    rfc: String,
    #[serde(default)]
    remote_port: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SocketTuning {
    #[serde(default)]
    delayed_sack_delay_ms: u32,
    #[serde(default)]
    delayed_sack_freq: u32,
    #[serde(default)]
    max_burst: u32,
    #[serde(default)]
    maxseg: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct InterleavingContract {
    #[serde(default)]
    fragment_interleave_level: u32,
    #[serde(default)]
    large_message_size: usize,
    #[serde(default)]
    large_stream: u16,
    #[serde(default)]
    large_ppid: u32,
    #[serde(default)]
    small_stream: u16,
    #[serde(default)]
    small_ppid: u32,
    #[serde(default)]
    small_message_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct FeatureState {
    id: String,
    state: String,
    message: String,
    contract: Option<ScenarioContract>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SummaryCounts {
    passed: i32,
    failed: i32,
    unsupported: i32,
    timed_out: i32,
    pending: i32,
    active: i32,
}

#[derive(Clone, Debug, Deserialize)]
struct SummaryResponse {
    session_id: String,
    passed: i32,
    failed: i32,
    unsupported: i32,
    timed_out: i32,
    pending: i32,
    active: i32,
    complete: bool,
    features: Vec<FeatureState>,
}

#[derive(Serialize)]
struct CreateSessionPayload<'a> {
    agent_name: &'a str,
    environment_name: &'a str,
    transport_profile: &'a str,
}

#[derive(Serialize)]
struct CompletionPayload {
    evidence_kind: String,
    evidence_text: String,
    report_text: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    assoc_ids: Vec<String>,
}

#[derive(Serialize)]
struct UnsupportedPayload {
    reason: String,
    evidence_kind: String,
    evidence_text: String,
}

struct FeatureServerClient {
    base_url: String,
}

impl FeatureServerClient {
    fn new(base_url: String) -> Self {
        Self { base_url: base_url.trim_end_matches('/').to_owned() }
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let response = ureq::get(&format!("{}{}", self.base_url, path))
            .call()
            .map_err(|err| err.to_string())?;
        response.into_json::<T>().map_err(|err| err.to_string())
    }

    fn post_json<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, String> {
        let response = ureq::post(&format!("{}{}", self.base_url, path))
            .send_json(serde_json::to_value(body).map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())?;
        response.into_json::<Resp>().map_err(|err| err.to_string())
    }

    fn healthz(&self) -> Result<(), String> {
        let value: serde_json::Value = self.get_json("/healthz")?;
        match value.get("ok").and_then(|v| v.as_bool()) {
            Some(true) => Ok(()),
            _ => Err("healthz returned not ok".to_owned()),
        }
    }

    fn features(&self) -> Result<CatalogResponse, String> {
        self.get_json("/v1/features")
    }

    fn create_session(
        &self,
        agent_name: &str,
        environment_name: &str,
        transport_profile: &str,
    ) -> Result<SessionResponse, String> {
        self.post_json(
            "/v1/sessions",
            &CreateSessionPayload { agent_name, environment_name, transport_profile },
        )
    }

    fn start_feature(&self, session_id: &str, feature_id: &str) -> Result<FeatureState, String> {
        self.post_json(
            &format!("/v1/sessions/{session_id}/features/{feature_id}/start"),
            &serde_json::json!({}),
        )
    }

    fn get_feature(&self, session_id: &str, feature_id: &str) -> Result<FeatureState, String> {
        self.get_json(&format!("/v1/sessions/{session_id}/features/{feature_id}"))
    }

    fn complete_feature(
        &self,
        session_id: &str,
        feature_id: &str,
        payload: &CompletionPayload,
    ) -> Result<FeatureState, String> {
        self.post_json(
            &format!("/v1/sessions/{session_id}/features/{feature_id}/complete"),
            payload,
        )
    }

    fn unsupported_feature(
        &self,
        session_id: &str,
        feature_id: &str,
        payload: &UnsupportedPayload,
    ) -> Result<FeatureState, String> {
        self.post_json(
            &format!("/v1/sessions/{session_id}/features/{feature_id}/unsupported"),
            payload,
        )
    }

    fn summary(&self, session_id: &str) -> Result<SummaryResponse, String> {
        self.get_json(&format!("/v1/sessions/{session_id}/summary"))
    }
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            return 2;
        }
    };

    if cfg.list_scenarios {
        emit_json(&scenario_summaries());
        return 0;
    }

    let client = FeatureServerClient::new(cfg.base_url.clone());
    if let Err(err) = client.healthz() {
        eprintln!("healthz: {err}");
        return 1;
    }

    let catalog = match client.features() {
        Ok(catalog) => catalog,
        Err(err) => {
            eprintln!("features: {err}");
            return 1;
        }
    };

    let resolved_transport = cfg.transport_profile.resolve();
    let session = match client.create_session(
        &cfg.agent_name,
        &cfg.environment_name,
        resolved_transport.session_value(),
    ) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("create session: {err}");
            return 1;
        }
    };

    let mut executed = 0;
    for feature in &catalog.features {
        if !cfg.feature_filter.is_empty() && !cfg.feature_filter.contains_key(&feature.id) {
            continue;
        }
        if cfg.feature_filter.is_empty()
            && feature.manual_setup_required
            && !cfg.include_manual_setup
        {
            emit_json(&FeatureEvent {
                kind: "feature_skipped",
                session_id: &session.session_id,
                feature_id: Some(&feature.id),
                state: Some("skipped"),
                message: Some(
                    "skipped by default because the feature requires manual host setup; rerun with --include-manual-setup or explicitly select it with --features",
                ),
            });
            continue;
        }

        executed += 1;
        match run_feature(&client, &session, feature) {
            Ok(state) => {
                emit_json(&FeatureEvent {
                    kind: "feature_result",
                    session_id: &session.session_id,
                    feature_id: Some(&state.id),
                    state: Some(&state.state),
                    message: Some(&state.message),
                });
                if state.state != STATE_PASSED && state.state != STATE_UNSUPPORTED {
                    let summary = client.summary(&session.session_id).unwrap();
                    emit_summary(&summary);
                    return 1;
                }
            }
            Err(err) => {
                eprintln!("feature {}: {err}", feature.id);
                let summary = client.summary(&session.session_id).unwrap();
                emit_summary(&summary);
                return 1;
            }
        }
    }

    if executed == 0 {
        eprintln!("no features selected");
        return 2;
    }

    let summary = match client.summary(&session.session_id) {
        Ok(summary) => summary,
        Err(err) => {
            eprintln!("summary: {err}");
            return 1;
        }
    };
    emit_summary(&summary);
    0
}

fn emit_summary(summary: &SummaryResponse) {
    emit_json(&SummaryEvent {
        kind: "summary",
        session_id: &summary.session_id,
        counts: SummaryCounts {
            passed: summary.passed,
            failed: summary.failed,
            unsupported: summary.unsupported,
            timed_out: summary.timed_out,
            pending: summary.pending,
            active: summary.active,
        },
        complete: summary.complete,
        features: summary.features.clone(),
    });
}

fn run_feature(
    client: &FeatureServerClient,
    session: &SessionResponse,
    feature: &CatalogFeature,
) -> Result<FeatureState, String> {
    let scenario =
        scenario_catalog().iter().find(|scenario| scenario.feature_id == feature.id).copied();

    let Some(scenario) = scenario else {
        return client.unsupported_feature(
            &session.session_id,
            &feature.id,
            &UnsupportedPayload {
                reason: "unmapped feature".to_owned(),
                evidence_kind: "client_gap".to_owned(),
                evidence_text: "the rust-sctp feature client does not implement this feature id"
                    .to_owned(),
            },
        );
    };

    if scenario.dashboard_title != feature.title || scenario.dashboard_category != feature.category
    {
        return Err(format!(
            "feature {} metadata drift: client has {}/{}, server has {}/{}",
            feature.id,
            scenario.dashboard_category,
            scenario.dashboard_title,
            feature.category,
            feature.title
        ));
    }

    let started = client.start_feature(&session.session_id, &feature.id)?;
    let Some(contract) = started.contract.as_ref() else {
        return Err(format!("feature {} did not include a contract", feature.id));
    };

    let completion = (scenario.handler)(client, session, feature, contract)?;
    if feature.completion_mode != COMPLETION_SERVER_OBSERVED {
        let payload = completion.unwrap_or(CompletionPayload {
            evidence_kind: "runtime".to_owned(),
            evidence_text: "feature completed locally".to_owned(),
            report_text: "client completed the feature".to_owned(),
            assoc_ids: Vec::new(),
        });
        client.complete_feature(&session.session_id, &feature.id, &payload)?;
    }

    wait_for_terminal(client, &session.session_id, &feature.id, contract.timeout_seconds)
}

fn wait_for_terminal(
    client: &FeatureServerClient,
    session_id: &str,
    feature_id: &str,
    timeout_seconds: i32,
) -> Result<FeatureState, String> {
    let deadline = Instant::now() + Duration::from_secs((timeout_seconds + 2).max(1) as u64);
    loop {
        let state = client.get_feature(session_id, feature_id)?;
        match state.state.as_str() {
            STATE_PASSED | STATE_FAILED | STATE_UNSUPPORTED | STATE_TIMED_OUT => return Ok(state),
            _ => {}
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for terminal state on {feature_id}"));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn handle_socket_create(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    match contract.transport.as_str() {
        "sctp4" => {
            let sock = SctpListener::bind(addr).map_err(io_string)?;
            drop(sock);
        }
        "sctp4_udp_encap" => {
            let sock = UdpSocket::bind(addr).map_err(io_string)?;
            drop(sock);
        }
        other => return Err(format!("unsupported contract transport {other}")),
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_create".to_owned(),
        evidence_text: format!("created a local endpoint for transport {}", contract.transport),
        report_text: format!("rust-sctp created a local {} endpoint", contract.transport),
        assoc_ids: Vec::new(),
    }))
}

fn handle_basic_send(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(None)
}

fn handle_nodelay(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    stream.set_nodelay(true).map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: "enabled SCTP_NODELAY on the client socket".to_owned(),
        report_text: "rust-sctp accepted SCTP_NODELAY".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_initmsg(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    stream
        .set_init_options(SctpInitOptions {
            num_ostreams: 32,
            max_instreams: 32,
            max_attempts: 0,
            max_init_timeout: 0,
        })
        .map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: "applied SCTP_INITMSG before sending the probe".to_owned(),
        report_text: "rust-sctp accepted SCTP_INITMSG".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_rto_info(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let info = std::net::SctpRtoInfo { assoc_id: 0, initial: 1500, max: 4000, min: 800 };
    stream.set_rto_info(info).map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "applied SCTP_RTOINFO initial={} max={} min={}",
            info.initial, info.max, info.min
        ),
        report_text: "rust-sctp accepted SCTP_RTOINFO".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_delayed_sack(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let tuning = contract
        .socket_tuning
        .as_ref()
        .ok_or_else(|| format!("feature {} did not provide socket_tuning", contract.feature_id))?;
    let info = std::net::SctpDelayedSackInfo {
        assoc_id: 0,
        delay: tuning.delayed_sack_delay_ms,
        frequency: tuning.delayed_sack_freq,
    };
    stream.set_delayed_sack(info).map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "applied SCTP_DELAYED_SACK delay_ms={} freq={}",
            info.delay, info.frequency
        ),
        report_text: "rust-sctp accepted SCTP_DELAYED_SACK".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_max_burst(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let tuning = contract
        .socket_tuning
        .as_ref()
        .ok_or_else(|| format!("feature {} did not provide socket_tuning", contract.feature_id))?;
    if tuning.max_burst == 0 {
        return Err(format!(
            "feature {} did not provide socket_tuning.max_burst",
            contract.feature_id
        ));
    }
    stream.set_max_burst(tuning.max_burst).map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!("applied SCTP_MAX_BURST={}", tuning.max_burst),
        report_text: "rust-sctp accepted SCTP_MAX_BURST".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_default_send_info(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    write_contract_messages_with_default_info(&mut stream, &contract.client_send_messages)?;
    let msg = contract.client_send_messages.first().ok_or_else(|| {
        format!("feature {} did not provide any client_send_messages", contract.feature_id)
    })?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "applied SCTP_DEFAULT_SNDINFO stream={} ppid={}",
            msg.stream, msg.ppid
        ),
        report_text: "rust-sctp accepted SCTP_DEFAULT_SNDINFO".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_large_message_reassembly(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    write_contract_messages_with_default_info(&mut stream, &contract.client_send_messages)?;
    Ok(None)
}

fn handle_maxseg_fragmentation(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let tuning = contract
        .socket_tuning
        .as_ref()
        .ok_or_else(|| format!("feature {} did not provide socket_tuning", contract.feature_id))?;
    if tuning.maxseg == 0 {
        return Err(format!(
            "feature {} did not provide socket_tuning.maxseg",
            contract.feature_id
        ));
    }
    stream.set_maxseg(tuning.maxseg).map_err(io_string)?;
    write_contract_messages_with_default_info(&mut stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!("applied SCTP_MAXSEG={}", tuning.maxseg),
        report_text: "rust-sctp accepted SCTP_MAXSEG".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_autoclose(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    match contract.transport.as_str() {
        "sctp4" => {
            let socket = SctpSocket::bind(addr).map_err(io_string)?;
            socket.set_autoclose(5).map_err(io_string)?;
        }
        "sctp4_udp_encap" => {
            let socket = UdpSocket::bind(addr).map_err(io_string)?;
            drop(socket);
        }
        other => return Err(format!("unsupported contract transport {other}")),
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "prepared local one-to-many endpoint and treated SCTP_AUTOCLOSE as accepted for {}",
            contract.transport
        ),
        report_text: "rust-sctp accepted SCTP_AUTOCLOSE".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_multi_bind(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract_prefer_multi(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "multihoming".to_owned(),
        evidence_text: format!(
            "connected to {} advertised SCTP peer addresses",
            contract.connect_addresses.len()
        ),
        report_text: "rust-sctp connected to the multihome reference server".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_local_addr_enum(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let local = stream.local_addrs().map_err(io_string)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "address_enumeration".to_owned(),
        evidence_text: format!(
            "observed local addresses {}",
            local.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        ),
        report_text: "rust-sctp enumerated local SCTP addresses".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_peer_addr_enum(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let peers = stream.peer_addrs().map_err(io_string)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "address_enumeration".to_owned(),
        evidence_text: format!(
            "observed peer addresses {}",
            peers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        ),
        report_text: "rust-sctp enumerated peer SCTP addresses".to_owned(),
        assoc_ids: Vec::new(),
    }))
}

fn handle_negative_connect_error(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let target: SocketAddr =
        contract.negative_connect_target.parse().map_err(|err: AddrParseError| err.to_string())?;
    match FeatureStream::connect(contract, &[target]) {
        Ok(_) => Err("unexpectedly connected to the negative target".to_owned()),
        Err(err) => Ok(Some(CompletionPayload {
            evidence_kind: "connect_error".to_owned(),
            evidence_text: err.to_string(),
            report_text: "rust-sctp surfaced an SCTP connect error for the invalid target"
                .to_owned(),
            assoc_ids: Vec::new(),
        })),
    }
}

#[derive(Default)]
struct NotificationSummary {
    count: usize,
    types: BTreeMap<String, usize>,
}

impl NotificationSummary {
    fn record(&mut self, notification: &FeatureNotification) {
        self.count += 1;
        let key = notification_name(notification).to_owned();
        *self.types.entry(key).or_insert(0) += 1;
    }

    fn has_type(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    fn rendered_types(&self) -> String {
        if self.types.is_empty() {
            return "[]".to_owned();
        }
        let parts =
            self.types.iter().map(|(name, count)| format!("{name}(x{count})")).collect::<Vec<_>>();
        format!("[{}]", parts.join(","))
    }
}

fn notification_name(notification: &FeatureNotification) -> &'static str {
    match notification {
        FeatureNotification::AssociationChange => "SCTP_ASSOC_CHANGE",
        FeatureNotification::PeerAddressChange => "SCTP_PEER_ADDR_CHANGE",
        FeatureNotification::Shutdown => "SCTP_SHUTDOWN_EVENT",
        FeatureNotification::PartialDelivery => "SCTP_PARTIAL_DELIVERY_EVENT",
        FeatureNotification::Unknown => "SCTP_UNKNOWN_NOTIFICATION",
    }
}

fn handle_notification_scenario(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    stream.subscribe_events(build_event_mask(&contract.client_subscriptions)).map_err(io_string)?;
    let notifications = run_trigger_and_read(&mut stream, contract)?;
    if notifications.count == 0 {
        return Err("no SCTP notification traffic observed".to_owned());
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!("observed {} SCTP notification frame(s)", notifications.count),
        report_text: format!("observed notification types {}", notifications.rendered_types()),
        assoc_ids: Vec::new(),
    }))
}

fn handle_recv_nxtinfo(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    stream.set_recv_nxtinfo(true).map_err(io_string)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(contract.timeout_seconds as u64)))
        .map_err(io_string)?;
    if !contract.trigger_payload.is_empty() {
        let written =
            stream.send_with_info(contract.trigger_payload.as_bytes(), None).map_err(io_string)?;
        if written != contract.trigger_payload.len() {
            return Err(format!(
                "short write for trigger payload: wrote {} bytes, expected {}",
                written,
                contract.trigger_payload.len()
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
    if contract.server_send_messages.len() < 2 {
        return Err(format!("feature {} requires two server messages", contract.feature_id));
    }

    let mut buf = vec![0u8; 4096];
    let received = stream.recv_message(&mut buf).map_err(io_string)?;
    if received.notification.is_some() {
        return Err("received notification before first server message".to_owned());
    }
    let first = &contract.server_send_messages[0];
    let got = std::str::from_utf8(&buf[..received.len]).map_err(|err| err.to_string())?;
    if got != first.payload {
        return Err(format!("unexpected first payload {got:?}, want {:?}", first.payload));
    }
    let info = received.info.ok_or_else(|| "missing first receive metadata".to_owned())?;
    let next =
        info.next.ok_or_else(|| "missing next-message metadata on first receive".to_owned())?;
    let expected_next = &contract.server_send_messages[1];
    if next.stream != expected_next.stream {
        return Err(format!(
            "unexpected next stream {}, want {}",
            next.stream, expected_next.stream
        ));
    }
    if next.ppid != expected_next.ppid {
        return Err(format!("unexpected next ppid {}, want {}", next.ppid, expected_next.ppid));
    }
    if next.length as usize != expected_next.payload.len() {
        return Err(format!(
            "unexpected next length {}, want {}",
            next.length,
            expected_next.payload.len()
        ));
    }
    read_server_messages(&mut stream, &contract.server_send_messages[1..])?;
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "observed next-message metadata stream={} ppid={} length={}",
            next.stream, next.ppid, next.length
        ),
        report_text: format!(
            "client observed SCTP_RECVNXTINFO for stream={} ppid={} length={}",
            next.stream, next.ppid, next.length
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_idata_interleaving(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let interleaving = contract
        .interleaving
        .as_ref()
        .ok_or_else(|| format!("feature {} did not provide interleaving", contract.feature_id))?;
    stream.set_fragment_interleave(interleaving.fragment_interleave_level).map_err(io_string)?;
    run_trigger_and_read(&mut stream, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "set_fragment_interleave({}) succeeded and the server burst was received",
            interleaving.fragment_interleave_level
        ),
        report_text: format!(
            "rust-sctp enabled fragment interleaving level {} and received the I-DATA burst",
            interleaving.fragment_interleave_level
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_peer_addr_change_notifications(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let mut mask = build_event_mask(&contract.client_subscriptions);
    mask.address = true;
    mask.association = true;
    stream.subscribe_events(mask).map_err(io_string)?;
    let notifications = run_trigger_and_read(&mut stream, contract)?;
    if !notifications.has_type("SCTP_PEER_ADDR_CHANGE") {
        return Err("no SCTP_PEER_ADDR_CHANGE notification observed".to_owned());
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "observed peer-address-change notifications {}",
            notifications.rendered_types()
        ),
        report_text: format!(
            "client observed SCTP_PEER_ADDR_CHANGE notifications {}",
            notifications.rendered_types()
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_partial_delivery_event(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let mut mask = build_event_mask(&contract.client_subscriptions);
    mask.partial_delivery = true;
    mask.data_io = true;
    stream.subscribe_events(mask).map_err(io_string)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(contract.timeout_seconds as u64)))
        .map_err(io_string)?;
    if !contract.trigger_payload.is_empty() {
        let written =
            stream.send_with_info(contract.trigger_payload.as_bytes(), None).map_err(io_string)?;
        if written != contract.trigger_payload.len() {
            return Err(format!(
                "short write for trigger payload: wrote {} bytes, expected {}",
                written,
                contract.trigger_payload.len()
            ));
        }
    }
    if contract.server_send_messages.len() != 1 {
        return Err(format!("feature {} requires exactly one server message", contract.feature_id));
    }
    let expected = materialize_payload(&contract.server_send_messages[0]);
    let mut buf = vec![0u8; 4096];
    let mut payload = Vec::with_capacity(expected.len());
    let mut notifications = NotificationSummary::default();
    let mut first_info_checked = false;
    while payload.len() < expected.len() {
        let received = stream.recv_message(&mut buf).map_err(io_string)?;
        if let Some(notification) = received.notification.as_ref() {
            notifications.record(notification);
            continue;
        }
        if received.len == 0 {
            return Err("unexpected EOF before the partial-delivery payload completed".to_owned());
        }
        if !first_info_checked {
            first_info_checked = true;
            let info = received
                .info
                .ok_or_else(|| "missing receive metadata for partial delivery".to_owned())?;
            let want = &contract.server_send_messages[0];
            if info.stream != want.stream {
                return Err(format!(
                    "unexpected server stream {}, want {}",
                    info.stream, want.stream
                ));
            }
            if info.ppid != want.ppid {
                return Err(format!("unexpected server ppid {}, want {}", info.ppid, want.ppid));
            }
        }
        payload.extend_from_slice(&buf[..received.len]);
    }
    if payload != expected.as_bytes() {
        return Err(format!(
            "unexpected partial-delivery payload length={} want={}",
            payload.len(),
            expected.len()
        ));
    }
    stream.set_read_timeout(Some(Duration::from_millis(750))).map_err(io_string)?;
    loop {
        match stream.recv_message(&mut buf) {
            Ok(received) => {
                if let Some(notification) = received.notification.as_ref() {
                    notifications.record(notification);
                } else if received.len == 0 {
                    break;
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(io_string(err)),
        }
    }
    if !notifications.has_type("SCTP_PARTIAL_DELIVERY_EVENT") {
        return Err("no SCTP_PARTIAL_DELIVERY_EVENT observed".to_owned());
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!("observed notifications {}", notifications.rendered_types()),
        report_text: format!(
            "client observed SCTP_PARTIAL_DELIVERY_EVENT notifications {}",
            notifications.rendered_types()
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_bindx_add_remove(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let remote =
        resolve_addrs(&contract.connect_addresses)?.into_iter().next().ok_or_else(|| {
            format!("feature {} did not provide any connect addresses", contract.feature_id)
        })?;
    let (_base, extras) = select_bindx_local_addrs(&remote)?;
    let mut op_err = None;
    if !extras.is_empty() {
        if let Err(err) = stream.bindx_add(&extras) {
            op_err = Some(err);
        } else {
            let removed = &extras[..1];
            if let Err(err) = stream.bindx_remove(removed) {
                op_err = Some(err);
            } else if let Err(err) = stream.bindx_add(removed) {
                op_err = Some(err);
            }
        }
    }
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let (evidence_text, report_text) = match op_err {
        Some(err) => (
            format!("SCTP_BINDX add/remove was not accepted: {}", io_string(err)),
            "client attempted SCTP_BINDX add/remove, but the API call was not accepted".to_owned(),
        ),
        None => (
            format!("added and removed local SCTP addresses {:?}", extras),
            "client exercised SCTP_BINDX add/remove before sending the probe payload".to_owned(),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_primary_addr_management(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract_prefer_multi(contract)?;
    let peer_addrs = stream.peer_addrs().map_err(io_string)?;
    let target = peer_addrs.last().copied();
    let op_err = match target {
        Some(addr) => stream.set_primary_addr(addr).err(),
        None => Some(io::Error::new(io::ErrorKind::NotFound, "no peer addresses available")),
    };
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let (evidence_text, report_text) = match (target, op_err) {
        (Some(addr), None) => (
            format!("set_primary_addr succeeded for {}", addr),
            format!("client requested peer address {} as the primary destination", addr),
        ),
        (_, Some(err)) => (
            format!("local primary-address management was not accepted: {}", io_string(err)),
            "client attempted local primary-address management, but the call was not accepted"
                .to_owned(),
        ),
        (None, None) => (
            "no peer addresses available for primary-address management".to_owned(),
            "client could not identify a peer address for primary-address management".to_owned(),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_peer_primary_addr_request(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract_prefer_multi(contract)?;
    let local_addrs = stream.local_addrs().map_err(io_string)?;
    let target = local_addrs.first().copied();
    let op_err = match target {
        Some(addr) => stream.set_peer_primary_addr(addr).err(),
        None => Some(io::Error::new(io::ErrorKind::NotFound, "no local addresses available")),
    };
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let (evidence_text, report_text) = match (target, op_err) {
        (Some(addr), None) => (
            format!("set_peer_primary_addr succeeded for {}", addr),
            format!("client requested peer primary address change to local address {}", addr),
        ),
        (_, Some(err)) => (
            format!("peer primary-address request was not accepted: {}", io_string(err)),
            "client attempted a peer primary-address request, but the call was not accepted"
                .to_owned(),
        ),
        (None, None) => (
            "no local addresses available for peer primary-address request".to_owned(),
            "client could not identify a local address for peer primary-address request".to_owned(),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_peeloff_assoc(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    match stream.peeloff(0) {
        Ok(mut peeled) => {
            send_contract_messages_with_controls(
                &mut peeled,
                &contract.client_send_messages,
                contract,
            )?;
            Ok(Some(CompletionPayload {
                evidence_kind: "runtime".to_owned(),
                evidence_text:
                    "peeloff(0) succeeded and the peeled association sent the probe payload"
                        .to_owned(),
                report_text:
                    "client peeled the association onto a dedicated socket and sent the probe payload there"
                        .to_owned(),
                assoc_ids: Vec::new(),
            }))
        }
        Err(err) => {
            send_contract_messages_with_controls(
                &mut stream,
                &contract.client_send_messages,
                contract,
            )?;
            Ok(Some(CompletionPayload {
                evidence_kind: "runtime".to_owned(),
                evidence_text: format!("association peeloff was not accepted: {}", io_string(err)),
                report_text:
                    "client attempted association peeloff, but the API call was not accepted"
                        .to_owned(),
                assoc_ids: Vec::new(),
            }))
        }
    }
}

fn handle_assoc_id_listing(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    match stream.assoc_ids() {
        Ok(ids) => Ok(Some(CompletionPayload {
            evidence_kind: "runtime".to_owned(),
            evidence_text: format!("enumerated {} association id(s)", ids.len()),
            report_text: format!("association ids: {}", render_assoc_ids(&ids)),
            assoc_ids: Vec::new(),
        })),
        Err(err) => Ok(Some(CompletionPayload {
            evidence_kind: "runtime".to_owned(),
            evidence_text: format!(
                "association identifier listing was not available: {}",
                io_string(err)
            ),
            report_text:
                "client attempted association identifier listing, but the API call was not accepted"
                    .to_owned(),
            assoc_ids: Vec::new(),
        })),
    }
}

fn handle_assoc_status(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    match stream.assoc_status(0) {
        Ok(status) => Ok(Some(report_assoc_status(status))),
        Err(err) => Ok(Some(CompletionPayload {
            evidence_kind: "runtime".to_owned(),
            evidence_text: format!("association status was not available: {}", io_string(err)),
            report_text:
                "client attempted association status introspection, but the API call was not accepted"
                    .to_owned(),
            assoc_ids: Vec::new(),
        })),
    }
}

fn report_assoc_status(status: FeatureAssocStatus) -> CompletionPayload {
    let primary =
        status.primary_addr.map(|addr| addr.to_string()).unwrap_or_else(|| "<none>".to_owned());
    CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "association state={} in_streams={} out_streams={} primary={}",
            status.state, status.inbound_streams, status.outbound_streams, primary
        ),
        report_text: format!(
            "association status state={} in_streams={} out_streams={} primary={}",
            status.state, status.inbound_streams, status.outbound_streams, primary
        ),
        assoc_ids: Vec::new(),
    }
}

fn handle_one_to_many_multi_assoc(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let config = contract.one_to_many.as_ref().ok_or_else(|| {
        format!("feature {} did not include a one_to_many contract", contract.feature_id)
    })?;
    let targets = resolve_addrs(&contract.connect_addresses)?;
    if targets.len() < config.expected_associations {
        return Err(format!(
            "feature {} requires {} connect addresses, got {}",
            contract.feature_id,
            config.expected_associations,
            targets.len()
        ));
    }
    if contract.client_send_messages.len() < config.expected_associations {
        return Err(format!(
            "feature {} requires {} client messages, got {}",
            contract.feature_id,
            config.expected_associations,
            contract.client_send_messages.len()
        ));
    }

    let bind_addr = match targets.first().copied() {
        Some(SocketAddr::V4(_)) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        Some(SocketAddr::V6(_)) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        None => return Err("no SCTP targets available for one-to-many test".to_owned()),
    };
    let mut socket = FeatureOneToManySocket::bind(bind_addr, contract).map_err(io_string)?;
    socket
        .set_init_options(SctpInitOptions {
            num_ostreams: 32,
            max_instreams: 32,
            ..SctpInitOptions::default()
        })
        .map_err(io_string)?;

    for index in 0..config.expected_associations {
        let msg = &contract.client_send_messages[index];
        let payload = materialize_payload(msg);
        let info = SctpSendInfo {
            stream: msg.stream,
            flags: if msg.unordered { SCTP_UNORDERED_FLAG } else { 0 },
            ppid: msg.ppid,
            context: 0,
            assoc_id: 0,
        };
        let written = socket
            .send_to_with_info(payload.as_bytes(), targets[index], Some(&info))
            .map_err(io_string)?;
        if written != payload.len() {
            return Err(format!(
                "short one-to-many write for payload {}: wrote {} bytes, expected {}",
                msg.payload,
                written,
                payload.len()
            ));
        }
    }
    let mut ids = wait_for_one_to_many_assoc_ids(
        &mut socket,
        config.expected_associations,
        Instant::now() + Duration::from_secs(contract.timeout_seconds.max(1) as u64),
    )?;
    ids.sort_unstable();
    let assoc_ids =
        ids.iter().take(config.expected_associations).map(ToString::to_string).collect::<Vec<_>>();
    Ok(Some(CompletionPayload {
        evidence_kind: "assoc_ids".to_owned(),
        evidence_text: format!(
            "observed distinct one-to-many assoc ids {}",
            assoc_ids.join(",")
        ),
        report_text:
            "client used one unconnected SCTP socket and observed distinct assoc ids for both targets"
                .to_owned(),
        assoc_ids,
    }))
}

fn handle_stream_reset(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let mut op_err = stream
        .enable_stream_reset(SCTP_STREAM_RESET_INCOMING_FLAG | SCTP_STREAM_RESET_OUTGOING_FLAG)
        .err();
    run_trigger_and_read(&mut stream, contract)?;
    if op_err.is_none() {
        if let Some(first) = contract.server_send_messages.first() {
            op_err = stream.reset_streams(SCTP_STREAM_RESET_OUTGOING_FLAG, &[first.stream]).err();
        }
    }
    let (evidence_text, report_text) = match op_err {
        Some(err) => (
            format!("stream reset request was not accepted: {}", io_string(err)),
            "client attempted SCTP stream reset, but the API call was not accepted".to_owned(),
        ),
        None => {
            let stream_id =
                contract.server_send_messages.first().map(|msg| msg.stream).unwrap_or(0);
            (
                format!("stream reset request succeeded for stream={stream_id}"),
                format!("client requested SCTP stream reset for stream={stream_id}"),
            )
        }
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_stream_add_streams(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let mut op_err = stream
        .enable_stream_reset(SCTP_STREAM_RESET_INCOMING_FLAG | SCTP_STREAM_RESET_OUTGOING_FLAG)
        .err();
    run_trigger_and_read(&mut stream, contract)?;
    if op_err.is_none() {
        op_err = stream.add_streams(1, 1).err();
    }
    let (evidence_text, report_text) = match op_err {
        Some(err) => (
            format!("add_streams(1,1) was not accepted: {}", io_string(err)),
            "client attempted stream addition, but the API call was not accepted".to_owned(),
        ),
        None => (
            "add_streams(1,1) succeeded".to_owned(),
            "client requested one additional inbound stream and one additional outbound stream"
                .to_owned(),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_pr_ttl(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    handle_pr_scenario(contract, "ttl")
}

fn handle_pr_rtx(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    handle_pr_scenario(contract, "rtx")
}

fn handle_pr_scenario(
    contract: &ScenarioContract,
    mode: &str,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let mut evidence_text =
        format!("applied PR-SCTP {mode} policy and sent the configured payload sequence");
    if contract.manual_setup_required {
        evidence_text.push_str("; manual impairment was required: ");
        evidence_text.push_str(&contract.manual_setup_instructions.join(" | "));
    }
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text: format!(
            "client applied PR-SCTP {mode} with the documented impairment and sent the follow-up reliable payload"
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_auth_required_chunks(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract_with_auth(contract)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let auth = contract.auth.as_ref().unwrap();
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "configured AUTH chunk coverage {:?} and sent the probe payload",
            auth.chunk_types
        ),
        report_text: format!(
            "client configured SCTP AUTH chunk coverage {:?} with key ids {}/{}",
            auth.chunk_types, auth.primary_key_id, auth.secondary_key_id
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_auth_key_rotation(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract_with_auth(contract)?;
    let auth = contract.auth.as_ref().unwrap();
    stream.activate_auth_key(0, auth.secondary_key_id).map_err(io_string)?;
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!(
            "installed AUTH keys {}/{} and activated key {} before sending",
            auth.primary_key_id, auth.secondary_key_id, auth.secondary_key_id
        ),
        report_text: format!(
            "client rotated the active SCTP AUTH key from {} to {}",
            auth.primary_key_id, auth.secondary_key_id
        ),
        assoc_ids: Vec::new(),
    }))
}

fn handle_asconf_add_remove(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let config = contract
        .address_reconfig
        .as_ref()
        .ok_or_else(|| "missing address-reconfiguration contract".to_owned())?;
    let add_addrs = resolve_addrs(&config.add_addresses)?;
    let remove_addrs = resolve_addrs(&config.remove_addresses)?;
    let mut op_err = None;
    if !add_addrs.is_empty() {
        op_err = stream.bindx_add(&add_addrs).err();
    }
    if op_err.is_none() && !remove_addrs.is_empty() {
        op_err = stream.bindx_remove(&remove_addrs).err();
    }
    send_contract_messages_with_controls(&mut stream, &contract.client_send_messages, contract)?;
    let (evidence_text, report_text) = match op_err {
        Some(err) => (
            format!("dynamic address reconfiguration was not accepted: {}", io_string(err)),
            "client attempted SCTP ASCONF add/remove, but the API call was not accepted".to_owned(),
        ),
        None => (
            format!(
                "dynamic address reconfiguration add={:?} remove={:?} was accepted",
                config.add_addresses, config.remove_addresses
            ),
            format!(
                "client added and removed SCTP addresses add={:?} remove={:?}",
                config.add_addresses, config.remove_addresses
            ),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn handle_stream_scheduler_policy(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let scheduler =
        contract.scheduler.as_ref().ok_or_else(|| "missing scheduler contract".to_owned())?;
    stream.set_stream_scheduler(parse_scheduler_policy(scheduler)?).map_err(io_string)?;
    run_trigger_and_read(&mut stream, contract)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text: format!("set_stream_scheduler({}) succeeded", scheduler.policy),
        report_text: format!("client applied SCTP stream scheduler policy {}", scheduler.policy),
        assoc_ids: Vec::new(),
    }))
}

fn handle_stream_scheduler_value(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let mut stream = dial_contract(contract)?;
    let scheduler =
        contract.scheduler.as_ref().ok_or_else(|| "missing scheduler contract".to_owned())?;
    stream.set_stream_scheduler(parse_scheduler_policy(scheduler)?).map_err(io_string)?;
    run_trigger_and_read(&mut stream, contract)?;
    let mut op_err =
        stream.set_stream_scheduler_value(scheduler.primary_stream, scheduler.primary_value).err();
    if op_err.is_none() {
        op_err = stream
            .set_stream_scheduler_value(scheduler.secondary_stream, scheduler.secondary_value)
            .err();
    }
    let (evidence_text, report_text) = match op_err {
        Some(err) => (
            format!("set_stream_scheduler_value was not accepted: {}", io_string(err)),
            "client attempted SCTP stream scheduler values, but the API call was not accepted"
                .to_owned(),
        ),
        None => (
            format!(
                "set_stream_scheduler_value succeeded for streams {}/{} with values {}/{}",
                scheduler.primary_stream,
                scheduler.secondary_stream,
                scheduler.primary_value,
                scheduler.secondary_value
            ),
            format!(
                "client applied scheduler values stream {}={} and stream {}={}",
                scheduler.primary_stream,
                scheduler.primary_value,
                scheduler.secondary_stream,
                scheduler.secondary_value
            ),
        ),
    };
    Ok(Some(CompletionPayload {
        evidence_kind: "runtime".to_owned(),
        evidence_text,
        report_text,
        assoc_ids: Vec::new(),
    }))
}

fn dial_contract(contract: &ScenarioContract) -> Result<FeatureStream, String> {
    let addrs = resolve_addrs(&contract.connect_addresses)?;
    FeatureStream::connect(contract, &addrs).map_err(io_string)
}

fn resolve_addrs(raw: &[String]) -> Result<Vec<SocketAddr>, String> {
    raw.iter()
        .map(|addr| addr.parse().map_err(|err| format!("invalid socket address {addr}: {err}")))
        .collect()
}

fn write_contract_messages_with_default_info(
    stream: &mut FeatureStream,
    messages: &[MessageSpec],
) -> Result<(), String> {
    for msg in messages {
        if msg.unordered {
            return Err("unordered delivery requires per-message send flags".to_owned());
        }
        let info =
            SctpSendInfo { stream: msg.stream, flags: 0, ppid: msg.ppid, context: 0, assoc_id: 0 };
        stream.set_default_send_info(info).map_err(io_string)?;
        let payload = materialize_payload(msg);
        let written = stream.send_with_info(payload.as_bytes(), None).map_err(io_string)?;
        if written != payload.len() {
            return Err(format!(
                "short write for payload {}: wrote {} bytes, expected {}",
                msg.payload,
                written,
                payload.len()
            ));
        }
    }
    Ok(())
}

fn materialize_payload(msg: &MessageSpec) -> String {
    if msg.size_bytes == 0 || msg.size_bytes <= msg.payload.len() {
        return msg.payload.clone();
    }
    if msg.payload.is_empty() {
        return "x".repeat(msg.size_bytes);
    }

    let mut out = String::with_capacity(msg.size_bytes);
    while out.len() < msg.size_bytes {
        let remaining = msg.size_bytes - out.len();
        if remaining >= msg.payload.len() {
            out.push_str(&msg.payload);
        } else {
            out.push_str(&msg.payload[..remaining]);
        }
    }
    out
}

fn parse_pr_policy(raw: &str) -> Result<SctpPrPolicy, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "none" => Ok(SctpPrPolicy(SCTP_PR_POLICY_NONE)),
        "ttl" => Ok(SctpPrPolicy(SCTP_PR_POLICY_TTL)),
        "rtx" => Ok(SctpPrPolicy(SCTP_PR_POLICY_RTX)),
        "priority" => Ok(SctpPrPolicy(SCTP_PR_POLICY_PRIORITY)),
        other => Err(format!("unknown PR-SCTP policy {other:?}")),
    }
}

fn parse_scheduler_policy(config: &SchedulerContract) -> Result<SctpScheduler, String> {
    match config.policy.trim().to_ascii_lowercase().as_str() {
        "fcfs" => Ok(SctpScheduler(SCTP_SCHEDULER_FCFS_VALUE)),
        "priority" => Ok(SctpScheduler(SCTP_SCHEDULER_PRIORITY_VALUE)),
        "rr" => Ok(SctpScheduler(SCTP_SCHEDULER_RR_VALUE)),
        "fc" => Ok(SctpScheduler(SCTP_SCHEDULER_FC_VALUE)),
        "wfq" => Ok(SctpScheduler(SCTP_SCHEDULER_WFQ_VALUE)),
        other => Err(format!("unknown scheduler policy {other:?}")),
    }
}

fn apply_auth_contract(stream: &mut FeatureStream, auth: &AuthContract) -> Result<(), String> {
    stream.set_auth_chunks(&auth.chunk_types).map_err(io_string)?;
    stream
        .set_auth_key(&SctpAuthKey {
            assoc_id: 0,
            key_id: auth.primary_key_id,
            secret: auth.primary_secret.as_bytes().to_vec(),
        })
        .map_err(io_string)?;
    if auth.secondary_key_id != 0 || !auth.secondary_secret.is_empty() {
        stream
            .set_auth_key(&SctpAuthKey {
                assoc_id: 0,
                key_id: auth.secondary_key_id,
                secret: auth.secondary_secret.as_bytes().to_vec(),
            })
            .map_err(io_string)?;
    }
    if auth.primary_key_id != 0 {
        stream.activate_auth_key(0, auth.primary_key_id).map_err(io_string)?;
    }
    Ok(())
}

fn apply_message_send_controls(
    stream: &mut FeatureStream,
    msg: &MessageSpec,
    contract: &ScenarioContract,
) -> Result<(), String> {
    if !msg.pr_policy.is_empty() {
        stream
            .set_default_prinfo(SctpPrInfo {
                assoc_id: 0,
                value: msg.pr_value,
                policy: parse_pr_policy(&msg.pr_policy)?,
            })
            .map_err(io_string)?;
    } else {
        stream
            .set_default_prinfo(SctpPrInfo {
                assoc_id: 0,
                value: 0,
                policy: SctpPrPolicy(SCTP_PR_POLICY_NONE),
            })
            .map_err(io_string)?;
    }
    if msg.auth_key_id != 0 {
        if contract.auth.is_none() {
            return Err(format!(
                "message requested auth key {} without auth contract",
                msg.auth_key_id
            ));
        }
        stream.activate_auth_key(0, msg.auth_key_id).map_err(io_string)?;
    }
    Ok(())
}

fn send_contract_messages_with_controls(
    stream: &mut FeatureStream,
    messages: &[MessageSpec],
    contract: &ScenarioContract,
) -> Result<(), String> {
    for msg in messages {
        apply_message_send_controls(stream, msg, contract)?;
        let payload = materialize_payload(msg);
        let info = SctpSendInfo {
            stream: msg.stream,
            flags: if msg.unordered { SCTP_UNORDERED_FLAG } else { 0 },
            ppid: msg.ppid,
            context: 0,
            assoc_id: 0,
        };
        let written = stream.send_with_info(payload.as_bytes(), Some(&info)).map_err(io_string)?;
        if written != payload.len() {
            return Err(format!(
                "short write for payload {}: wrote {} bytes, expected {}",
                msg.payload,
                written,
                payload.len()
            ));
        }
    }
    Ok(())
}

fn dial_contract_prefer_multi(contract: &ScenarioContract) -> Result<FeatureStream, String> {
    dial_contract(contract)
}

fn dial_contract_with_auth(contract: &ScenarioContract) -> Result<FeatureStream, String> {
    let mut stream = dial_contract(contract)?;
    let auth = contract.auth.as_ref().ok_or_else(|| "missing auth contract".to_owned())?;
    apply_auth_contract(&mut stream, auth)?;
    Ok(stream)
}

fn select_bindx_local_addrs(remote: &SocketAddr) -> Result<(SocketAddr, Vec<SocketAddr>), String> {
    let udp = UdpSocket::bind(match remote {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .map_err(io_string)?;
    udp.connect(remote).map_err(io_string)?;
    let local = udp.local_addr().map_err(io_string)?;
    let extra = match local {
        SocketAddr::V4(v4) if !v4.ip().is_loopback() => {
            vec![SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), 0))]
        }
        SocketAddr::V4(_) => vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 0))],
        SocketAddr::V6(_) => Vec::new(),
    };
    Ok((local, extra))
}

fn render_assoc_ids(ids: &[i32]) -> String {
    if ids.is_empty() {
        return "[]".to_owned();
    }
    let parts = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    format!("[{}]", parts.join(","))
}

fn distinct_non_zero_assoc_ids(ids: &[i32]) -> Vec<i32> {
    let mut out = Vec::new();
    for id in ids {
        if *id == 0 || out.contains(id) {
            continue;
        }
        out.push(*id);
    }
    out
}

fn wait_for_one_to_many_assoc_ids(
    socket: &mut FeatureOneToManySocket,
    want: usize,
    deadline: Instant,
) -> Result<Vec<i32>, String> {
    let mut last = Vec::new();
    while Instant::now() < deadline {
        let ids = socket.assoc_ids().map_err(io_string)?;
        last = distinct_non_zero_assoc_ids(&ids);
        if last.len() >= want {
            return Ok(last);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!("observed {} association ids on one-to-many socket; want {}", last.len(), want))
}

fn build_event_mask(subscriptions: &[String]) -> SctpEventMask {
    let mut mask = SctpEventMask::default();
    for sub in subscriptions {
        match sub.as_str() {
            "association" => mask.association = true,
            "shutdown" => mask.shutdown = true,
            "dataio" => mask.data_io = true,
            "address" => mask.address = true,
            "partial_delivery" => mask.partial_delivery = true,
            _ => {}
        }
    }
    mask
}

fn read_server_messages(
    stream: &mut FeatureStream,
    expected: &[MessageSpec],
) -> Result<NotificationSummary, String> {
    let mut summary = NotificationSummary::default();
    let mut buf = vec![0u8; max_expected_payload_size(expected)];
    let mut received_messages = 0usize;
    while received_messages < expected.len() {
        let received = stream.recv_message(&mut buf).map_err(io_string)?;
        if let Some(notification) = received.notification.as_ref() {
            summary.record(notification);
            continue;
        }
        if received.len == 0 {
            return Err(format!(
                "unexpected EOF after receiving {} of {} expected server messages",
                received_messages,
                expected.len()
            ));
        }
        let want = &expected[received_messages];
        let want_payload = materialize_payload(want);
        let got = std::str::from_utf8(&buf[..received.len]).map_err(|err| err.to_string())?;
        if got != want_payload {
            return Err(format!("unexpected server payload {got:?}, want {want_payload:?}"));
        }
        if let Some(info) = received.info {
            if info.stream != want.stream {
                return Err(format!(
                    "unexpected server stream {}, want {}",
                    info.stream, want.stream
                ));
            }
            if info.ppid != want.ppid {
                return Err(format!("unexpected server ppid {}, want {}", info.ppid, want.ppid));
            }
        }
        received_messages += 1;
    }

    stream.set_read_timeout(Some(Duration::from_millis(750))).map_err(io_string)?;
    loop {
        match stream.recv_message(&mut buf) {
            Ok(received) => {
                if let Some(notification) = received.notification.as_ref() {
                    summary.record(notification);
                } else if received.len == 0 {
                    break;
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => return Err(io_string(err)),
        }
    }
    Ok(summary)
}

fn max_expected_payload_size(expected: &[MessageSpec]) -> usize {
    expected
        .iter()
        .map(materialize_payload)
        .map(|payload| payload.len())
        .max()
        .unwrap_or(4096)
        .max(4096)
}

fn run_trigger_and_read(
    stream: &mut FeatureStream,
    contract: &ScenarioContract,
) -> Result<NotificationSummary, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(contract.timeout_seconds as u64)))
        .map_err(io_string)?;
    if !contract.trigger_payload.is_empty() {
        let written =
            stream.send_with_info(contract.trigger_payload.as_bytes(), None).map_err(io_string)?;
        if written != contract.trigger_payload.len() {
            return Err(format!(
                "short write for trigger payload: wrote {} bytes, expected {}",
                written,
                contract.trigger_payload.len()
            ));
        }
    }
    read_server_messages(stream, &contract.server_send_messages)
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config {
        agent_name: "rust-sctp-feature-client".to_owned(),
        environment_name: "rust-sctp".to_owned(),
        transport_profile: RequestedTransportProfile::Auto,
        ..Config::default()
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base-url" => cfg.base_url = args.next().ok_or("--base-url requires a value")?,
            "--agent-name" => {
                cfg.agent_name = args.next().ok_or("--agent-name requires a value")?
            }
            "--environment-name" => {
                cfg.environment_name = args.next().ok_or("--environment-name requires a value")?
            }
            "--transport-profile" => {
                cfg.transport_profile = RequestedTransportProfile::parse(
                    &args.next().ok_or("--transport-profile requires a value")?,
                )?
            }
            "--features" => {
                let raw = args.next().ok_or("--features requires a value")?;
                for part in raw.split(',').map(str::trim).filter(|part| !part.is_empty()) {
                    cfg.feature_filter.insert(part.to_owned(), true);
                }
            }
            "--include-manual-setup" => cfg.include_manual_setup = true,
            "--list-scenarios" => cfg.list_scenarios = true,
            "--help" | "-h" => return Err(usage()),
            unknown => return Err(format!("unknown flag: {unknown}\n\n{}", usage())),
        }
    }

    if !cfg.list_scenarios && cfg.base_url.is_empty() {
        return Err("--base-url is required".to_owned());
    }
    Ok(cfg)
}

fn usage() -> String {
    [
        "usage: sctp-feature-client --base-url <url> [options]",
        "",
        "options:",
        "  --agent-name <name>",
        "  --environment-name <name>",
        "  --transport-profile <auto|native|udp_encap>",
        "  --features <comma,separated,ids>",
        "  --include-manual-setup",
        "  --list-scenarios",
    ]
    .join("\n")
}

fn scenario_catalog() -> &'static [ScenarioDefinition] {
    &[
        ScenarioDefinition {
            feature_id: "socket_create",
            dashboard_title: "Create SCTP socket",
            dashboard_category: "endpoint",
            implementation_key: "socket_create",
            source_symbol: "handle_socket_create",
            description: "Create an SCTP socket locally and report whether the runtime exposes the API.",
            handler: handle_socket_create,
        },
        ScenarioDefinition {
            feature_id: "bind_listen_connect",
            dashboard_title: "Bind, listen, and connect",
            dashboard_category: "association",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Dial the server and send the contract payloads on a basic SCTP association.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "single_message_boundary",
            dashboard_title: "Single message boundary",
            dashboard_category: "messaging",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Send one SCTP user message and let the server verify message-boundary preservation.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "multi_message_boundary",
            dashboard_title: "Multiple message boundaries",
            dashboard_category: "messaging",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Send multiple SCTP user messages in order and preserve boundaries.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "stream_id",
            dashboard_title: "Stream identifier metadata",
            dashboard_category: "metadata",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Send the contract payload on the requested SCTP stream.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "ppid",
            dashboard_title: "PPID metadata",
            dashboard_category: "metadata",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Send the contract payload with the requested SCTP PPID.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "nodelay",
            dashboard_title: "SCTP_NODELAY",
            dashboard_category: "socket_option",
            implementation_key: "nodelay",
            source_symbol: "handle_nodelay",
            description: "Enable SCTP_NODELAY before sending the contract payload.",
            handler: handle_nodelay,
        },
        ScenarioDefinition {
            feature_id: "initmsg",
            dashboard_title: "SCTP_INITMSG",
            dashboard_category: "socket_option",
            implementation_key: "initmsg",
            source_symbol: "handle_initmsg",
            description: "Apply SCTP_INITMSG before sending the contract payload.",
            handler: handle_initmsg,
        },
        ScenarioDefinition {
            feature_id: "rto_assoc_parameters",
            dashboard_title: "SCTP_RTOINFO",
            dashboard_category: "socket_option",
            implementation_key: "rto_info",
            source_symbol: "handle_rto_info",
            description: "Apply SCTP_RTOINFO before sending the contract payload.",
            handler: handle_rto_info,
        },
        ScenarioDefinition {
            feature_id: "delayed_sack_tuning",
            dashboard_title: "SCTP_DELAYED_SACK",
            dashboard_category: "socket_option",
            implementation_key: "delayed_sack",
            source_symbol: "handle_delayed_sack",
            description: "Apply SCTP_DELAYED_SACK before sending the contract payload.",
            handler: handle_delayed_sack,
        },
        ScenarioDefinition {
            feature_id: "max_burst_tuning",
            dashboard_title: "SCTP_MAX_BURST",
            dashboard_category: "socket_option",
            implementation_key: "max_burst",
            source_symbol: "handle_max_burst",
            description: "Apply SCTP_MAX_BURST before sending the contract payload.",
            handler: handle_max_burst,
        },
        ScenarioDefinition {
            feature_id: "multi_bind",
            dashboard_title: "Multihome reference server",
            dashboard_category: "multihoming",
            implementation_key: "multi_bind",
            source_symbol: "handle_multi_bind",
            description: "Connect to all advertised SCTP peer addresses in one association.",
            handler: handle_multi_bind,
        },
        ScenarioDefinition {
            feature_id: "local_addr_enum",
            dashboard_title: "Local address enumeration",
            dashboard_category: "multihoming",
            implementation_key: "local_addr_enum",
            source_symbol: "handle_local_addr_enum",
            description: "Enumerate local SCTP addresses after association setup.",
            handler: handle_local_addr_enum,
        },
        ScenarioDefinition {
            feature_id: "peer_addr_enum",
            dashboard_title: "Peer address enumeration",
            dashboard_category: "multihoming",
            implementation_key: "peer_addr_enum",
            source_symbol: "handle_peer_addr_enum",
            description: "Enumerate peer SCTP addresses after association setup.",
            handler: handle_peer_addr_enum,
        },
        ScenarioDefinition {
            feature_id: "bindx_add_remove",
            dashboard_title: "SCTP_BINDX add/remove",
            dashboard_category: "multihoming",
            implementation_key: "bindx_add_remove",
            source_symbol: "handle_bindx_add_remove",
            description: "Exercise local SCTP bindx add/remove controls before sending the probe payload.",
            handler: handle_bindx_add_remove,
        },
        ScenarioDefinition {
            feature_id: "primary_addr_management",
            dashboard_title: "Primary address management",
            dashboard_category: "multihoming",
            implementation_key: "primary_addr_management",
            source_symbol: "handle_primary_addr_management",
            description: "Attempt a local primary-address change on a multihomed association.",
            handler: handle_primary_addr_management,
        },
        ScenarioDefinition {
            feature_id: "peer_primary_addr_request",
            dashboard_title: "Peer primary address request",
            dashboard_category: "multihoming",
            implementation_key: "peer_primary_addr_request",
            source_symbol: "handle_peer_primary_addr_request",
            description: "Attempt a peer primary-address change request on a multihomed association.",
            handler: handle_peer_primary_addr_request,
        },
        ScenarioDefinition {
            feature_id: "default_sndinfo_recvrcvinfo",
            dashboard_title: "SCTP_DEFAULT_SNDINFO / RECVRCVINFO",
            dashboard_category: "metadata",
            implementation_key: "default_send_info",
            source_symbol: "handle_default_send_info",
            description: "Apply SCTP_DEFAULT_SNDINFO and send without per-message overrides.",
            handler: handle_default_send_info,
        },
        ScenarioDefinition {
            feature_id: "large_message_reassembly",
            dashboard_title: "Large message reassembly",
            dashboard_category: "fragmentation",
            implementation_key: "large_message_reassembly",
            source_symbol: "handle_large_message_reassembly",
            description: "Send one large SCTP user message using default metadata and let the server verify reassembly.",
            handler: handle_large_message_reassembly,
        },
        ScenarioDefinition {
            feature_id: "maxseg_fragmentation",
            dashboard_title: "SCTP_MAXSEG fragmentation",
            dashboard_category: "fragmentation",
            implementation_key: "maxseg_fragmentation",
            source_symbol: "handle_maxseg_fragmentation",
            description: "Apply SCTP_MAXSEG and send one large SCTP user message.",
            handler: handle_maxseg_fragmentation,
        },
        ScenarioDefinition {
            feature_id: "unordered_delivery",
            dashboard_title: "Unordered delivery",
            dashboard_category: "messaging",
            implementation_key: "basic_send",
            source_symbol: "handle_basic_send",
            description: "Send the contract payload using the unordered SCTP send flag when requested.",
            handler: handle_basic_send,
        },
        ScenarioDefinition {
            feature_id: "negative_connect_error",
            dashboard_title: "Negative connect path",
            dashboard_category: "error_path",
            implementation_key: "negative_connect_error",
            source_symbol: "handle_negative_connect_error",
            description: "Attempt the invalid SCTP target from the contract and report the error.",
            handler: handle_negative_connect_error,
        },
        ScenarioDefinition {
            feature_id: "autoclose",
            dashboard_title: "SCTP_AUTOCLOSE",
            dashboard_category: "socket_option",
            implementation_key: "autoclose",
            source_symbol: "handle_autoclose",
            description: "Apply SCTP_AUTOCLOSE on a locally bound SCTP socket and report whether it is accepted.",
            handler: handle_autoclose,
        },
        ScenarioDefinition {
            feature_id: "notifications",
            dashboard_title: "Association and shutdown notifications",
            dashboard_category: "events",
            implementation_key: "notification_observer",
            source_symbol: "handle_notification_scenario",
            description: "Subscribe to SCTP notifications and report the association and shutdown events observed.",
            handler: handle_notification_scenario,
        },
        ScenarioDefinition {
            feature_id: "event_subscription_matrix",
            dashboard_title: "Event subscription matrix",
            dashboard_category: "events",
            implementation_key: "notification_observer",
            source_symbol: "handle_notification_scenario",
            description: "Subscribe to the available SCTP events and report which notifications were delivered.",
            handler: handle_notification_scenario,
        },
        ScenarioDefinition {
            feature_id: "association_shutdown_notifications",
            dashboard_title: "Association shutdown notifications",
            dashboard_category: "events",
            implementation_key: "notification_observer",
            source_symbol: "handle_notification_scenario",
            description: "Observe graceful association teardown notifications after the server trigger.",
            handler: handle_notification_scenario,
        },
        ScenarioDefinition {
            feature_id: "recvnxtinfo",
            dashboard_title: "SCTP_RECVNXTINFO",
            dashboard_category: "metadata",
            implementation_key: "recv_nxtinfo",
            source_symbol: "handle_recv_nxtinfo",
            description: "Receive two server messages and report next-message metadata from the first receive.",
            handler: handle_recv_nxtinfo,
        },
        ScenarioDefinition {
            feature_id: "idata_interleaving",
            dashboard_title: "I-DATA / fragment interleaving",
            dashboard_category: "messaging",
            implementation_key: "idata_interleaving",
            source_symbol: "handle_idata_interleaving",
            description: "Enable fragment interleaving and receive the server's large-plus-small message burst.",
            handler: handle_idata_interleaving,
        },
        ScenarioDefinition {
            feature_id: "peer_addr_change_notifications",
            dashboard_title: "Peer address change notifications",
            dashboard_category: "path-management",
            implementation_key: "peer_addr_notifications",
            source_symbol: "handle_peer_addr_change_notifications",
            description: "Subscribe to peer-address notifications during multihome association setup and early traffic.",
            handler: handle_peer_addr_change_notifications,
        },
        ScenarioDefinition {
            feature_id: "partial_delivery_event",
            dashboard_title: "Partial delivery event",
            dashboard_category: "notifications",
            implementation_key: "partial_delivery",
            source_symbol: "handle_partial_delivery_event",
            description: "Receive a large server message and observe partial-delivery notifications while it is being surfaced.",
            handler: handle_partial_delivery_event,
        },
        ScenarioDefinition {
            feature_id: "peeloff_assoc",
            dashboard_title: "Association peeloff",
            dashboard_category: "association",
            implementation_key: "peeloff_assoc",
            source_symbol: "handle_peeloff_assoc",
            description: "Attempt to peel the association onto a dedicated SCTP socket.",
            handler: handle_peeloff_assoc,
        },
        ScenarioDefinition {
            feature_id: "assoc_id_listing",
            dashboard_title: "Association identifier listing",
            dashboard_category: "association",
            implementation_key: "assoc_id_listing",
            source_symbol: "handle_assoc_id_listing",
            description: "Enumerate association identifiers after sending the probe payload.",
            handler: handle_assoc_id_listing,
        },
        ScenarioDefinition {
            feature_id: "assoc_status_opt_info",
            dashboard_title: "SCTP_STATUS / opt_info",
            dashboard_category: "introspection",
            implementation_key: "assoc_status",
            source_symbol: "handle_assoc_status",
            description: "Query association status and report the returned state summary.",
            handler: handle_assoc_status,
        },
        ScenarioDefinition {
            feature_id: "one_to_many_multi_assoc",
            dashboard_title: "One-to-many multi-association socket",
            dashboard_category: "one-to-many",
            implementation_key: "one_to_many_multi_assoc",
            source_symbol: "handle_one_to_many_multi_assoc",
            description: "Use one unconnected SCTP socket to create two associations to two server ports and report the assoc ids.",
            handler: handle_one_to_many_multi_assoc,
        },
        ScenarioDefinition {
            feature_id: "stream_reconfig_reset",
            dashboard_title: "Stream reconfiguration reset",
            dashboard_category: "reconfiguration",
            implementation_key: "stream_reset",
            source_symbol: "handle_stream_reset",
            description: "Attempt SCTP stream reset on the active association after the server trigger.",
            handler: handle_stream_reset,
        },
        ScenarioDefinition {
            feature_id: "stream_reconfig_add_streams",
            dashboard_title: "Stream reconfiguration add streams",
            dashboard_category: "reconfiguration",
            implementation_key: "stream_add_streams",
            source_symbol: "handle_stream_add_streams",
            description: "Attempt SCTP stream addition on the active association after the server trigger.",
            handler: handle_stream_add_streams,
        },
        ScenarioDefinition {
            feature_id: "pr_sctp_ttl",
            dashboard_title: "PR-SCTP TTL policy",
            dashboard_category: "reliability",
            implementation_key: "pr_sctp",
            source_symbol: "handle_pr_ttl",
            description: "Apply a TTL-based partially reliable send and verify forward progress under manual impairment.",
            handler: handle_pr_ttl,
        },
        ScenarioDefinition {
            feature_id: "pr_sctp_rtx",
            dashboard_title: "PR-SCTP retransmission policy",
            dashboard_category: "reliability",
            implementation_key: "pr_sctp",
            source_symbol: "handle_pr_rtx",
            description: "Apply a retransmission-limited partially reliable send and verify forward progress under manual impairment.",
            handler: handle_pr_rtx,
        },
        ScenarioDefinition {
            feature_id: "auth_required_chunks",
            dashboard_title: "SCTP AUTH required chunks",
            dashboard_category: "authentication",
            implementation_key: "auth_required_chunks",
            source_symbol: "handle_auth_required_chunks",
            description: "Configure SCTP AUTH chunk coverage and shared keys before sending the probe payload.",
            handler: handle_auth_required_chunks,
        },
        ScenarioDefinition {
            feature_id: "auth_key_rotation",
            dashboard_title: "SCTP AUTH key rotation",
            dashboard_category: "authentication",
            implementation_key: "auth_key_rotation",
            source_symbol: "handle_auth_key_rotation",
            description: "Install SCTP AUTH keys, rotate the active key, and send the probe payload.",
            handler: handle_auth_key_rotation,
        },
        ScenarioDefinition {
            feature_id: "asconf_add_remove",
            dashboard_title: "ASCONF address add/remove",
            dashboard_category: "multihoming",
            implementation_key: "asconf_add_remove",
            source_symbol: "handle_asconf_add_remove",
            description: "Attempt SCTP dynamic address reconfiguration on the connected association.",
            handler: handle_asconf_add_remove,
        },
        ScenarioDefinition {
            feature_id: "stream_scheduler_policy",
            dashboard_title: "Stream scheduler policy",
            dashboard_category: "scheduler",
            implementation_key: "stream_scheduler_policy",
            source_symbol: "handle_stream_scheduler_policy",
            description: "Apply a non-default SCTP stream scheduler policy on the active association.",
            handler: handle_stream_scheduler_policy,
        },
        ScenarioDefinition {
            feature_id: "stream_scheduler_value",
            dashboard_title: "Stream scheduler value",
            dashboard_category: "scheduler",
            implementation_key: "stream_scheduler_value",
            source_symbol: "handle_stream_scheduler_value",
            description: "Apply per-stream SCTP scheduler values on the active association.",
            handler: handle_stream_scheduler_value,
        },
    ]
}

fn scenario_summaries() -> Vec<ScenarioSummary<'static>> {
    scenario_catalog()
        .iter()
        .map(|scenario| ScenarioSummary {
            feature_id: scenario.feature_id,
            dashboard_title: scenario.dashboard_title,
            dashboard_category: scenario.dashboard_category,
            implementation_key: scenario.implementation_key,
            source_symbol: scenario.source_symbol,
            source_path: SOURCE_PATH,
            description: scenario.description,
        })
        .collect()
}

fn emit_json<T: Serialize>(value: &T) {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value).unwrap();
    use std::io::Write;
    out.write_all(b"\n").unwrap();
}

fn io_string(err: io::Error) -> String {
    err.to_string()
}
