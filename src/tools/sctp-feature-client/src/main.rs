#![feature(sctp)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use std::net::{
    AddrParseError, SocketAddr, SctpInitOptions, SctpListener, SctpMultiAddr, SctpSendInfo,
    SctpStream,
};
use std::thread;
use std::time::{Duration, Instant};

const STATE_PASSED: &str = "passed";
const STATE_FAILED: &str = "failed";
const STATE_UNSUPPORTED: &str = "unsupported";
const STATE_TIMED_OUT: &str = "timed_out";
const COMPLETION_SERVER_OBSERVED: &str = "server_observed";

const SOURCE_PATH: &str = "src/tools/sctp-feature-client/src/main.rs";

type Handler = fn(&FeatureServerClient, &SessionResponse, &CatalogFeature, &ScenarioContract) -> Result<Option<CompletionPayload>, String>;

#[derive(Default)]
struct Config {
    base_url: String,
    agent_name: String,
    environment_name: String,
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
    server: String,
    features: Vec<CatalogFeature>,
}

#[derive(Clone, Deserialize)]
struct CatalogFeature {
    id: String,
    title: String,
    category: String,
    summary: String,
    completion_mode: String,
    timeout_seconds: i32,
    manual_setup_required: bool,
}

#[derive(Deserialize)]
struct SessionResponse {
    session_id: String,
    dashboard_path: String,
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
    manual_setup_instructions: Vec<String>,
    report_prompt: String,
    instructions_text: String,
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
}

#[derive(Serialize)]
struct CompletionPayload {
    evidence_kind: String,
    evidence_text: String,
    report_text: String,
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
    ) -> Result<SessionResponse, String> {
        self.post_json(
            "/v1/sessions",
            &CreateSessionPayload { agent_name, environment_name },
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

    let session = match client.create_session(&cfg.agent_name, &cfg.environment_name) {
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
    let scenario = scenario_catalog()
        .iter()
        .find(|scenario| scenario.feature_id == feature.id)
        .copied();

    let Some(scenario) = scenario else {
        return client.unsupported_feature(
            &session.session_id,
            &feature.id,
            &UnsupportedPayload {
                reason: "unmapped feature".to_owned(),
                evidence_kind: "client_gap".to_owned(),
                evidence_text: "the rust-sctp feature client does not implement this feature id".to_owned(),
            },
        );
    };

    if scenario.dashboard_title != feature.title || scenario.dashboard_category != feature.category {
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
    _contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let sock = SctpListener::bind(addr).map_err(io_string)?;
    drop(sock);
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_create".to_owned(),
        evidence_text: "created SCTP listener socket successfully".to_owned(),
        report_text: "rust-sctp created an SCTP socket locally".to_owned(),
    }))
}

fn handle_basic_send(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(None)
}

fn handle_nodelay(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    stream.set_nodelay(true).map_err(io_string)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: "enabled SCTP_NODELAY on the client socket".to_owned(),
        report_text: "rust-sctp accepted SCTP_NODELAY".to_owned(),
    }))
}

fn handle_initmsg(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    stream
        .set_init_options(SctpInitOptions {
            num_ostreams: 32,
            max_instreams: 32,
            max_attempts: 0,
            max_init_timeout: 0,
        })
        .map_err(io_string)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: "applied SCTP_INITMSG before sending the probe".to_owned(),
        report_text: "rust-sctp accepted SCTP_INITMSG".to_owned(),
    }))
}

fn handle_rto_info(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    let info = std::net::SctpRtoInfo { assoc_id: 0, initial: 1500, max: 4000, min: 800 };
    stream.set_rto_info(info).map_err(io_string)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "applied SCTP_RTOINFO initial={} max={} min={}",
            info.initial, info.max, info.min
        ),
        report_text: "rust-sctp accepted SCTP_RTOINFO".to_owned(),
    }))
}

fn handle_delayed_sack(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
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
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!(
            "applied SCTP_DELAYED_SACK delay_ms={} freq={}",
            info.delay, info.frequency
        ),
        report_text: "rust-sctp accepted SCTP_DELAYED_SACK".to_owned(),
    }))
}

fn handle_max_burst(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    let tuning = contract
        .socket_tuning
        .as_ref()
        .ok_or_else(|| format!("feature {} did not provide socket_tuning", contract.feature_id))?;
    if tuning.max_burst == 0 {
        return Err(format!("feature {} did not provide socket_tuning.max_burst", contract.feature_id));
    }
    stream.set_max_burst(tuning.max_burst).map_err(io_string)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!("applied SCTP_MAX_BURST={}", tuning.max_burst),
        report_text: "rust-sctp accepted SCTP_MAX_BURST".to_owned(),
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
    let msg = contract
        .client_send_messages
        .first()
        .ok_or_else(|| format!("feature {} did not provide any client_send_messages", contract.feature_id))?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!("applied SCTP_DEFAULT_SNDINFO stream={} ppid={}", msg.stream, msg.ppid),
        report_text: "rust-sctp accepted SCTP_DEFAULT_SNDINFO".to_owned(),
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
        return Err(format!("feature {} did not provide socket_tuning.maxseg", contract.feature_id));
    }
    stream.set_maxseg(tuning.maxseg).map_err(io_string)?;
    write_contract_messages_with_default_info(&mut stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: format!("applied SCTP_MAXSEG={}", tuning.maxseg),
        report_text: "rust-sctp accepted SCTP_MAXSEG".to_owned(),
    }))
}

fn handle_autoclose(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    _contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let stream = SctpStream::bind(addr).map_err(io_string)?;
    stream.set_autoclose(5).map_err(io_string)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "socket_option".to_owned(),
        evidence_text: "applied SCTP_AUTOCLOSE=5 on a locally bound socket".to_owned(),
        report_text: "rust-sctp accepted SCTP_AUTOCLOSE".to_owned(),
    }))
}

fn handle_multi_bind(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let addrs = resolve_addrs(&contract.connect_addresses)?;
    let multi = SctpMultiAddr::new(addrs).map_err(io_string)?;
    let stream = SctpStream::connect_multi(&multi).map_err(io_string)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "multihoming".to_owned(),
        evidence_text: format!("connected to {} advertised SCTP peer addresses", multi.addrs().len()),
        report_text: "rust-sctp connected to the multihome reference server".to_owned(),
    }))
}

fn handle_local_addr_enum(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    let local = stream.local_addrs().map_err(io_string)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "address_enumeration".to_owned(),
        evidence_text: format!(
            "observed local addresses {}",
            local.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        ),
        report_text: "rust-sctp enumerated local SCTP addresses".to_owned(),
    }))
}

fn handle_peer_addr_enum(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let stream = dial_contract(contract)?;
    send_contract_messages(&stream, &contract.client_send_messages)?;
    let peers = stream.peer_addrs().map_err(io_string)?;
    Ok(Some(CompletionPayload {
        evidence_kind: "address_enumeration".to_owned(),
        evidence_text: format!(
            "observed peer addresses {}",
            peers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
        ),
        report_text: "rust-sctp enumerated peer SCTP addresses".to_owned(),
    }))
}

fn handle_negative_connect_error(
    _client: &FeatureServerClient,
    _session: &SessionResponse,
    _feature: &CatalogFeature,
    contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    let target: SocketAddr = contract
        .negative_connect_target
        .parse()
        .map_err(|err: AddrParseError| err.to_string())?;
    match SctpStream::connect(target) {
        Ok(_) => Err("unexpectedly connected to the negative target".to_owned()),
        Err(err) => Ok(Some(CompletionPayload {
            evidence_kind: "connect_error".to_owned(),
            evidence_text: err.to_string(),
            report_text: "rust-sctp surfaced an SCTP connect error for the invalid target".to_owned(),
        })),
    }
}

fn handle_unsupported(
    client: &FeatureServerClient,
    session: &SessionResponse,
    feature: &CatalogFeature,
    _contract: &ScenarioContract,
) -> Result<Option<CompletionPayload>, String> {
    client
        .unsupported_feature(
            &session.session_id,
            &feature.id,
            &UnsupportedPayload {
                reason: "unimplemented runtime feature".to_owned(),
                evidence_kind: "runtime_gap".to_owned(),
                evidence_text: "the current rust-sctp runtime does not expose the API needed for this feature yet".to_owned(),
            },
        )
        .map(|_| None)
}

fn dial_contract(contract: &ScenarioContract) -> Result<SctpStream, String> {
    let addrs = resolve_addrs(&contract.connect_addresses)?;
    if addrs.is_empty() {
        return Err("contract did not include any SCTP connect addresses".to_owned());
    }
    let init = SctpInitOptions { num_ostreams: 32, max_instreams: 32, ..SctpInitOptions::default() };
    if addrs.len() == 1 {
        SctpStream::connect_with_init_options(addrs[0], init).map_err(io_string)
    } else {
        let multi = SctpMultiAddr::new(addrs).map_err(io_string)?;
        SctpStream::connect_multi_with_init_options(&multi, init).map_err(io_string)
    }
}

fn resolve_addrs(raw: &[String]) -> Result<Vec<SocketAddr>, String> {
    raw.iter()
        .map(|addr| addr.parse().map_err(|err| format!("invalid socket address {addr}: {err}")))
        .collect()
}

fn send_contract_messages(stream: &SctpStream, messages: &[MessageSpec]) -> Result<(), String> {
    for msg in messages {
        let payload = materialize_payload(msg);
        let info = SctpSendInfo {
            stream: msg.stream,
            flags: if msg.unordered { 1 } else { 0 },
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

fn write_contract_messages_with_default_info(
    stream: &mut SctpStream,
    messages: &[MessageSpec],
) -> Result<(), String> {
    for msg in messages {
        if msg.unordered {
            return Err("unordered delivery requires per-message send flags".to_owned());
        }
        let info = SctpSendInfo {
            stream: msg.stream,
            flags: 0,
            ppid: msg.ppid,
            context: 0,
            assoc_id: 0,
        };
        stream.set_default_send_info(info).map_err(io_string)?;
        let payload = materialize_payload(msg);
        stream.write_all(payload.as_bytes()).map_err(io_string)?;
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

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config {
        agent_name: "rust-sctp-feature-client".to_owned(),
        environment_name: "rust-sctp".to_owned(),
        ..Config::default()
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--base-url" => cfg.base_url = args.next().ok_or("--base-url requires a value")?,
            "--agent-name" => cfg.agent_name = args.next().ok_or("--agent-name requires a value")?,
            "--environment-name" => {
                cfg.environment_name = args.next().ok_or("--environment-name requires a value")?
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
            implementation_key: "unsupported",
            source_symbol: "handle_unsupported",
            description: "Currently unsupported by the Rust client until notification delivery is surfaced.",
            handler: handle_unsupported,
        },
        ScenarioDefinition {
            feature_id: "event_subscription_matrix",
            dashboard_title: "Event subscription matrix",
            dashboard_category: "events",
            implementation_key: "unsupported",
            source_symbol: "handle_unsupported",
            description: "Currently unsupported by the Rust client until notification delivery is surfaced.",
            handler: handle_unsupported,
        },
        ScenarioDefinition {
            feature_id: "association_shutdown_notifications",
            dashboard_title: "Association shutdown notifications",
            dashboard_category: "events",
            implementation_key: "unsupported",
            source_symbol: "handle_unsupported",
            description: "Currently unsupported by the Rust client until notification delivery is surfaced.",
            handler: handle_unsupported,
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
