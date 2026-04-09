#![feature(sctp)]

use std::env;
use std::io;
use std::net::{SocketAddr, SctpListener, SctpSendInfo, SctpStream};
use std::process;
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone)]
struct MessageSpec {
    payload: String,
    stream: u16,
    ppid: u32,
}

#[derive(Default)]
struct Options {
    mode: String,
    bind: Option<SocketAddr>,
    connect: Option<SocketAddr>,
    expect_failure: Option<String>,
    read_messages: usize,
    messages: Vec<MessageSpec>,
}

fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    };

    let result = match opts.mode.as_str() {
        "server" => run_server(&opts),
        "client" => run_client(&opts),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported mode")),
    };
    if let Err(err) = result {
        emit_error(&err.to_string());
        process::exit(1);
    }
}

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or("missing mode")?;
    let mut opts = Options { mode, ..Options::default() };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let raw = args.next().ok_or("missing value for --bind")?;
                opts.bind = Some(SocketAddr::from_str(&raw).map_err(|err| err.to_string())?);
            }
            "--connect" => {
                let raw = args.next().ok_or("missing value for --connect")?;
                opts.connect = Some(SocketAddr::from_str(&raw).map_err(|err| err.to_string())?);
            }
            "--expect-failure" => {
                opts.expect_failure = Some(args.next().ok_or("missing value for --expect-failure")?);
            }
            "--read-messages" => {
                let raw = args.next().ok_or("missing value for --read-messages")?;
                opts.read_messages = raw.parse::<usize>().map_err(|err| err.to_string())?;
            }
            "--message" => {
                let raw = args.next().ok_or("missing value for --message")?;
                opts.messages.push(parse_message(&raw)?);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(opts)
}

fn parse_message(raw: &str) -> Result<MessageSpec, String> {
    let mut parts = raw.splitn(3, ':');
    let payload = parts.next().ok_or("message missing payload")?.to_owned();
    let stream = parts
        .next()
        .ok_or("message missing stream")?
        .parse::<u16>()
        .map_err(|err| err.to_string())?;
    let ppid = parts
        .next()
        .ok_or("message missing ppid")?
        .parse::<u32>()
        .map_err(|err| err.to_string())?;
    Ok(MessageSpec { payload, stream, ppid })
}

fn run_server(opts: &Options) -> io::Result<()> {
    let bind = opts
        .bind
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "server mode requires --bind"))?;
    let listener = SctpListener::bind(bind)?;
    emit_ready(&listener.local_addr()?.to_string());

    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut buf = vec![0u8; 8192];
    let mut recv_count = 0usize;
    while recv_count < opts.read_messages {
        let received = stream.recv_message(&mut buf)?;
        if let Some(notification) = received.notification {
            emit_notify(&format!("{notification:?}"));
            continue;
        }
        if received.len == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        let (stream_id, ppid, assoc_id) = match received.info {
            Some(info) => (info.stream, info.ppid, info.assoc_id),
            None => (0, 0, 0),
        };
        let payload = String::from_utf8_lossy(&buf[..received.len]).to_string();
        emit_recv(&payload, stream_id, ppid, assoc_id);
        recv_count += 1;
    }
    emit_complete("recv_count", recv_count);
    Ok(())
}

fn run_client(opts: &Options) -> io::Result<()> {
    let connect = opts
        .connect
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "client mode requires --connect"))?;
    let mut stream = match SctpStream::connect(connect) {
        Ok(stream) => stream,
        Err(err) => {
            if matches!(opts.expect_failure.as_deref(), Some("connect" | "connect_or_send")) {
                emit_expected_failure("connect", &err.to_string());
                return Ok(());
            }
            return Err(err);
        }
    };

    for message in &opts.messages {
        let info = SctpSendInfo {
            stream: message.stream,
            flags: 0,
            ppid: message.ppid,
            context: 0,
            assoc_id: 0,
        };
        if let Err(err) = stream.send_with_info(message.payload.as_bytes(), Some(&info)) {
            if matches!(opts.expect_failure.as_deref(), Some("send" | "connect_or_send")) {
                emit_expected_failure("send", &err.to_string());
                return Ok(());
            }
            return Err(err);
        }
        emit_sent(&message.payload, message.stream, message.ppid);
    }

    if opts.expect_failure.is_some() {
        return Err(io::Error::other("expected failure was not observed"));
    }
    emit_complete("sent_count", opts.messages.len());
    Ok(())
}

fn escape_json(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r")
}

fn emit_ready(addr: &str) {
    println!("{{\"event\":\"ready\",\"local_addrs\":[\"{}\"]}}", escape_json(addr));
}

fn emit_recv(payload: &str, stream: u16, ppid: u32, assoc_id: i32) {
    println!(
        "{{\"event\":\"recv\",\"payload\":\"{}\",\"stream\":{},\"ppid\":{},\"assoc_id\":{}}}",
        escape_json(payload),
        stream,
        ppid,
        assoc_id
    );
}

fn emit_sent(payload: &str, stream: u16, ppid: u32) {
    println!(
        "{{\"event\":\"sent\",\"payload\":\"{}\",\"stream\":{},\"ppid\":{}}}",
        escape_json(payload),
        stream,
        ppid
    );
}

fn emit_notify(notification: &str) {
    println!(
        "{{\"event\":\"notify\",\"message\":\"{}\"}}",
        escape_json(notification)
    );
}

fn emit_expected_failure(stage: &str, message: &str) {
    println!(
        "{{\"event\":\"expected_failure\",\"stage\":\"{}\",\"message\":\"{}\"}}",
        escape_json(stage),
        escape_json(message)
    );
}

fn emit_complete(field: &str, count: usize) {
    println!("{{\"event\":\"complete\",\"{}\":{}}}", field, count);
}

fn emit_error(message: &str) {
    println!("{{\"event\":\"error\",\"message\":\"{}\"}}", escape_json(message));
}
