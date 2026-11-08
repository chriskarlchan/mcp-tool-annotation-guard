// Copyright 2026 Salesforce, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Requests the guard forwards without reading a body (GET, DELETE, OPTIONS,
//! HEAD) must not carry anything the guard didn't check to the server:
//!
//! - No upgrade (to a WebSocket, for example): after an upgrade the
//!   connection no longer carries HTTP requests, so the guard could not
//!   check the messages on it. MCP over HTTP never upgrades.
//! - No body: over HTTP/2 a request can send a body without a
//!   `Content-Length` header.
//!
//! It also sends a refused call with unusual body framing
//! (`Transfer-Encoding` and `Content-Length` together, codings other than
//! `chunked`, repeated or malformed lengths), which must never reach the
//! server either.
//!
//! The upstream is a small server in this test that accepts every upgrade and
//! counts the bodies it receives on those methods, on host port
//! `PASSTHROUGH_MOCK_PORT` (default 8092), reached from the gateway container
//! at `host.docker.internal`. HTTP/2 requests are sent with `curl`.
//!
//! Opt-in (needs Docker Desktop and curl): `make build && cargo test --test
//! passthrough -- --ignored --nocapture`

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pdk_test::port::Port;
use pdk_test::services::flex::{ApiConfig, Flex, FlexConfig, PolicyConfig};
use pdk_test::services::httpmock::HttpMockConfig;
use pdk_test::{pdk_test, TestComposite};
use serde_json::json;

use common::*;

const PORT: Port = 8081;
const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
/// Unknown to the guard, so every call to it is refused.
const REFUSED_TOOL: &str = "delete_repository";
const REFUSED_CALL: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_repository","arguments":{}}}"#;

fn mock_port() -> u16 {
    std::env::var("PASSTHROUGH_MOCK_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8092)
}

/// What reached the upstream.
#[derive(Default)]
struct Seen {
    upgrades: AtomicUsize,
    /// Bodies on methods other than POST.
    bodies: AtomicUsize,
    /// Requests that name the refused tool.
    refused_tool: AtomicUsize,
}

fn read_body(
    reader: &mut BufReader<TcpStream>,
    length: usize,
    chunked: bool,
) -> std::io::Result<Vec<u8>> {
    if !chunked {
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        return Ok(body);
    }
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        reader.read_line(&mut size)?;
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"))?;
        let mut chunk = vec![0; size + 2];
        reader.read_exact(&mut chunk)?;
        if size == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..size]);
    }
}

/// Accepts an upgrade, then echoes whatever arrives on the connection.
/// Answers anything else with an empty JSON-RPC result.
fn serve(mut stream: TcpStream, seen: &Seen) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let method = request_line.split(' ').next().unwrap_or("").to_owned();
    let (mut upgrade, mut length, mut chunked) = (false, 0, false);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end().to_ascii_lowercase();
        if line.is_empty() {
            break;
        }
        if line.starts_with("upgrade:") {
            upgrade = true;
        }
        if let Some(value) = line.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        if line.starts_with("transfer-encoding:") && line.contains("chunked") {
            chunked = true;
        }
    }
    if !upgrade {
        let body = read_body(&mut reader, length, chunked)?;
        if String::from_utf8_lossy(&body).contains(REFUSED_TOOL) {
            println!(
                "upstream got the refused tool: {}",
                String::from_utf8_lossy(&body)
            );
            seen.refused_tool.fetch_add(1, Ordering::SeqCst);
        }
        if method != "POST" && !body.is_empty() {
            println!(
                "upstream got a {method} body: {}",
                String::from_utf8_lossy(&body)
            );
            seen.bodies.fetch_add(1, Ordering::SeqCst);
        }
        let reply = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        return write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
            reply.len()
        );
    }
    seen.upgrades.fetch_add(1, Ordering::SeqCst);
    stream.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
    )?;
    let mut buffer = [0; 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..read])?;
    }
}

fn start_upstream(port: u16) -> anyhow::Result<Arc<Seen>> {
    // Docker Desktop delivers host.docker.internal connections on loopback.
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let seen = Arc::new(Seen::default());
    let shared = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = Arc::clone(&shared);
            std::thread::spawn(move || {
                let _ = serve(stream, &seen);
            });
        }
    });
    Ok(seen)
}

/// Sends `head` on a new HTTP/1.1 connection and returns the status line.
fn status_line(address: &str, head: &str) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(head.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(line.trim_end().to_owned())
}

/// Sends an HTTP/2 request (without TLS) with `curl` and returns the HTTP
/// version and status, such as `2 200`. With `body`, the body is streamed
/// from stdin, so the request has no `Content-Length`.
fn h2(url: &str, method: &str, body: Option<&str>) -> anyhow::Result<String> {
    let mut command = Command::new("curl");
    command
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_version} %{http_code}",
        ])
        .args(["--http2-prior-knowledge", "--max-time", "10", "-X", method])
        .args(["-H", "content-type: application/json"])
        .args(["-H", "accept: application/json, text/event-stream"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if body.is_some() {
        command.args(["-T", "-"]);
    }
    let mut child = command.arg(url).spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    if let Some(body) = body {
        stdin.write_all(body.as_bytes())?;
    }
    drop(stdin);
    let output = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[pdk_test]
#[ignore = "needs host.docker.internal (Docker Desktop) and curl; run explicitly"]
async fn passthrough_requests_carry_nothing_unchecked() -> anyhow::Result<()> {
    let port = mock_port();
    let seen = start_upstream(port)?;

    // Only used for its address: the gateway reaches the upstream on the host.
    let host_upstream = HttpMockConfig::builder()
        .hostname("host.docker.internal")
        .port(port)
        .build();
    let guard = PolicyConfig::builder()
        .name(POLICY_NAME)
        .configuration(json!({}))
        .build();
    let api = ApiConfig::builder()
        .name("passthroughApi")
        .upstream(&host_upstream)
        .path("/")
        .port(PORT)
        .policies([guard])
        .build();
    let flex_config = FlexConfig::builder()
        .version(flex_version())
        .hostname("local-flex")
        .with_api(api)
        .config_mounts([(POLICY_DIR, "policy"), (COMMON_CONFIG_DIR, "common")])
        .build();
    let composite = TestComposite::builder()
        .with_service(flex_config)
        .build()
        .await?;
    let flex: Flex = composite.service()?;
    let base = flex.external_url(PORT).unwrap().to_string();
    let base = base.trim_end_matches('/');
    let url = format!("{base}/mcp");
    let address = base.trim_start_matches("http://").to_owned();
    println!("Omni Gateway {}", flex_version());

    let post = |extra: &str| {
        format!(
            "POST /mcp HTTP/1.1\r\nhost: local-flex\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\n{extra}content-length: {}\r\n\r\n{PING}",
            PING.len()
        )
    };
    let websocket = "connection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n";
    // What Java's HttpClient (used by the MCP Java SDK) sends on plain HTTP.
    let h2c = "connection: Upgrade, HTTP2-Settings\r\nupgrade: h2c\r\nhttp2-settings: AAEAAEAAAAIAAAABAAMAAABkAAQBAAAAAAUAAEAA\r\n";

    // Requests that don't upgrade still pass, also with the upgrade
    // headers some HTTP/2 clients send that the gateway doesn't act on.
    for (label, head) in [
        (
            "plain GET",
            "GET /mcp HTTP/1.1\r\nhost: local-flex\r\naccept: text/event-stream\r\nconnection: close\r\n\r\n".to_owned(),
        ),
        ("plain POST", post("connection: close\r\n")),
        (
            "h2c GET",
            format!("GET /mcp HTTP/1.1\r\nhost: local-flex\r\naccept: text/event-stream\r\n{h2c}\r\n"),
        ),
        ("h2c POST", post(h2c)),
    ] {
        let line = status_line(&address, &head)?;
        println!("{label}: {line}");
        assert!(line.starts_with("HTTP/1.1 200"), "{}: {}", label, line);
    }

    // Omni Gateway 1.13.0 forwards WebSocket upgrades, and the guard refuses
    // them (405). Some versions, such as 1.11.4, refuse them themselves
    // (403), as they refuse other upgrades. Either way the connection is not
    // upgraded and the server never sees the request.
    for (label, head) in [
        (
            "websocket GET",
            format!("GET /mcp HTTP/1.1\r\nhost: local-flex\r\n{websocket}\r\n"),
        ),
        ("websocket POST", post(websocket)),
        (
            "other upgrade GET",
            "GET /mcp HTTP/1.1\r\nhost: local-flex\r\nconnection: Upgrade\r\nupgrade: mcp\r\n\r\n"
                .to_owned(),
        ),
    ] {
        let line = status_line(&address, &head)?;
        println!("{label}: {line}");
        let refused = ["HTTP/1.1 403", "HTTP/1.1 405"]
            .iter()
            .any(|status| line.starts_with(status));
        assert!(refused, "{}: {}", label, line);
    }
    assert_eq!(
        seen.upgrades.load(Ordering::SeqCst),
        0,
        "an upgrade reached the server"
    );

    // HTTP/2 without a body passes.
    let status = h2(&url, "GET", None)?;
    println!("h2 GET: {status}");
    assert_eq!(
        status, "2 200",
        "the gateway must accept HTTP/2 without TLS"
    );
    let status = h2(&url, "POST", Some(PING))?;
    println!("h2 POST: {status}");
    assert_eq!(status, "2 200");

    // HTTP/2 bodies without Content-Length on bodiless methods are refused.
    for method in ["GET", "DELETE", "OPTIONS"] {
        let status = h2(&url, method, Some(PING))?;
        println!("h2 {method} with a body: {status}");
        assert_eq!(status, "2 405", "{}", method);
    }
    assert_eq!(
        seen.bodies.load(Ordering::SeqCst),
        0,
        "a body on a bodiless method reached the server"
    );

    // A refused call with unusual framing. The gateway either rejects the
    // framing or hands the guard the body it forwards, so the call is
    // refused either way.
    let head = "POST /mcp HTTP/1.1\r\nhost: local-flex\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\nconnection: close\r\n";
    let chunked = format!("{:x}\r\n{REFUSED_CALL}\r\n0\r\n\r\n", REFUSED_CALL.len());
    let length = REFUSED_CALL.len();
    for (label, request) in [
        ("plain", format!("{head}content-length: {length}\r\n\r\n{REFUSED_CALL}")),
        ("chunked", format!("{head}transfer-encoding: chunked\r\n\r\n{chunked}")),
        (
            "chunked and content-length",
            format!("{head}transfer-encoding: chunked\r\ncontent-length: 4\r\n\r\n{chunked}"),
        ),
        (
            "content-length and chunked",
            format!("{head}content-length: 4\r\ntransfer-encoding: chunked\r\n\r\n{chunked}"),
        ),
        (
            "gzip, chunked",
            format!("{head}transfer-encoding: gzip, chunked\r\n\r\n{chunked}"),
        ),
        (
            "chunked, identity",
            format!("{head}transfer-encoding: chunked, identity\r\n\r\n{chunked}"),
        ),
        (
            "xchunked",
            format!("{head}transfer-encoding: xchunked\r\ncontent-length: {length}\r\n\r\n{REFUSED_CALL}"),
        ),
        (
            "space before colon",
            format!("{head}transfer-encoding : chunked\r\ncontent-length: 4\r\n\r\n{chunked}"),
        ),
        (
            "repeated content-length",
            format!("{head}content-length: 4\r\ncontent-length: {length}\r\n\r\n{REFUSED_CALL}"),
        ),
        (
            "signed content-length",
            format!("{head}content-length: +{length}\r\n\r\n{REFUSED_CALL}"),
        ),
        (
            "body after an empty request",
            format!("{head}content-length: 0\r\n\r\n{REFUSED_CALL}"),
        ),
    ] {
        let line = status_line(&address, &request).unwrap_or_else(|e| format!("no status: {e}"));
        println!("{label}: {line}");
    }
    let status = h2(&url, "POST", Some(REFUSED_CALL))?;
    println!("h2 POST of the refused call: {status}");
    assert_eq!(
        seen.refused_tool.load(Ordering::SeqCst),
        0,
        "a refused call reached the server"
    );
    Ok(())
}
