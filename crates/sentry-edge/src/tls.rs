//! `edge-https` — TLS front for the inline reverse proxy (F8).
//!
//! The listener peeks the ClientHello *before* the rustls handshake to
//! extract SNI/JA3/JA4 telemetry, feeds a `TlsHandshake` event through the
//! shared pipeline (a `Block` verdict drops the connection immediately) and
//! then serves the decrypted requests through the same axum router the
//! plain listener uses. Per-connection state (`ConnectInfo` + the
//! TLS-terminated marker + `x-forwarded-proto`) is injected here, so the
//! proxy handler and the challenge cookie see the real client and the real
//! scheme.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tower_service::Service as _;
use tracing::{debug, info, warn};

use crate::clienthello::{self, ClientHello, Probe};
use crate::proxy::TlsEdgeConfig;
use crate::{EdgeRuntime, TlsTerminated};

/// Total budget for reading the ClientHello and completing the handshake —
/// slowloris-style stalls at the TLS layer are dropped, not queued.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve the inline HTTPS edge until the process stops.
pub async fn serve_tls(
    runtime: EdgeRuntime,
    cfg: TlsEdgeConfig,
    app: Router,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    let server = load_server_config(&cfg)?;
    let addr: SocketAddr = cfg.listen.parse().map_err(|e| {
        sentry_core::error::CoreError::Config(format!("invalid edge tls listen address: {e}"))
    })?;
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        sentry_core::error::CoreError::Config(format!("edge tls bind on {addr} failed: {e}"))
    })?;
    info!(
        addr = %addr,
        cert = %cfg.cert.display(),
        "edge (inline) listening on https"
    );
    let acceptor: TlsAcceptor = TlsAcceptor::from(server);
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        // Sticky blocks deny before any TLS bytes flow — the client only
        // sees a closed connection, no handshake, no event.
        if runtime.is_hard_blocked(peer.ip()) {
            debug!(ip = %peer.ip(), "edge-tls: blocked ip dropped before handshake");
            continue;
        }
        let runtime = runtime.clone();
        let cfg = cfg.clone();
        let app = app.clone();
        let acceptor = acceptor.clone();
        let decided = decided.clone();
        tokio::spawn(handle_conn(runtime, cfg, app, acceptor, decided, tcp, peer));
    }
}

/// Serve on an already-bound listener (testable variant of [`serve_tls`]).
pub async fn serve_tls_on(
    runtime: EdgeRuntime,
    cfg: TlsEdgeConfig,
    server: Arc<rustls::ServerConfig>,
    listener: TcpListener,
    app: Router,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    info!(
        addr = %listener.local_addr().map_err(|e| {
            sentry_core::error::CoreError::Config(format!("edge tls local addr: {e}"))
        })?,
        cert = %cfg.cert.display(),
        "edge (inline) listening on https"
    );
    let acceptor: TlsAcceptor = TlsAcceptor::from(server);
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            continue;
        };
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        // Sticky blocks deny before any TLS bytes flow — the client only
        // sees a closed connection, no handshake, no event.
        if runtime.is_hard_blocked(peer.ip()) {
            debug!(ip = %peer.ip(), "edge-tls: blocked ip dropped before handshake");
            continue;
        }
        let runtime = runtime.clone();
        let cfg = cfg.clone();
        let app = app.clone();
        let acceptor = acceptor.clone();
        let decided = decided.clone();
        tokio::spawn(handle_conn(runtime, cfg, app, acceptor, decided, tcp, peer));
    }
}

async fn handle_conn(
    runtime: EdgeRuntime,
    cfg: TlsEdgeConfig,
    app: Router,
    acceptor: TlsAcceptor,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
    mut tcp: TcpStream,
    peer: SocketAddr,
) {
    let prefix = match read_hello_prefix(&mut tcp).await {
        Ok(p) => p,
        Err(e) => {
            if let Some(m) = runtime.tls_metrics() {
                m.failures.inc();
            }
            debug!(error = %e, ip = %peer.ip(), "edge-tls: client hello read failed");
            return;
        }
    };
    let hello = match clienthello::parse(&prefix) {
        Probe::Hello(h) => Some(h),
        Probe::NeedMore => {
            if let Some(m) = runtime.tls_metrics() {
                m.failures.inc();
            }
            warn!(ip = %peer.ip(), "edge-tls: client hello exceeded the size cap");
            return;
        }
        Probe::Invalid => {
            if let Some(m) = runtime.tls_metrics() {
                m.failures.inc();
            }
            debug!(ip = %peer.ip(), "edge-tls: first bytes are not a TLS ClientHello");
            return;
        }
    };

    let prefixed = PrefixedStream::new(prefix, tcp);
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(prefixed)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            if let Some(m) = runtime.tls_metrics() {
                m.failures.inc();
            }
            debug!(error = %e, ip = %peer.ip(), "edge-tls: handshake failed");
            return;
        }
        Err(_) => {
            if let Some(m) = runtime.tls_metrics() {
                m.failures.inc();
            }
            debug!(ip = %peer.ip(), "edge-tls: handshake timed out");
            return;
        }
    };
    let (_, server_conn) = tls.get_ref();
    let version = server_conn
        .protocol_version()
        .map(version_name)
        .unwrap_or_else(|| "unknown".to_string());
    let cipher = server_conn
        .negotiated_cipher_suite()
        .map(|c| format!("{c:?}"))
        .unwrap_or_else(|| "unknown".to_string());

    if let Some(hello) = &hello {
        let blocked =
            emit_handshake_event(&runtime, &cfg, &decided, peer, hello, &version, &cipher).await;
        if blocked {
            return;
        }
    }

    // Serve the decrypted requests through the same router as plain HTTP.
    let service =
        hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            req.extensions_mut().insert(TlsTerminated);
            req.headers_mut().insert(
                axum::http::HeaderName::from_static("x-forwarded-proto"),
                axum::http::HeaderValue::from_static("https"),
            );
            let mut app = app.clone();
            async move { app.call(req.map(axum::body::Body::new)).await }
        });
    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    if let Err(e) = builder.serve_connection(TokioIo::new(tls), service).await {
        debug!(error = %e, ip = %peer.ip(), "edge-tls: http connection error");
    }
}

/// Peek (consume) bytes until the ClientHello is fully buffered, then hand
/// the same bytes back to rustls through [`PrefixedStream`].
async fn read_hello_prefix(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            if !matches!(clienthello::parse(&buf), Probe::NeedMore) {
                break;
            }
            if buf.len() >= clienthello::MAX_HELLO_BYTES {
                break;
            }
            let n = tcp.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client hello read timed out"))??;
    Ok(buf)
}

#[allow(clippy::too_many_arguments)]
async fn emit_handshake_event(
    runtime: &EdgeRuntime,
    cfg: &TlsEdgeConfig,
    decided: &mpsc::Sender<sentry_core::ProcessedEvent>,
    peer: SocketAddr,
    hello: &ClientHello,
    version: &str,
    cipher: &str,
) -> bool {
    let mismatch = sni_mismatch(&cfg.allowed_hosts, hello.sni.as_deref());
    if !cfg.handshake_events && mismatch.is_none() {
        return false;
    }
    let data = sentry_core::event::TlsData {
        sni: hello.sni.clone(),
        ja3: hello.ja3.clone(),
        ja4: hello.ja4.clone(),
        cipher: Some(cipher.to_string()),
        version: Some(version.to_string()),
        alpn: hello.alpn.clone(),
    };
    let mut evt = sentry_core::event::Event::new(
        sentry_core::event::SourceKind::EdgeTls,
        peer.ip(),
        sentry_core::ProtocolData::TlsHandshake(data),
    );
    evt.transport = sentry_core::event::Transport::Tcp;
    evt.client_port = Some(peer.port());
    let processed = runtime.process(evt);
    let processed = match &mismatch {
        Some(reason) => {
            if let Some(m) = runtime.tls_metrics() {
                m.sni_mismatches.inc();
            }
            runtime.pipeline().rescore_from(
                &processed,
                vec![sentry_core::analysis::Signal {
                    kind: sentry_core::analysis::SignalKind::TlsSniMismatch,
                    weight: sentry_core::analysis::TLS_SNI_MISMATCH_WEIGHT,
                    detail: Some(reason.clone()),
                }],
            )
        }
        None => processed,
    };
    if let Some(m) = runtime.tls_metrics() {
        m.handshakes.with_label_values(&[version]).inc();
    }
    let blocked = matches!(
        processed.decision.action,
        sentry_core::Verdict::Block | sentry_core::Verdict::Quarantine
    );
    let _ = decided.try_send(processed);
    if blocked {
        // TLS layer has no per-request semantics — the whole connection is
        // dropped, which is exactly the enforcement the edge wants here.
        info!(ip = %peer.ip(), "edge-tls: connection blocked by pipeline verdict");
    }
    blocked
}

/// `None` when the SNI check is disabled or the SNI is allowed.
fn sni_mismatch(allowed: &[String], sni: Option<&str>) -> Option<String> {
    if allowed.is_empty() {
        return None;
    }
    match sni {
        None => Some("missing sni".to_string()),
        Some(s) if allowed.iter().any(|h| h.eq_ignore_ascii_case(s)) => None,
        Some(s) => Some(format!("unknown sni {s}")),
    }
}

fn version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".to_string(),
        rustls::ProtocolVersion::TLSv1_1 => "TLS1.1".to_string(),
        rustls::ProtocolVersion::TLSv1_0 => "TLS1.0".to_string(),
        other => format!("{other:?}"),
    }
}

fn load_server_config(
    cfg: &TlsEdgeConfig,
) -> Result<Arc<rustls::ServerConfig>, sentry_core::error::CoreError> {
    let cert_pem = std::fs::File::open(&cfg.cert).map_err(|e| {
        sentry_core::error::CoreError::Config(format!(
            "edge tls: opening cert {}: {e}",
            cfg.cert.display()
        ))
    })?;
    let key_pem = std::fs::File::open(&cfg.key).map_err(|e| {
        sentry_core::error::CoreError::Config(format!(
            "edge tls: opening key {}: {e}",
            cfg.key.display()
        ))
    })?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .collect::<Result<_, _>>()
        .map_err(|e| {
            sentry_core::error::CoreError::Config(format!(
                "edge tls: parsing cert {}: {e}",
                cfg.cert.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(sentry_core::error::CoreError::Config(
            "edge tls: no certificates found in the cert file".to_string(),
        ));
    }
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
        .map_err(|e| {
            sentry_core::error::CoreError::Config(format!(
                "edge tls: parsing key {}: {e}",
                cfg.key.display()
            ))
        })?
        .ok_or_else(|| {
            sentry_core::error::CoreError::Config(format!(
                "edge tls: no private key found in {}",
                cfg.key.display()
            ))
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| {
            sentry_core::error::CoreError::Config(format!("edge tls: protocol versions: {e}"))
        })?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            sentry_core::error::CoreError::Config(format!("edge tls: cert/key mismatch: {e}"))
        })?;
    let mut config = config;
    // HTTP/1.1 only: the edge forwards each request through reqwest to the
    // upstream, so h2 would add no fidelity and more surface.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// `notAfter` of the first certificate in a PEM file, for the expiry gauge.
pub fn cert_not_after(path: &std::path::Path) -> Option<std::time::SystemTime> {
    let pem = std::fs::read(path).ok()?;
    let (_, pem_obj) = x509_parser::pem::parse_x509_pem(&pem).ok()?;
    let cert = pem_obj.parse_x509().ok()?;
    let secs = cert.validity().not_after.timestamp();
    u64::try_from(secs)
        .ok()
        .and_then(|s| std::time::SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(s)))
}

/// AsyncRead/AsyncWrite wrapper that replays the ClientHello bytes already
/// consumed by the telemetry peek before delegating to the inner stream.
pub(crate) struct PrefixedStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_mismatch_rules() {
        let allowed = vec!["api.example.com".to_string()];
        assert_eq!(sni_mismatch(&allowed, None).as_deref(), Some("missing sni"));
        assert_eq!(sni_mismatch(&allowed, Some("api.example.com")), None);
        assert_eq!(sni_mismatch(&allowed, Some("API.Example.COM")), None);
        assert_eq!(
            sni_mismatch(&allowed, Some("evil.com")).as_deref(),
            Some("unknown sni evil.com")
        );
        // Empty allowlist disables the check entirely.
        assert_eq!(sni_mismatch(&[], None), None);
        assert_eq!(sni_mismatch(&[], Some("anything")), None);
    }

    #[test]
    fn version_names() {
        assert_eq!(version_name(rustls::ProtocolVersion::TLSv1_3), "TLS1.3");
        assert_eq!(version_name(rustls::ProtocolVersion::TLSv1_2), "TLS1.2");
    }

    /// Self-signed PEM pair written to a temp dir (per-test unique names).
    fn write_test_cert(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("sentry-edge-tls-test-{tag}-cert.pem"));
        let key_path = dir.join(format!("sentry-edge-tls-test-{tag}-key.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    fn test_tls_cfg(tag: &str) -> TlsEdgeConfig {
        let (cert, key) = write_test_cert(tag);
        TlsEdgeConfig {
            listen: "127.0.0.1:0".to_string(),
            cert,
            key,
            redirect_https: false,
            allowed_hosts: vec![],
            handshake_events: true,
        }
    }

    #[tokio::test]
    async fn non_tls_garbage_fails_the_handshake_and_counts() {
        use prometheus::CounterVec;

        let cfg = test_tls_cfg("garbage");
        let handshakes =
            CounterVec::new(prometheus::Opts::new("t_handshakes", "test"), &["version"]).unwrap();
        let failures = prometheus::Counter::new("t_failures", "test").unwrap();
        let sni_mismatches = prometheus::Counter::new("t_mismatches", "test").unwrap();
        let pipeline = std::sync::Arc::new(sentry_core::pipeline::Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        let runtime =
            crate::EdgeRuntime::new(pipeline, None, 0).with_tls_metrics(crate::TlsMetrics {
                handshakes: handshakes.clone(),
                failures: failures.clone(),
                sni_mismatches: sni_mismatches.clone(),
            });
        let (dec_tx, _dec_rx) = mpsc::channel(8);
        let app = Router::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = load_server_config(&cfg).unwrap();
        let server_task = tokio::spawn(serve_tls_on(runtime, cfg, server, listener, app, dec_tx));

        // Bytes that are not a TLS record: the edge must drop the
        // connection and count the failure, never panic or hang.
        let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        use tokio::io::AsyncWriteExt;
        conn.write_all(b"NOT-TLS AT ALL\r\n\r\n").await.unwrap();
        drop(conn);
        // A real ClientHello whose handshake can never complete (no valid
        // response handling) — just exercises the accept path again.
        let mut conn2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        conn2.write_all(&curl_like_client_hello()).await.unwrap();
        drop(conn2);

        // Both connections must fail the handshake: the garbage bytes are
        // rejected at the record layer, and the valid-but-abandoned hello
        // dies when the client disappears mid-handshake.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        server_task.abort();
        assert_eq!(failures.get(), 2.0, "both aborted handshakes counted");
    }

    /// A syntactically valid ClientHello record (Chrome-like ciphers).
    fn curl_like_client_hello() -> Vec<u8> {
        // Minimal SNI-less hello: legacy 0x0303, no session, three ciphers,
        // compression null, no extensions.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x00; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        let mut record = vec![0x16, 0x03, 0x01];
        let msg_len = body.len();
        record.extend_from_slice(&((msg_len + 4) as u16).to_be_bytes());
        record.push(0x01);
        record.push(((msg_len >> 16) & 0xFF) as u8);
        record.push(((msg_len >> 8) & 0xFF) as u8);
        record.push((msg_len & 0xFF) as u8);
        record.extend_from_slice(&body);
        record
    }
}
