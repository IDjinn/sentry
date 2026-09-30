//! `edge-tcp` — inline TCP front for non-HTTP services (F3.9b).
//!
//! Sentry owns the public port; on each accepted connection it scores a
//! synthetic SYN event through the pipeline (rules → reputation → policy).
//! `Block`/`Quarantine` close the connection immediately; everything else is
//! piped byte-for-byte to the real backend. HTTP-level concepts (challenge
//! pages) don't exist on raw TCP, so `Challenge` is treated as allow-with-log
//! and `RateLimit` as allow — per-IP pressure is enforced upstream of the
//! verdict (rate-limit rules fire as `RateLimit` only when a backend is
//! configured; on TCP the block ladder is the enforcement path).

use std::time::Duration;

use sentry_core::analysis::Verdict;
use sentry_core::event::{SourceKind, TcpData, TcpStage, Transport};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::EdgeRuntime;

/// Inline TCP listener configuration.
#[derive(Debug, Clone)]
pub struct TcpEdgeConfig {
    /// Public listen address (`0.0.0.0:2222`).
    pub listen: String,
    /// Real backend address (`127.0.0.1:22`).
    pub upstream: String,
    /// Upstream connect timeout seconds (default 5).
    pub connect_timeout_secs: u64,
}

/// Serve the inline TCP edge until the process stops.
pub async fn serve_tcp(
    runtime: EdgeRuntime,
    cfg: TcpEdgeConfig,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
) -> sentry_core::error::Result<()> {
    let listener = TcpListener::bind(&cfg.listen).await.map_err(|e| {
        sentry_core::error::CoreError::Config(format!("edge-tcp bind on {}: {e}", cfg.listen))
    })?;
    info!(listen = %cfg.listen, upstream = %cfg.upstream, "edge-tcp listening");
    let connect_timeout = Duration::from_secs(cfg.connect_timeout_secs.max(1));
    loop {
        let Ok((mut inbound, peer)) = listener.accept().await else {
            continue;
        };
        let runtime = runtime.clone();
        let cfg = cfg.clone();
        let decided = decided.clone();
        tokio::spawn(async move {
            // Score a synthetic SYN event through the shared pipeline.
            let evt = sentry_core::event::Event::new(
                SourceKind::Tcp,
                peer.ip(),
                sentry_core::ProtocolData::Tcp(TcpData {
                    stage: TcpStage::Syn,
                    ..TcpData::default()
                }),
            );
            let mut evt = evt;
            evt.transport = Transport::Tcp;
            evt.client_port = Some(peer.port());
            let processed = runtime.process(evt);
            let _ = decided.try_send(processed.clone());

            match processed.decision.action {
                Verdict::Block | Verdict::Quarantine => {
                    info!(ip = %peer.ip(), "edge-tcp: connection blocked");
                    let _ = inbound.shutdown().await;
                    return;
                }
                _ => {}
            }

            let upstream_conn = match tokio::time::timeout(
                connect_timeout,
                TcpStream::connect(&cfg.upstream),
            )
            .await
            {
                Ok(Ok(stream)) => Some(stream),
                Ok(Err(e)) => {
                    warn!(error = %e, upstream = %cfg.upstream, "edge-tcp upstream connect failed");
                    None
                }
                Err(_) => {
                    warn!(upstream = %cfg.upstream, "edge-tcp upstream connect timed out");
                    None
                }
            };
            if let Some(mut outbound) = upstream_conn {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                let _ = inbound.shutdown().await;
            }
        });
    }
}
