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

use std::net::SocketAddr;
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
        let Ok((inbound, peer)) = listener.accept().await else {
            continue;
        };
        let runtime = runtime.clone();
        let cfg = cfg.clone();
        let decided = decided.clone();
        tokio::spawn(handle_conn(
            runtime,
            cfg,
            decided,
            inbound,
            peer,
            connect_timeout,
        ));
    }
}

async fn handle_conn(
    runtime: EdgeRuntime,
    cfg: TcpEdgeConfig,
    decided: mpsc::Sender<sentry_core::ProcessedEvent>,
    mut inbound: TcpStream,
    peer: SocketAddr,
    connect_timeout: Duration,
) {
    // Sticky blocks close the connection before the pipeline runs.
    if runtime.is_hard_blocked(peer.ip()) {
        info!(ip = %peer.ip(), "edge-tcp: blocked ip denied (fast-path)");
        let _ = inbound.shutdown().await;
        return;
    }

    // Score a synthetic SYN event through the shared pipeline.
    let mut evt = sentry_core::event::Event::new(
        SourceKind::Tcp,
        peer.ip(),
        sentry_core::ProtocolData::Tcp(TcpData {
            stage: TcpStage::Syn,
            ..TcpData::default()
        }),
    );
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

    let upstream_conn =
        match tokio::time::timeout(connect_timeout, TcpStream::connect(&cfg.upstream)).await {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentry_core::pipeline::Pipeline;
    use sentry_core::BlockTable;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    fn runtime(table: Arc<BlockTable>) -> EdgeRuntime {
        let pipeline = Arc::new(Pipeline::new(
            sentry_core::RuleSet::default(),
            sentry_core::RouteValidator::new(vec![]),
        ));
        EdgeRuntime::new(pipeline, None, 0).with_block_table(table)
    }

    fn cfg() -> TcpEdgeConfig {
        TcpEdgeConfig {
            listen: "127.0.0.1:0".to_string(),
            upstream: "127.0.0.1:9".to_string(),
            connect_timeout_secs: 1,
        }
    }

    #[tokio::test]
    async fn blocked_ip_closes_before_pipeline() {
        let table = Arc::new(BlockTable::new());
        table.block("127.0.0.1".parse().unwrap(), None);
        let (dec_tx, mut dec_rx) = mpsc::channel(8);

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(l.local_addr().unwrap())
            .await
            .unwrap();
        let (inbound, peer) = l.accept().await.unwrap();

        handle_conn(
            runtime(table.clone()),
            cfg(),
            dec_tx,
            inbound,
            peer,
            Duration::from_secs(1),
        )
        .await;

        let mut buf = [0u8; 16];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0, "connection closed");
        assert!(
            dec_rx.try_recv().is_err(),
            "blocked ip must not produce a pipeline event"
        );
    }

    #[tokio::test]
    async fn unblocked_ip_still_reaches_the_pipeline() {
        let table = Arc::new(BlockTable::new());
        let (dec_tx, mut dec_rx) = mpsc::channel(8);

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(l.local_addr().unwrap())
            .await
            .unwrap();
        let (inbound, peer) = l.accept().await.unwrap();

        handle_conn(
            runtime(table),
            cfg(),
            dec_tx,
            inbound,
            peer,
            Duration::from_secs(1),
        )
        .await;

        let processed = dec_rx
            .try_recv()
            .expect("non-blocked ip must reach the pipeline");
        assert!(processed.event.tcp().is_some());
        let mut buf = [0u8; 16];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "dead upstream drops the connection"
        );
    }
}
