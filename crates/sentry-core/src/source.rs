//! The [`Source`] trait: implemented by every data-origin plugin
//! (`sentry-source-nginx`, `sentry-source-tcp`, …).
//!
//! A source produces a stream of [`RawEvent`](crate::event::RawEvent)s over a
//! tokio channel. The core ingestor consumes that channel, enriches events
//! with geo/asn and promotes them to full [`Event`](crate::event::Event)s.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use tokio::sync::mpsc;
use tracing::error;

use crate::error::Result;
use crate::event::RawEvent;
use crate::throttle::DropLogThrottle;

/// A plugin that observes accesses and emits raw events.
///
/// Implementations should open their data origin (log file, socket, packet
/// capture, API poller) inside [`stream`](Source::stream) and push
/// [`RawEvent`]s into the returned channel. When the origin is exhausted or
/// a fatal error occurs, the sender should be dropped (closing the channel)
/// after emitting an error via `tracing::error!`.
#[async_trait]
pub trait Source: Send + Sync {
    /// Stable, lowercase plugin name (e.g. `"nginx"`).
    fn name(&self) -> &'static str;

    /// Start streaming raw events.
    ///
    /// Returns the **receiver** end of a bounded channel. The source retains
    /// the sender and pushes events asynchronously. Closing the sender
    /// signals end-of-stream to the ingestor.
    async fn stream(&self) -> Result<mpsc::Receiver<RawEvent>>;

    /// Optional graceful shutdown hook.
    ///
    /// Called by the daemon on SIGINT/SIGTERM. Default impl is a no-op so
    /// simple sources (file tail) don't need to implement it.
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

/// Helper to build a `(sender, receiver)` pair with a sensible buffer size.
///
/// Exposed so sources don't each reinvent the channel sizing.
pub fn event_channel(buffer: usize) -> (mpsc::Sender<RawEvent>, mpsc::Receiver<RawEvent>) {
    mpsc::channel(buffer)
}

/// Per-source drop-log throttles, so a flood collapses into one aggregated
/// log line per window instead of one line per dropped event.
static DROP_THROTTLES: LazyLock<Mutex<HashMap<&'static str, DropLogThrottle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Wrapper that logs and converts a send error into a `CoreError`.
///
/// Sources call this when pushing events to fail loudly instead of silently
/// dropping on a closed channel. Channel-full drops are logged with a
/// per-source throttle (first drop immediately, then one aggregated line per
/// [`DropLogThrottle::DEFAULT_WINDOW`]); a closed channel always logs.
pub fn send_or_log(tx: &mpsc::Sender<RawEvent>, evt: RawEvent, source_name: &'static str) {
    use mpsc::error::TrySendError;
    match tx.try_send(evt) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            let mut throttles = DROP_THROTTLES.lock().unwrap();
            let throttle = throttles.entry(source_name).or_default();
            if let Some(count) = throttle.record(std::time::Instant::now()) {
                if count > 1 {
                    error!(
                        source = source_name,
                        dropped = count,
                        "event channel full, dropped events in the last 5s"
                    );
                } else {
                    error!(source = source_name, "event channel full, dropping event");
                }
            }
        }
        Err(TrySendError::Closed(_)) => {
            error!(source = source_name, "event channel closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ProtocolData, RawData, SourceKind, Transport};

    fn sample_event() -> RawEvent {
        RawEvent {
            source: SourceKind::Tcp,
            timestamp: chrono::Utc::now(),
            transport: Transport::Tcp,
            client_ip: None,
            client_port: None,
            server_port: None,
            bytes_in: None,
            bytes_out: None,
            duration_ms: None,
            raw: None,
            protocol: ProtocolData::Raw(RawData::default()),
        }
    }

    #[test]
    fn event_channel_returns_bounded_pair() {
        let (tx, rx) = event_channel(4);
        assert_eq!(rx.capacity(), 4);
        assert!(tx.try_send(sample_event()).is_ok());
        assert_eq!(rx.capacity(), 3);
    }

    #[tokio::test]
    async fn send_or_log_succeeds_into_open_channel() {
        let (tx, mut rx) = event_channel(1);
        send_or_log(&tx, sample_event(), "tcp");
        assert!(rx.recv().await.is_some());
    }
}
