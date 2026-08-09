//! The [`Source`] trait: implemented by every data-origin plugin
//! (`sentry-source-nginx`, `sentry-source-tcp`, …).
//!
//! A source produces a stream of [`RawEvent`](crate::event::RawEvent)s over a
//! tokio channel. The core ingestor consumes that channel, enriches events
//! with geo/asn and promotes them to full [`Event`](crate::event::Event)s.

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::error;

use crate::error::Result;
use crate::event::RawEvent;

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

/// Wrapper that logs and converts a send error into a `CoreError`.
///
/// Sources call this when pushing events to fail loudly instead of silently
/// dropping on a closed channel.
pub fn send_or_log(tx: &mpsc::Sender<RawEvent>, evt: RawEvent, source_name: &'static str) {
    use mpsc::error::TrySendError;
    match tx.try_send(evt) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            error!(source = source_name, "event channel full, dropping event");
        }
        Err(TrySendError::Closed(_)) => {
            error!(source = source_name, "event channel closed");
        }
    }
}
