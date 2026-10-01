//! rDNS bot-verification wiring (F7.7): the hickory-backed resolver and the
//! daemon's background verification worker.
//!
//! The pipeline (and the inline edge, which shares it) only reads the
//! in-memory cache; this module performs the actual PTR + forward-confirm
//! lookups off the hot path and feeds the cache.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use sentry_core::botverify::{
    verify_with, BotDnsResolver, BotStatus, DnsOutcome, SharedBotVerifier,
};
use tracing::debug;

use crate::metrics::Metrics;

/// [`BotDnsResolver`] backed by hickory (system resolvers, with timeout).
pub struct HickoryDns {
    resolver: TokioAsyncResolver,
}

impl HickoryDns {
    /// Build a resolver with the given per-query timeout and 2 attempts.
    pub fn new(timeout: Duration) -> color_eyre::Result<Self> {
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        let resolver =
            TokioAsyncResolver::tokio(hickory_resolver::config::ResolverConfig::default(), opts);
        Ok(Self { resolver })
    }
}

#[async_trait]
impl BotDnsResolver for HickoryDns {
    async fn ptr(&self, ip: IpAddr) -> DnsOutcome<String> {
        match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => DnsOutcome::Records(lookup.iter().map(|n| n.to_string()).collect()),
            Err(e) => {
                debug!(error = %e, ip = %ip, "bot verify: PTR lookup failed");
                DnsOutcome::Error
            }
        }
    }

    async fn a(&self, host: String) -> DnsOutcome<IpAddr> {
        match self.resolver.lookup_ip(host.clone()).await {
            Ok(lookup) => DnsOutcome::Records(lookup.iter().collect()),
            Err(e) => {
                debug!(error = %e, host = %host, "bot verify: forward lookup failed");
                DnsOutcome::Error
            }
        }
    }
}

/// Metric label for a verification outcome.
fn result_label(status: &BotStatus) -> &'static str {
    match status {
        BotStatus::Verified(_) => "verified",
        BotStatus::Spoofed => "spoofed",
        BotStatus::Unknown => "error",
    }
}

/// Background worker: drains queued (ip, engine) claims, verifies each with
/// a per-claim timeout, caches the outcome and bumps metrics. Prunes the
/// cache about once a minute. Runs until the task is aborted.
pub async fn bot_verify_worker(
    verifier: SharedBotVerifier,
    dns: Arc<dyn BotDnsResolver>,
    timeout: Duration,
    batch: usize,
    metrics: Metrics,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    let mut ticks: u64 = 0;
    loop {
        tick.tick().await;
        for (ip, engine) in verifier.take_pending(batch) {
            let attempt = tokio::time::timeout(timeout, verify_with(engine, ip, dns.as_ref()));
            let status = match attempt.await {
                Ok(status) => status,
                Err(_) => {
                    debug!(ip = %ip, engine = engine.as_str(), "bot verify: timed out");
                    BotStatus::Unknown
                }
            };
            metrics
                .bot_verifications
                .with_label_values(&[result_label(&status)])
                .inc();
            verifier.insert(ip, status);
            debug!(ip = %ip, engine = engine.as_str(), status = result_label(&status), "bot verified");
        }
        ticks += 1;
        if ticks % 120 == 0 {
            verifier.prune();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_labels_cover_all_statuses() {
        assert_eq!(
            result_label(&BotStatus::Verified(
                sentry_core::botverify::BotEngine::Google
            )),
            "verified"
        );
        assert_eq!(result_label(&BotStatus::Spoofed), "spoofed");
        assert_eq!(result_label(&BotStatus::Unknown), "error");
    }
}
