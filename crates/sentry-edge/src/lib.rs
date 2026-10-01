//! Inline edge for Sentry (F3.1 + F3.9a/b).
//!
//! Three building blocks on top of the same [`Pipeline`]:
//!
//! - [`middleware`]: reusable axum middleware (`sentry_middleware`) —
//!   `Inline` (decide before the handler) or `Shadow` (observe a copy).
//!   This is the "axum middleware receiving a copy of the request" from the
//!   backlog, and lets Rust apps embed Sentry without a proxy hop.
//! - [`proxy`]: the `edge-http` reverse proxy — Sentry listens first,
//!   applies the verdict (Block→403, RateLimit→429, Challenge→challenge
//!   page), then forwards to the protected upstream. Chain:
//!   `client → sentry-edge → nginx → app`.
//! - [`tcp_listener`]: `edge-tcp` — an inline TCP front for non-HTTP
//!   services; connect-time verdict (block closes the connection), then a
//!   byte pipe to the real backend.
//!
//! Default deployment stays `passive` (log tailing); inline requires
//! explicit opt-in (`[deployment] mode = "inline"`) and a healthy upstream.

#![forbid(unsafe_code)]

pub mod challenge;
pub mod clienthello;
pub mod middleware;
pub mod pages;
pub mod proxy;
pub mod tcp_listener;
#[cfg(feature = "edge-tls")]
pub mod tls;

/// Marker request extension: the edge itself terminated TLS on this
/// connection (F8). Distinguishes a real HTTPS connection from a spoofable
/// `x-forwarded-proto` header — the HTTP→HTTPS redirect decision uses it,
/// never the header alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsTerminated;

/// Prometheus handles for the TLS acceptor (F8), wired by the daemon.
#[derive(Clone)]
pub struct TlsMetrics {
    /// `sentry_edge_tls_handshakes_total{version}`.
    pub handshakes: prometheus::CounterVec,
    /// `sentry_edge_tls_handshake_failures_total` — truncated hellos,
    /// malformed records, failed or timed-out handshakes.
    pub failures: prometheus::Counter,
    /// `sentry_edge_tls_sni_mismatch_total` — missing or unknown SNI.
    pub sni_mismatches: prometheus::Counter,
}

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use axum::http::HeaderMap;
use axum::response::Response;
use sentry_core::config::ChallengeBackend;
use sentry_core::event::Event;
use sentry_core::pipeline::Pipeline;
use sentry_core::BlockTable;
use uuid::Uuid;

use crate::challenge::{cookie_value, JsChallenge, COOKIE_NAME};
use crate::middleware::MiddlewareMode;

/// Optional event enrichment hook (geo / reputation) supplied by the host.
pub type Enricher = Arc<dyn Fn(&mut Event) + Send + Sync>;

/// Gate outcome for a `Challenge` verdict (F7.8).
#[derive(Debug)]
pub enum ChallengeGate {
    /// Let the request through (solved cookie or verified crawler).
    Pass,
    /// Serve this PoW interstitial.
    Page(Response),
    /// Presented cookie failed verification — terminal 403, no retry loop.
    Blocked(Response),
    /// No challenge configured — use the caller's static fallback.
    Disabled,
}

/// Shared edge runtime: pipeline + enrichment + capture limits + mode.
#[derive(Clone)]
pub struct EdgeRuntime {
    pipeline: Arc<Pipeline>,
    enrich: Option<Enricher>,
    body_cap: usize,
    mode: MiddlewareMode,
    block_table: Option<Arc<BlockTable>>,
    block_hits: Option<prometheus::Counter>,
    trust: Option<sentry_core::SharedTrustSet>,
    challenge: Option<Arc<JsChallenge>>,
    bot_verifier: Option<sentry_core::SharedBotVerifier>,
    challenge_metrics: Option<prometheus::CounterVec>,
    challenge_backend: ChallengeBackend,
    tls_metrics: Option<TlsMetrics>,
    request_duration: Option<prometheus::Histogram>,
}

impl EdgeRuntime {
    /// Build a runtime around a pipeline. `body_cap` (bytes) bounds how much
    /// of a request body is captured into the event for inspection
    /// (0 disables body capture — the default). Mode defaults to
    /// [`MiddlewareMode::Inline`]; see [`Self::with_mode`].
    pub fn new(pipeline: Arc<Pipeline>, enrich: Option<Enricher>, body_cap: usize) -> Self {
        Self {
            pipeline,
            enrich,
            body_cap,
            mode: MiddlewareMode::Inline,
            block_table: None,
            block_hits: None,
            trust: None,
            challenge: None,
            bot_verifier: None,
            challenge_metrics: None,
            challenge_backend: ChallengeBackend::default(),
            tls_metrics: None,
            request_duration: None,
        }
    }

    /// Consult `table` before the pipeline runs so a sticky block denies
    /// traffic even when the current request alone would score as benign.
    pub fn with_block_table(mut self, table: Arc<BlockTable>) -> Self {
        self.block_table = Some(table);
        self
    }

    /// Resolve the peer's real client IP with the trusted-proxy set (F7.2):
    /// header-borne candidates only win when the peer is a trusted proxy.
    pub fn with_trust(mut self, trust: sentry_core::SharedTrustSet) -> Self {
        self.trust = Some(trust);
        self
    }

    /// Trusted-proxy set, when attached.
    pub fn trust(&self) -> Option<&sentry_core::SharedTrustSet> {
        self.trust.as_ref()
    }

    /// Counter incremented on every fast-path denial.
    pub fn with_block_hits(mut self, hits: prometheus::Counter) -> Self {
        self.block_hits = Some(hits);
        self
    }

    /// Histogram observed with the wall-clock time spent handling each
    /// request (middleware and reverse proxy), for latency panels.
    pub fn with_request_duration(mut self, histogram: prometheus::Histogram) -> Self {
        self.request_duration = Some(histogram);
        self
    }

    /// Serve a JavaScript proof-of-work challenge on `Challenge` verdicts
    /// (F7.8) instead of the static 403 page.
    pub fn with_challenge(mut self, challenge: Arc<JsChallenge>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Consult the rDNS bot-verification cache so verified crawlers bypass
    /// the JS challenge (real search bots don't execute JavaScript).
    pub fn with_bot_verifier(mut self, verifier: sentry_core::SharedBotVerifier) -> Self {
        self.bot_verifier = Some(verifier);
        self
    }

    /// `sentry_edge_challenge_total{result}` counter (served / passed /
    /// bot_bypass / delegated).
    pub fn with_challenge_metrics(mut self, counter: prometheus::CounterVec) -> Self {
        self.challenge_metrics = Some(counter);
        self
    }

    /// Set who executes `Challenge` verdicts (`[edge] challenge_backend`):
    /// `Sentry` runs the built-in PoW; `Cloudflare` delegates to the CF
    /// provider — the verdict becomes a Cloudflare rule via its API.
    pub fn with_challenge_backend(mut self, backend: ChallengeBackend) -> Self {
        self.challenge_backend = backend;
        self
    }

    /// Challenge enforcement backend.
    pub fn challenge_backend(&self) -> ChallengeBackend {
        self.challenge_backend
    }

    /// TLS acceptor counters (F8): handshakes by version, failures, SNI
    /// mismatches.
    pub fn with_tls_metrics(mut self, metrics: TlsMetrics) -> Self {
        self.tls_metrics = Some(metrics);
        self
    }

    /// TLS acceptor counters, when attached.
    pub fn tls_metrics(&self) -> Option<&TlsMetrics> {
        self.tls_metrics.as_ref()
    }

    fn challenge_metric(&self, result: &str) {
        if let Some(m) = &self.challenge_metrics {
            m.with_label_values(&[result]).inc();
        }
    }

    /// Gate for a `Challenge` verdict (F7.8): browsers solve the proof-of-
    /// work once per bucket; rDNS-verified crawlers bypass entirely. With
    /// `challenge_backend = "cloudflare"` the challenge is delegated to the
    /// Cloudflare provider (the verdict becomes a CF rule via its API) and
    /// this gate only serves a hold page — no local PoW.
    pub fn challenge_gate(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        trace: Option<Uuid>,
    ) -> ChallengeGate {
        if self.challenge_backend == ChallengeBackend::Cloudflare {
            self.challenge_metric("delegated");
            return ChallengeGate::Page(pages::delegated_challenge_page(trace));
        }

        let Some(ch) = self.challenge.as_ref() else {
            return ChallengeGate::Disabled;
        };

        // Verified crawlers bypass: search bots don't execute JavaScript,
        // and their identity has been forward-confirmed via rDNS. A spoofed
        // claim gets no bypass (and, being JS-less, stays stuck on the PoW).
        if let Some(verifier) = &self.bot_verifier {
            let claims = sentry_core::botverify::claimed_engine(
                headers
                    .get(axum::http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok()),
            )
            .is_some();
            if claims
                && matches!(
                    verifier.get(client_ip),
                    Some(sentry_core::botverify::BotStatus::Verified(_))
                )
            {
                self.challenge_metric("bot_bypass");
                return ChallengeGate::Pass;
            }
        }

        // Solved challenge: any request carries the cookie once the browser
        // reloads after the PoW. A present-but-invalid cookie is a failed
        // attempt (terminal 403); an expired one just re-challenges.
        if let Some(value) = cookie_value(headers, COOKIE_NAME) {
            match ch.classify_cookie(client_ip, &value, SystemTime::now()) {
                crate::challenge::CookieCheck::Valid => {
                    self.challenge_metric("passed");
                    return ChallengeGate::Pass;
                }
                crate::challenge::CookieCheck::Failed => {
                    self.challenge_metric("failed");
                    return ChallengeGate::Blocked(pages::challenge_failed_page(trace));
                }
                crate::challenge::CookieCheck::Stale => {}
            }
        }

        self.challenge_metric("served");
        ChallengeGate::Page(ch.page_response(client_ip, headers, SystemTime::now()))
    }

    /// Pipeline reference.
    pub fn pipeline(&self) -> &Arc<Pipeline> {
        &self.pipeline
    }

    /// Body capture cap in bytes (0 = disabled).
    pub fn body_cap(&self) -> usize {
        self.body_cap
    }

    /// Enrich an event with the host-provided hook (geo / reputation).
    pub fn enrich(&self, evt: &mut Event) {
        if let Some(enrich) = &self.enrich {
            enrich(evt);
        }
    }

    /// Run the pipeline on an already-built event (enrich → process).
    pub fn process(&self, mut evt: Event) -> sentry_core::ProcessedEvent {
        self.enrich(&mut evt);
        self.pipeline.process(&evt)
    }

    /// Fast-path check: whether `ip` must be denied before the pipeline runs.
    /// Returns true only for IPs on the block table; increments the block-hit
    /// counter and logs when it fires.
    pub fn is_hard_blocked(&self, ip: IpAddr) -> bool {
        // Trusted IPs (`[real_ip] trusted_ips`) bypass even sticky blocks —
        // the "you can't lock yourself out" guard (F7.2).
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(ip) {
                return false;
            }
        }
        let Some(table) = &self.block_table else {
            return false;
        };
        if !table.is_blocked(ip) {
            return false;
        }
        if let Some(hits) = &self.block_hits {
            hits.inc();
        }
        tracing::debug!(ip = %ip, "edge fast-path: blocked ip denied before pipeline");
        true
    }
}

/// Resolve the real client IP by fixed precedence (ARCHITECTURE §8.1):
/// `CF-Connecting-IP` > `True-Client-IP` > `X-Real-IP` > first XFF hop >
/// peer address.
///
/// Legacy behavior: headers always win. Prefer [`Self::real_client_ip_with`]
/// with a trust set on anything exposed to non-proxy peers.
pub fn real_client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    real_client_ip_with(headers, peer, None)
}

/// Like [`real_client_ip`], but header-borne candidates are only honored
/// when `peer` is a trusted proxy (F7.2) — a direct-to-origin client cannot
/// spoof a forged `CF-Connecting-IP`.
pub fn real_client_ip_with(
    headers: &HeaderMap,
    peer: IpAddr,
    trust: Option<&sentry_core::SharedTrustSet>,
) -> IpAddr {
    let header_ip = |name: &str| -> Option<IpAddr> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
    };
    let from_headers = || {
        header_ip("cf-connecting-ip")
            .or_else(|| header_ip("true-client-ip"))
            .or_else(|| header_ip("x-real-ip"))
            .or_else(|| header_ip("x-forwarded-for"))
    };
    match trust {
        Some(trust) if !trust.is_trusted_proxy(peer) => peer,
        _ => from_headers().unwrap_or(peer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_ip_precedence_order() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(real_client_ip(&h, peer), peer);

        h.insert("x-forwarded-for", "198.51.100.9, 10.0.0.2".parse().unwrap());
        assert_eq!(
            real_client_ip(&h, peer),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );

        h.insert("x-real-ip", "203.0.113.4".parse().unwrap());
        assert_eq!(
            real_client_ip(&h, peer),
            "203.0.113.4".parse::<IpAddr>().unwrap()
        );

        h.insert("true-client-ip", "203.0.113.5".parse().unwrap());
        assert_eq!(
            real_client_ip(&h, peer),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );

        h.insert("cf-connecting-ip", "203.0.113.6".parse().unwrap());
        assert_eq!(
            real_client_ip(&h, peer),
            "203.0.113.6".parse::<IpAddr>().unwrap()
        );
    }
}
