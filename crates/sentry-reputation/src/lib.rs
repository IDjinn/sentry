//! Reputation feed synchronization (F3.7).
//!
//! Fetches public IP blocklists (Tor exit nodes, Spamhaus DROP, FireHOL, …)
//! over HTTP(S), parses them with [`sentry_core::parse_feed`] and keeps a
//! shared [`sentry_core::ReputationStore`] fresh. The daemon attaches the
//! lookup result to every event next to the geo enrichment; a failed refresh
//! keeps the previous data so a flaky upstream never widens the allow path.
//!
//! Feed URLs are user configuration, so they are treated as untrusted input:
//! only `http`/`https` is allowed and loopback/private/reserved hosts are
//! rejected both in the configured URL (after DNS resolution) and on every
//! redirect hop.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use sentry_core::config::FeedConfig;
use sentry_core::rules::ReputationTier;
use sentry_core::{parse_feed, Event, ReputationStore};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Hard cap on a feed body — blocklists are a few hundred KB; anything past
/// this is a misconfigured URL (e.g. an HTML error page).
pub const MAX_FEED_BYTES: usize = 10 * 1024 * 1024;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

/// Outcome of the last refresh of one feed.
#[derive(Debug, Clone, Default)]
pub struct FeedStatus {
    /// Entries currently held for this feed.
    pub entries: usize,
    /// When the feed last refreshed successfully.
    pub last_refresh: Option<DateTime<Utc>>,
    /// Error of the last failed refresh, if any.
    pub last_error: Option<String>,
}

/// Shared reputation service: fetcher + store + per-feed status.
pub struct ReputationService {
    client: reqwest::Client,
    store: Arc<RwLock<ReputationStore>>,
    feeds: Vec<FeedConfig>,
    status: Arc<Mutex<HashMap<String, FeedStatus>>>,
    /// Fetched entries of `user_agent` / `path` dataset feeds (F7.6),
    /// keyed by feed name. IP feeds never land here.
    datasets: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl ReputationService {
    /// Build a service from the configured feeds (only enabled ones with a
    /// URL are kept). No network I/O happens here.
    pub fn new(configured: &[FeedConfig]) -> Self {
        let feeds: Vec<FeedConfig> = configured
            .iter()
            .filter(|f| f.enabled && !f.url.is_empty() && !f.name.is_empty())
            .cloned()
            .collect();
        let policy = reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if let Err(e) = static_url_check(attempt.url()) {
                attempt.error(e)
            } else {
                attempt.follow()
            }
        });
        let client = reqwest::Client::builder()
            .redirect(policy)
            .user_agent(concat!("sentry/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            client,
            store: Arc::new(RwLock::new(ReputationStore::new())),
            feeds,
            status: Arc::new(Mutex::new(HashMap::new())),
            datasets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Whether any feed is configured.
    pub fn is_active(&self) -> bool {
        !self.feeds.is_empty()
    }

    /// Handle to the shared store (also used by the daemon for enrichment).
    pub fn store(&self) -> Arc<RwLock<ReputationStore>> {
        Arc::clone(&self.store)
    }

    /// Enrich an event in place with the reputation lookup of its client IP.
    pub fn enrich(&self, evt: &mut Event) {
        if evt.reputation.is_none() {
            evt.reputation = self.store.read().unwrap().lookup(evt.client_ip);
        }
    }

    /// Fetch all feeds concurrently, logging and recording per-feed status.
    ///
    /// A failing feed never fails the call — the previous entries stay live.
    pub async fn refresh_all(&self) {
        join_all(self.feeds.iter().map(|f| self.refresh_one(f))).await;
    }

    /// Fetch one feed and swap its entries in the shared store (or, for
    /// `user_agent` / `path` datasets, in the dataset map — F7.6).
    ///
    /// Errors are recorded in the per-feed status either way, so a feed that
    /// never synced shows up in `statuses` with its reason.
    pub async fn refresh_one(&self, feed: &FeedConfig) -> Result<usize, ReputationError> {
        match self.fetch_and_apply(feed).await {
            Ok(entries) => Ok(entries),
            Err(e) => {
                let mut status = self.status.lock().await;
                status.entry(feed.name.clone()).or_default().last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Snapshot of a dataset feed's fetched entries (F7.6).
    pub async fn dataset(&self, name: &str) -> Option<Vec<String>> {
        self.datasets.lock().await.get(name).cloned()
    }

    async fn fetch_and_apply(&self, feed: &FeedConfig) -> Result<usize, ReputationError> {
        let body = self.fetch_body(feed).await?;
        let entries = match feed.kind {
            sentry_core::config::FeedKind::Ip => {
                let tier = ReputationTier::parse(&feed.tier).ok_or_else(|| {
                    ReputationError::Url(format!(
                        "feed `{}`: unknown reputation tier `{}`",
                        feed.name, feed.tier
                    ))
                })?;
                let nets = parse_feed(&body);
                let count = nets.len();
                self.store
                    .write()
                    .unwrap()
                    .replace_feed(&feed.name, tier, nets);
                count
            }
            sentry_core::config::FeedKind::UserAgent | sentry_core::config::FeedKind::Path => {
                let list = sentry_core::parse_string_list(&body);
                let count = list.len();
                self.datasets.lock().await.insert(feed.name.clone(), list);
                count
            }
        };

        let mut status = self.status.lock().await;
        let entry = status.entry(feed.name.clone()).or_default();
        entry.entries = entries;
        entry.last_refresh = Some(Utc::now());
        entry.last_error = None;
        Ok(entries)
    }

    /// SSRF-guarded fetch of a feed body (shared by IP feeds and datasets).
    async fn fetch_body(&self, feed: &FeedConfig) -> Result<String, ReputationError> {
        let url = validate_feed_url(&feed.url)?;
        if let Some(host) = url.host_str() {
            resolve_host(host, url.port_or_known_default().unwrap_or(80)).await?;
        }
        let mut request = self.client.get(url).timeout(FETCH_TIMEOUT);
        for (header, env_var) in &feed.headers_env {
            if let Ok(value) = std::env::var(env_var) {
                if !value.is_empty() {
                    request = request.header(header.as_str(), value);
                }
            }
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(ReputationError::Fetch(format!(
                "feed `{}`: HTTP {}",
                feed.name,
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|len| len as usize > MAX_FEED_BYTES)
        {
            return Err(ReputationError::TooLarge(feed.name.clone()));
        }
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_FEED_BYTES {
                return Err(ReputationError::TooLarge(feed.name.clone()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Spawn one background refresh task per feed (cadence = `refresh_hours`).
    ///
    /// Call after an initial [`refresh_all`](Self::refresh_all): the tasks
    /// skip their immediate tick so the startup fetch is not duplicated.
    pub fn spawn_refresh_tasks(self: &Arc<Self>) {
        for feed in self.feeds.clone() {
            let svc = Arc::clone(self);
            let period = Duration::from_secs(u64::from(feed.refresh_hours.max(1)) * 3600);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(period);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Err(e) = svc.refresh_one(&feed).await {
                        warn!(feed = %feed.name, error = %e, "reputation feed refresh failed");
                    }
                }
            });
        }
    }

    /// Snapshot of the per-feed statuses, sorted by feed name.
    pub async fn statuses(&self) -> Vec<(String, FeedStatus)> {
        let mut out: Vec<(String, FeedStatus)> = self
            .status
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Log a summary line per feed (startup diagnostics).
    pub async fn log_summary(&self) {
        for (name, st) in self.statuses().await {
            match &st.last_error {
                Some(err) => warn!(feed = %name, error = %err, "reputation feed degraded"),
                None => info!(feed = %name, entries = st.entries, "reputation feed synced"),
            }
        }
    }
}

/// Errors produced while syncing a feed.
#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    /// URL rejected by the SSRF guard or unparseable.
    #[error("{0}")]
    Url(String),
    /// Transport / HTTP failure.
    #[error("{0}")]
    Fetch(String),
    /// Feed body exceeded [`MAX_FEED_BYTES`].
    #[error("feed `{0}` exceeded the {MAX_FEED_BYTES}-byte cap")]
    TooLarge(String),
}

impl From<reqwest::Error> for ReputationError {
    fn from(e: reqwest::Error) -> Self {
        Self::Fetch(e.to_string())
    }
}

/// Validate a feed URL: `http`/`https` only, host must not be `localhost`
/// or a loopback/private/reserved IP literal.
pub fn validate_feed_url(url: &str) -> Result<reqwest::Url, ReputationError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| ReputationError::Url(format!("invalid URL `{url}`: {e}")))?;
    static_url_check(&parsed).map_err(ReputationError::Url)?;
    Ok(parsed)
}

/// Scheme + host-literal half of the guard (also applied to redirect hops,
/// where DNS resolution is not possible synchronously).
fn static_url_check(url: &reqwest::Url) -> Result<(), String> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(format!(
            "scheme `{}` not allowed (http/https only)",
            url.scheme()
        ));
    }
    let host = url.host_str().unwrap_or_default();
    if host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("localdomain")
        || host.ends_with(".localhost")
        || host.ends_with(".localdomain")
    {
        return Err("localhost hosts are not allowed".into());
    }
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        if ip_is_rejected(ip) {
            return Err(format!("host `{host}` is loopback/private/reserved"));
        }
    }
    Ok(())
}

/// Resolve a hostname and reject it when any address is loopback, private or
/// reserved (DNS-level half of the guard; IP literals were already checked).
async fn resolve_host(host: &str, port: u16) -> Result<(), ReputationError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ReputationError::Url(format!("DNS lookup for `{host}` failed: {e}")))?
        .collect();
    for addr in addrs {
        if ip_is_rejected(addr.ip()) {
            return Err(ReputationError::Url(format!(
                "host `{host}` resolves to loopback/private/reserved {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// Whether an IP is loopback, private, link-local, unspecified or otherwise
/// reserved — never a legitimate public feed host.
pub fn ip_is_rejected(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_rejected(v4),
        IpAddr::V6(v6) => v6_is_rejected(v6),
    }
}

fn v4_is_rejected(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64) // 100.64/10 CGNAT
}

fn v6_is_rejected(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || ip.is_unspecified()
        || first & 0xfe00 == 0xfc00 // unique-local fc00::/7
        || first & 0xffc0 == 0xfe80 // link-local
        || first & 0xff00 == 0xff00 // multicast
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_http_urls() {
        for url in [
            "https://check.torproject.org/exit-addresses",
            "https://www.spamhaus.org/drop/drop.txt",
            "http://example.com/list.txt",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        ] {
            assert!(validate_feed_url(url).is_ok(), "{url} should be allowed");
        }
    }

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_feed_url("ftp://example.com/feed").is_err());
        assert!(validate_feed_url("file:///etc/passwd").is_err());
        assert!(validate_feed_url("not a url").is_err());
    }

    #[test]
    fn rejects_localhost_and_private_hosts() {
        for url in [
            "http://localhost/feed.txt",
            "http://127.0.0.1/feed.txt",
            "http://127.0.0.1:8080/feed.txt",
            "http://10.0.0.1/feed.txt",
            "http://192.168.1.10/feed.txt",
            "http://172.16.0.1/feed.txt",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1/feed.txt",
            "http://0.0.0.0/feed.txt",
            "http://[::1]/feed.txt",
            "http://[fe80::1]/feed.txt",
            "http://[fd00::1]/feed.txt",
            "https://localhost.localdomain/feed.txt",
        ] {
            assert!(validate_feed_url(url).is_err(), "{url} should be rejected");
        }
    }

    #[test]
    fn static_check_covers_redirect_hops() {
        for url in [
            "http://10.0.0.1/x",
            "http://[fd00::1]/x",
            "http://localhost/x",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                static_url_check(&parsed).is_err(),
                "{url} should be rejected"
            );
        }
        let ok = reqwest::Url::parse("https://example.com/x").unwrap();
        assert!(static_url_check(&ok).is_ok());
    }

    #[test]
    fn service_filters_disabled_feeds() {
        let cfg = vec![
            FeedConfig {
                name: "on".into(),
                url: "https://example.com/a".into(),
                ..FeedConfig::default()
            },
            FeedConfig {
                name: "off".into(),
                url: "https://example.com/b".into(),
                enabled: false,
                ..FeedConfig::default()
            },
            FeedConfig::default(),
        ];
        let svc = ReputationService::new(&cfg);
        assert!(svc.is_active());
        assert!(svc.store.read().unwrap().is_empty());
    }
}
