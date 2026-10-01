//! Behavioral attack-pattern detection: per-IP sliding windows over HTTP
//! auth routes and well-known probe paths (F3.8).
//!
//! Three detectors complement the generic scan trackers ([`crate::scan`]):
//!
//! - **AuthBruteForce** — many `401`/`403` responses on authentication
//!   routes from one IP: password guessing against a login endpoint.
//! - **CredentialStuffing** — the same auth-failure volume spread over many
//!   *distinct User-Agents*: stolen credential lists replayed by a tool that
//!   rotates fingerprints to defeat naive UA-based blocking.
//! - **DirectoryBruteForce** — systematic probing of well-known sensitive
//!   paths (`/admin`, `/wp-admin`, `/backup`, `/db.sql`, …) answered with
//!   404. Known-good crawler UAs are exempt so an honest Googlebot sweeping
//!   the site is not flagged.
//!
//! Like the scan trackers, signals re-fire on every qualifying event so the
//! repetition bonus and strike escalation keep raising the verdict the longer
//! the attack runs.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::analysis::{Signal, SignalKind};
use crate::config::BehaviorConfig;

/// Default weight of the `AuthBruteForce` signal.
pub const AUTH_BRUTE_FORCE_WEIGHT: u8 = 35;
/// Default weight of the `CredentialStuffing` signal.
pub const CREDENTIAL_STUFFING_WEIGHT: u8 = 40;
/// Default weight of the `DirectoryBruteForce` signal.
pub const DIRECTORY_BRUTE_FORCE_WEIGHT: u8 = 30;
/// Default weight of the `SuspiciousLoginSuccess` signal.
pub const SUSPICIOUS_LOGIN_SUCCESS_WEIGHT: u8 = 45;

/// Substrings identifying authentication routes.
pub const DEFAULT_LOGIN_PATTERNS: &[&str] = &[
    "login", "signin", "sign-in", "logon", "auth", "session", "token", "password", "wp-login",
];

/// Well-known paths probed by directory brute-force tools.
pub const DEFAULT_WORDLIST: &[&str] = &[
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/backup",
    "/backups",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/phpmyadmin",
    "/pma",
    "/config.php",
    "/wp-config.php",
    "/setup",
    "/install",
    "/.htaccess",
    "/.htpasswd",
    "/console",
    "/actuator",
    "/manager/html",
    "/jenkins",
    "/adminer.php",
    "/_ignition",
    "/eval-stdin.php",
    "/hnap1",
    "/remote/fgt_lang",
    "/gponform",
    "/autodiscover",
    "/restapi/logoncustomization",
    "/telerik.web.ui",
    "/cgi-bin",
    "/node_modules",
    "/vendor/phpunit",
];

/// User-Agent substrings of legitimate crawlers, exempt from
/// `DirectoryBruteForce`.
const GOOD_BOTS: &[&str] = &[
    "googlebot",
    "bingbot",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "slurp",
    "applebot",
    "facebookexternalhit",
    "twitterbot",
];

#[derive(Debug, Clone)]
struct AuthHit {
    ua: Option<String>,
    ts: Instant,
}

/// Per-IP behavioral windows for auth failures and wordlist probes.
#[derive(Debug)]
pub struct BehaviorTracker {
    window: Duration,
    auth_failures: u32,
    distinct_uas: u32,
    wordlist_hits: u32,
    suspicious_success_min_failures: u32,
    login_patterns: Vec<String>,
    wordlist: Vec<String>,
    auth: HashMap<IpAddr, Vec<AuthHit>>,
    wordlist_windows: HashMap<IpAddr, Vec<Instant>>,
}

impl BehaviorTracker {
    /// Create from config.
    pub fn from_config(cfg: &BehaviorConfig) -> Self {
        let login_patterns = match cfg.login_patterns.is_empty() {
            false => cfg.login_patterns.clone(),
            true => DEFAULT_LOGIN_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let wordlist = match cfg.wordlist_paths.is_empty() {
            false => cfg.wordlist_paths.clone(),
            true => DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect(),
        };
        Self {
            window: Duration::from_secs(cfg.window_secs),
            auth_failures: cfg.auth_failures,
            distinct_uas: cfg.distinct_uas,
            wordlist_hits: cfg.wordlist_hits,
            suspicious_success_min_failures: cfg.suspicious_success_min_failures,
            login_patterns,
            wordlist,
            auth: HashMap::new(),
            wordlist_windows: HashMap::new(),
        }
    }

    /// Create with explicit thresholds and the default pattern lists.
    pub fn new(
        window_secs: u64,
        auth_failures: u32,
        distinct_uas: u32,
        wordlist_hits: u32,
    ) -> Self {
        Self::from_config(&BehaviorConfig {
            window_secs,
            auth_failures,
            distinct_uas,
            wordlist_hits,
            ..BehaviorConfig::default()
        })
    }

    /// Record an HTTP observation and return the behavioral signals it
    /// triggered. Only auth failures (401/403) and wordlist 404s leave
    /// state behind; everything else returns no signal.
    pub fn record(
        &mut self,
        ip: IpAddr,
        path: &str,
        status: Option<u16>,
        user_agent: Option<&str>,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        let now = Instant::now();
        let path_lower = path.to_ascii_lowercase();

        if matches!(status, Some(401 | 403)) && self.is_login_path(&path_lower) {
            const MAX_AUTH_HITS: usize = 64;
            let hits = self.auth.entry(ip).or_default();
            hits.retain(|h| now.duration_since(h.ts) < self.window);
            if hits.len() >= MAX_AUTH_HITS {
                let overflow = hits.len() - MAX_AUTH_HITS + 1;
                hits.drain(..overflow);
            }
            hits.push(AuthHit {
                ua: user_agent.map(str::to_string),
                ts: now,
            });

            let distinct = hits
                .iter()
                .map(|h| h.ua.as_deref().unwrap_or(""))
                .collect::<std::collections::HashSet<_>>()
                .len() as u32;
            if self.auth_failures > 0 && hits.len() as u32 >= self.auth_failures {
                signals.push(Signal {
                    kind: SignalKind::AuthBruteForce,
                    weight: AUTH_BRUTE_FORCE_WEIGHT,
                    detail: Some(format!(
                        "{} auth failures in {}s",
                        hits.len(),
                        self.window.as_secs()
                    )),
                });
            }
            if self.distinct_uas > 0 && distinct >= self.distinct_uas {
                signals.push(Signal {
                    kind: SignalKind::CredentialStuffing,
                    weight: CREDENTIAL_STUFFING_WEIGHT,
                    detail: Some(format!(
                        "{distinct} distinct user-agents failing auth in {}s",
                        self.window.as_secs()
                    )),
                });
            }
        }

        // A successful auth from an IP that just piled up failures is the
        // moment the brute force (maybe) worked — the highest-value alert in
        // the window. Alerts on the success instead of only on the failures,
        // which fire constantly and get ignored. The window is consumed so a
        // follow-up session doesn't re-fire on every request.
        if matches!(status, Some(s) if (200..300).contains(&s)) && self.is_login_path(&path_lower) {
            if let Some(hits) = self.auth.get_mut(&ip) {
                hits.retain(|h| now.duration_since(h.ts) < self.window);
                if self.suspicious_success_min_failures > 0
                    && hits.len() as u32 >= self.suspicious_success_min_failures
                {
                    signals.push(Signal {
                        kind: SignalKind::SuspiciousLoginSuccess,
                        weight: SUSPICIOUS_LOGIN_SUCCESS_WEIGHT,
                        detail: Some(format!(
                            "login success after {} auth failures in {}s",
                            hits.len(),
                            self.window.as_secs()
                        )),
                    });
                    self.auth.remove(&ip);
                }
            }
        }

        if status == Some(404)
            && self.is_wordlist_path(&path_lower)
            && !self.is_good_bot(user_agent)
        {
            const MAX_WORDLIST_HITS: usize = 64;
            let hits = self.wordlist_windows.entry(ip).or_default();
            hits.retain(|t| now.duration_since(*t) < self.window);
            if hits.len() >= MAX_WORDLIST_HITS {
                let overflow = hits.len() - MAX_WORDLIST_HITS + 1;
                hits.drain(..overflow);
            }
            hits.push(now);
            if self.wordlist_hits > 0 && hits.len() as u32 >= self.wordlist_hits {
                signals.push(Signal {
                    kind: SignalKind::DirectoryBruteForce,
                    weight: DIRECTORY_BRUTE_FORCE_WEIGHT,
                    detail: Some(format!(
                        "{} wordlist paths 404 in {}s",
                        hits.len(),
                        self.window.as_secs()
                    )),
                });
            }
        }

        signals
    }

    /// Drop IPs whose windows have gone quiet.
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.auth.retain(|_, hits| {
            hits.retain(|h| now.duration_since(h.ts) < self.window);
            !hits.is_empty()
        });
        self.wordlist_windows.retain(|_, hits| {
            hits.retain(|t| now.duration_since(*t) < self.window);
            !hits.is_empty()
        });
    }

    fn is_login_path(&self, path_lower: &str) -> bool {
        self.login_patterns
            .iter()
            .any(|p| path_lower.contains(&p.to_ascii_lowercase()))
    }

    fn is_wordlist_path(&self, path_lower: &str) -> bool {
        self.wordlist.iter().any(|w| {
            let w = w.to_ascii_lowercase();
            path_lower == w || path_lower.starts_with(&format!("{w}/"))
        })
    }

    fn is_good_bot(&self, user_agent: Option<&str>) -> bool {
        let Some(ua) = user_agent else {
            return false;
        };
        let ua = ua.to_ascii_lowercase();
        GOOD_BOTS.iter().any(|b| ua.contains(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    const UA: &str = "Mozilla/5.0 (X11; Linux x86_64)";

    #[test]
    fn auth_failures_trigger_brute_force() {
        let mut t = BehaviorTracker::new(300, 3, 100, 5);
        assert!(t.record(ip(), "/login", Some(401), Some(UA)).is_empty());
        assert!(t.record(ip(), "/login", Some(403), Some(UA)).is_empty());
        let sigs = t.record(ip(), "/login", Some(401), Some(UA));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::AuthBruteForce);
        assert_eq!(sigs[0].weight, 35);
    }

    #[test]
    fn same_ua_never_triggers_stuffing() {
        let mut t = BehaviorTracker::new(300, 1, 3, 5);
        for _ in 0..10 {
            let sigs = t.record(ip(), "/api/login", Some(401), Some(UA));
            assert!(sigs
                .iter()
                .all(|s| s.kind != SignalKind::CredentialStuffing));
        }
    }

    #[test]
    fn rotating_uas_trigger_stuffing() {
        let mut t = BehaviorTracker::new(300, 100, 3, 5);
        assert!(t
            .record(ip(), "/login", Some(401), Some("curl/8"))
            .is_empty());
        assert!(t
            .record(ip(), "/login", Some(401), Some("python-requests/2"))
            .is_empty());
        let sigs = t.record(ip(), "/login", Some(401), Some("Go-http-client/2"));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::CredentialStuffing);
        assert_eq!(sigs[0].weight, 40);
    }

    #[test]
    fn non_auth_routes_and_successes_are_ignored() {
        let mut t = BehaviorTracker::new(300, 2, 2, 2);
        for _ in 0..5 {
            assert!(t.record(ip(), "/api/users", Some(401), Some(UA)).is_empty());
            assert!(t.record(ip(), "/login", Some(200), Some(UA)).is_empty());
            assert!(t.record(ip(), "/login", Some(500), Some(UA)).is_empty());
        }
    }

    #[test]
    fn wordlist_404s_trigger_directory_brute_force() {
        let mut t = BehaviorTracker::new(300, 10, 10, 3);
        assert!(t.record(ip(), "/admin", Some(404), Some(UA)).is_empty());
        assert!(t
            .record(ip(), "/wp-admin/setup.php", Some(404), Some(UA))
            .is_empty());
        let sigs = t.record(ip(), "/backup/db.sql", Some(404), Some(UA));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::DirectoryBruteForce);
        assert_eq!(sigs[0].weight, 30);
    }

    #[test]
    fn random_paths_do_not_count_as_wordlist() {
        let mut t = BehaviorTracker::new(300, 10, 10, 2);
        assert!(t.record(ip(), "/a1b2.php", Some(404), Some(UA)).is_empty());
        assert!(t.record(ip(), "/zzz", Some(404), Some(UA)).is_empty());
    }

    #[test]
    fn good_bots_are_exempt_from_directory_brute_force() {
        let mut t = BehaviorTracker::new(300, 10, 10, 2);
        for _ in 0..10 {
            assert!(t
                .record(
                    ip(),
                    "/admin",
                    Some(404),
                    Some("Mozilla/5.0 (compatible; Googlebot/2.1)")
                )
                .is_empty());
        }
    }

    #[test]
    fn separate_ips_do_not_share_windows() {
        let mut t = BehaviorTracker::new(300, 2, 10, 2);
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
        assert!(t.record(ip(), "/login", Some(401), Some(UA)).is_empty());
        assert!(t.record(other, "/login", Some(401), Some(UA)).is_empty());
    }

    #[test]
    fn success_after_brute_force_fires_and_consumes_window() {
        let mut t = BehaviorTracker::new(300, 3, 100, 5);
        t.record(ip(), "/login", Some(401), Some(UA));
        t.record(ip(), "/login", Some(401), Some(UA));
        // Below the threshold of 3: a success is just a success.
        assert!(t.record(ip(), "/login", Some(200), Some(UA)).is_empty());
        // Fail again to reach 3, then succeed.
        for _ in 0..3 {
            t.record(ip(), "/login", Some(401), Some(UA));
        }
        let sigs = t.record(ip(), "/login", Some(200), Some(UA));
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::SuspiciousLoginSuccess);
        assert_eq!(sigs[0].weight, 45);
        assert!(sigs[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("5 auth failures"));
        // Window consumed: the next success does not re-fire.
        assert!(t.record(ip(), "/login", Some(200), Some(UA)).is_empty());
    }

    #[test]
    fn success_without_failures_is_ignored() {
        let mut t = BehaviorTracker::new(300, 3, 100, 5);
        assert!(t.record(ip(), "/login", Some(200), Some(UA)).is_empty());
        assert!(t.record(ip(), "/login", Some(302), Some(UA)).is_empty());
    }

    #[test]
    fn success_on_non_auth_route_never_fires() {
        let mut t = BehaviorTracker::new(300, 2, 100, 5);
        for _ in 0..5 {
            t.record(ip(), "/login", Some(401), Some(UA));
        }
        assert!(t.record(ip(), "/api/users", Some(200), Some(UA)).is_empty());
        // The failures survive for the real login route.
        assert_eq!(
            t.record(ip(), "/login", Some(200), Some(UA))[0].kind,
            SignalKind::SuspiciousLoginSuccess
        );
    }

    #[test]
    fn suspicious_success_can_be_disabled() {
        let cfg = BehaviorConfig {
            suspicious_success_min_failures: 0,
            ..BehaviorConfig::default()
        };
        let mut t = BehaviorTracker::from_config(&cfg);
        for _ in 0..10 {
            t.record(ip(), "/login", Some(401), Some(UA));
        }
        assert!(t.record(ip(), "/login", Some(200), Some(UA)).is_empty());
    }

    #[test]
    fn prune_drops_quiet_ips() {
        let mut t = BehaviorTracker::new(0, 1, 1, 1);
        t.record(ip(), "/login", Some(401), Some(UA));
        t.record(ip(), "/admin", Some(404), Some(UA));
        t.prune();
        assert!(t.auth.is_empty());
        assert!(t.wordlist_windows.is_empty());
    }

    #[test]
    fn custom_patterns_from_config() {
        let cfg = BehaviorConfig {
            login_patterns: vec!["/secret-door".into()],
            wordlist_paths: vec!["/vault".into()],
            auth_failures: 1,
            wordlist_hits: 1,
            ..BehaviorConfig::default()
        };
        let mut t = BehaviorTracker::from_config(&cfg);
        assert!(t.record(ip(), "/login", Some(401), Some(UA)).is_empty());
        assert_eq!(
            t.record(ip(), "/secret-door", Some(401), Some(UA))[0].kind,
            SignalKind::AuthBruteForce
        );
        assert_eq!(
            t.record(ip(), "/vault/x", Some(404), Some(UA))[0].kind,
            SignalKind::DirectoryBruteForce
        );
    }
}
