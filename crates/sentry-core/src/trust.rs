//! Trusted-infrastructure sets (F7.2): which peers may set header-borne
//! client IPs (trusted proxies — e.g. the Cloudflare ranges) and which
//! clients must never be banned (admin workstations, uptime probes — the
//! nginx-honeypot `TRUSTED_IPS` concept).
//!
//! Without a trusted-proxy check, the nginx parser's header precedence
//! (ARCHITECTURE §8.1) lets anyone connecting **directly** to nginx spoof
//! their client IP with a forged `CF-Connecting-IP` header. With a
//! [`TrustSet`], header-borne candidates are only honored when the log's
//! `$remote_addr` (or the edge peer address) is itself a trusted proxy.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use ipnet::IpNet;

use crate::config::RealIpConfig;

/// Bundled Cloudflare IPv4 ranges (<https://www.cloudflare.com/ips-v4>),
/// refreshed at runtime when `[real_ip] cloudflare = true`.
pub const CLOUDFLARE_IPV4: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Bundled Cloudflare IPv6 ranges (<https://www.cloudflare.com/ips-v6>).
pub const CLOUDFLARE_IPV6: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Parse one set entry: CIDR or bare IP (widened to `/32` or `/128`).
pub fn parse_net(entry: &str) -> Result<IpNet, String> {
    let s = entry.trim();
    if s.is_empty() {
        return Err("empty entry".into());
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    s.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|e| format!("not a CIDR or IP: {e}"))
}

/// Parse a fetched ranges list (one CIDR/IP per line, `#` comments) — the
/// format of cloudflare.com/ips-v4 and ips-v6.
pub fn parse_range_list(text: &str) -> Vec<IpNet> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                None
            } else {
                parse_net(l).ok()
            }
        })
        .collect()
}

/// The bundled Cloudflare ranges.
pub fn cloudflare_ranges() -> Vec<IpNet> {
    let mut nets: Vec<IpNet> = CLOUDFLARE_IPV4
        .iter()
        .filter_map(|s| s.parse::<IpNet>().ok())
        .collect();
    nets.extend(
        CLOUDFLARE_IPV6
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok()),
    );
    nets
}

/// Trusted-proxy + never-ban membership.
#[derive(Debug, Clone, Default)]
pub struct TrustSet {
    proxies: Vec<IpNet>,
    never_ban: Vec<IpNet>,
}

impl TrustSet {
    /// Build from `[real_ip]` config. Invalid entries are a config error
    /// (fail at load, not at runtime).
    pub fn from_config(cfg: &RealIpConfig) -> Result<Self, String> {
        let mut ts = Self::default();
        if cfg.cloudflare {
            ts.proxies.extend(cloudflare_ranges());
        }
        for entry in &cfg.trusted_proxies {
            ts.proxies.push(parse_net(entry)?);
        }
        for entry in &cfg.trusted_ips {
            ts.never_ban.push(parse_net(entry)?);
        }
        Ok(ts)
    }

    /// Add trusted-proxy ranges (used by the runtime Cloudflare refresh).
    pub fn add_proxies(&mut self, nets: impl IntoIterator<Item = IpNet>) {
        self.proxies.extend(nets);
    }

    /// Whether `ip` may set header-borne client IPs.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.proxies.iter().any(|n| n.contains(&ip))
    }

    /// Whether `ip` is exempt from bans, blocks and reports.
    pub fn is_never_ban(&self, ip: IpAddr) -> bool {
        self.never_ban.iter().any(|n| n.contains(&ip))
    }

    /// Whether neither set has entries.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty() && self.never_ban.is_empty()
    }

    /// Number of trusted-proxy ranges.
    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }

    /// Number of never-ban entries.
    pub fn never_ban_count(&self) -> usize {
        self.never_ban.len()
    }
}

/// Cheap-cloning handle shared by the nginx parser, inline edge, pipeline
/// and actions. Updated in place by the Cloudflare ranges refresh task.
#[derive(Clone, Debug, Default)]
pub struct SharedTrustSet(Arc<RwLock<TrustSet>>);

impl SharedTrustSet {
    /// Wrap a set.
    pub fn new(ts: TrustSet) -> Self {
        Self(Arc::new(RwLock::new(ts)))
    }

    /// Whether `ip` may set header-borne client IPs.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.0.read().unwrap().is_trusted_proxy(ip)
    }

    /// Whether `ip` is exempt from bans, blocks and reports.
    pub fn is_never_ban(&self, ip: IpAddr) -> bool {
        self.0.read().unwrap().is_never_ban(ip)
    }

    /// Whether neither set has entries.
    pub fn is_empty(&self) -> bool {
        self.0.read().unwrap().is_empty()
    }

    /// Replace the contents (Cloudflare ranges refresh).
    pub fn update(&self, ts: TrustSet) {
        *self.0.write().unwrap() = ts;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(proxies: &[&str], never: &[&str], cloudflare: bool) -> RealIpConfig {
        RealIpConfig {
            trusted_proxies: proxies.iter().map(|s| s.to_string()).collect(),
            cloudflare,
            trusted_ips: never.iter().map(|s| s.to_string()).collect(),
            refresh_secs: 0,
        }
    }

    #[test]
    fn parses_cidr_and_bare_ip() {
        assert_eq!(parse_net("10.0.0.0/8").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(
            parse_net("203.0.113.7").unwrap().to_string(),
            "203.0.113.7/32"
        );
        assert_eq!(
            parse_net("2001:db8::1").unwrap().to_string(),
            "2001:db8::1/128"
        );
        assert!(parse_net("").is_err());
        assert!(parse_net("nope").is_err());
    }

    #[test]
    fn cloudflare_proxy_is_trusted_direct_is_not() {
        let ts = TrustSet::from_config(&cfg(&[], &[], true)).unwrap();
        // CF edge peer: headers honored.
        assert!(ts.is_trusted_proxy("104.16.0.1".parse().unwrap()));
        assert!(ts.is_trusted_proxy("2606:4700::1".parse().unwrap()));
        // Direct client: headers ignored.
        assert!(!ts.is_trusted_proxy("198.51.100.9".parse().unwrap()));
        assert!(!ts.is_empty());
    }

    #[test]
    fn config_proxies_extend_cloudflare() {
        let ts = TrustSet::from_config(&cfg(&["10.0.0.0/8"], &[], true)).unwrap();
        assert!(ts.is_trusted_proxy("10.1.2.3".parse().unwrap()));
        assert!(ts.is_trusted_proxy("172.64.0.1".parse().unwrap()));
    }

    #[test]
    fn invalid_proxy_entry_is_a_config_error() {
        assert!(TrustSet::from_config(&cfg(&["bad-entry"], &[], false)).is_err());
        assert!(TrustSet::from_config(&cfg(&[], &["bad-entry"], false)).is_err());
    }

    #[test]
    fn never_ban_membership() {
        let ts =
            TrustSet::from_config(&cfg(&[], &["203.0.113.7", "192.168.1.0/24"], false)).unwrap();
        assert!(ts.is_never_ban("203.0.113.7".parse().unwrap()));
        assert!(ts.is_never_ban("192.168.1.200".parse().unwrap()));
        assert!(!ts.is_never_ban("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn shared_handle_updates_in_place() {
        let shared = SharedTrustSet::new(TrustSet::default());
        assert!(!shared.is_trusted_proxy("104.16.0.1".parse().unwrap()));
        shared.update(TrustSet::from_config(&cfg(&[], &[], true)).unwrap());
        assert!(shared.is_trusted_proxy("104.16.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_cloudflare_range_list_format() {
        let text = "# comment\n173.245.48.0/20\n\n2400:cb00::/32 # trailing\nbad-line\n";
        let nets = parse_range_list(text);
        assert_eq!(nets.len(), 2);
    }
}
