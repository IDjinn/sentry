//! IP reputation feeds: in-memory store, feed-text parser and signal
//! mapping (F3.7).
//!
//! Public blocklists (Tor exit nodes, Spamhaus DROP, FireHOL, …) are plain
//! text lists of IPs and CIDRs. [`parse_feed`] extracts the networks from any
//! of the common formats, [`ReputationStore`] answers longest-prefix-wins
//! lookups, and [`reputation_signals`] turns the enrichment attached to an
//! [`Event`] into scored signals. The fetching itself lives in the
//! `sentry-reputation` crate (the core stays I/O-free).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::analysis::{Signal, SignalKind};
use crate::config::FeedConfig;
use crate::event::Event;
use crate::rules::{ReputationTier, Rule, RuleAction, RuleMatch, RuleSource};

/// Default weight of the `TorExitNode` signal (§16 risk table).
pub const TOR_EXIT_NODE_WEIGHT: u8 = 15;
/// Default weight of the `KnownBadIp` signal (§16 risk table).
pub const KNOWN_BAD_IP_WEIGHT: u8 = 50;
/// Default weight of the `VpnProxy` signal.
pub const VPN_PROXY_WEIGHT: u8 = 20;
/// Default weight of the `PromiscuousScanner` signal (F3.10 scanner
/// taxonomy).
pub const PROMISCUOUS_SCANNER_WEIGHT: u8 = 10;

/// In-memory IP → reputation lookup built from synced feeds.
///
/// Entries are keyed by `(prefix_len, masked_network)` so a lookup probes
/// prefix lengths from the longest down and the first hit is by definition
/// the longest-prefix match. Feeds may overlap; a longer prefix always wins
/// and on an exact overlap the most recently inserted feed wins.
#[derive(Debug, Default, Clone)]
pub struct ReputationStore {
    entries: HashMap<(u8, IpAddr), ReputationEntry>,
    feed_keys: HashMap<String, Vec<(u8, IpAddr)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReputationEntry {
    tier: ReputationTier,
    feed: String,
}

impl ReputationStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace all entries contributed by `feed` with `nets` (tagged `tier`).
    ///
    /// Refreshes call this so stale addresses vanish instead of lingering
    /// until the next restart.
    pub fn replace_feed(
        &mut self,
        feed: &str,
        tier: ReputationTier,
        nets: impl IntoIterator<Item = IpNet>,
    ) {
        if let Some(old) = self.feed_keys.remove(feed) {
            for key in old {
                if self.entries.get(&key).is_some_and(|e| e.feed == feed) {
                    self.entries.remove(&key);
                }
            }
        }
        let mut keys = Vec::new();
        for net in nets {
            let key = net_key(&net);
            self.entries.insert(
                key,
                ReputationEntry {
                    tier,
                    feed: feed.to_string(),
                },
            );
            keys.push(key);
        }
        self.feed_keys.insert(feed.to_string(), keys);
    }

    /// Look up the reputation of an IP. `None` when no feed covers it.
    pub fn lookup(&self, ip: IpAddr) -> Option<crate::event::ReputationInfo> {
        let found = match ip {
            IpAddr::V4(v4) => (0u8..=32)
                .rev()
                .find_map(|prefix| self.entries.get(&(prefix, mask_v4(v4, prefix)))),
            IpAddr::V6(v6) => (0u8..=128)
                .rev()
                .find_map(|prefix| self.entries.get(&(prefix, mask_v6(v6, prefix)))),
        };
        found.map(|entry| crate::event::ReputationInfo {
            tier: entry.tier,
            source: entry.feed.clone(),
        })
    }

    /// Total number of entries across all feeds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries contributed by a given feed.
    pub fn feed_len(&self, feed: &str) -> usize {
        self.feed_keys.get(feed).map(Vec::len).unwrap_or(0)
    }
}

fn net_key(net: &IpNet) -> (u8, IpAddr) {
    match net {
        IpNet::V4(v4) => (v4.prefix_len(), IpAddr::V4(v4.network())),
        IpNet::V6(v6) => (v6.prefix_len(), IpAddr::V6(v6.network())),
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> IpAddr {
    if prefix == 0 {
        return IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    }
    let bits = u32::from(ip) & (u32::MAX << (32 - u32::from(prefix)));
    IpAddr::V4(Ipv4Addr::from(bits))
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> IpAddr {
    if prefix == 0 {
        return IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    }
    let bits = u128::from(ip) & (u128::MAX << (128 - u32::from(prefix)));
    IpAddr::V6(Ipv6Addr::from(bits))
}

/// Extract networks from a plain-text feed body.
///
/// One address per line; tokens are split on whitespace and `;` and the
/// first token that parses as an IP or CIDR wins, which transparently covers
/// Spamhaus DROP (`1.2.3.0/24 ; SBL123 ; org`), the Tor Project
/// `exit-addresses` dump (`ExitAddress 1.2.3.4 2026-08-30 …`), FireHOL
/// netsets and bare IP lists. `#` comment lines and unparseable lines are
/// skipped.
pub fn parse_feed(body: &str) -> Vec<IpNet> {
    let mut nets = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in line.split([' ', '\t', ';']) {
            if let Some(net) = parse_net(token) {
                nets.push(net);
                break;
            }
        }
    }
    nets
}

fn parse_net(token: &str) -> Option<IpNet> {
    if let Ok(net) = token.parse::<IpNet>() {
        return Some(net);
    }
    token.parse::<IpAddr>().ok().map(IpNet::from)
}

/// Map the reputation enrichment on an event to scored signals.
///
/// `Clean`, `Suspicious`, `Unknown` and `Authorized` tiers are informational
/// and produce no signal; `Tor`, `Malicious`, `VpnProxy`/`Datacenter` and
/// `Promiscuous` map to the catalog kinds the scorer already knows (weights
/// per the §16 risk table, overridable via `[scorer].weights`).
pub fn reputation_signals(evt: &Event) -> Vec<Signal> {
    let Some(rep) = evt.reputation.as_ref() else {
        return Vec::new();
    };
    let (kind, weight) = match rep.tier {
        ReputationTier::Tor => (SignalKind::TorExitNode, TOR_EXIT_NODE_WEIGHT),
        ReputationTier::Malicious => (SignalKind::KnownBadIp, KNOWN_BAD_IP_WEIGHT),
        ReputationTier::VpnProxy | ReputationTier::Datacenter => {
            (SignalKind::VpnProxy, VPN_PROXY_WEIGHT)
        }
        ReputationTier::Promiscuous => (SignalKind::PromiscuousScanner, PROMISCUOUS_SCANNER_WEIGHT),
        ReputationTier::Unknown
        | ReputationTier::Clean
        | ReputationTier::Suspicious
        | ReputationTier::Authorized => {
            return Vec::new();
        }
    };
    vec![Signal {
        kind,
        weight,
        detail: Some(format!("feed:{}", rep.source)),
    }]
}

/// Build the synthetic enforcement rule for a feed whose config carries an
/// `action` (`block`, `challenge`, `rate_limit`, …).
///
/// Feeds without an `action` only enrich events — the `tor` / `vpn_proxy`
/// packs or user rules then match on `reputation = …` themselves.
pub fn feed_rule(feed: &FeedConfig) -> Result<Option<Rule>, String> {
    if feed.action.is_empty() {
        return Ok(None);
    }
    let tier = ReputationTier::parse(&feed.tier).ok_or_else(|| {
        format!(
            "unknown reputation tier `{}` (known: unknown | clean | suspicious | malicious | datacenter | vpn | tor | authorized | promiscuous)",
            feed.tier
        )
    })?;
    let action = parse_rule_action(&feed.action).ok_or_else(|| {
        format!(
            "unknown feed action `{}` (known: allow | block | challenge | rate_limit | log | tag)",
            feed.action
        )
    })?;
    Ok(Some(Rule {
        id: format!("feed:{}", feed.name),
        name: format!("reputation feed `{}` ({})", feed.name, feed.tier),
        priority: 50,
        enabled: true,
        match_: RuleMatch::Reputation(tier),
        action,
        ttl: None,
        source: RuleSource::Feed,
        tags: vec!["feed".into(), format!("feed:{}", feed.name)],
        created_at: Some(chrono::Utc::now()),
    }))
}

fn parse_rule_action(s: &str) -> Option<RuleAction> {
    match s.trim().to_ascii_lowercase().as_str() {
        "allow" => Some(RuleAction::Allow),
        "block" => Some(RuleAction::Block),
        "challenge" => Some(RuleAction::Challenge),
        "rate_limit" | "ratelimit" => Some(RuleAction::RateLimit),
        "log" => Some(RuleAction::Log),
        "tag" => Some(RuleAction::Tag),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, ProtocolData, ReputationInfo};

    fn v4(o1: u8, o2: u8, o3: u8, o4: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(o1, o2, o3, o4))
    }

    fn http_evt(ip: IpAddr) -> Event {
        Event::new(
            crate::event::SourceKind::Synthetic,
            ip,
            ProtocolData::Http(HttpData {
                path: "/".into(),
                ..HttpData::default()
            }),
        )
    }

    #[test]
    fn parses_spamhaus_drop_format() {
        let body = "; Spamhaus DROP\n1.2.3.0/24 ; SBL12345 ; Some Org\n4.5.6.7 ; SBL99 ; Other\n# comment\n\nnot an ip\n";
        let nets = parse_feed(body);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].to_string(), "1.2.3.0/24");
        assert_eq!(nets[1].to_string(), "4.5.6.7/32");
    }

    #[test]
    fn parses_tor_exit_addresses() {
        let body = "ExitNode 0019BD1A0B504A6J2A5A8B6C4F0C1D6E9F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6\nPublished 2026-08-29 00:01:02\nExitAddress 104.244.72.115 2026-08-29 06:07:08\nExitAddress 209.141.41.121 2026-08-29 06:07:08\n";
        let nets = parse_feed(body);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].to_string(), "104.244.72.115/32");
        assert_eq!(nets[1].to_string(), "209.141.41.121/32");
    }

    #[test]
    fn parses_netset_and_ipv6() {
        let body = "# firehol-style\n198.20.69.96/29\n2001:db8::/32\n2a01:4f8:1c17::/48\n";
        let nets = parse_feed(body);
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[2].to_string(), "2a01:4f8:1c17::/48");
    }

    #[test]
    fn lookup_exact_and_prefix() {
        let mut store = ReputationStore::new();
        store.replace_feed(
            "test",
            ReputationTier::Malicious,
            vec!["1.2.3.4/32".parse().unwrap(), "10.0.0.0/8".parse().unwrap()],
        );
        assert_eq!(
            store.lookup(v4(1, 2, 3, 4)).map(|r| r.tier),
            Some(ReputationTier::Malicious)
        );
        assert_eq!(
            store.lookup(v4(10, 200, 1, 1)).map(|r| r.tier),
            Some(ReputationTier::Malicious)
        );
        assert!(store.lookup(v4(10, 0, 0, 5)).is_some());
        assert!(store.lookup(v4(11, 0, 0, 1)).is_none());
        assert_eq!(store.len(), 2);
        assert_eq!(store.feed_len("test"), 2);
        assert_eq!(store.feed_len("other"), 0);
    }

    #[test]
    fn longest_prefix_wins_across_feeds() {
        let mut store = ReputationStore::new();
        store.replace_feed(
            "wide",
            ReputationTier::Datacenter,
            vec!["1.2.0.0/16".parse().unwrap()],
        );
        store.replace_feed(
            "narrow",
            ReputationTier::Tor,
            vec!["1.2.3.0/24".parse().unwrap()],
        );
        let hit = store.lookup(v4(1, 2, 3, 99)).unwrap();
        assert_eq!(hit.tier, ReputationTier::Tor);
        assert_eq!(hit.source, "narrow");
        let wide = store.lookup(v4(1, 2, 9, 9)).unwrap();
        assert_eq!(wide.tier, ReputationTier::Datacenter);
    }

    #[test]
    fn replace_feed_drops_stale_entries() {
        let mut store = ReputationStore::new();
        store.replace_feed(
            "f",
            ReputationTier::Malicious,
            vec!["1.1.1.1/32".parse().unwrap()],
        );
        assert!(store.lookup(v4(1, 1, 1, 1)).is_some());
        store.replace_feed(
            "f",
            ReputationTier::Malicious,
            vec!["2.2.2.2/32".parse().unwrap()],
        );
        assert!(store.lookup(v4(1, 1, 1, 1)).is_none());
        assert!(store.lookup(v4(2, 2, 2, 2)).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn ipv6_lookup() {
        let mut store = ReputationStore::new();
        store.replace_feed(
            "v6",
            ReputationTier::Tor,
            vec!["2a01:4f8::/29".parse().unwrap()],
        );
        let ip: IpAddr = "2a01:4f8:1c17:c5::1".parse().unwrap();
        assert_eq!(store.lookup(ip).map(|r| r.tier), Some(ReputationTier::Tor));
        let miss: IpAddr = "2a02::1".parse().unwrap();
        assert!(store.lookup(miss).is_none());
    }

    #[test]
    fn signals_follow_tier() {
        let mut evt = http_evt(v4(1, 2, 3, 4));
        assert!(reputation_signals(&evt).is_empty());

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Tor,
            source: "tor_exit".into(),
        });
        let sigs = reputation_signals(&evt);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::TorExitNode);
        assert_eq!(sigs[0].weight, 15);
        assert_eq!(sigs[0].detail.as_deref(), Some("feed:tor_exit"));

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Malicious,
            source: "drop".into(),
        });
        assert_eq!(reputation_signals(&evt)[0].kind, SignalKind::KnownBadIp);
        assert_eq!(reputation_signals(&evt)[0].weight, 50);

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Clean,
            source: "allow".into(),
        });
        assert!(reputation_signals(&evt).is_empty());
    }

    #[test]
    fn scanner_taxonomy_tiers() {
        let mut evt = http_evt(v4(1, 2, 3, 4));

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Promiscuous,
            source: "promiscuous_scanners".into(),
        });
        let sigs = reputation_signals(&evt);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::PromiscuousScanner);
        assert_eq!(sigs[0].weight, 10);
        assert_eq!(sigs[0].detail.as_deref(), Some("feed:promiscuous_scanners"));

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Authorized,
            source: "pentest_vendor".into(),
        });
        assert!(reputation_signals(&evt).is_empty());

        assert_eq!(
            ReputationTier::parse("promiscuous"),
            Some(ReputationTier::Promiscuous)
        );
        assert_eq!(
            ReputationTier::parse("promiscuous_scanner"),
            Some(ReputationTier::Promiscuous)
        );
        assert_eq!(
            ReputationTier::parse("authorized"),
            Some(ReputationTier::Authorized)
        );
        assert_eq!(
            ReputationTier::parse("authorized_scanner"),
            Some(ReputationTier::Authorized)
        );
    }

    #[test]
    fn feed_rule_builds_and_skips() {
        let mut feed = FeedConfig {
            name: "spamhaus".into(),
            url: "https://example.invalid/drop.txt".into(),
            ..FeedConfig::default()
        };
        assert!(feed_rule(&feed).unwrap().is_none());

        feed.action = "block".into();
        let rule = feed_rule(&feed).unwrap().unwrap();
        assert_eq!(rule.id, "feed:spamhaus");
        assert_eq!(rule.action, RuleAction::Block);
        assert_eq!(rule.source, RuleSource::Feed);
        assert!(matches!(
            rule.match_,
            RuleMatch::Reputation(ReputationTier::Malicious)
        ));

        feed.tier = "nope".into();
        assert!(feed_rule(&feed).is_err());
        feed.tier = "tor".into();
        feed.action = "zap".into();
        assert!(feed_rule(&feed).is_err());
    }

    #[test]
    fn reputation_ruleset_end_to_end() {
        use crate::rules::RuleSet;
        let feed = FeedConfig {
            name: "tor_exit".into(),
            url: "https://example.invalid/tor".into(),
            tier: "tor".into(),
            action: "block".into(),
            ..FeedConfig::default()
        };
        let rule = feed_rule(&feed).unwrap().unwrap();
        let ruleset = RuleSet::new(vec![rule]);

        let mut evt = http_evt(v4(104, 244, 72, 115));
        assert!(ruleset.evaluate(&evt).is_none());

        evt.reputation = Some(ReputationInfo {
            tier: ReputationTier::Tor,
            source: "tor_exit".into(),
        });
        let (matched, short) = ruleset.evaluate(&evt).unwrap();
        assert!(short);
        assert_eq!(matched.action, RuleAction::Block);
    }
}
