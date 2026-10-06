//! Built-in reputation feed presets: curated public blocklists shipped as
//! ready-to-enable [`FeedConfig`] sets, so users get working reputation
//! feeds with one config line instead of hand-collecting URLs.
//!
//! Enable by name via `[rules] feed_presets = ["tor_exit", …]`. Expansion
//! happens at config load ([`SentryConfig::resolve_feed_presets`]); a
//! user-defined `[[rules.feeds]]` with the same name always wins. Preset
//! feeds default to `action = "block"` — enabling a preset means blocking,
//! not annotating (unlike hand-written feeds, which default to enrichment
//! only).
//!
//! Lists are fetched from their official sources over https and pass
//! through the same SSRF-guarded fetcher as user feeds.

use crate::config::FeedConfig;

/// A named bundle of feed entries.
pub struct FeedPreset {
    /// Config name (`feed_presets = ["…"]`).
    pub name: &'static str,
    /// One-line description shown by `sentry feeds list`.
    pub description: &'static str,
    /// Feeds this preset expands to.
    pub feeds: &'static [FeedPresetFeed],
}

/// One feed inside a preset.
pub struct FeedPresetFeed {
    /// Feed name (`[[rules.feeds]] name` after expansion).
    pub name: &'static str,
    /// Official list URL (https only).
    pub url: &'static str,
    /// Reputation tier for enrichment (`vpn`, `tor`, …).
    pub tier: &'static str,
    /// Refresh cadence in hours.
    pub refresh_hours: u32,
}

/// All built-in presets, enabled by name in `[rules] feed_presets`.
pub const PRESETS: &[FeedPreset] = &[
    FeedPreset {
        name: "tor_exit",
        description: "Tor exit nodes (check.torproject.org bulk list)",
        feeds: &[FeedPresetFeed {
            name: "tor_exit",
            url: "https://check.torproject.org/torbulkexitlist",
            tier: "tor",
            refresh_hours: 12,
        }],
    },
    FeedPreset {
        name: "firehol_level1",
        description: "FireHOL level 1: known-bad aggregate (Spamhaus DROP/eDROP, DShield, …)",
        feeds: &[FeedPresetFeed {
            name: "firehol_level1",
            url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            tier: "malicious",
            refresh_hours: 24,
        }],
    },
    FeedPreset {
        name: "proxy_list",
        description: "Open proxies (mmpx12/proxy-list aggregate: http/https/socks/tor)",
        feeds: &[FeedPresetFeed {
            name: "proxy_list",
            url: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/ips-list.txt",
            tier: "vpn",
            refresh_hours: 12,
        }],
    },
    FeedPreset {
        name: "open_source_vpn_ips",
        description: "Commercial VPN exit ranges (Joe12387/open-source-vpn-ip-lists: mullvad, nordvpn, …)",
        feeds: VPN_PROVIDER_FEEDS,
    },
    FeedPreset {
        name: "anti_vpn",
        description: "Datacenter/VPN aggregate (THEzombiePL/Anti-VPN-List: FireHOL anonymous, X4BNet, Nullified ASN)",
        feeds: &[FeedPresetFeed {
            name: "anti_vpn",
            url: "https://raw.githubusercontent.com/THEzombiePL/Anti-VPN-List/main/malicious-ips.txt",
            tier: "datacenter",
            refresh_hours: 6,
        }],
    },
];

const VPN_PROVIDER_FEEDS: &[FeedPresetFeed] = &[
    FeedPresetFeed {
        name: "vpn_airvpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/airvpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_ivpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/ivpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_mullvad",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/mullvad.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_nordvpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/nordvpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_ovpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/ovpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_pia",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/pia.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_protonvpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/protonvpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_riseupvpn",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/riseupvpn.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_surfshark",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/surfshark.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
    FeedPresetFeed {
        name: "vpn_windscribe",
        url: "https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/windscribe.txt",
        tier: "vpn",
        refresh_hours: 24,
    },
];

/// Look up a preset by its config name.
pub fn preset(name: &str) -> Option<&'static FeedPreset> {
    PRESETS.iter().find(|p| p.name == name)
}

/// Expand one preset feed into a user-facing [`FeedConfig`].
///
/// Presets block by default — that is the point of enabling one.
fn preset_feed(f: &FeedPresetFeed) -> FeedConfig {
    FeedConfig {
        name: f.name.to_string(),
        url: f.url.to_string(),
        tier: f.tier.to_string(),
        refresh_hours: f.refresh_hours,
        action: "block".to_string(),
        ..FeedConfig::default()
    }
}

/// Append feeds for every enabled preset that is not already defined in
/// `feeds` (user config wins on name collision). Idempotent. Returns the
/// names in `enabled` that match no preset — callers should warn.
pub fn expand(feeds: &mut Vec<FeedConfig>, enabled: &[String]) -> Vec<String> {
    let mut unknown = Vec::new();
    for name in enabled {
        match preset(name) {
            Some(p) => {
                for f in p.feeds {
                    if !feeds.iter().any(|existing| existing.name == f.name) {
                        feeds.push(preset_feed(f));
                    }
                }
            }
            None => unknown.push(name.clone()),
        }
    }
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_names_are_unique_and_snake_case() {
        let mut names: Vec<_> = PRESETS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len);
        for p in PRESETS {
            assert_eq!(p.name, p.name.to_lowercase());
            assert!(!p.description.is_empty());
            assert!(!p.feeds.is_empty());
        }
    }

    #[test]
    fn preset_feed_names_are_unique_across_presets() {
        let mut names: Vec<_> = PRESETS
            .iter()
            .flat_map(|p| p.feeds.iter().map(|f| f.name))
            .collect();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len);
    }

    #[test]
    fn preset_urls_are_https() {
        for p in PRESETS {
            for f in p.feeds {
                assert!(f.url.starts_with("https://"), "{} is not https", f.url);
                assert!(f.refresh_hours > 0);
                assert!(
                    f.tier == "tor"
                        || f.tier == "vpn"
                        || f.tier == "malicious"
                        || f.tier == "datacenter"
                );
            }
        }
    }

    #[test]
    fn expand_blocks_by_default_and_skips_user_defined() {
        let user = FeedConfig {
            name: "tor_exit".to_string(),
            url: "https://example.invalid/my-tor.txt".to_string(),
            ..FeedConfig::default()
        };
        let mut feeds = vec![user];
        let unknown = expand(
            &mut feeds,
            &["tor_exit".to_string(), "firehol_level1".to_string()],
        );
        assert!(unknown.is_empty());
        let tor = feeds.iter().find(|f| f.name == "tor_exit").unwrap();
        assert_eq!(tor.url, "https://example.invalid/my-tor.txt");
        assert!(tor.action.is_empty());
        let firehol = feeds.iter().find(|f| f.name == "firehol_level1").unwrap();
        assert_eq!(firehol.action, "block");
        assert_eq!(firehol.tier, "malicious");
    }

    #[test]
    fn expand_is_idempotent_and_reports_unknown() {
        let mut feeds = Vec::new();
        let enabled: Vec<String> = ["proxy_list", "nope"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(expand(&mut feeds, &enabled), vec!["nope".to_string()]);
        let count = feeds.len();
        assert_eq!(expand(&mut feeds, &enabled), vec!["nope".to_string()]);
        assert_eq!(feeds.len(), count);
        assert_eq!(feeds[0].name, "proxy_list");
        assert_eq!(feeds[0].action, "block");
    }

    #[test]
    fn open_source_vpn_preset_covers_all_provider_files() {
        let p = preset("open_source_vpn_ips").unwrap();
        assert!(p.feeds.len() >= 10);
        assert!(p
            .feeds
            .iter()
            .all(|f| f.tier == "vpn" && f.name.starts_with("vpn_")));
    }
}
