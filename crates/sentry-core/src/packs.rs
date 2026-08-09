//! Default rule packs: pre-built rules for common threats.
//!
//! Each pack generates [`Rule`]s that are merged into the active [`RuleSet`].
//! Packs can be in `shadow` (log only), `enforce` (act), or `off` mode.

use crate::rules::{Rule, RuleAction, RuleMatch, RuleSet, RuleSource};

/// Pack mode: `shadow` logs only, `enforce` acts, `off` disables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackMode {
    /// Log matches but don't act (shadow mode).
    Shadow,
    /// Act on matches (enforce mode).
    Enforce,
    /// Disabled.
    Off,
}

impl PackMode {
    /// Parse from a string.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => Self::Enforce,
            "shadow" => Self::Shadow,
            _ => Self::Off,
        }
    }

    /// Whether this mode produces real actions.
    pub fn is_enforce(self) -> bool {
        self == Self::Enforce
    }

    /// All known default pack names, in display order.
    pub fn all_pack_names() -> &'static [&'static str] {
        &[
            "sensitive_paths",
            "crawlers_bad",
            "crawlers_good",
            "empty_ua",
            "http_anomaly",
            "vpn_proxy",
            "tor",
            "rate_scan",
            "country_blocklist",
        ]
    }
}

/// Build the default ruleset from configured pack modes.
pub fn build_default_ruleset(pack_modes: &std::collections::HashMap<String, String>) -> RuleSet {
    let mut rules = Vec::new();

    let sp_mode = pack_modes
        .get("sensitive_paths")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Enforce);
    if sp_mode != PackMode::Off {
        rules.extend(sensitive_path_rules(sp_mode.is_enforce()));
    }

    let cb_mode = pack_modes
        .get("crawlers_bad")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if cb_mode != PackMode::Off {
        rules.extend(bad_crawler_rules(cb_mode.is_enforce()));
    }

    let cg_mode = pack_modes
        .get("crawlers_good")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Off);
    if cg_mode != PackMode::Off {
        rules.extend(good_crawler_rules(cg_mode.is_enforce()));
    }

    let eu_mode = pack_modes
        .get("empty_ua")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if eu_mode != PackMode::Off {
        rules.extend(empty_ua_rules(eu_mode.is_enforce()));
    }

    let ha_mode = pack_modes
        .get("http_anomaly")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if ha_mode != PackMode::Off {
        rules.extend(http_anomaly_rules(ha_mode.is_enforce()));
    }

    let vpn_mode = pack_modes
        .get("vpn_proxy")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if vpn_mode != PackMode::Off {
        rules.extend(vpn_proxy_rules(vpn_mode.is_enforce()));
    }

    let tor_mode = pack_modes
        .get("tor")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if tor_mode != PackMode::Off {
        rules.extend(tor_rules(tor_mode.is_enforce()));
    }

    let rs_mode = pack_modes
        .get("rate_scan")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if rs_mode != PackMode::Off {
        rules.extend(rate_scan_rules(rs_mode.is_enforce()));
    }

    let cb_mode2 = pack_modes
        .get("country_blocklist")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Off);
    if cb_mode2 != PackMode::Off {
        let countries = pack_countries(pack_modes, "country_blocklist");
        if !countries.is_empty() {
            rules.extend(country_blocklist_rules(cb_mode2.is_enforce(), &countries));
        }
    }

    RuleSet::new(rules)
}

/// Extract country codes from pack params.
fn pack_countries(
    pack_modes: &std::collections::HashMap<String, String>,
    pack_name: &str,
) -> Vec<String> {
    pack_modes
        .get(pack_name)
        .and_then(|s| {
            let mode = PackMode::parse(s);
            if mode == PackMode::Off {
                return None;
            }
            Some(())
        })
        .and_then(|_| pack_modes.get(&format!("{pack_name}__countries")).cloned())
        .map(|s| {
            s.trim_matches(|c: char| c == '[' || c == ']' || c == '"')
                .split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Sensitive path rules — block access to `.env`, `.git/`, `.ssh/`, etc.
fn sensitive_path_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    let paths: &[&str] = &[
        r"^/\.(env|git|svn|hg|bzr|ssh|aws|gcp|azure|kube|docker|terraform|npmrc|pypirc|netrc|htpasswd|ds_store)",
        r"/(wp-admin|wp-login\.php|phpmyadmin|pma|adminer|wp-content)(?:/|$)",
        r"/server-status|/server-info|/nginx-status|/fpm-status",
        r"/actuator(/env|/heapdump|/threaddump)",
        r"\.(sql|bak|backup|old|swp|orig|save)$",
        r"/manager/html$",
    ];
    let mut rules: Vec<Rule> = paths
        .iter()
        .enumerate()
        .map(|(i, pat)| Rule {
            id: format!("sensitive_path_{i}"),
            name: format!("block sensitive path ({i})"),
            priority: 5,
            enabled: true,
            match_: RuleMatch::Path {
                op: crate::rules::PathOp::Regex,
                pattern: format!("(?i){pat}"),
            },
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["sensitive_paths".into()],
            created_at: None,
        })
        .collect();

    rules.push(Rule {
        id: "sensitive_path_well_known_security".into(),
        name: "allow .well-known/security.txt (RFC 9116)".into(),
        priority: 1,
        enabled: true,
        match_: RuleMatch::Path {
            op: crate::rules::PathOp::Regex,
            pattern: r"^/\.well-known/security\.txt$".into(),
        },
        action: RuleAction::Allow,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["sensitive_paths".into(), "allowlist".into()],
        created_at: None,
    });

    rules
}

/// Bad crawler rules — block known scanner User-Agents.
///
/// The list aggregates signatures from:
/// - tryrankly.com crawler/scrapper index
/// - useragentstring.com UA database
/// - common pentesting tool UAs
fn bad_crawler_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "bad_crawler".into(),
        name: "block bad crawler/scanner UA".into(),
        priority: 10,
        enabled: true,
        match_: RuleMatch::UserAgent(crate::rules::StrOp::Regex {
            pattern: r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nessus|acunetix|dirbuster|gobuster|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|python-urllib|go-http-client|scrapy|crawler4j|semrush|ahrefs|mj12bot|dotbot|petalbot|bytespider|yandexaccessibilitybot|seznambot|dataforseobot|screaming.frog|sitechecker|siteauditbot|linkchecker|wget|curl/[0-9]|lwp-|mechanize|httpclient|okhttp|axios|got/|fetch/|node-fetch|java/|perl/|ruby|php/|lua-curl|winhttp|httprequest|scrapy-requests|httpx|subfinder|amass|theHarvester|shodan|censys|project.sonar|securitytrails|intelx\.io|censys\.io|netsparker|appscan|paros|ratproxy|w3af|skipfish|whatweb|joomscan|wpscan|droopescan|cloudflare-nginx|semrushbot|BLEXBot|BLEXBot/1\.0|bombabot|coccocbot|dotbot/1|duckduckbot|exabot|ezooms|facebot|facebookexternalhit|feedfetcher-google|googlebot|ia_archiver|icc-crawler|inversebot|ips-agent|java.*outeq|kalooga|koepa|libwww-perl|linkdex\.com|lwp-trivial|maui|mediapartners-google|meanpath|memorybot|mojeek|nejlo|netvamps|newsearch|page2rss|peach|picsearch|postrank|psyduck|purebot|pycurl|queryseekerspider|r6-commentreader|rssingbot|searchsite|seeker|semrush|seokicks|seznambot|seznambot/3\.0|showlink|simplepie|sitebot|sistrix|sogou|spbot|sputnik|surveybot|topicbot|trendictionbot|tuezilla|tweetmemebot|tweetbot|twiceler|twitterbot|universalfeedparser|urlappendbot|vagabondo|voilabot|vortex|wasalive|webcollage|webcrawler|webmon|webspider|wesee|wikiwix|wotbox|yacybot|yacy|yahooslurp|yahoo\!.slurp|yandexbot|yeti|yoofind|yoo|zao|zeal|zermelo|zeus|zibber|zitebot|zoombot|zoomspider|zoominfo|zyborg| crawly|crawl|scrap|spider|bot/|http|agent|fetch|check|monitor|scan|test|valid|analyz|index|track|survey|probe|collect|archive|validator|link|crawlbot|researchscan|preview|previewbot|content-fetcher|feedly|feedparser|inoreader|newsblur|tiny\.tiny|tinyrss|rss|atom|superfeedr|feedburner|bloglines|blogsearch|blogtrottr|blogping|weblogs|icerocket|blogument|blogosphere|blogster|blogflux|blogcatalog|blogrank|blogrolling|blogapart|blogometer|blogwise|blogburst|blogalytics|blogtactic|blogvertise|blogvertise|blogware|blogsmith|blogsmithmedia|blogomunity|blogosis|blogosurvey|blogowogo|blogpatrol|blogpulse|blogwise|blogwise|blogwise)".into(),
        }),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["crawlers_bad".into()],
        created_at: None,
    }]
}

/// Empty User-Agent rule.
fn empty_ua_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Challenge
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "empty_ua".into(),
        name: "challenge empty User-Agent".into(),
        priority: 15,
        enabled: true,
        match_: RuleMatch::UserAgent(crate::rules::StrOp::Equals {
            value: String::new(),
        }),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["empty_ua".into()],
        created_at: None,
    }]
}

/// HTTP anomaly rules — block rare methods (TRACE, CONNECT).
fn http_anomaly_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    vec![
        Rule {
            id: "http_anomaly_trace".into(),
            name: "block TRACE method".into(),
            priority: 12,
            enabled: true,
            match_: RuleMatch::Method(crate::event::HttpMethod::Trace),
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["http_anomaly".into()],
            created_at: None,
        },
        Rule {
            id: "http_anomaly_connect".into(),
            name: "block CONNECT method".into(),
            priority: 12,
            enabled: true,
            match_: RuleMatch::Method(crate::event::HttpMethod::Connect),
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["http_anomaly".into()],
            created_at: None,
        },
    ]
}

/// VPN/proxy rules — challenge IPs classified as VPN/proxy by reputation.
fn vpn_proxy_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Challenge
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "vpn_proxy".into(),
        name: "challenge VPN/proxy IPs".into(),
        priority: 20,
        enabled: true,
        match_: RuleMatch::Reputation(crate::rules::ReputationTier::VpnProxy),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["vpn_proxy".into()],
        created_at: None,
    }]
}

/// Tor exit node rules — block/challenge Tor exit nodes.
fn tor_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "tor_exit_nodes".into(),
        name: "block Tor exit nodes".into(),
        priority: 20,
        enabled: true,
        match_: RuleMatch::Reputation(crate::rules::ReputationTier::Tor),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["tor".into()],
        created_at: None,
    }]
}

/// Good crawler rules — allow known legitimate bots (Googlebot, Bingbot, etc.).
/// Verification via reverse-DNS is the app's responsibility; this just
/// allowlists by User-Agent so known-good bots bypass the pipeline.
fn good_crawler_rules(_enforce: bool) -> Vec<Rule> {
    vec![Rule {
        id: "crawlers_good".into(),
        name: "allow legitimate crawlers/bots".into(),
        priority: 2,
        enabled: true,
        match_: RuleMatch::UserAgent(crate::rules::StrOp::Regex {
            pattern: r"(?i)^(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot|LinkedInBot|Applebot|Puppeteer|WhatsApp|TelegramBot|Discordbot|SkypeUriPreview|W3C_Validator|curl/8|Go-http-client/1\.1)".into(),
        }),
        action: RuleAction::Allow,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["crawlers_good".into()],
        created_at: None,
    }]
}

/// Rate scan rules — rate-limit IPs with many 404s in a short window
/// (directory brute-force detection).
fn rate_scan_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::RateLimit
    } else {
        RuleAction::Log
    };
    vec![Rule {
        id: "rate_scan_404".into(),
        name: "rate-limit >10 404s per 60s (directory brute-force)".into(),
        priority: 15,
        enabled: true,
        match_: RuleMatch::Rate {
            count: 10,
            per_secs: 60,
            scope: crate::rules::RateScope::PerIp,
        },
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["rate_scan".into()],
        created_at: None,
    }]
}

/// Country blocklist rules — block requests from specified countries.
fn country_blocklist_rules(enforce: bool, countries: &[String]) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    let pattern = countries
        .iter()
        .map(|c| regex::escape(c))
        .collect::<Vec<_>>()
        .join("|");
    vec![Rule {
        id: "country_blocklist".into(),
        name: format!("block countries: {}", countries.join(",")),
        priority: 10,
        enabled: true,
        match_: RuleMatch::Country(pattern),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["country_blocklist".into()],
        created_at: None,
    }]
}
