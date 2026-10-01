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
            "honeypot_paths",
            "crawlers_bad",
            "crawlers_good",
            "empty_ua",
            "http_anomaly",
            "vpn_proxy",
            "tor",
            "rate_scan",
            "country_blocklist",
            "host_allowlist",
        ]
    }
}

/// Build the default ruleset from configured pack modes.
pub fn build_default_ruleset(pack_modes: &std::collections::HashMap<String, String>) -> RuleSet {
    build_default_ruleset_with(pack_modes, false)
}

/// Build the default ruleset with bot-verification gating (F7.7): when
/// enabled, `crawlers_good` only allowlists verifiable engines
/// (Googlebot/bingbot/…) whose rDNS forward-confirmation passed; the
/// remaining UA-allowlisted clients keep the ungated rule.
pub fn build_default_ruleset_with(
    pack_modes: &std::collections::HashMap<String, String>,
    bot_verify_enabled: bool,
) -> RuleSet {
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
        rules.extend(good_crawler_rules(cg_mode.is_enforce(), bot_verify_enabled));
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
        let countries = pack_list_param(pack_modes, "country_blocklist", "countries");
        if !countries.is_empty() {
            rules.extend(country_blocklist_rules(cb_mode2.is_enforce(), &countries));
        }
    }

    let hp_mode = pack_modes
        .get("honeypot_paths")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Shadow);
    if hp_mode != PackMode::Off {
        rules.extend(honeypot_path_rules(hp_mode.is_enforce()));
    }

    let hal_mode = pack_modes
        .get("host_allowlist")
        .map(|s| PackMode::parse(s))
        .unwrap_or(PackMode::Off);
    if hal_mode != PackMode::Off {
        let domains = pack_list_param(pack_modes, "host_allowlist", "domains");
        if !domains.is_empty() {
            rules.extend(host_allowlist_rules(hal_mode.is_enforce(), &domains));
        }
    }

    RuleSet::new(rules)
}

/// Extract a list param (`<pack>__<param>`) from the pack mode map; empty
/// when the pack is off or the param is absent.
fn pack_list_param(
    pack_modes: &std::collections::HashMap<String, String>,
    pack_name: &str,
    param: &str,
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
        .and_then(|_| pack_modes.get(&format!("{pack_name}__{param}")).cloned())
        .map(|s| {
            s.trim_matches(|c: char| c == '[' || c == ']' || c == '"')
                .split(',')
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Sensitive path rules — block access to `.env`, `.git/`, `.ssh/`, admin
/// panels, and known CVE exploit probes. Patterns come from
/// [`crate::lists::SENSITIVE_PATHS`] so the pack, the heuristic, and its
/// prefilter stay in sync.
fn sensitive_path_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    let mut rules: Vec<Rule> = crate::lists::SENSITIVE_PATHS
        .iter()
        .enumerate()
        .map(|(i, p)| Rule {
            id: format!("sensitive_path_{i}"),
            name: format!("block sensitive path ({i})"),
            priority: 5,
            enabled: true,
            match_: RuleMatch::Path {
                op: crate::rules::PathOp::Regex,
                pattern: format!("(?i){}", p.pattern),
            },
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["sensitive_paths".into()],
            created_at: None,
        log_level: None,
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
        log_level: None,
    });

    rules
}

/// Honeypot path rules (nginx-honeypot `honey.conf` style) — broad bait
/// paths that are too generic to block on a real site; shadow by default.
fn honeypot_path_rules(enforce: bool) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    crate::lists::HONEYPOT_PATHS
        .iter()
        .enumerate()
        .map(|(i, pat)| Rule {
            id: format!("honeypot_path_{i}"),
            name: format!("honeypot path trap ({i})"),
            priority: 8,
            enabled: true,
            match_: RuleMatch::Path {
                op: crate::rules::PathOp::Regex,
                pattern: format!("(?i){pat}"),
            },
            action,
            ttl: None,
            source: RuleSource::DefaultPack,
            tags: vec!["honeypot_paths".into()],
            created_at: None,
        log_level: None,
        })
        .collect()
}

/// Host allowlist rules — requests whose `Host` header is not one of the
/// configured domains (including Host-less requests) are scanner/IDN
/// homograph noise hitting the bare IP; blocked when enforced.
fn host_allowlist_rules(enforce: bool, domains: &[String]) -> Vec<Rule> {
    let action = if enforce {
        RuleAction::Block
    } else {
        RuleAction::Log
    };
    let pattern = format!(
        "^(?i)(?:{})(?::\\d+)?$",
        domains
            .iter()
            .map(|d| regex::escape(d.trim()))
            .collect::<Vec<_>>()
            .join("|")
    );
    vec![Rule {
        id: "host_allowlist".into(),
        name: format!("require Host in {}", domains.join(",")),
        priority: 8,
        enabled: true,
        match_: RuleMatch::Not(Box::new(RuleMatch::Header {
            name: "host".into(),
            op: crate::rules::StrOp::Regex { pattern },
        })),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["host_allowlist".into()],
        created_at: None,
        log_level: None,
    }]
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
            pattern: r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|zmap|rustscan|unicornscan|nessus|acunetix|dirbuster|dirsearch|gobuster|feroxbuster|ffuf|wfuzz|wpscan|hydra|metasploit|burp|httrack|libwww|python-requests|python-urllib|go-http-client|scrapy|crawler4j|semrush|ahrefs|mj12bot|dotbot|petalbot|bytespider|yandexaccessibilitybot|seznambot|dataforseobot|screaming.frog|sitechecker|siteauditbot|linkchecker|nuclei|arachni|openvas|havij|commix|xsser|dalfox|gospider|hakrawler|webbandit|emailcollector|wget|curl/[0-9]|lwp-|mechanize|httpclient|okhttp|axios|got/|fetch/|node-fetch|java/|perl/|ruby|php/|lua-curl|winhttp|httprequest|scrapy-requests|httpx|subfinder|amass|theHarvester|shodan|censys|project.sonar|securitytrails|intelx\.io|censys\.io|netsparker|appscan|paros|ratproxy|w3af|skipfish|whatweb|joomscan|droopescan|cloudflare-nginx|semrushbot|BLEXBot|BLEXBot/1\.0|bombabot|coccocbot|dotbot/1|duckduckbot|exabot|ezooms|facebot|facebookexternalhit|feedfetcher-google|googlebot|ia_archiver|icc-crawler|inversebot|ips-agent|java.*outeq|kalooga|koepa|libwww-perl|linkdex\.com|lwp-trivial|maui|mediapartners-google|meanpath|memorybot|mojeek|nejlo|netvamps|newsearch|page2rss|peach|picsearch|postrank|psyduck|purebot|pycurl|queryseekerspider|r6-commentreader|rssingbot|searchsite|seeker|semrushbot|seokicks|seznambot|seznambot/3\.0|showlink|simplepie|sitebot|sistrix|sogou|spbot|sputnik|surveybot|topicbot|trendictionbot|tuezilla|tweetmemebot|tweetbot|twiceler|twitterbot|universalfeedparser|urlappendbot|vagabondo|voilabot|vortex|wasalive|webcollage|webcrawler|webmon|webspider|wesee|wikiwix|wotbox|yacybot|yacy|yahooslurp|yahoo\!.slurp|yandexbot|yeti|yoofind|yoo|zao|zeal|zermelo|zeus|zibber|zitebot|zoombot|zoomspider|zoominfo|zyborg| crawly|crawl|scrap|spider|bot/|http|agent|fetch|check|monitor|scan|test|valid|analyz|index|track|survey|probe|collect|archive|validator|link|crawlbot|researchscan|preview|previewbot|content-fetcher|feedly|feedparser|inoreader|newsblur|tiny\.tiny|tinyrss|rss|atom|superfeedr|feedburner|bloglines|blogsearch|blogtrottr|blogping|weblogs|icerocket|blogument|blogosphere|blogster|blogflux|blogcatalog|blogrank|blogrolling|blogapart|blogometer|blogwise|blogburst|blogalytics|blogtactic|blogvertise|blogware|blogsmith|blogsmithmedia|blogomunity|blogosis|blogosurvey|blogowogo|blogpatrol|blogpulse)".into(),
        }),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["crawlers_bad".into()],
        created_at: None,
        log_level: None,
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
        log_level: None,
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
        log_level: None,
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
        log_level: None,
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
        log_level: None,
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
        log_level: None,
    }]
}

/// Good crawler rules — allow known legitimate bots (Googlebot, Bingbot, etc.).
/// Verification via reverse-DNS is the app's responsibility; this just
/// allowlists by User-Agent so known-good bots bypass the pipeline.
///
/// With `bot_verify` (F7.7) the verifiable engines additionally require a
/// passing `bot_verified` condition (rDNS forward-confirmation), and the
/// unverifiable remainder keeps a plain UA rule so enabling verification
/// doesn't silently revoke their allow.
fn good_crawler_rules(_enforce: bool, bot_verify: bool) -> Vec<Rule> {
    const VERIFIABLE: &str = r"(?i)^(Googlebot|Bingbot|Slurp|Baiduspider|YandexBot)";
    const UNVERIFIABLE: &str = r"(?i)^(DuckDuckBot|facebookexternalhit|Twitterbot|LinkedInBot|Applebot|Puppeteer|WhatsApp|TelegramBot|Discordbot|SkypeUriPreview|W3C_Validator|curl/8|Go-http-client/1\.1)";
    let ua_rule = |id: &str, pattern: &str, priority: i32, gate: Option<RuleMatch>| Rule {
        id: id.into(),
        name: format!("allow legitimate crawlers/bots ({id})"),
        priority,
        enabled: true,
        match_: match gate {
            Some(extra) => RuleMatch::All(vec![
                RuleMatch::UserAgent(crate::rules::StrOp::Regex {
                    pattern: pattern.into(),
                }),
                extra,
            ]),
            None => RuleMatch::UserAgent(crate::rules::StrOp::Regex {
                pattern: pattern.into(),
            }),
        },
        action: RuleAction::Allow,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["crawlers_good".into()],
        created_at: None,
        log_level: None,
    };

    if bot_verify {
        vec![
            ua_rule(
                "crawlers_good_verified",
                VERIFIABLE,
                2,
                Some(RuleMatch::BotVerified("true".into())),
            ),
            ua_rule("crawlers_good_unverified_ok", UNVERIFIABLE, 3, None),
        ]
    } else {
        vec![ua_rule(
            "crawlers_good",
            r"(?i)^(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot|LinkedInBot|Applebot|Puppeteer|WhatsApp|TelegramBot|Discordbot|SkypeUriPreview|W3C_Validator|curl/8|Go-http-client/1\.1)",
            2,
            None,
        )]
    }
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
        match_: RuleMatch::All(vec![
            RuleMatch::Status(404),
            RuleMatch::Rate {
                count: 10,
                per_secs: 60,
                scope: crate::rules::RateScope::PerIp,
            },
        ]),
        action,
        ttl: None,
        source: RuleSource::DefaultPack,
        tags: vec!["rate_scan".into()],
        created_at: None,
        log_level: None,
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
        log_level: None,
    }]
}
