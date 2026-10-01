//! Shared suspicious-content lists.
//!
//! Single source of truth for the path lists consumed by both the rule
//! packs ([`crate::packs`]) and the heuristics engine
//! ([`crate::heuristics`]): adding a pattern here updates the pack rules,
//! the heuristic regex, and its Aho-Corasick prefilter literals together.
//!
//! Sources: the local decoy deployment,
//! [nginx-honeypot](https://github.com/dvershinin/nginx-honeypot)
//! (`honey.conf`) and
//! [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker).

/// A sensitive-path regex fragment plus the prefilter literals its
/// alternation branches contain.
///
/// The `SensitivePath` heuristic is gated by the Aho-Corasick prefilter
/// (F5): the family regex only runs when one of the family's literals
/// appears in the scanned text. Every branch of `pattern` must therefore
/// contain at least one of `literals`, or that branch silently stops
/// matching. The structural test in this module anchors each literal to the
/// pattern text; the heuristic corpus covers every branch end to end.
#[derive(Debug)]
pub struct PathPattern {
    /// Regex fragment; consumers wrap it with `(?i)`.
    pub pattern: &'static str,
    /// Plain (lowercase) substrings the prefilter gates on.
    pub literals: &'static [&'static str],
}

/// Sensitive paths — pack `sensitive_paths` (enforce by default) and the
/// `SensitivePath` heuristic: dotfile secrets, admin panels, server status
/// endpoints, backup artifacts, and known CVE exploit probes
/// (Laravel `_ignition`, PHPUnit `eval-stdin`, Exchange Autodiscover/ECP,
/// MobileIron MIFS, Telerik WebResource, GPON/Fortinet/D-Link appliance
/// panels).
pub const SENSITIVE_PATHS: &[PathPattern] = &[
    PathPattern {
        pattern: r"^/\.(env|git|svn|hg|bzr|ssh|aws|gcp|azure|kube|docker|terraform|npmrc|pypirc|netrc|htpasswd|ds_store)",
        literals: &["/."],
    },
    PathPattern {
        pattern: r"/(wp-admin|wp-login\.php|phpmyadmin|pma|adminer|wp-content)(?:/|$)",
        literals: &[
            "wp-admin",
            "wp-login",
            "phpmyadmin",
            "pma",
            "adminer",
            "wp-content",
        ],
    },
    PathPattern {
        pattern: r"/(server-status|server-info|nginx-status|fpm-status)",
        literals: &["server-status", "server-info", "nginx-status", "fpm-status"],
    },
    PathPattern {
        pattern: r"/actuator(/env|/heapdump|/threaddump)",
        literals: &["actuator"],
    },
    PathPattern {
        pattern: r"(\.sql|\.bak|\.backup|\.old|\.swp|\.orig|\.save)$",
        literals: &[".sql", ".bak", ".backup", ".old", ".swp", ".orig", ".save"],
    },
    PathPattern {
        pattern: r"/manager/html$",
        literals: &["/manager/html"],
    },
    PathPattern {
        pattern: r"_ignition/execute-solution",
        literals: &["_ignition"],
    },
    PathPattern {
        pattern: r"/autodiscover/autodiscover\.xml",
        literals: &["autodiscover"],
    },
    PathPattern {
        pattern: r"/mifs/\.;/services/logservice",
        literals: &["mifs"],
    },
    PathPattern {
        pattern: r"vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php",
        literals: &["eval-stdin"],
    },
    PathPattern {
        pattern: r"/hnap1",
        literals: &["hnap1"],
    },
    PathPattern {
        pattern: r"/remote/fgt_lang",
        literals: &["fgt_lang"],
    },
    PathPattern {
        pattern: r"/ecp/current/exporttool",
        literals: &["exporttool"],
    },
    PathPattern {
        pattern: r"/restapi/logoncustomization",
        literals: &["logoncustomization"],
    },
    PathPattern {
        pattern: r"telerik\.web\.ui\.webresource\.axd",
        literals: &["telerik.web.ui"],
    },
    PathPattern {
        pattern: r"/gponform/diag_form",
        literals: &["gponform"],
    },
    PathPattern {
        pattern: r"/wp-includes/.*\.php$",
        literals: &["wp-includes"],
    },
];

/// Honeypot paths — pack `honeypot_paths` (shadow by default): broad
/// indicators that are deliberate bait in a decoy but too generic to block
/// on a real site (any `.aspx`, any dotfile path, framework internals).
/// The pack is rules-only; it is not part of the heuristic prefilter.
pub const HONEYPOT_PATHS: &[&str] = &[
    r"\.aspx$",
    "cgi-bin",
    "node_modules",
    "/actuator/health",
    r"^/\.",
];

/// Merged case-insensitive regex for the sensitive-path family (heuristic).
pub fn sensitive_paths_regex() -> String {
    let mut re = String::from("(?i)");
    for (i, p) in SENSITIVE_PATHS.iter().enumerate() {
        if i > 0 {
            re.push('|');
        }
        re.push_str("(?:");
        re.push_str(p.pattern);
        re.push(')');
    }
    re
}

/// Prefilter literals for the sensitive-path family (one entry per
/// alternation branch across all patterns).
pub fn sensitive_path_literals() -> impl Iterator<Item = &'static str> {
    SENSITIVE_PATHS
        .iter()
        .flat_map(|p| p.literals.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// Every literal must appear in its own pattern text (backslashes
    /// stripped, lowercased) — catches typos like a literal renamed while
    /// the regex branch kept the old spelling, which would silently ungate
    /// that branch.
    #[test]
    fn literals_are_anchored_to_their_pattern() {
        for p in SENSITIVE_PATHS {
            let plain = p.pattern.replace('\\', "").to_ascii_lowercase();
            assert!(
                !p.literals.is_empty(),
                "pattern {:?} has no literals",
                p.pattern
            );
            for lit in p.literals {
                assert!(
                    plain.contains(lit),
                    "literal {lit:?} not found in pattern {:?}",
                    p.pattern
                );
            }
        }
    }

    /// The merged heuristic regex must compile and match one sample per
    /// alternation branch — the end-to-end guarantee that the pack and the
    /// heuristic stay in sync.
    #[test]
    fn merged_regex_matches_every_branch() {
        let re = Regex::new(&sensitive_paths_regex()).unwrap();
        let samples = [
            "/.env",
            "/.git/config",
            "/wp-admin/setup.php",
            "/wp-login.php",
            "/phpmyadmin/index.php",
            "/pma/",
            "/adminer",
            "/wp-content/plugins/x.php",
            "/server-status",
            "/server-info",
            "/nginx-status",
            "/fpm-status",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/threaddump",
            "/backup.sql",
            "/site.bak",
            "/db.backup",
            "/page.old",
            "/index.php.swp",
            "/file.orig",
            "/f.save",
            "/manager/html",
            "/_ignition/execute-solution",
            "/Autodiscover/Autodiscover.xml",
            "/mifs/.;/services/LogService",
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/HNAP1",
            "/remote/fgt_lang",
            "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
            "/RestAPI/LogonCustomization",
            "/Telerik.Web.UI.WebResource.axd",
            "/GponForm/diag_Form",
            "/wp-includes/js/jquery/jquery.php",
        ];
        for s in samples {
            assert!(
                re.is_match(&s.to_ascii_lowercase()),
                "merged regex missed {s:?}"
            );
        }
    }

    /// Clean paths must not match (the allowlisted RFC 9116 file above all).
    #[test]
    fn merged_regex_ignores_benign_paths() {
        let re = Regex::new(&sensitive_paths_regex()).unwrap();
        for s in [
            "/.well-known/security.txt",
            "/api/users?page=1",
            "/static/main.css",
            "/posts/my-processor-notes",
        ] {
            assert!(
                !re.is_match(&s.to_ascii_lowercase()),
                "false positive on {s:?}"
            );
        }
    }
}
