//! Native security-header injection (F16).
//!
//! The inline edge adds the hardening headers an origin forgot (HSTS, CSP,
//! frame/sniff/referrer/permissions/cross-origin policies) and strips
//! information-disclosure headers (`Server`, `X-Powered-By`, …), so a site
//! is protected without relying on nginx or a CDN. This module is pure: it
//! compiles the config into a rule list and, given what a response already
//! carries, plans which headers to add. The edge applies the plan.

use crate::config::EdgeSecurityHeadersConfig;

/// Which responses a header applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Every response (assets, redirects, API replies).
    All,
    /// HTML documents only — meaningless (and bloat) on assets.
    Document,
}

#[derive(Debug, Clone)]
struct Rule {
    name: &'static str,
    value: String,
    scope: Scope,
    secure_only: bool,
}

/// One planned header write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderWrite {
    /// Lowercase header name.
    pub name: &'static str,
    /// Header value.
    pub value: String,
}

/// Compiled injector, built once at startup.
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    rules: Vec<Rule>,
    strip: Vec<String>,
    override_origin: bool,
    upgrade_insecure: bool,
}

impl SecurityHeaders {
    /// Compile the config; `None` when disabled or nothing would be done.
    pub fn from_config(cfg: &EdgeSecurityHeadersConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let mut rules = Vec::new();
        let mut add = |name: &'static str, value: &str, scope: Scope, secure_only: bool| {
            if let Some(v) = active(value) {
                rules.push(Rule {
                    name,
                    value: v,
                    scope,
                    secure_only,
                });
            }
        };
        add("strict-transport-security", &cfg.hsts, Scope::All, true);
        add(
            "content-security-policy",
            &cfg.content_security_policy,
            Scope::Document,
            false,
        );
        add(
            "x-frame-options",
            &cfg.x_frame_options,
            Scope::Document,
            false,
        );
        add(
            "x-content-type-options",
            &cfg.x_content_type_options,
            Scope::All,
            false,
        );
        add(
            "referrer-policy",
            &cfg.referrer_policy,
            Scope::Document,
            false,
        );
        add(
            "permissions-policy",
            &cfg.permissions_policy,
            Scope::Document,
            false,
        );
        add(
            "x-xss-protection",
            &cfg.x_xss_protection,
            Scope::Document,
            false,
        );
        add(
            "cross-origin-opener-policy",
            &cfg.cross_origin_opener_policy,
            Scope::Document,
            false,
        );
        add(
            "cross-origin-resource-policy",
            &cfg.cross_origin_resource_policy,
            Scope::All,
            false,
        );
        add(
            "cross-origin-embedder-policy",
            &cfg.cross_origin_embedder_policy,
            Scope::Document,
            false,
        );
        let strip: Vec<String> = cfg
            .strip
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        if rules.is_empty() && strip.is_empty() {
            return None;
        }
        Some(Self {
            rules,
            strip,
            override_origin: cfg.override_origin,
            upgrade_insecure: cfg.upgrade_insecure_requests,
        })
    }

    /// Headers to remove from the response (lowercase).
    pub fn strip(&self) -> &[String] {
        &self.strip
    }

    /// Plan the header writes for one response. `has` reports whether the
    /// response already carries a header (lowercase name); `is_document` is
    /// true for HTML; `secure` is true on HTTPS (HSTS and
    /// `upgrade-insecure-requests` are HTTPS-only).
    pub fn plan<F>(&self, has: F, is_document: bool, secure: bool) -> Vec<HeaderWrite>
    where
        F: Fn(&str) -> bool,
    {
        let mut out = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            if rule.scope == Scope::Document && !is_document {
                continue;
            }
            if rule.secure_only && !secure {
                continue;
            }
            if !self.override_origin && has(rule.name) {
                continue;
            }
            let mut value = rule.value.clone();
            if rule.name == "content-security-policy"
                && secure
                && self.upgrade_insecure
                && !value.contains("upgrade-insecure-requests")
            {
                value.push_str("; upgrade-insecure-requests");
            }
            out.push(HeaderWrite {
                name: rule.name,
                value,
            });
        }
        out
    }
}

/// Whether a `Content-Type` value is an HTML document.
pub fn is_html(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    let mime = ct.split(';').next().unwrap_or_default().trim();
    mime.eq_ignore_ascii_case("text/html") || mime.eq_ignore_ascii_case("application/xhtml+xml")
}

fn active(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("off") {
        None
    } else {
        Some(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> SecurityHeaders {
        SecurityHeaders::from_config(&EdgeSecurityHeadersConfig::default()).unwrap()
    }

    fn names(plan: &[HeaderWrite]) -> Vec<&'static str> {
        plan.iter().map(|w| w.name).collect()
    }

    #[test]
    fn disabled_config_yields_none() {
        let cfg = EdgeSecurityHeadersConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(SecurityHeaders::from_config(&cfg).is_none());
    }

    #[test]
    fn html_over_https_gets_the_full_set_except_coep() {
        let plan = sh().plan(|_| false, true, true);
        let n = names(&plan);
        for h in [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
        ] {
            assert!(n.contains(&h), "missing {h}");
        }
        assert!(
            !n.contains(&"cross-origin-embedder-policy"),
            "coep is opt-in"
        );
    }

    #[test]
    fn hsts_and_upgrade_insecure_are_https_only() {
        let plan = sh().plan(|_| false, true, false);
        assert!(!names(&plan).contains(&"strict-transport-security"));
        let csp = plan
            .iter()
            .find(|w| w.name == "content-security-policy")
            .unwrap();
        assert!(!csp.value.contains("upgrade-insecure-requests"));
        let secure = sh().plan(|_| false, true, true);
        let csp = secure
            .iter()
            .find(|w| w.name == "content-security-policy")
            .unwrap();
        assert!(csp.value.ends_with("; upgrade-insecure-requests"));
    }

    #[test]
    fn assets_only_get_all_scope_headers() {
        let n = names(&sh().plan(|_| false, false, true));
        assert_eq!(
            n,
            vec![
                "strict-transport-security",
                "x-content-type-options",
                "cross-origin-resource-policy"
            ]
        );
    }

    #[test]
    fn origin_headers_are_respected_unless_override() {
        let has = |n: &str| n == "x-frame-options" || n == "content-security-policy";
        let n = names(&sh().plan(has, true, true));
        assert!(!n.contains(&"x-frame-options"));
        assert!(!n.contains(&"content-security-policy"));
        let cfg = EdgeSecurityHeadersConfig {
            override_origin: true,
            ..Default::default()
        };
        let forced = SecurityHeaders::from_config(&cfg).unwrap();
        assert!(names(&forced.plan(has, true, true)).contains(&"x-frame-options"));
    }

    #[test]
    fn off_disables_individual_headers_and_strip_is_normalized() {
        let cfg = EdgeSecurityHeadersConfig {
            x_frame_options: "off".into(),
            referrer_policy: " ".into(),
            cross_origin_embedder_policy: "credentialless".into(),
            strip: vec![" Server ".into(), "".into()],
            ..Default::default()
        };
        let s = SecurityHeaders::from_config(&cfg).unwrap();
        let n = names(&s.plan(|_| false, true, true));
        assert!(!n.contains(&"x-frame-options"));
        assert!(!n.contains(&"referrer-policy"));
        assert!(n.contains(&"cross-origin-embedder-policy"));
        assert_eq!(s.strip(), ["server".to_string()]);
    }

    #[test]
    fn default_strip_covers_disclosure_headers() {
        let s = sh();
        for h in ["server", "x-powered-by"] {
            assert!(s.strip().iter().any(|x| x == h));
        }
    }

    #[test]
    fn html_detection() {
        assert!(is_html(Some("text/html; charset=utf-8")));
        assert!(is_html(Some("Application/XHTML+xml")));
        assert!(!is_html(Some("application/json")));
        assert!(!is_html(None));
    }
}
