//! Profile → config artifacts: routes, packs and rules in the shapes the
//! main config uses, plus the `sentry.auto.conf` serialization.

use sentry_core::config::{RouteDefConfig, RuleDefConfig, RulePackConfig};
use sentry_core::routes_learn::normalize_routes;

use crate::FrameworkProfile;

/// Config fragments generated from detected profiles.
#[derive(Debug, Clone, Default)]
pub struct AutoArtifacts {
    /// `[[routes.known]]` entries (deduped, canonical form).
    pub routes: Vec<RouteDefConfig>,
    /// `[[rules.pack]]` entries (deduped by name; `enforce` wins over
    /// `shadow` on conflict).
    pub packs: Vec<RulePackConfig>,
    /// `[[rules.custom]]` entries (deduped by name).
    pub rules: Vec<RuleDefConfig>,
}

/// Build artifacts from one or more profiles.
pub fn from_profiles(profiles: &[FrameworkProfile]) -> AutoArtifacts {
    let route_defs: Vec<sentry_core::pipeline::RouteDef> = profiles
        .iter()
        .flat_map(|p| {
            p.routes.iter().map(|r| sentry_core::pipeline::RouteDef {
                path: r.path.clone(),
                methods: r.methods.clone(),
            })
        })
        .collect();

    let mut packs: Vec<RulePackConfig> = Vec::new();
    for profile in profiles {
        for suggestion in &profile.recommended_packs {
            match packs.iter_mut().find(|p| p.name == suggestion.name) {
                Some(existing) => {
                    if suggestion.mode == "enforce" {
                        existing.mode = "enforce".to_string();
                    }
                }
                None => packs.push(RulePackConfig {
                    name: suggestion.name.clone(),
                    mode: suggestion.mode.clone(),
                    params: Default::default(),
                }),
            }
        }
    }
    packs.sort_by(|a, b| a.name.cmp(&b.name));

    let mut rules: Vec<RuleDefConfig> = Vec::new();
    for profile in profiles {
        for suggestion in &profile.recommended_rules {
            if rules.iter().any(|r| r.name == suggestion.name) {
                continue;
            }
            rules.push(RuleDefConfig {
                name: suggestion.name.clone(),
                priority: suggestion.priority,
                r#match: suggestion.match_expr.clone(),
                action: suggestion.action.clone(),
                tags: suggestion.tags.clone(),
                log_level: None,
            });
        }
    }

    AutoArtifacts {
        routes: normalize_routes(route_defs)
            .into_iter()
            .map(|d| RouteDefConfig {
                path: d.path,
                methods: d.methods,
            })
            .collect(),
        packs,
        rules,
    }
}

impl AutoArtifacts {
    /// True when there is nothing worth writing.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.packs.is_empty() && self.rules.is_empty()
    }

    /// Serialize as `sentry.auto.conf` — only the `routes` and `rules`
    /// blocks the cascade loader merges.
    pub fn to_conf(&self) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut cfg = sentry_core::config::SentryConfig::default();
        cfg.routes.known = self.routes.clone();
        cfg.rules.packs = self.packs.clone();
        cfg.rules.custom = self.rules.clone();
        sentry_core::conf::to_text(&cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FoundRoute, PackSuggestion, RuleSuggestion};

    fn profile(name: &str, routes: Vec<FoundRoute>) -> FrameworkProfile {
        FrameworkProfile {
            framework: name.to_string(),
            routes,
            ..Default::default()
        }
    }

    #[test]
    fn merges_and_dedupes_profiles() {
        let mut profiles = vec![
            profile(
                "nginx",
                vec![
                    FoundRoute::new("/api/*", &[], "a.conf"),
                    FoundRoute::new("/", &[], "a.conf"),
                ],
            ),
            profile(
                "wordpress",
                vec![
                    FoundRoute::new("/wp-login.php", &["GET", "POST"], "stock"),
                    FoundRoute::new("/api/*", &["GET"], "stock"),
                ],
            ),
        ];
        profiles[0].recommended_packs.push(PackSuggestion {
            name: "sensitive_paths".to_string(),
            mode: "shadow".to_string(),
        });
        profiles[1].recommended_packs.push(PackSuggestion {
            name: "sensitive_paths".to_string(),
            mode: "enforce".to_string(),
        });
        profiles[1].recommended_rules.push(RuleSuggestion {
            name: "r1".to_string(),
            priority: 40,
            match_expr: r#"path = "/xmlrpc.php""#.to_string(),
            action: "block".to_string(),
            tags: vec!["auto".to_string()],
        });
        profiles[1].recommended_rules.push(RuleSuggestion {
            name: "r1".to_string(),
            priority: 40,
            match_expr: "dup".to_string(),
            action: "log".to_string(),
            tags: vec![],
        });

        let artifacts = from_profiles(&profiles);
        let paths: Vec<&str> = artifacts.routes.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, vec!["/", "/api/*", "/wp-login.php"]);
        let api = artifacts
            .routes
            .iter()
            .find(|r| r.path == "/api/*")
            .unwrap();
        assert!(api.methods.is_empty(), "any-method wins over GET");
        assert_eq!(artifacts.packs.len(), 1);
        assert_eq!(artifacts.packs[0].mode, "enforce");
        assert_eq!(artifacts.rules.len(), 1, "duplicate rule names dedupe");
    }

    #[test]
    fn conf_round_trip_through_config() {
        let mut profile = profile(
            "nginx",
            vec![
                FoundRoute::new("/admin/*", &[], "x"),
                FoundRoute::new("/health", &["GET"], "x"),
            ],
        );
        profile.recommended_packs.push(PackSuggestion {
            name: "rate_scan".to_string(),
            mode: "enforce".to_string(),
        });
        profile.recommended_rules.push(RuleSuggestion {
            name: "wp_xmlrpc_block".to_string(),
            priority: 40,
            match_expr: r#"path = "/xmlrpc.php""#.to_string(),
            action: "block".to_string(),
            tags: vec!["auto".to_string()],
        });
        let text = from_profiles(&[profile]).to_conf();

        assert!(text.contains("routes {"), "{text}");
        assert!(text.contains("\"/admin/*\": any"), "{text}");
        assert!(text.contains("rate_scan: enforce"), "{text}");
        assert!(text.contains("rule wp_xmlrpc_block {"), "{text}");

        let parsed = sentry_core::conf::from_str(&text, "sentry.auto.conf")
            .expect("generated conf loads as config fragments");
        assert_eq!(parsed.routes.known.len(), 2);
        assert_eq!(parsed.rules.packs[0].name, "rate_scan");
        assert_eq!(parsed.rules.custom[0].action, "block");
        assert_eq!(parsed.rules.custom[0].r#match, r#"path = "/xmlrpc.php""#);
    }

    #[test]
    fn empty_artifacts_serialize_to_empty_string() {
        let artifacts = from_profiles(&[]);
        assert!(artifacts.is_empty());
        assert_eq!(artifacts.to_conf(), "");
    }
}
