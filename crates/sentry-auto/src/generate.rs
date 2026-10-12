//! Profile → config artifacts: routes, packs and rules in the shapes the
//! main config uses, plus the `sentry.auto.toml` serialization.

use sentry_core::config::{RouteDefConfig, RuleDefConfig, RulePackConfig};
use sentry_core::routes_learn::normalize_routes;
use serde::Serialize;

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

    /// Serialize as `sentry.auto.toml` — only the `routes` and `rules`
    /// sections the cascade loader merges. Empty fields are omitted so the
    /// generated file stays reviewable.
    pub fn to_toml(&self) -> String {
        #[derive(Serialize)]
        struct RouteOut<'a> {
            path: &'a str,
            #[serde(skip_serializing_if = "slice_is_empty")]
            methods: &'a [String],
        }
        #[derive(Serialize)]
        struct PackOut<'a> {
            name: &'a str,
            mode: &'a str,
            #[serde(skip_serializing_if = "params_is_empty")]
            params: &'a std::collections::HashMap<String, toml::Value>,
        }
        #[derive(Serialize)]
        struct RuleOut<'a> {
            name: &'a str,
            priority: i32,
            r#match: &'a str,
            action: &'a str,
            #[serde(skip_serializing_if = "slice_is_empty")]
            tags: &'a [String],
        }
        #[derive(Serialize)]
        struct RoutesSection<'a> {
            known: Vec<RouteOut<'a>>,
        }
        #[derive(Serialize)]
        struct RulesSection<'a> {
            #[serde(rename = "pack", skip_serializing_if = "Vec::is_empty")]
            packs: Vec<PackOut<'a>>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            custom: Vec<RuleOut<'a>>,
        }
        #[derive(Serialize)]
        struct AutoToml<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            routes: Option<RoutesSection<'a>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            rules: Option<RulesSection<'a>>,
        }
        let file = AutoToml {
            routes: (!self.routes.is_empty()).then(|| RoutesSection {
                known: self
                    .routes
                    .iter()
                    .map(|r| RouteOut {
                        path: &r.path,
                        methods: &r.methods,
                    })
                    .collect(),
            }),
            rules: (!self.packs.is_empty() || !self.rules.is_empty()).then(|| RulesSection {
                packs: self
                    .packs
                    .iter()
                    .map(|p| PackOut {
                        name: &p.name,
                        mode: &p.mode,
                        params: &p.params,
                    })
                    .collect(),
                custom: self
                    .rules
                    .iter()
                    .map(|r| RuleOut {
                        name: &r.name,
                        priority: r.priority,
                        r#match: &r.r#match,
                        action: &r.action,
                        tags: &r.tags,
                    })
                    .collect(),
            }),
        };
        toml::to_string_pretty(&file).unwrap_or_default()
    }
}

fn params_is_empty(map: &std::collections::HashMap<String, toml::Value>) -> bool {
    map.is_empty()
}

fn slice_is_empty(slice: &&[String]) -> bool {
    slice.is_empty()
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
    fn toml_round_trip_through_config() {
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
        let toml_text = from_profiles(&[profile]).to_toml();

        assert!(toml_text.contains("[[routes.known]]"));
        assert!(toml_text.contains("path = \"/admin/*\""));
        assert!(toml_text.contains("[[rules.pack]]"));
        assert!(toml_text.contains("name = \"rate_scan\""));
        assert!(toml_text.contains("[[rules.custom]]"));
        assert!(toml_text.contains("path = \"/xmlrpc.php\""));

        let parsed: sentry_core::config::SentryConfig =
            toml::from_str(&toml_text).expect("generated TOML loads as config fragments");
        assert_eq!(parsed.routes.known.len(), 2);
        assert_eq!(parsed.rules.packs[0].name, "rate_scan");
        assert_eq!(parsed.rules.custom[0].action, "block");
    }

    #[test]
    fn empty_artifacts_serialize_to_empty_string() {
        let artifacts = from_profiles(&[]);
        assert!(artifacts.is_empty());
        assert_eq!(artifacts.to_toml(), "");
    }
}
