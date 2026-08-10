//! Route learner: infers stable route shapes from observed HTTP events.
//!
//! The learner collapses dynamic-looking path segments (numeric ids, uuids,
//! long alphanumeric hashes) into `{id}` templates and counts how often each
//! shape is hit, by how many distinct IPs, over how many events. A shape that
//! crosses the configured thresholds (`min_hits`, `min_ips`) is reported as a
//! learned [`RouteDef`].
//!
//! This is a pure in-memory computation over a slice of events — it does not
//! touch the database. The daemon/CLI calls [`RouteLearner::learn`] on recent
//! events (from Postgres) and then persists the inferred routes via
//! `RouteRepo::insert`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::event::Event;
use crate::pipeline::RouteDef;

/// Configuration for a learning pass.
#[derive(Debug, Clone)]
pub struct LearnOptions {
    /// Minimum total hits for a shape to be considered stable.
    pub min_hits: u32,
    /// Minimum number of distinct IPs that hit the shape.
    pub min_ips: u32,
}

impl Default for LearnOptions {
    fn default() -> Self {
        Self {
            min_hits: 10,
            min_ips: 2,
        }
    }
}

/// Learn route shapes from a slice of observed events.
///
/// Non-HTTP events are ignored. The returned routes are deduped by lowercased
/// path and sorted by path for deterministic output.
pub fn learn(events: &[Event], opts: &LearnOptions) -> Vec<RouteDef> {
    #[derive(Default)]
    struct Bucket {
        hits: u32,
        ips: BTreeSet<std::net::IpAddr>,
        methods: BTreeSet<String>,
    }

    let mut buckets: HashMap<String, Bucket> = HashMap::new();
    for evt in events {
        let Some(http) = evt.http() else { continue };
        let shape = shape_of(&http.path);
        let b = buckets.entry(shape).or_default();
        b.hits += 1;
        b.ips.insert(evt.client_ip);
        if let Some(m) = http.method {
            b.methods.insert(m.as_str().to_ascii_uppercase());
        }
    }

    let mut out: BTreeMap<String, RouteDef> = BTreeMap::new();
    for (shape, b) in buckets {
        if b.hits < opts.min_hits || (b.ips.len() as u32) < opts.min_ips {
            continue;
        }
        let methods: Vec<String> = b.methods.into_iter().collect();
        out.insert(
            shape.clone(),
            RouteDef {
                path: shape,
                methods,
            },
        );
    }
    out.into_values().collect()
}

/// Reduce a literal path to its shape template by collapsing dynamic
/// segments into `{id}`.
///
/// `/users/42/posts/7` → `/users/{id}/posts/{id}`.
/// Static segments and segments already containing `{` are left alone.
fn shape_of(path: &str) -> String {
    let mut segs: Vec<&str> = Vec::new();
    for s in path.split('/') {
        if !s.is_empty() {
            segs.push(s);
        }
    }
    let mut out: Vec<String> = Vec::with_capacity(segs.len());
    for s in segs {
        if s.starts_with('{') {
            out.push(s.to_string());
        } else if is_dynamic_segment(s) {
            out.push("{id}".to_string());
        } else {
            out.push(s.to_string());
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

fn is_dynamic_segment(s: &str) -> bool {
    if s.parse::<u64>().is_ok() {
        return true;
    }
    // UUID-like: 8-4-4-4-12 hex groups.
    if s.len() == 36
        && s.chars().filter(|c| *c == '-').count() == 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return true;
    }
    // Long opaque ids (hashes, ULIDs): alphanumeric, 16-40 chars.
    if s.len() >= 16 && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpData, HttpMethod, ProtocolData, SourceKind};
    use std::net::{IpAddr, Ipv4Addr};

    fn evt(ip: [u8; 4], method: Option<HttpMethod>, path: &str) -> Event {
        Event::new(
            SourceKind::Nginx,
            IpAddr::V4(Ipv4Addr::from(ip)),
            ProtocolData::Http(HttpData {
                path: path.to_string(),
                method,
                ..Default::default()
            }),
        )
    }

    #[test]
    fn learns_stable_shape_across_ips() {
        let events: Vec<Event> = [
            evt([1, 1, 1, 1], Some(HttpMethod::Get), "/users/1"),
            evt([1, 1, 1, 1], Some(HttpMethod::Get), "/users/2"),
            evt([2, 2, 2, 2], Some(HttpMethod::Get), "/users/3"),
            evt([3, 3, 3, 3], Some(HttpMethod::Get), "/users/4"),
            evt([1, 1, 1, 1], Some(HttpMethod::Get), "/health"),
            evt([2, 2, 2, 2], Some(HttpMethod::Get), "/health"),
            evt([3, 3, 3, 3], Some(HttpMethod::Get), "/health"),
        ]
        .into_iter()
        .collect();

        let routes = learn(
            &events,
            &LearnOptions {
                min_hits: 3,
                min_ips: 2,
            },
        );
        let paths: Vec<String> = routes.iter().map(|r| r.path.clone()).collect();
        assert!(paths.contains(&"/users/{id}".to_string()));
        assert!(paths.contains(&"/health".to_string()));
    }

    #[test]
    fn filters_low_hit_shapes() {
        let events = [
            evt([1, 1, 1, 1], Some(HttpMethod::Get), "/rare/1"),
            evt([2, 2, 2, 2], Some(HttpMethod::Get), "/rare/2"),
        ];
        let routes = learn(&events, &LearnOptions::default());
        assert!(routes.iter().all(|r| r.path != "/rare/{id}"));
    }

    #[test]
    fn filters_single_ip_scan() {
        // Same IP hitting many numeric ids — not "stable", it's a scan.
        let events: Vec<Event> = (1..20)
            .map(|i| evt([9, 9, 9, 9], Some(HttpMethod::Get), &format!("/items/{i}")))
            .collect();
        let routes = learn(&events, &LearnOptions::default());
        assert!(routes.is_empty());
    }

    #[test]
    fn preserves_existing_templates() {
        assert_eq!(shape_of("/users/{id}/posts"), "/users/{id}/posts");
    }

    #[test]
    fn collapses_uuid_segment() {
        assert_eq!(
            shape_of("/posts/550e8400-e29b-41d4-a716-446655440000"),
            "/posts/{id}"
        );
    }

    #[test]
    fn keeps_short_static_segments() {
        assert_eq!(shape_of("/api/v1/users"), "/api/v1/users");
    }

    #[test]
    fn learner_config_defaults_are_sane() {
        let c = crate::config::RouteLearnerConfig::default();
        assert!(!c.enabled, "disabled by default");
        assert!(c.interval_secs >= 30, "interval at least 30s");
        assert!(c.window_secs >= c.interval_secs, "window >= interval");
        assert!(c.min_hits >= 1);
        assert!(c.min_ips >= 1);
    }
}
