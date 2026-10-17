//! Pure helpers backing the live HTTP probe. The fetching itself lives in
//! sentry-cli (`sentry_cli::auto`) — this module only turns probe artifacts
//! (robots.txt, sitemaps, status codes) into route candidates.

/// `robots.txt` facts relevant to the probe: declared paths and sitemap
/// URLs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Robots {
    /// `Allow:` / `Disallow:` paths (the site's own route inventory).
    pub paths: Vec<String>,
    /// Absolute `Sitemap:` URLs.
    pub sitemaps: Vec<String>,
}

/// Parse robots.txt (tolerant): keys are case-insensitive, comments are
/// stripped, an empty `Disallow:` (allow-everything) is ignored.
pub fn parse_robots(text: &str) -> Robots {
    let mut out = Robots::default();
    for line in text.lines() {
        let line = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        }
        .trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "allow" | "disallow" => {
                if value != "*" {
                    out.paths.push(value.to_string());
                }
            }
            "sitemap" => out.sitemaps.push(value.to_string()),
            _ => {}
        }
    }
    out
}

/// Extract `<loc>…</loc>` URLs from a sitemap (plain or index — the caller
/// decides whether a child URL should be fetched recursively).
pub fn parse_sitemap(text: &str) -> Vec<String> {
    static LOC_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?is)<loc>\s*(.*?)\s*</loc>").expect("valid regex")
    });
    LOC_RE
        .captures_iter(text)
        .filter_map(|c| {
            let url = c.get(1)?.as_str().trim();
            (!url.is_empty()).then(|| url.to_string())
        })
        .collect()
}

/// Reduce an absolute URL to its path part (query/fragment dropped,
/// leading slash guaranteed).
pub fn url_path(url: &str) -> String {
    let no_proto = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => url,
    };
    let path = match no_proto.find('/') {
        Some(idx) => &no_proto[idx..],
        None => "/",
    };
    let path = path.split(['?', '#']).next().unwrap_or("/");
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// A probe answer counts as an existing route unless the server says the
/// path is definitively absent.
pub fn status_is_route(status: u16) -> bool {
    status != 404 && status != 410
}

/// A random path probed before the real candidates: when it answers with
/// anything other than 404/410 the server has a catch-all (SPA fallback),
/// and every hit matching its (status, body length) signature is noise.
pub type Hit = (String, u16, usize);

/// Drop catch-all noise from probe hits (see the type docs). The sentinel
/// itself is never a route.
pub fn filter_catch_all(sentinel: Option<(u16, usize)>, hits: Vec<Hit>) -> Vec<String> {
    hits.into_iter()
        .filter(|(_, status, len)| Some((*status, *len)) != sentinel)
        .map(|(path, _, _)| path)
        .collect()
}

/// Common paths probed on a live host, curated for breadth (frameworks,
/// admin panels, APIs, metadata). Ordered by likelihood so a truncated run
/// keeps the interesting ones.
pub const COMMON_PATHS: &[&str] = &[
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/admin",
    "/admin/login",
    "/administrator/",
    "/api",
    "/api/v1",
    "/api/health",
    "/health",
    "/healthz",
    "/status",
    "/login",
    "/logout",
    "/signin",
    "/signup",
    "/register",
    "/dashboard",
    "/account",
    "/profile",
    "/settings",
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/admin-ajax.php",
    "/xmlrpc.php",
    "/wp-json/",
    "/user/login",
    "/users/sign_in",
    "/accounts/login",
    "/auth/login",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/graphql",
    "/graphiql",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/actuator/health",
    "/actuator",
    "/metrics",
    "/debug",
    "/console",
    "/phpmyadmin/",
    "/adminer.php",
    "/server-status",
    "/info.php",
    "/feed",
    "/rss",
    "/sitemap_index.xml",
    "/static/",
    "/assets/",
    "/cdn-cgi/trace",
];

/// Where live APIs commonly publish their OpenAPI/Swagger document
/// (FastAPI, Spring, .NET, NestJS, Rails/rswag, plain static files). A hit
/// only counts when the body parses as a spec, so SPA fallbacks are inert.
pub const SPEC_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/api-docs/swagger.json",
];

/// Extra paths a forced profile contributes to the probe list.
pub fn profile_paths(name: &str) -> &'static [&'static str] {
    match name {
        "wordpress" => &[
            "/wp-login.php",
            "/wp-admin/",
            "/wp-admin/admin-ajax.php",
            "/xmlrpc.php",
            "/wp-json/",
            "/wp-content/debug.log",
        ],
        "laravel" => &[
            "/api",
            "/telescope",
            "/horizon",
            "/storage/logs/laravel.log",
        ],
        "nextjs" => &["/_next/static/", "/api/health"],
        "express" => &["/graphql", "/static/"],
        "react" => &["/assets/", "/static/js/"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn robots_extracts_paths_and_sitemaps() {
        let robots = parse_robots(
            "# comment\nUser-agent: *\nDisallow: /admin/\nAllow: /public/\nSitemap: https://x.io/sitemap.xml\nDisallow:\n",
        );
        assert_eq!(robots.paths, vec!["/admin/", "/public/"]);
        assert_eq!(robots.sitemaps, vec!["https://x.io/sitemap.xml"]);
    }

    #[test]
    fn sitemap_locs_case_insensitive() {
        let locs = parse_sitemap(
            r#"<urlset xmlns="x"><URL><LOC> https://x.io/a </LOC></URL><url><loc>https://x.io/b?q=1</loc></url></urlset>"#,
        );
        assert_eq!(locs, vec!["https://x.io/a", "https://x.io/b?q=1"]);
    }

    #[test]
    fn url_path_strips_host_query_fragment() {
        assert_eq!(url_path("https://x.io:8443/a/b?q=1#f"), "/a/b");
        assert_eq!(url_path("https://x.io"), "/");
        assert_eq!(url_path("/relative"), "/relative");
    }

    #[test]
    fn statuses() {
        assert!(status_is_route(200));
        assert!(status_is_route(403));
        assert!(status_is_route(500));
        assert!(!status_is_route(404));
        assert!(!status_is_route(410));
    }

    #[test]
    fn catch_all_signature_filters_noise() {
        let hits = vec![
            ("/real".to_string(), 200u16, 100usize),
            ("/spa-noise".to_string(), 200u16, 100usize),
            ("/differs".to_string(), 403u16, 0usize),
        ];
        let kept = filter_catch_all(Some((200, 100)), hits.clone());
        assert_eq!(kept, vec!["/differs"]);
        let all = filter_catch_all(None, hits);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn common_paths_have_leading_slash() {
        assert!(COMMON_PATHS.iter().all(|p| p.starts_with('/')));
        assert!(COMMON_PATHS.len() >= 50);
        assert!(SPEC_PATHS.iter().all(|p| p.starts_with('/')));
    }
}
