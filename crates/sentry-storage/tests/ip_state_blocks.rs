//! Regression: INET columns must come back as bare addresses.
//!
//! `ip::text` on an INET column renders CIDR notation (`203.0.113.7/32`),
//! which `IpAddr::from_str` rejects — every consumer that parses the value
//! (block-table pre-warm, hot-reload, offender memory) silently dropped all
//! rows. The repo selects through `host()` instead; these tests pin that.

use std::net::IpAddr;

use sentry_storage::Repo;

fn pg_url() -> Option<String> {
    std::env::var("SENTRY_STORAGE__POSTGRES__URL")
        .ok()
        .filter(|u| !u.is_empty())
}

#[tokio::test]
async fn blocked_rows_are_bare_addresses() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: SENTRY_STORAGE__POSTGRES__URL is not set");
        return;
    };
    let pool = sentry_storage::PgPool::connect_lazy(&url).unwrap();
    sentry_storage::migrations::run(&pool).await.unwrap();
    let repo = Repo::new(pool);

    let ip: IpAddr = "203.0.113.190".parse().unwrap();
    repo.ip_state().unblock(ip).await.ok();

    repo.ip_state().block(ip, Some("test"), None).await.unwrap();
    let rows = repo.ip_state().blocked(10_000).await.unwrap();
    let row = rows
        .iter()
        .find(|r| r.ip.starts_with("203.0.113.190"))
        .expect("blocked row must be present");
    let parsed: IpAddr = row
        .ip
        .parse()
        .expect("ip must be a bare address, not CIDR notation");
    assert_eq!(parsed, ip);
    assert!(row.expires_at.is_none(), "permanent block roundtrips");

    repo.ip_state()
        .block(
            ip,
            Some("test"),
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .await
        .unwrap();
    let rows = repo.ip_state().blocked(10_000).await.unwrap();
    let row = rows
        .iter()
        .find(|r| r.ip.starts_with("203.0.113.190"))
        .expect("re-blocked row must be present");
    assert!(row.expires_at.is_some(), "re-block refreshes expiry");
    assert!(row.ip.parse::<IpAddr>().is_ok());

    repo.ip_state().unblock(ip).await.unwrap();
}

#[tokio::test]
async fn offender_rows_are_bare_addresses() {
    let Some(url) = pg_url() else {
        eprintln!("skipping: SENTRY_STORAGE__POSTGRES__URL is not set");
        return;
    };
    let pool = sentry_storage::PgPool::connect_lazy(&url).unwrap();
    sentry_storage::migrations::run(&pool).await.unwrap();
    let repo = Repo::new(pool);

    let ip: IpAddr = "203.0.113.191".parse().unwrap();
    let recorded = repo.ip_state().record_violation(ip, 60).await.unwrap();
    assert!(recorded.ip.parse::<IpAddr>().is_ok());
    if let Some(row) = repo.ip_state().offender(ip).await.unwrap() {
        let parsed: IpAddr = row
            .ip
            .parse()
            .expect("offender ip must be a bare address, not CIDR notation");
        assert_eq!(parsed, ip);
    }
    repo.ip_state().unblock(ip).await.unwrap();
}
