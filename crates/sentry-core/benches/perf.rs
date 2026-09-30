//! Hot-path benchmarks (F5): heuristics, rules engine and the full pipeline.
//!
//! Run with `cargo bench -p sentry-core`. Baselines live in
//! ARCHITECTURE.md §21 before/after each optimization round.

use std::net::{IpAddr, Ipv4Addr};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use sentry_core::event::{Event, HttpData, ProtocolData, SourceKind};
use sentry_core::pipeline::{Pipeline, RouteValidator};

fn evt(path: &str, ua: &str) -> Event {
    Event::new(
        SourceKind::Synthetic,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        ProtocolData::Http(HttpData {
            path: path.to_string(),
            query: Some("page=2&sort=desc".to_string()),
            user_agent: Some(ua.to_string()),
            ..Default::default()
        }),
    )
}

fn attack_evt() -> Event {
    evt(
        "/login?id=1'+OR+1=1--&file=../../../etc/passwd",
        "sqlmap/1.5",
    )
}

fn clean_evt() -> Event {
    evt("/api/users/42", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
}

fn bench(c: &mut Criterion) {
    let engine = sentry_core::heuristics::HeuristicEngine::with_defaults();
    let ruleset = sentry_core::packs::build_default_ruleset(&Default::default());
    let pipeline = Pipeline::new(
        sentry_core::packs::build_default_ruleset(&Default::default()),
        RouteValidator::new(Vec::new()),
    );
    let clean = clean_evt();
    let attack = attack_evt();

    let mut g = c.benchmark_group("hotpath");
    g.sample_size(40);
    g.measurement_time(std::time::Duration::from_secs(3));

    g.bench_with_input(BenchmarkId::new("heuristics", "clean"), &clean, |b, e| {
        b.iter(|| engine.analyze(e))
    });
    g.bench_with_input(BenchmarkId::new("heuristics", "attack"), &attack, |b, e| {
        b.iter(|| engine.analyze(e))
    });
    g.bench_with_input(BenchmarkId::new("rules", "clean"), &clean, |b, e| {
        b.iter(|| ruleset.evaluate(e))
    });
    g.bench_with_input(BenchmarkId::new("pipeline", "clean"), &clean, |b, e| {
        b.iter(|| pipeline.process(e))
    });
    g.bench_with_input(BenchmarkId::new("pipeline", "attack"), &attack, |b, e| {
        b.iter(|| pipeline.process(e))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
