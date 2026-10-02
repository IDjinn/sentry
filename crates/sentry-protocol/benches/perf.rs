//! Criterion benchmarks for the compiled protocol validator (F9).
//!
//! Measures the compiled instruction-table path against a regex-only
//! baseline validating the same frame, plus compile time and a
//! 100-frame connection stream. Run with:
//!
//! ```bash
//! cargo bench -p sentry-protocol
//! ```

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use sentry_protocol::compile::CompileOptions;
use sentry_protocol::{Compiled, ConnectionState, ProtocolEngine, ProtocolSchema};

const GAME_SCHEMA: &str = include_str!("../tests/fixtures/game-relay.protocol.yaml");

/// Builds a valid SSO frame: [len:4][header:2][len:2]"GAME-user-3324".
fn sso_frame(ticket: &[u8]) -> Vec<u8> {
    let mut payload = (ticket.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(ticket);
    let mut out = Vec::new();
    out.extend_from_slice(&(2 + payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&400u16.to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn compiled() -> Compiled {
    let schema = ProtocolSchema::from_yaml(GAME_SCHEMA).unwrap();
    let mut compiled = Compiled::default();
    compiled.add(schema, &CompileOptions::default()).unwrap();
    compiled
}

/// Regex-only baseline for the same frame: header allowlist matched as a
/// hex-string regex, ticket shape matched with a second regex — what a
/// naive regex-based monitor would do.
fn regex_baseline(frame: &[u8]) -> bool {
    use regex::bytes::Regex;
    let header_ok = Regex::new(r"^\x01\x90$").unwrap(); // 400 big-endian
    let ticket_ok = Regex::new(r"(?s)^GAME-[a-zA-Z0-9]+-3324$").unwrap();
    if frame.len() < 8 {
        return false;
    }
    if !header_ok.is_match(&frame[4..6]) {
        return false;
    }
    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if frame.len() != 4 + declared {
        return false;
    }
    let ticket_len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
    if frame.len() != 8 + ticket_len {
        return false;
    }
    ticket_ok.is_match(&frame[8..])
}

fn bench_hotpath(c: &mut Criterion) {
    let mut group = c.benchmark_group("hotpath");
    group.sample_size(40);
    group.measurement_time(std::time::Duration::from_secs(3));

    let compiled = compiled();
    let engine = ProtocolEngine::new(compiled);
    let snapshot = engine.current();
    let proto = snapshot.for_port(14901).unwrap();
    let ticket = b"GAME-bench-runner-3324";
    let frame = sso_frame(ticket);

    group.bench_function("protocol/frame_sso", |b| {
        b.iter(|| {
            let mut s = ConnectionState::new();
            let _ = black_box(
                sentry_protocol::feed_on(black_box(proto), &mut s, black_box(&frame)).is_ok(),
            );
        })
    });

    group.bench_function("regex/frame_sso_baseline", |b| {
        b.iter(|| black_box(regex_baseline(black_box(&frame))))
    });

    group.bench_function("protocol/dispatch_unknown_header", |b| {
        b.iter(|| {
            let mut s = ConnectionState::new();
            let bad = [0u8, 0, 0, 4, 0x1F, 0x90, 0, 0];
            let _ = black_box(
                sentry_protocol::feed_on(black_box(proto), &mut s, black_box(&bad)).is_err(),
            );
        })
    });

    group.bench_function("protocol/stream_100_frames", |b| {
        b.iter(|| {
            let mut s = ConnectionState::new();
            for _ in 0..100 {
                let _ = black_box(sentry_protocol::feed_on(
                    black_box(proto),
                    &mut s,
                    black_box(&frame),
                ));
            }
        })
    });

    group.finish();
}

fn bench_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile");
    group.sample_size(40);
    group.measurement_time(std::time::Duration::from_secs(3));

    group.bench_function("protocol/compile_game_schema", |b| {
        b.iter(|| {
            let schema = ProtocolSchema::from_yaml(black_box(GAME_SCHEMA)).unwrap();
            let mut compiled = Compiled::default();
            compiled.add(schema, &CompileOptions::default()).unwrap();
            black_box(compiled);
        })
    });

    group.finish();
}

/// SIMD vs scalar comparison (F9): the `simd` feature swaps the crate's
/// internal hot paths to memchr/simdutf8; this group measures both
/// strategies side by side on realistic buffers.
fn bench_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_vs_scalar");
    group.sample_size(40);
    group.measurement_time(std::time::Duration::from_secs(3));

    // Terminator scan, as used by ReadUntil: 4 KiB run with the
    // terminator at the end (worst case for a byte-by-byte loop).
    let buf = {
        let mut b = vec![b'A'; 4096];
        b[4095] = 0x02;
        b
    };

    group.bench_function("read_until/scalar", |b| {
        b.iter(|| black_box(black_box(&buf).iter().position(|&x| x == 0x02)))
    });
    group.bench_function("read_until/simd_memchr", |b| {
        b.iter(|| black_box(memchr::memchr(0x02, black_box(&buf))))
    });

    // UTF-8 validation, as used by Decode::Utf8: 4 KiB ASCII payload.
    let text = "GAME-protocol-frame-payload-0123456789 ".repeat(96);

    group.bench_function("utf8_validate/scalar_std", |b| {
        b.iter(|| black_box(std::str::from_utf8(black_box(text.as_bytes())).is_ok()))
    });
    group.bench_function("utf8_validate/simd_simdutf8", |b| {
        b.iter(|| black_box(simdutf8::basic::from_utf8(black_box(text.as_bytes())).is_ok()))
    });

    group.finish();
}

criterion_group!(benches, bench_hotpath, bench_compile, bench_simd);
criterion_main!(benches);
