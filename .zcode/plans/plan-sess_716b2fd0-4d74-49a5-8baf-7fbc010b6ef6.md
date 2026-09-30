# F3.10 — Cross-IP scan→attack correlation + scanner taxonomy

Verified: F3.1/F3.2/F3.3/F3.6/F3.9 already exist (crates, daemon wiring, config confirmed in code) — out of scope, except ticking their stale BACKLOG.md boxes. Everything below implements F3.10 (BACKLOG.md:75), which has zero existing implementation.

## A. New correlation tracker — `crates/sentry-core/src/correlation.rs` (new module)

`CorrelationTracker`, modeled exactly on `ScanTracker` (scan.rs:37–110: `from_config`, explicit-arg `new`, `Arc<RwLock<>>` held by Pipeline, `prune()`):

- State: `by_prefix: HashMap<IpAddr, Vec<ScanEntry>>` (v4 masked /24, v6 masked /64 — masking pattern from `mask_v4`/`mask_v6`, reputation.rs:123–137) and `by_asn: HashMap<u32, Vec<ScanEntry>>`. `ScanEntry { scanner: IpAddr, at: Instant, label: String }` (label: "masscan"/"zmap"/"nmap" from `tcpfp::scanner_name`, "http-404-scan" for RandomScan/ScanBehavior).
- API: `record_scan(scanner, asn, label)` (pushes to both maps; per-key cap 64, drop-oldest like other trackers); `correlate(attacker, asn) -> Option<CorrelationHit>` — most recent entry **from a different IP** within the window; prefix match wins over ASN match; `prune()`.
- Explicit classification helpers (variants verified against analysis.rs:91–152 at implementation time): `is_scan_signal` → {RandomScan, ScanBehavior, TcpScanner}; `is_attack_signal` → {SQLi, XSS, PathTraversal, LFI, Log4Shell, CmdInjection, SensitivePath, AuthBruteForce, CredentialStuffing, DirectoryBruteForce, SuspiciousLoginSuccess, LlmMalicious}.

## B. Config — `crates/sentry-core/src/config.rs` + lib.rs re-export

`CorrelationConfig` mirroring `ScanConfig` (config.rs:329–367, same serde/default/impl-Default pattern; `enabled` default mirrors ScanConfig's): `enabled`, `window_secs` (default 900 = 15 min). Field `#[serde(default)] pub correlation` on `SentryConfig` next to `scan`/`behavior`; re-export in lib.rs. Example section in `config/sentry.example.toml` near `[scan]`, plus a commented `[[rules.feeds]]` promiscuous-scanners example (`tier = "promiscuous"`).

## C. Pipeline — `crates/sentry-core/src/pipeline.rs`

- New `SignalKind::ScanAttackCorrelation` (analysis.rs) with `pub const SCAN_ATTACK_CORRELATION_WEIGHT: u8 = 20` in correlation.rs; add `"scan_attack_correlation"` arms to **both** `weight_for` (523–559) and `weight_for_signal` (563–593) so `[scorer.weights]` overrides work.
- Field `correlation: Option<Arc<RwLock<CorrelationTracker>>>` + chained builder `with_correlation_tracker` (pattern of `with_scan_tracker`, 388).
- In `process()`, after the behavior block (~472) and **before** repetition bonus/scoring: lock tracker, `record_scan` for each scan signal present, and if any attack signal is present call `correlate` → push `Signal { kind: ScanAttackCorrelation, weight from weight_for, detail: "<label> from <scanner_ip> (same /24|/64|ASN) Ns ago" }`. Takes the whole `&Event` (uses `evt.client_ip`, `evt.asn`) so TCP SYN scans correlate too — unlike the HTTP-only trackers.

## D. Scanner taxonomy — `crates/sentry-core/src/rules.rs` + reputation.rs

- `ReputationTier`: add `Authorized` and `Promiscuous` variants + `parse()` aliases ("authorized", "promiscuous"). Grep ALL `ReputationTier` match/serialization sites and update exhaustively: `parse` (rules.rs:471–487), DSL matcher (rules.rs:612–616), `reputation_signals` (reputation.rs:177–196), siem.rs, serde attrs, any dashboard payload code — compiler + clippy `-D warnings` will police non-wildcard matches.
- `reputation_signals`: `Promiscuous` → new `SignalKind::PromiscuousScanner` (`PROMISCUOUS_SCANNER_WEIGHT: u8 = 10`, key `"promiscuous_scanner"` in both weight maps — scanner that publishes recon for anyone is not benign); `Authorized` → no signal (trusted; users can write a DSL Allow rule on `reputation = "authorized"`).

## E. Daemon — `crates/sentry-cli/src/daemon.rs`

Construct `correlation_tracker` gated on `cfg.correlation.enabled` (~256 pattern), `.with_correlation_tracker(...)` in the pipeline chain (~290), prune `tokio::spawn` every 60s (~355 pattern). Small Prometheus counter `sentry_correlation_hits_total` incremented in the main pump when a processed event carries the signal (mirror feed metrics).

## F. Tests (inline `#[cfg(test)]`, house pattern)

- correlation.rs: /24 and /64 prefix correlation, different-IP requirement, ASN fallback when prefixes differ, window expiry, per-key cap, prune.
- pipeline.rs tests (helpers `http_evt`/`http_evt_status`): 404-burst from IP A then SQLi from IP B same /24 → signal present and score/verdict reacts; same IP → no signal; TcpScanner TCP event records a scan; weight override via `[scorer.weights]`.
- reputation.rs: promiscuous → signal, authorized → none, parse aliases round-trip. config.rs: `CorrelationConfig` serde defaults.

## G. Docs

- Main repo: tick stale BACKLOG.md boxes F3.1–F3.9 + F3.10 when done; AGENTS.md gains the F3.10 ✅ entry (+ fix tcpfp.rs location note: lives in sentry-core, not sentry-source-tcp); ARCHITECTURE.md gains F3.10 in the F3 section + a short design subsection (match existing style).
- Docs submodule (`docs/` → sentry-docs): add the two new signals/weights to the risk-levels weight table and document `[correlation]` + the new tiers in the config reference, in **both** `/pt` and `/en`. Commit **inside the submodule only**; no pushes anywhere (you push/deploy).

## Non-goals

Correlation-state persistence across restarts (in-memory like all trackers, 15-min window makes it moot); DB-backed correlation; new default rule packs.

## Validation

`cargo fmt --all -- --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all` (baseline 288 passing; expect ~300+).