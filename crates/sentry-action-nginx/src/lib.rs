//! nginx edge provider (F7.8): enforces `Block`/`Challenge` verdicts on a
//! co-located nginx by generating config includes and reloading it — the
//! passive-deployment counterpart to the inline edge's native JS challenge.
//!
//! Two enforcement planes, both driven from one in-memory entry map:
//!
//! - **Deny list** (`sentry-deny.conf`): `deny <ip>;` lines for `Block`
//!   verdicts (and `RateLimit` with `rate_limit_deny = true`), included
//!   once in the `http` context (a `conf.d/*.conf` include usually is).
//! - **JS challenge map** (`sentry-challenge.conf`): a `geo` block mapping
//!   `Challenge`-verdict IPs to `$sentry_challenge_ip`, consumed by a static
//!   server-include snippet (`sentry-challenge-if.conf`) that turns on the
//!   getpagespeed `js_challenge` module for those clients:
//!
//! ```nginx
//! # inside your server { } block:
//! include /etc/nginx/conf.d/sentry/sentry-challenge-if.conf;
//! ```
//!
//! Files are rewritten atomically (tmp + rename) and stamped
//! `# sentry:<created_unix>:<ttl_secs>` so expiry survives restarts, the
//! same convention the Cloudflare provider uses in rule notes. Reloads are
//! debounced (≥1/s) and gated on `nginx -t` when `validate = true` — a
//! broken reload is skipped, never applied. Deny entries reconcile against
//! `ip_state` (the DB is the source of truth); challenge entries are
//! ephemeral by design.
//!
//! Needs the daemon running on the same host as nginx with write access to
//! `conf_dir` and permission to run `nginx -s reload`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sentry_core::analysis::Verdict;
use sentry_core::challenge::{ChallengeProvider, EdgeOptions};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

/// Which enforcement plane an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// `deny <addr>;` in the deny list.
    Deny,
    /// `<addr> 1;` in the challenge geo map.
    Challenge,
}

/// One provisioned address (rendered form, so v6 CIDR is pre-applied).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    kind: EntryKind,
    created: u64,
    ttl: u64,
}

/// Provider configuration.
#[derive(Debug, Clone)]
pub struct NginxConfig {
    /// Directory receiving the generated includes; must be inside nginx's
    /// include path (default `/etc/nginx/conf.d/sentry`).
    pub conf_dir: PathBuf,
    /// Reload command (`nginx -s reload`). Split on whitespace, run without
    /// a shell.
    pub reload_cmd: String,
    /// Run `nginx -t` before every reload; skip the reload when it fails.
    pub validate: bool,
    /// Entry TTL when the action's [`EdgeOptions`] carry no explicit TTL.
    pub ttl: Duration,
    /// Also deny `RateLimit` verdicts (default off — rate limiting is not a
    /// ban; nginx `limit_req` is the right tool for it).
    pub rate_limit_deny: bool,
    /// Apply IPv6 blocks to a whole CIDR (e.g. `64` = /64, parity with the
    /// Cloudflare list mode). `None` keeps exact-address entries.
    pub ipv6_prefix: Option<u8>,
    /// Geo variable for the challenge map.
    pub geo_var: String,
    /// Emit the optional `bot_verifier on;` snippet for the getpagespeed
    /// bot-verifier module (requires the module + Redis on the host).
    pub provision_bots: bool,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            conf_dir: PathBuf::from("/etc/nginx/conf.d/sentry"),
            reload_cmd: "nginx -s reload".into(),
            validate: true,
            ttl: Duration::from_secs(86400),
            rate_limit_deny: false,
            ipv6_prefix: None,
            geo_var: "$sentry_challenge_ip".into(),
            provision_bots: true,
        }
    }
}

/// A command to execute (kept plain for tests — no shell involved).
#[derive(Debug, PartialEq, Eq)]
pub struct Cmd {
    /// Program (resolved via PATH).
    pub program: String,
    /// Argument list.
    pub args: Vec<String>,
}

/// Split a reload command into program + args.
pub fn parse_cmd(spec: &str) -> Option<Cmd> {
    let mut parts = spec.split_whitespace();
    let program = parts.next()?.to_string();
    Some(Cmd {
        program,
        args: parts.map(str::to_string).collect(),
    })
}

/// Render the unix timestamp now (entry stamps).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render an address for config output: exact, or CIDR-truncated IPv6 when
/// `ipv6_prefix` is set (host bits masked to the network address).
pub fn render_addr(ip: IpAddr, ipv6_prefix: Option<u8>) -> String {
    match (ip, ipv6_prefix) {
        (IpAddr::V6(v6), Some(prefix)) if (1..=128).contains(&prefix) => {
            format!("{}/{}", v6_network(v6, prefix), prefix)
        }
        (ip, _) => ip.to_string(),
    }
}

/// Zero the host bits of `addr` beyond `prefix` (pure, testable).
fn v6_network(addr: std::net::Ipv6Addr, prefix: u8) -> std::net::Ipv6Addr {
    let keep = prefix as usize;
    let segments: [u16; 8] = addr
        .segments()
        .iter()
        .enumerate()
        .map(|(i, seg)| {
            let start = i * 16;
            if keep >= start + 16 {
                *seg
            } else if keep > start {
                seg & (u16::MAX << (16 - (keep - start)))
            } else {
                0
            }
        })
        .collect::<Vec<u16>>()
        .try_into()
        .expect("8 segments");
    std::net::Ipv6Addr::from(segments)
}

/// The `deny <addr>;` include body.
pub fn deny_conf(entries: &[(String, u64, u64)]) -> String {
    let mut out = String::from(
        "# Managed by Sentry (F7.8) — do not edit; rewritten atomically.\n\
         # Stamp format: sentry:<created_unix>:<ttl_secs>\n",
    );
    for (addr, created, ttl) in entries {
        out.push_str(&format!("deny {addr};  # sentry:{created}:{ttl}\n"));
    }
    out
}

/// The challenge `geo` map body (consumes nginx-module-js-challenge).
pub fn challenge_geo_conf(geo_var: &str, entries: &[(String, u64, u64)]) -> String {
    let mut out = format!(
        "# Managed by Sentry (F7.8) — do not edit; rewritten atomically.\n\
         # Requires nginx-module-js-challenge (getpagespeed). http context.\n\
         geo {geo_var} {{\n    default 0;\n"
    );
    for (addr, created, ttl) in entries {
        out.push_str(&format!("    {addr} 1;  # sentry:{created}:{ttl}\n"));
    }
    out.push_str("}\n");
    out
}

/// The static server-context snippet enabling the challenge for mapped IPs.
pub fn challenge_if_conf(geo_var: &str) -> String {
    format!(
        "# Managed by Sentry (F7.8) — include inside your server {{ }} block:\n\
         #   include <conf_dir>/sentry-challenge-if.conf;\n\
         if ({geo_var}) {{ js_challenge on; }}\n"
    )
}

/// Bot-verification server snippet (getpagespeed nginx-module-bot-verifier;
/// needs Redis/KeyDB + a `resolver` directive — see the module docs).
pub fn bot_verifier_snippet() -> String {
    "# Managed by Sentry (F7.8) — optional: verify claimed search bots via\n\
     # reverse DNS + forward confirmation (nginx-module-bot-verifier).\n\
     # Requirements: `dnf install nginx-module-bot-verifier keydb`, a\n\
     # `resolver` directive, and realip for proxied clients.\n\
     # Include inside your server { } block:\n\
     bot_verifier on;\n\
     # bot_verifier_redis_expiry 7200;\n"
        .to_string()
}

/// Parse a `sentry:<created>:<ttl>` stamp from a trailing comment.
pub fn parse_stamp(comment: &str) -> Option<(u64, u64)> {
    let rest = comment.trim().strip_prefix("sentry:")?;
    let mut parts = rest.split(':');
    let created = parts.next()?.parse().ok()?;
    let ttl = parts.next()?.parse().ok()?;
    Some((created, ttl))
}

/// The nginx provider: owns the entry map, renders the includes and runs
/// the debounced validate/reload worker.
pub struct NginxProvider {
    cfg: NginxConfig,
    trust: Option<sentry_core::SharedTrustSet>,
    entries: RwLock<HashMap<String, Entry>>,
    dirty: AtomicBool,
    reload_tx: mpsc::UnboundedSender<()>,
    disabled: AtomicBool,
}

impl NginxProvider {
    /// Create the provider and start its reload worker. `trust` is the
    /// never-ban guard: trusted IPs are never written to any include.
    pub fn new(cfg: NginxConfig, trust: Option<sentry_core::SharedTrustSet>) -> Arc<Self> {
        let (reload_tx, reload_rx) = mpsc::unbounded_channel();
        let provider = Arc::new(Self {
            cfg,
            trust,
            entries: RwLock::new(HashMap::new()),
            dirty: AtomicBool::new(false),
            reload_tx,
            disabled: AtomicBool::new(false),
        });
        let worker = Arc::clone(&provider);
        tokio::spawn(async move {
            nginx_reload_worker(worker, reload_rx).await;
        });
        provider
    }

    /// Provider configuration (read-only view, e.g. for `status` output).
    pub fn config(&self) -> &NginxConfig {
        &self.cfg
    }

    /// Insert/update one entry; returns whether the file content changes.
    async fn upsert(&self, addr: String, kind: EntryKind, ttl: u64) -> bool {
        let mut entries = self.entries.write().await;
        match entries.get(&addr) {
            Some(e) if e.kind == kind && e.ttl == ttl => return false,
            _ => {}
        }
        entries.insert(
            addr,
            Entry {
                kind,
                created: unix_now(),
                ttl,
            },
        );
        true
    }

    /// Drop expired entries; returns how many were removed.
    pub async fn prune_expired(&self) -> usize {
        let now = unix_now();
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, e| now < e.created.saturating_add(e.ttl));
        before - entries.len()
    }

    /// Render both include bodies from the current entry map.
    pub async fn render(&self) -> (String, String) {
        let entries = self.entries.read().await;
        let mut denies: Vec<(String, u64, u64)> = entries
            .iter()
            .filter(|(_, e)| e.kind == EntryKind::Deny)
            .map(|(addr, e)| (addr.clone(), e.created, e.ttl))
            .collect();
        let mut challenges: Vec<(String, u64, u64)> = entries
            .iter()
            .filter(|(_, e)| e.kind == EntryKind::Challenge)
            .map(|(addr, e)| (addr.clone(), e.created, e.ttl))
            .collect();
        denies.sort();
        challenges.sort();
        drop(entries);
        (
            deny_conf(&denies),
            challenge_geo_conf(&self.cfg.geo_var, &challenges),
        )
    }

    /// Live entry count (deny + challenge).
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Whether no entries are held.
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Reconcile deny entries against the expected map (from `ip_state`),
    /// rendered through the same `ipv6_prefix` rule as `apply`. Challenge
    /// entries are untouched; returns `(added, removed)` and schedules a
    /// reload when something changed.
    pub async fn sync_denies(&self, expected: &HashMap<IpAddr, Option<u64>>) -> (usize, usize) {
        let rendered: std::collections::HashSet<String> = expected
            .keys()
            .map(|ip| render_addr(*ip, self.cfg.ipv6_prefix))
            .collect();
        let mut added = 0;
        let mut removed = 0;
        {
            let entries = self.entries.read().await;
            for addr in &rendered {
                if !entries.get(addr).is_some_and(|e| e.kind == EntryKind::Deny) {
                    added += 1;
                }
            }
            for (addr, e) in entries.iter() {
                if e.kind == EntryKind::Deny && !rendered.contains(addr) {
                    removed += 1;
                }
            }
        }
        if added == 0 && removed == 0 {
            return (0, 0);
        }
        let ttl = self.cfg.ttl.as_secs();
        let now = unix_now();
        {
            let mut entries = self.entries.write().await;
            for addr in &rendered {
                match entries.get(addr) {
                    Some(e) if e.kind == EntryKind::Deny => {}
                    _ => {
                        entries.insert(
                            addr.clone(),
                            Entry {
                                kind: EntryKind::Deny,
                                created: now,
                                ttl,
                            },
                        );
                    }
                }
            }
            entries.retain(|addr, e| e.kind != EntryKind::Deny || rendered.contains(addr));
        }
        self.dirty.store(true, Ordering::Relaxed);
        let _ = self.reload_tx.send(());
        (added, removed)
    }

    async fn enforce(&self, ip: IpAddr, kind: EntryKind, ttl_secs: u64) -> sentry_core::Result<()> {
        if self.disabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        let addr = render_addr(ip, self.cfg.ipv6_prefix);
        if self.upsert(addr, kind, ttl_secs).await {
            self.dirty.store(true, Ordering::Relaxed);
            let _ = self.reload_tx.send(());
        }
        Ok(())
    }
}

/// One worker pass: prune → render → atomic write → validate → reload.
async fn write_and_reload(provider: &NginxProvider) {
    provider.prune_expired().await;
    let (deny, challenge) = provider.render().await;
    let dir = &provider.cfg.conf_dir;
    if let Err(e) = tokio::fs::create_dir_all(dir).await {
        warn!(error = %e, dir = %dir.display(), "nginx provider: cannot create conf_dir — disabling");
        provider.disabled.store(true, Ordering::Relaxed);
        return;
    }
    let mut files: Vec<(&str, String)> = vec![
        ("sentry-deny.conf", deny),
        ("sentry-challenge.conf", challenge),
        (
            "sentry-challenge-if.conf",
            challenge_if_conf(&provider.cfg.geo_var),
        ),
    ];
    if provider.cfg.provision_bots {
        files.push(("sentry-bots.conf", bot_verifier_snippet()));
    }
    for (name, content) in files {
        let path = dir.join(name);
        if !should_write(&path, &content).await {
            continue;
        }
        let tmp = dir.join(format!("{name}.tmp"));
        if let Err(e) = tokio::fs::write(&tmp, &content).await {
            warn!(error = %e, file = name, "nginx provider: atomic write failed");
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            warn!(error = %e, file = name, "nginx provider: rename failed");
            return;
        }
        debug!(file = name, "nginx include rewritten");
    }
    if provider.cfg.validate {
        let Some(test_cmd) = parse_cmd("nginx -t") else {
            return;
        };
        let (ok, out) = run_cmd(&test_cmd).await;
        if !ok {
            warn!(output = %out.trim(), "nginx -t failed — reload skipped");
            return;
        }
    }
    let Some(cmd) = parse_cmd(&provider.cfg.reload_cmd) else {
        return;
    };
    let (ok, out) = run_cmd(&cmd).await;
    if ok {
        info!("nginx reloaded with regenerated sentry includes");
    } else {
        warn!(cmd = %provider.cfg.reload_cmd, output = %out.trim(), "nginx reload failed");
    }
}

async fn should_write(path: &std::path::Path, content: &str) -> bool {
    match tokio::fs::read_to_string(path).await {
        Ok(current) => current != content,
        Err(_) => true,
    }
}

async fn run_cmd(cmd: &Cmd) -> (bool, String) {
    match tokio::process::Command::new(&cmd.program)
        .args(&cmd.args)
        .output()
        .await
    {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), text)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Debounced reload worker: coalesces dirty signals to at most one
/// write+validate+reload pass per second, and sweeps expired entries every
/// minute even when idle.
async fn nginx_reload_worker(provider: Arc<NginxProvider>, mut rx: mpsc::UnboundedReceiver<()>) {
    let mut ticks: u64 = 0;
    loop {
        // Drain everything queued (coalescing), then wait for a tick.
        if rx.recv().await.is_none() {
            return;
        }
        while rx.try_recv().is_ok() {}
        tokio::time::sleep(Duration::from_secs(1)).await;
        while rx.try_recv().is_ok() {}
        if provider.dirty.swap(false, Ordering::Relaxed) {
            write_and_reload(&provider).await;
        }
        ticks += 1;
        if ticks % 60 == 0 && provider.prune_expired().await > 0 {
            write_and_reload(&provider).await;
        }
    }
}

#[async_trait]
impl ChallengeProvider for NginxProvider {
    fn name(&self) -> &'static str {
        "nginx"
    }

    async fn apply(
        &self,
        ip: IpAddr,
        verdict: Verdict,
        opts: &EdgeOptions,
    ) -> sentry_core::Result<()> {
        // Never-ban guard (F7.2): trusted IPs never reach nginx config.
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(ip) {
                debug!(ip = %ip, "nginx provider: refused for trusted ip");
                return Ok(());
            }
        }
        let ttl = if opts.ttl.is_zero() {
            self.cfg.ttl
        } else {
            opts.ttl
        };
        let (kind, ttl) = match verdict {
            Verdict::Block => (Some(EntryKind::Deny), ttl),
            Verdict::Challenge => (Some(EntryKind::Challenge), ttl),
            Verdict::RateLimit if self.cfg.rate_limit_deny => (Some(EntryKind::Deny), ttl),
            other => {
                debug!(verdict = ?other, "nginx provider: nothing to enforce");
                (None, ttl)
            }
        };
        match kind {
            Some(kind) => self.enforce(ip, kind, ttl.as_secs()).await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmd_splits_without_shell() {
        let cmd = parse_cmd("nginx -s reload").unwrap();
        assert_eq!(cmd.program, "nginx");
        assert_eq!(cmd.args, vec!["-s", "reload"]);
        assert!(parse_cmd("").is_none());
    }

    #[test]
    fn render_addr_applies_v6_prefix_only() {
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(render_addr(v6, Some(64)), "2001:db8:1:2::/64");
        assert_eq!(render_addr(v6, Some(63)), "2001:db8:1:2::/63");
        // /20 keeps the first 20 bits: `2001:` plus the zero high nibble
        // of `0db8`.
        assert_eq!(render_addr(v6, Some(20)), "2001::/20");
        assert_eq!(render_addr(v6, None), "2001:db8:1:2:3:4:5:6");
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(render_addr(v4, Some(64)), "203.0.113.7");
    }

    #[test]
    fn deny_conf_shape_and_stamps() {
        let body = deny_conf(&[
            ("203.0.113.7".into(), 1_717_200_000, 86_400),
            ("198.51.100.9".into(), 1_717_200_001, 600),
        ]);
        assert!(body.contains("deny 203.0.113.7;  # sentry:1717200000:86400"));
        assert!(body.contains("deny 198.51.100.9;  # sentry:1717200001:600"));
        assert!(body.starts_with("# Managed by Sentry"));
    }

    #[test]
    fn challenge_geo_conf_shape() {
        let body = challenge_geo_conf(
            "$sentry_challenge_ip",
            &[("203.0.113.9".into(), 1_717_200_000, 3_600)],
        );
        assert!(body.contains("geo $sentry_challenge_ip {"));
        assert!(body.contains("default 0;"));
        assert!(body.contains("    203.0.113.9 1;  # sentry:1717200000:3600"));
        assert!(body.trim_end().ends_with('}'));
    }

    #[test]
    fn if_conf_and_bot_snippet_reference_modules() {
        let ifc = challenge_if_conf("$sentry_challenge_ip");
        assert!(ifc.contains("if ($sentry_challenge_ip) { js_challenge on; }"));
        let bots = bot_verifier_snippet();
        assert!(bots.contains("bot_verifier on;"));
    }

    #[test]
    fn parse_stamp_round_trip() {
        assert_eq!(
            parse_stamp("sentry:1717200000:86400"),
            Some((1_717_200_000, 86_400))
        );
        assert_eq!(parse_stamp("garbage"), None);
        assert_eq!(parse_stamp("sentry:x:y"), None);
    }

    #[tokio::test]
    async fn upsert_and_render_partition_kinds() {
        let provider = NginxProvider::new(NginxConfig::default(), None);
        provider
            .upsert("203.0.113.7".into(), EntryKind::Deny, 60)
            .await;
        provider
            .upsert("203.0.113.9".into(), EntryKind::Challenge, 60)
            .await;
        let (deny, geo) = provider.render().await;
        assert!(deny.contains("deny 203.0.113.7;"));
        assert!(!deny.contains("203.0.113.9"));
        assert!(geo.contains("203.0.113.9 1;"));
        assert!(!geo.contains("203.0.113.7"));
        assert_eq!(provider.len().await, 2);

        // Same kind+ttl → no change.
        assert!(
            !provider
                .upsert("203.0.113.7".into(), EntryKind::Deny, 60)
                .await
        );
    }

    #[tokio::test]
    async fn expired_entries_are_pruned() {
        let provider = NginxProvider::new(NginxConfig::default(), None);
        provider
            .upsert("203.0.113.7".into(), EntryKind::Deny, 0)
            .await;
        provider
            .upsert("203.0.113.8".into(), EntryKind::Deny, 3_600)
            .await;
        assert_eq!(provider.prune_expired().await, 1);
        assert_eq!(provider.len().await, 1);
    }

    #[tokio::test]
    async fn sync_denies_reconciles_expected_only() {
        let provider = NginxProvider::new(NginxConfig::default(), None);
        provider
            .upsert("203.0.113.7".into(), EntryKind::Deny, 60)
            .await;
        provider
            .upsert("203.0.113.99".into(), EntryKind::Challenge, 60)
            .await;

        let mut expected = HashMap::new();
        expected.insert("198.51.100.9".parse().unwrap(), None);
        expected.insert("203.0.113.7".parse().unwrap(), Some(120));

        let (added, removed) = provider.sync_denies(&expected).await;
        assert_eq!((added, removed), (1, 0));
        let (deny, geo) = provider.render().await;
        assert!(deny.contains("deny 198.51.100.9;"));
        // Challenge entries survive the deny reconcile.
        assert!(geo.contains("203.0.113.99 1;"));

        // Now drop 198.51.100.9 from expected → removed on the next sync.
        let mut only = HashMap::new();
        only.insert("203.0.113.7".parse().unwrap(), None);
        let (added, removed) = provider.sync_denies(&only).await;
        assert_eq!((added, removed), (0, 1));
    }

    #[tokio::test]
    async fn worker_writes_includes_atomically() {
        let dir = std::env::temp_dir().join(format!("sentry-nginx-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = NginxConfig {
            conf_dir: dir.clone(),
            reload_cmd: "true".into(),
            validate: false,
            ..Default::default()
        };
        let provider = NginxProvider::new(cfg, None);
        provider
            .upsert("203.0.113.7".into(), EntryKind::Deny, 3_600)
            .await;
        provider.dirty.store(true, Ordering::Relaxed);
        let _ = provider.reload_tx.send(());
        // Worker: recv → drain → 1s debounce → write.
        tokio::time::sleep(Duration::from_millis(1800)).await;
        let deny = tokio::fs::read_to_string(dir.join("sentry-deny.conf"))
            .await
            .expect("deny include written");
        assert!(deny.contains("deny 203.0.113.7;"));
        let ifc = tokio::fs::read_to_string(dir.join("sentry-challenge-if.conf"))
            .await
            .expect("if snippet written");
        assert!(ifc.contains("js_challenge on;"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
