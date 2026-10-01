//! Local firewall ban provider (F7.3): enforces `Block`/`Challenge`/
//! `RateLimit` verdicts at the kernel level, complementing the CDN edge
//! (`sentry-action-cloudflare`) for deployments that own the box.
//!
//! Three backends, auto-detected in this order (config-overridable), the
//! same ladder the nginx-honeypot project uses:
//!
//! 1. **nftables** (recommended): a dedicated `sentry` table with
//!    `blocks_v4`/`blocks_v6` sets (`flags timeout`) and an input-hook DROP
//!    rule. Elements carry per-element timeouts, so bans expire in-kernel
//!    with no reaper; a ban is one atomic netlink message (sub-millisecond).
//! 2. **ipset** (legacy EL7/8/9 fast path): `hash:ip` sets with per-element
//!    timeouts + an iptables `-m set` DROP rule.
//! 3. **firewalld** (portable path where the nftables backend hides legacy
//!    ipset): runtime ipsets managed through `firewall-cmd`.
//!
//! The database (`ip_state`) is the source of truth: a `sync` reconciles
//! the live set against blocked IPs, so bans survive restarts (re-seeded)
//! and manual unblocks converge within the reconcile cadence. Never-ban
//! IPs (`[real_ip] trusted_ips`) are refused here as a final guard.
//!
//! Requires root or `CAP_NET_ADMIN` — see the systemd unit notes in
//! `deploy/` (`AmbientCapabilities=CAP_NET_ADMIN` or a restricted sudoers
//! stanza for the exact commands).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sentry_core::analysis::Verdict;
use sentry_core::challenge::{ChallengeProvider, EdgeOptions};
use tracing::{debug, info, warn};

/// Local firewall backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    /// raw nftables (`nft`) — dedicated table, timeout sets.
    Nftables,
    /// legacy ipset + iptables (`ipset`, `iptables`, `ip6tables`).
    Ipset,
    /// firewalld runtime ipsets (`firewall-cmd`).
    Firewalld,
}

impl FirewallBackend {
    /// Parse from config (`"nftables" | "ipset" | "firewalld" | "auto"`).
    pub fn parse(s: &str) -> Option<Option<Self>> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(None),
            "nftables" | "nft" | "nftset" => Some(Some(Self::Nftables)),
            "ipset" => Some(Some(Self::Ipset)),
            "firewalld" => Some(Some(Self::Firewalld)),
            _ => None,
        }
    }

    /// Stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Ipset => "ipset",
            Self::Firewalld => "firewalld",
        }
    }
}

/// Firewall action configuration.
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Backend selection; `None` = auto-detect.
    pub backend: Option<FirewallBackend>,
    /// Ban TTL for `Block`/`Challenge` verdicts when the action's
    /// `EdgeOptions` carry no explicit TTL.
    pub ttl: Duration,
    /// Shorter ban TTL for `RateLimit` verdicts.
    pub rate_limit_ttl: Duration,
    /// nftables table name.
    pub table: String,
    /// Set name prefix — `sentry_blocks` yields `sentry_blocks_v4`/`_v6`.
    pub set_prefix: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: None,
            ttl: Duration::from_secs(86400),
            rate_limit_ttl: Duration::from_secs(600),
            table: "sentry".into(),
            set_prefix: "sentry_blocks".into(),
        }
    }
}

/// A fully-specified command to execute (kept plain for tests).
#[derive(Debug, PartialEq, Eq)]
pub struct Cmd {
    /// Program name (resolved via PATH; no shell involved).
    pub program: &'static str,
    /// Argument list.
    pub args: Vec<String>,
    /// Optional stdin payload (nft scripts).
    pub stdin: Option<String>,
}

/// Provisioning script for one address family (idempotent: the
/// declare → delete → create pattern resets our table without touching
/// anything else; bans are re-seeded from `ip_state` by the reconcile).
pub fn nft_provision_script(table: &str, set: &str, v6: bool) -> String {
    let family = if v6 { "ip6" } else { "ip" };
    let addr_type = if v6 { "ipv6_addr" } else { "ipv4_addr" };
    let match_expr = if v6 {
        "ip6 saddr".to_string()
    } else {
        "ip saddr".to_string()
    };
    format!(
        "table {family} {table}\n\
         delete table {family} {table}\n\
         table {family} {table} {{\n\
         \x20 set {set} {{ type {addr_type}; flags timeout; }}\n\
         \x20 chain input {{ type filter hook input priority -1; policy accept;\n\
         \x20   {match_expr} @{set} drop\n\
         \x20 }}\n\
         }}\n"
    )
}

/// Ban command: add an element with a per-element timeout.
pub fn nft_ban_cmd(table: &str, set: &str, ip: IpAddr, ttl_secs: u64) -> Cmd {
    Cmd {
        program: "nft",
        args: vec![
            "add".into(),
            "element".into(),
            family_of(ip).into(),
            table.into(),
            set.into(),
            format!("{{ {ip} timeout {ttl_secs}s }}"),
        ],
        stdin: None,
    }
}

/// Unban command.
pub fn nft_unban_cmd(table: &str, set: &str, ip: IpAddr) -> Cmd {
    Cmd {
        program: "nft",
        args: vec![
            "delete".into(),
            "element".into(),
            family_of(ip).into(),
            table.into(),
            set.into(),
            format!("{{ {ip} }}"),
        ],
        stdin: None,
    }
}

/// List command (JSON; parse with [`parse_nft_set_elements`]).
pub fn nft_list_cmd(table: &str, set: &str, v6: bool) -> Cmd {
    Cmd {
        program: "nft",
        args: vec![
            "-j".into(),
            "list".into(),
            "set".into(),
            (if v6 { "ip6" } else { "ip" }).into(),
            table.into(),
            set.into(),
        ],
        stdin: None,
    }
}

/// Parse `nft -j list set` output into `(ip, remaining_timeout_secs)`.
/// Elements without a timeout (shouldn't happen — sets are created with
/// `flags timeout`) come back as `None`.
pub fn parse_nft_set_elements(json: &str) -> Vec<(IpAddr, Option<u64>)> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(items) = value.get("nftables").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let Some(set) = item
            .get("set")
            .and_then(|s| s.get("elem"))
            .and_then(|e| e.as_array())
        else {
            continue;
        };
        for elem in set {
            // With timeouts: {"elem": {"val": "1.2.3.4", "timeout": 86400000}}
            let val = elem
                .get("elem")
                .and_then(|e| e.get("val"))
                .and_then(|v| v.as_str())
                // Without timeouts: plain "1.2.3.4"
                .or_else(|| elem.as_str());
            let Some(val) = val else { continue };
            let Ok(ip) = val.parse::<IpAddr>() else {
                continue;
            };
            let timeout_ms = elem
                .get("elem")
                .and_then(|e| e.get("timeout"))
                .and_then(|t| t.as_u64());
            out.push((ip, timeout_ms.map(|ms| ms / 1000)));
        }
    }
    out
}

/// ipset create args (`-exist` keeps it idempotent). The set-level
/// `timeout` option enables per-element timeouts on `add`.
pub fn ipset_create_cmd(set: &str, v6: bool) -> Cmd {
    Cmd {
        program: "ipset",
        args: vec![
            "create".into(),
            set.into(),
            "hash:ip".into(),
            "family".into(),
            (if v6 { "inet6" } else { "inet" }).into(),
            "timeout".into(),
            "0".into(),
            "maxelem".into(),
            "1000000".into(),
            "-exist".into(),
        ],
        stdin: None,
    }
}

/// iptables rule wiring the set into INPUT (v6 → ip6tables). Run `-C`
/// first (via [`ipset_rule_check_cmd`]); only `-I` when it exits non-zero.
pub fn ipset_rule_insert_cmd(set: &str, v6: bool) -> Cmd {
    cmd_set_rule(set, v6, "-I")
}

/// iptables rule existence check (`-C`, exit code only).
pub fn ipset_rule_check_cmd(set: &str, v6: bool) -> Cmd {
    cmd_set_rule(set, v6, "-C")
}

fn cmd_set_rule(set: &str, v6: bool, flag: &str) -> Cmd {
    Cmd {
        program: if v6 { "ip6tables" } else { "iptables" },
        args: vec![
            "-w".into(),
            flag.into(),
            "INPUT".into(),
            "-m".into(),
            "set".into(),
            "--match-set".into(),
            set.into(),
            "src".into(),
            "-j".into(),
            "DROP".into(),
        ],
        stdin: None,
    }
}

/// ipset ban (per-element timeout; `-exist` makes re-bans refresh).
pub fn ipset_add_cmd(set: &str, ip: IpAddr, ttl_secs: u64) -> Cmd {
    Cmd {
        program: "ipset",
        args: vec![
            "add".into(),
            set.into(),
            ip.to_string(),
            "timeout".into(),
            ttl_secs.to_string(),
            "-exist".into(),
        ],
        stdin: None,
    }
}

/// ipset unban.
pub fn ipset_del_cmd(set: &str, ip: IpAddr) -> Cmd {
    Cmd {
        program: "ipset",
        args: vec!["del".into(), set.into(), ip.to_string()],
        stdin: None,
    }
}

/// ipset member list.
pub fn ipset_list_cmd(set: &str) -> Cmd {
    Cmd {
        program: "ipset",
        args: vec!["list".into(), set.into()],
        stdin: None,
    }
}

/// Parse `ipset list <set>` members: lines after `Members:`, of the form
/// `1.2.3.4` or `1.2.3.4 timeout 86395`.
pub fn parse_ipset_members(output: &str) -> Vec<(IpAddr, Option<u64>)> {
    let mut out = Vec::new();
    let mut in_members = false;
    for line in output.lines() {
        if line.trim() == "Members:" {
            in_members = true;
            continue;
        }
        if !in_members {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        let Ok(ip) = first.parse::<IpAddr>() else {
            continue;
        };
        let timeout = match (tokens.next(), tokens.next()) {
            (Some("timeout"), Some(secs)) => secs.parse::<u64>().ok(),
            _ => None,
        };
        out.push((ip, timeout));
    }
    out
}

/// firewalld runtime ipset creation (tolerates "already exists").
pub fn firewalld_create_cmd(set: &str) -> Cmd {
    Cmd {
        program: "firewall-cmd",
        args: vec![
            "--new-ipset".into(),
            set.into(),
            "--type=hash:ip".into(),
            "--option=timeout=86400".into(),
            "--option=maxelem=1000000".into(),
        ],
        stdin: None,
    }
}

/// Bind the ipset to the `drop` zone (block all traffic from its members).
pub fn firewalld_bind_cmd(set: &str) -> Cmd {
    Cmd {
        program: "firewall-cmd",
        args: vec!["--zone=drop".into(), format!("--add-source=ipset:{set}")],
        stdin: None,
    }
}

/// firewalld ban (runtime; firewalld has no per-entry timeout — expiry is
/// handled by the daemon's reconcile removing the entry).
pub fn firewalld_add_cmd(set: &str, ip: IpAddr) -> Cmd {
    Cmd {
        program: "firewall-cmd",
        args: vec![
            "--ipset".into(),
            set.into(),
            "--add-entry".into(),
            ip.to_string(),
        ],
        stdin: None,
    }
}

/// firewalld unban.
pub fn firewalld_del_cmd(set: &str, ip: IpAddr) -> Cmd {
    Cmd {
        program: "firewall-cmd",
        args: vec![
            "--ipset".into(),
            set.into(),
            "--remove-entry".into(),
            ip.to_string(),
        ],
        stdin: None,
    }
}

/// firewalld entry list.
pub fn firewalld_list_cmd(set: &str) -> Cmd {
    Cmd {
        program: "firewall-cmd",
        args: vec!["--ipset".into(), set.into(), "--get-entries".into()],
        stdin: None,
    }
}

/// Parse `firewall-cmd --get-entries` output (one entry per line).
pub fn parse_firewalld_entries(output: &str) -> Vec<(IpAddr, Option<u64>)> {
    output
        .lines()
        .filter_map(|l| l.trim().parse::<IpAddr>().ok().map(|ip| (ip, None)))
        .collect()
}

fn family_of(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}

/// Detection probes per backend: cheap, read-only commands whose success
/// indicates the backend is usable.
pub fn detect_probes() -> Vec<(FirewallBackend, Cmd)> {
    vec![
        (
            FirewallBackend::Nftables,
            Cmd {
                program: "nft",
                args: vec!["list".into(), "tables".into()],
                stdin: None,
            },
        ),
        (
            FirewallBackend::Ipset,
            Cmd {
                program: "ipset",
                args: vec!["version".into()],
                stdin: None,
            },
        ),
        (
            FirewallBackend::Firewalld,
            Cmd {
                program: "firewall-cmd",
                args: vec!["--state".into()],
                stdin: None,
            },
        ),
    ]
}

/// Run a [`Cmd`], returning (exit_success, stdout+stderr). Public for the
/// `sentry firewall status` probe.
pub async fn run_cmd(cmd: &Cmd) -> (bool, String) {
    let mut command = tokio::process::Command::new(cmd.program);
    command
        .args(&cmd.args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (false, format!("{}: {e}", cmd.program));
        }
    };
    if let Some(payload) = &cmd.stdin {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }
    }
    match child.wait_with_output().await {
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

/// Local firewall provider implementing
/// [`ChallengeProvider`](sentry_core::ChallengeProvider).
pub struct FirewallProvider {
    cfg: FirewallConfig,
    trust: Option<sentry_core::SharedTrustSet>,
    backend: Arc<tokio::sync::OnceCell<FirewallBackend>>,
    provisioned: Arc<tokio::sync::OnceCell<()>>,
}

impl FirewallProvider {
    /// Create the provider. `trust` (never-ban set) is a final guard: even
    /// a manually blocked trusted IP is refused at the kernel boundary.
    pub fn new(cfg: FirewallConfig, trust: Option<sentry_core::SharedTrustSet>) -> Self {
        Self {
            cfg,
            trust,
            backend: Arc::new(tokio::sync::OnceCell::new()),
            provisioned: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    fn set_name(&self, v6: bool) -> String {
        format!("{}{}", self.cfg.set_prefix, if v6 { "_v6" } else { "_v4" })
    }

    async fn detect_backend(&self) -> Result<FirewallBackend, String> {
        if let Some(explicit) = self.cfg.backend {
            return Ok(explicit);
        }
        for (backend, probe) in detect_probes() {
            let (ok, out) = run_cmd(&probe).await;
            if ok {
                info!(backend = backend.as_str(), "firewall backend detected");
                return Ok(backend);
            }
            debug!(backend = backend.as_str(), output = %out, "firewall probe unavailable");
        }
        Err(
            "no usable firewall backend — install nftables (recommended), ipset+iptables, \
             or firewalld, and grant the daemon CAP_NET_ADMIN"
                .to_string(),
        )
    }

    async fn backend_or_warn(&self) -> Option<FirewallBackend> {
        match self.backend.get_or_try_init(|| self.detect_backend()).await {
            Ok(b) => Some(*b),
            Err(e) => {
                warn!(error = %e, "firewall ban skipped");
                None
            }
        }
    }

    async fn provision(&self, backend: FirewallBackend) {
        let _ = self
            .provisioned
            .get_or_try_init(|| async {
                match backend {
                    FirewallBackend::Nftables => {
                        for v6 in [false, true] {
                            let script =
                                nft_provision_script(&self.cfg.table, &self.set_name(v6), v6);
                            let cmd = Cmd {
                                program: "nft",
                                args: vec!["-f".into(), "-".into()],
                                stdin: Some(script),
                            };
                            let (ok, out) = run_cmd(&cmd).await;
                            if !ok {
                                warn!(
                                    family = if v6 { "v6" } else { "v4" },
                                    output = %out,
                                    "nft provision failed"
                                );
                            }
                        }
                    }
                    FirewallBackend::Ipset => {
                        for v6 in [false, true] {
                            let set = self.set_name(v6);
                            let (ok, out) = run_cmd(&ipset_create_cmd(&set, v6)).await;
                            if !ok {
                                warn!(set = %set, output = %out, "ipset create failed");
                            }
                            for cmd in [
                                ipset_rule_check_cmd(&set, v6),
                                ipset_rule_insert_cmd(&set, v6),
                            ] {
                                let (ok, out) = run_cmd(&cmd).await;
                                // -C exits non-zero when absent → -I runs; -I
                                // failing for real is the only bad case.
                                if cmd.args[0] == "-I" && !ok {
                                    warn!(set = %set, output = %out, "iptables rule insert failed");
                                }
                            }
                        }
                    }
                    FirewallBackend::Firewalld => {
                        for v6 in [false, true] {
                            let set = self.set_name(v6);
                            for cmd in [firewalld_create_cmd(&set), firewalld_bind_cmd(&set)] {
                                let (ok, out) = run_cmd(&cmd).await;
                                let tolerated = out.contains("already") || out.contains("EXISTS");
                                if !ok && !tolerated {
                                    warn!(set = %set, output = %out, "firewalld setup failed");
                                }
                            }
                        }
                    }
                }
                Ok::<(), String>(())
            })
            .await;
    }

    async fn ban(&self, ip: IpAddr, ttl_secs: u64) -> Result<(), String> {
        let Some(backend) = self.backend_or_warn().await else {
            return Ok(());
        };
        self.provision(backend).await;
        let cmd = match backend {
            FirewallBackend::Nftables => {
                nft_ban_cmd(&self.cfg.table, &self.set_name(is_v6(ip)), ip, ttl_secs)
            }
            FirewallBackend::Ipset => ipset_add_cmd(&self.set_name(is_v6(ip)), ip, ttl_secs),
            FirewallBackend::Firewalld => firewalld_add_cmd(&self.set_name(is_v6(ip)), ip),
        };
        let (ok, out) = run_cmd(&cmd).await;
        if ok {
            debug!(backend = backend.as_str(), ip = %ip, ttl_secs, "firewall ban applied");
            Ok(())
        } else {
            Err(format!(
                "firewall ban failed ({}): {}",
                backend.as_str(),
                out.trim()
            ))
        }
    }

    /// Remove one IP from the sets.
    pub async fn unban(&self, ip: IpAddr) -> Result<(), String> {
        let Some(backend) = self.backend.get().copied() else {
            return Ok(());
        };
        let cmd = match backend {
            FirewallBackend::Nftables => {
                nft_unban_cmd(&self.cfg.table, &self.set_name(is_v6(ip)), ip)
            }
            FirewallBackend::Ipset => ipset_del_cmd(&self.set_name(is_v6(ip)), ip),
            FirewallBackend::Firewalld => firewalld_del_cmd(&self.set_name(is_v6(ip)), ip),
        };
        let (ok, out) = run_cmd(&cmd).await;
        if ok {
            Ok(())
        } else {
            Err(format!("firewall unban failed: {}", out.trim()))
        }
    }

    /// List the live set contents: `(ip, remaining_timeout_secs)`.
    pub async fn list(&self) -> Result<Vec<(IpAddr, Option<u64>)>, String> {
        let Some(backend) = self.backend.get().copied() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for v6 in [false, true] {
            let set = self.set_name(v6);
            let cmd = match backend {
                FirewallBackend::Nftables => nft_list_cmd(&self.cfg.table, &set, v6),
                FirewallBackend::Ipset => ipset_list_cmd(&set),
                FirewallBackend::Firewalld => firewalld_list_cmd(&set),
            };
            let (ok, text) = run_cmd(&cmd).await;
            if !ok {
                return Err(format!("firewall list failed: {}", text.trim()));
            }
            out.extend(match backend {
                FirewallBackend::Nftables => parse_nft_set_elements(&text),
                FirewallBackend::Ipset => parse_ipset_members(&text),
                FirewallBackend::Firewalld => parse_firewalld_entries(&text),
            });
        }
        Ok(out)
    }

    /// Reconcile the live sets against the expected block list (DB is the
    /// source of truth). Adds missing entries and removes extras; returns
    /// `(added, removed)`.
    pub async fn sync(
        &self,
        expected: &HashMap<IpAddr, Option<u64>>,
    ) -> Result<(usize, usize), String> {
        let live = self.list().await?;
        let live_map: HashMap<IpAddr, Option<u64>> = live.into_iter().collect();
        let mut added = 0;
        let mut removed = 0;
        for (ip, ttl) in expected.iter() {
            if !live_map.contains_key(ip) {
                let ttl = ttl.unwrap_or_else(|| self.cfg.ttl.as_secs());
                if self.ban(*ip, ttl).await.is_ok() {
                    added += 1;
                }
            }
        }
        for ip in live_map.keys() {
            if !expected.contains_key(ip) && self.unban(*ip).await.is_ok() {
                removed += 1;
            }
        }
        Ok((added, removed))
    }

    /// Backend resolved at runtime (None until the first ban/sync).
    pub fn resolved_backend(&self) -> Option<FirewallBackend> {
        self.backend.get().copied()
    }

    /// Resolve (and cache) the backend without banning anything — used by
    /// `sentry firewall status`.
    pub async fn resolve_backend(&self) -> Result<FirewallBackend, String> {
        let backend = self.detect_backend().await?;
        let _ = self.backend.set(backend);
        Ok(backend)
    }
}

fn is_v6(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(_))
}

#[async_trait]
impl ChallengeProvider for FirewallProvider {
    fn name(&self) -> &'static str {
        "firewall"
    }

    async fn apply(
        &self,
        ip: IpAddr,
        verdict: Verdict,
        opts: &EdgeOptions,
    ) -> sentry_core::Result<()> {
        // Final never-ban guard (F7.2): trusted IPs are refused even when a
        // manual block slipped past the pipeline.
        if let Some(trust) = &self.trust {
            if trust.is_never_ban(ip) {
                debug!(ip = %ip, "firewall ban refused for trusted ip");
                return Ok(());
            }
        }
        let ttl = if opts.ttl.is_zero() {
            self.cfg.ttl
        } else {
            opts.ttl
        };
        let ttl = match verdict {
            Verdict::RateLimit => self.cfg.rate_limit_ttl.min(ttl),
            _ => ttl,
        };
        self.ban(ip, ttl.as_secs())
            .await
            .map_err(sentry_core::CoreError::Config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_provision_script_shape() {
        let script = nft_provision_script("sentry", "sentry_blocks_v4", false);
        assert!(script.contains("table ip sentry"));
        assert!(script.contains("delete table ip sentry"));
        assert!(script.contains("type ipv4_addr; flags timeout;"));
        assert!(script.contains("ip saddr @sentry_blocks_v4 drop"));
        assert!(script.contains("priority -1"));
        let v6 = nft_provision_script("sentry", "sentry_blocks_v6", true);
        assert!(v6.contains("table ip6 sentry"));
        assert!(v6.contains("type ipv6_addr"));
        assert!(v6.contains("ip6 saddr"));
    }

    #[test]
    fn nft_ban_unban_args() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let ban = nft_ban_cmd("sentry", "sentry_blocks_v4", ip, 86400);
        assert_eq!(ban.program, "nft");
        assert_eq!(ban.args[0], "add");
        assert_eq!(ban.args[5], "{ 198.51.100.7 timeout 86400s }");
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(nft_ban_cmd("sentry", "s", v6, 60).args[2], "ip6");
        assert_eq!(nft_unban_cmd("sentry", "s", ip).args[0], "delete");
    }

    #[test]
    fn parses_nft_json_elements() {
        let json = r#"{"nftables":[
            {"metainfo":{"version":"1.0.9"}},
            {"set":{"family":"ip","name":"blocks_v4","flags":["timeout"],
              "elem":[{"elem":{"val":"1.2.3.4","timeout":86395000}},{"elem":{"val":"5.6.7.8","timeout":1000}}]}}
        ]}"#;
        let elems = parse_nft_set_elements(json);
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0], ("1.2.3.4".parse().unwrap(), Some(86395)));
        assert_eq!(elems[1], ("5.6.7.8".parse().unwrap(), Some(1)));
        assert!(parse_nft_set_elements("not json").is_empty());
    }

    #[test]
    fn parses_ipset_members() {
        let out =
            "Name: sentry_blocks_v4\nType: hash:ip\nMembers:\n1.2.3.4 timeout 86395\n5.6.7.8\n";
        let elems = parse_ipset_members(out);
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0], ("1.2.3.4".parse().unwrap(), Some(86395)));
        assert_eq!(elems[1], ("5.6.7.8".parse().unwrap(), None));
    }

    #[test]
    fn ipset_and_firewalld_cmds() {
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            ipset_add_cmd("s4", ip, 600).args,
            vec!["add", "s4", "198.51.100.7", "timeout", "600", "-exist"]
        );
        assert_eq!(ipset_rule_check_cmd("s4", false).program, "iptables");
        assert_eq!(ipset_rule_check_cmd("s4", false).args[1], "-C");
        assert_eq!(ipset_rule_insert_cmd("s4", true).program, "ip6tables");
        let fw = firewalld_add_cmd("s4", ip);
        assert_eq!(fw.program, "firewall-cmd");
        assert!(fw.args.contains(&"198.51.100.7".to_string()));
    }

    #[test]
    fn parses_firewalld_entries() {
        let out = "198.51.100.7\n203.0.113.9\nnot-an-ip\n";
        let entries = parse_firewalld_entries(out);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|(_, t)| t.is_none()));
    }

    #[test]
    fn backend_parse() {
        assert_eq!(FirewallBackend::parse("auto"), Some(None));
        assert_eq!(
            FirewallBackend::parse("nftset"),
            Some(Some(FirewallBackend::Nftables))
        );
        assert_eq!(
            FirewallBackend::parse("firewalld"),
            Some(Some(FirewallBackend::Firewalld))
        );
        assert_eq!(FirewallBackend::parse("pf"), None);
    }

    #[tokio::test]
    async fn trusted_ip_is_refused() {
        let mut ts = sentry_core::TrustSet::default();
        ts.add_proxies(std::iter::empty());
        let trust = sentry_core::SharedTrustSet::new(
            sentry_core::TrustSet::from_config(&sentry_core::config::RealIpConfig {
                trusted_ips: vec!["203.0.113.99".into()],
                cloudflare: false,
                ..Default::default()
            })
            .unwrap(),
        );
        let provider = FirewallProvider::new(FirewallConfig::default(), Some(trust));
        let ip: IpAddr = "203.0.113.99".parse().unwrap();
        let opts = EdgeOptions {
            ttl: Duration::from_secs(3600),
            mode: None,
        };
        provider.apply(ip, Verdict::Block, &opts).await.unwrap();
        // Nothing provisioned, nothing executed — the guard refused first.
        assert!(provider.resolved_backend().is_none());
    }
}
