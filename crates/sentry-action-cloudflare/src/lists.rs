//! Cloudflare IP Lists + custom firewall rule — IPv6 prefix blocking (F2.14).
//!
//! IP Access Rules accept exact addresses only, so a /128 rule misses an
//! IPv6 host that rotates its interface ID within its /64 (privacy
//! extensions). When `ipv6_prefix` is configured (e.g. 64), block/rate-limit
//! verdicts for IPv6 clients are applied to the address's prefix network via
//! an account-level IP List (name configurable, `sentry_blocks` by default)
//! referenced by a single zone custom rule:
//!
//! ```text
//!   (ip.src in $sentry_blocks)  →  action: block
//! ```
//!
//! The list and the rule are provisioned idempotently at startup reconcile.
//! TTL bookkeeping reuses the access-rules note format on each item's
//! `comment` (`sentry:<created_unix>:<ttl_secs>`), so expiry survives
//! restarts. Item creation is idempotent — posting an existing IP overwrites
//! its comment — unlike access rules (CF error 10009).
//!
//! Verdict routing: `Block`/`RateLimit` on IPv6 → prefix list item (the rule
//! action is `block`; per-item modes are not expressible with a single rule,
//! matching the access-rules `rate_limit` → `block` fallback). `Challenge`
//! keeps an exact-address access rule — challenges are interactive and
//! per-browser. IPv4 always uses access rules (/32 already covers rotation).
//!
//! The token needs `Account → Filter Lists: Edit` (list CRUD) and
//! `Zone → Rulesets: Edit` (custom rule), besides the access-rules
//! permission. Provisioning failures (missing permission, plan limit)
//! soft-disable list mode with a warning — access rules keep working — and
//! the reaper retries provisioning on its next cycle. List failures never
//! trip the insert circuit breaker.
//!
//! Item operations are asynchronous at the API (queued FIFO per list);
//! Sentry treats the HTTP response as the operation's acceptance without
//! polling `bulk_operations` status — eventual consistency is acceptable.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use sentry_core::analysis::Verdict;
use sentry_core::error::{CoreError, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

use super::{
    build_note, is_sentry_note, plan_rule, unix_now, CloudflareProvider, PlannedAction,
    ReconcileReport,
};

/// Description tagging the custom rule provisioned by Sentry. Used to find
/// (and idempotently update) our rule inside the phase entrypoint.
pub(crate) const CUSTOM_RULE_DESCRIPTION: &str = "sentry: ipv6 prefix blocks";

/// Description of the IP List created by Sentry.
pub(crate) const LIST_DESCRIPTION: &str =
    "Managed by Sentry — IPv6 prefix blocks (items expire via reaper)";

/// Page size when listing items (cursor-paginated endpoint).
const ITEMS_PER_PAGE: u32 = 100;

/// Hard cap on item pagination loops (defensive; 100 pages × 100 items).
const MAX_ITEM_PAGES: u32 = 100;

impl CloudflareProvider {
    /// Whether IPv6 prefix blocking is configured.
    pub fn list_mode_enabled(&self) -> bool {
        self.cfg.ipv6_prefix.is_some()
    }

    /// Whether IPv6 prefix blocking is configured and not soft-disabled.
    pub(crate) fn lists_active(&self) -> bool {
        self.cfg.ipv6_prefix.is_some()
            && !self
                .lists_disabled
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Soft-disable list mode (permission or plan failure). Access rules are
    /// unaffected; the reaper retries provisioning on its next cycle.
    pub(crate) fn disable_lists(&self, reason: &str) {
        if !self
            .lists_disabled
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            warn!(
                reason,
                "cloudflare ip list mode disabled — falling back to exact-address access rules (retried by the reaper)"
            );
        }
    }

    /// Operational summary for `sentry cloudflare status`: the managed
    /// list's item count, when list mode is enabled and the list is
    /// reachable.
    pub async fn list_summary(&self) -> Option<(String, usize)> {
        if !self.list_mode_enabled() {
            return None;
        }
        let account = self.resolve_account().await?;
        let id = self.get_list_id(&account).await.ok()??;
        let count = self.list_items(&account, &id).await.ok()?.len();
        Some((self.cfg.list_name.clone(), count))
    }

    fn account_lists_url(&self, account: &str) -> String {
        format!("https://api.cloudflare.com/client/v4/accounts/{account}/rules/lists")
    }

    /// Resolve the account id: config/env override first, then the value
    /// cached from a zone lookup, then a fresh zone lookup.
    pub(crate) async fn resolve_account(&self) -> Option<String> {
        if let Some(a) = self.cfg.account.clone() {
            return Some(a);
        }
        if let Some(a) = self.account_id.read().await.clone() {
            return Some(a);
        }
        let info = self.verify().await.ok()?;
        if !info.token_valid {
            return None;
        }
        if let Some(ref a) = info.account_id {
            *self.account_id.write().await = Some(a.clone());
        }
        info.account_id
    }

    /// Resolve the IP List id, provisioning list + custom rule on first use.
    /// Returns `None` (and soft-disables list mode) when provisioning fails.
    pub(crate) async fn resolve_list_id(&self, account: &str) -> Option<String> {
        if let Some(id) = self.list_id.read().await.clone() {
            return Some(id);
        }
        let id = match self.find_or_create_list(account).await {
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, "cloudflare ip list provisioning failed");
                self.disable_lists("ip list provisioning failed");
                return None;
            }
        };
        if let Err(e) = self.ensure_custom_rule().await {
            warn!(error = %e, "cloudflare custom rule provisioning failed");
            self.disable_lists("custom rule provisioning failed");
            return None;
        }
        *self.list_id.write().await = Some(id.clone());
        Some(id)
    }

    /// Ensure a /<prefix> item for `v6` exists in the list. Returns `false`
    /// when list mode is unavailable (caller falls back to an exact-address
    /// access rule for the original IP).
    pub(crate) async fn apply_list_item(&self, v6: Ipv6Addr, prefix: u8, ttl: Duration) -> bool {
        let key = normalize_v6(v6, prefix);
        if self.is_cached(key).await {
            return true;
        }
        let Some(account) = self.resolve_account().await else {
            self.disable_lists("account id unavailable (set SENTRY_CF_ACCOUNT or grant zone read)");
            return false;
        };
        let Some(list_id) = self.resolve_list_id(&account).await else {
            return false;
        };
        let IpAddr::V6(net) = key else {
            return false;
        };
        let cidr = format!("{net}/{prefix}");

        self.record(key, ttl).await;
        match self
            .add_item(&account, &list_id, &cidr, &build_note(ttl.as_secs()))
            .await
        {
            Ok(()) => {
                self.register_success();
                info!(cidr = %cidr, "cloudflare ip list item ensured");
                true
            }
            Err(e) => {
                warn!(error = %e, cidr = %cidr, "cloudflare add list item failed — falling back to access rule");
                self.evict(key).await;
                if format!("{e}").contains("HTTP 404") {
                    // The list vanished at the edge: drop the cached id so the
                    // next resolve re-creates it.
                    *self.list_id.write().await = None;
                }
                false
            }
        }
    }

    /// Startup reconcile of the list path: provision list + custom rule,
    /// adopt live items into the dedup cache, delete expired ones.
    pub(crate) async fn reconcile_lists(&self, report: &mut ReconcileReport) {
        if self.cfg.ipv6_prefix.is_none() {
            return;
        }
        let Some(account) = self.resolve_account().await else {
            self.disable_lists("account id unavailable (set SENTRY_CF_ACCOUNT or grant zone read)");
            report.lists_disabled = true;
            return;
        };
        let Some(list_id) = self.resolve_list_id(&account).await else {
            report.lists_disabled = true;
            return;
        };

        let items = match self.list_items(&account, &list_id).await {
            Ok(items) => items,
            Err(e) => {
                warn!(error = %e, "cloudflare reconcile: list items fetch failed");
                return;
            }
        };
        report.list_items = items.len();

        let now = unix_now();
        let mut expired: Vec<(String, Option<IpAddr>)> = Vec::new();
        for item in items {
            if !is_sentry_note(item.comment.as_deref()) {
                continue;
            }
            let key = parse_list_item_net(&item.ip);
            match plan_rule(item.comment.as_deref(), now, self.cfg.ttl.as_secs()) {
                PlannedAction::Delete => expired.push((item.id, key)),
                PlannedAction::Adopt {
                    remaining_secs,
                    restamp,
                } => {
                    // Posting an existing IP overwrites its comment, so a
                    // legacy note is migrated by re-posting the item.
                    if restamp {
                        match self
                            .add_item(
                                &account,
                                &list_id,
                                &item.ip,
                                &build_note(self.cfg.ttl.as_secs()),
                            )
                            .await
                        {
                            Ok(()) => report.list_restamped += 1,
                            Err(e) => warn!(
                                error = %e,
                                item = %item.ip,
                                "cloudflare reconcile: item note migration failed"
                            ),
                        }
                    }
                    if let Some(k) = key {
                        if remaining_secs > 0 {
                            self.record(k, Duration::from_secs(remaining_secs)).await;
                            report.list_adopted += 1;
                        }
                    }
                }
                PlannedAction::Skip => {}
            }
        }

        if !expired.is_empty() {
            let ids: Vec<String> = expired.iter().map(|(id, _)| id.clone()).collect();
            match self.delete_items(&account, &list_id, &ids).await {
                Ok(()) => {
                    for (_, key) in &expired {
                        if let Some(k) = key {
                            self.forget(*k).await;
                        }
                    }
                    report.list_deleted = expired.len();
                }
                Err(e) => {
                    warn!(error = %e, "cloudflare reconcile: delete expired list items failed")
                }
            }
        }
    }

    /// Delete the list items whose encoded TTL has lapsed. Retries list
    /// provisioning first when list mode was soft-disabled (self-heal).
    pub(crate) async fn reap_list_items(&self) -> Result<usize> {
        if self
            .lists_disabled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            self.list_id.write().await.take();
            let Some(account) = self.resolve_account().await else {
                return Ok(0);
            };
            if self.resolve_list_id(&account).await.is_none() {
                return Ok(0);
            }
            self.lists_disabled
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }

        let Some(account) = self.resolve_account().await else {
            return Ok(0);
        };
        let Some(list_id) = self.list_id.read().await.clone() else {
            return Ok(0);
        };
        let items = self.list_items(&account, &list_id).await?;

        let now = unix_now();
        let mut expired: Vec<(String, Option<IpAddr>)> = Vec::new();
        for item in items {
            if !is_sentry_note(item.comment.as_deref()) {
                continue;
            }
            if plan_rule(item.comment.as_deref(), now, self.cfg.ttl.as_secs())
                != PlannedAction::Delete
            {
                continue;
            }
            expired.push((item.id, parse_list_item_net(&item.ip)));
        }
        if expired.is_empty() {
            return Ok(0);
        }

        let ids: Vec<String> = expired.iter().map(|(id, _)| id.clone()).collect();
        self.delete_items(&account, &list_id, &ids).await?;
        for (_, key) in &expired {
            if let Some(k) = key {
                self.forget(*k).await;
            }
        }
        Ok(expired.len())
    }

    /// Find the managed IP List by name, creating it when absent.
    /// Returns the list id.
    pub(crate) async fn find_or_create_list(&self, account: &str) -> Result<String> {
        if let Some(id) = self.get_list_id(account).await? {
            return Ok(id);
        }
        let url = self.account_lists_url(account);
        let body = json!({
            "name": self.cfg.list_name,
            "kind": "ip",
            "description": LIST_DESCRIPTION,
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.cfg.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("create ip list: {e}")))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            let id = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("result")?.get("id")?.as_str().map(str::to_string));
            return match id {
                Some(id) => {
                    info!(list = %self.cfg.list_name, id = %id, "created cloudflare ip list");
                    Ok(id)
                }
                None => Err(CoreError::Challenge(
                    "create ip list: response missing result.id".into(),
                )),
            };
        }
        // Lost a creation race (or the list appeared meanwhile): re-check.
        if let Some(id) = self.get_list_id(account).await? {
            return Ok(id);
        }
        Err(CoreError::Challenge(format!(
            "create ip list: HTTP {status}: {text}"
        )))
    }

    async fn get_list_id(&self, account: &str) -> Result<Option<String>> {
        let url = self.account_lists_url(account);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.cfg.token)
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("list rules lists: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(CoreError::Challenge(format!(
                "list rules lists: HTTP {status}: {body}"
            )));
        }
        let body: ListsResponse = resp.json().await.unwrap_or_default();
        Ok(body
            .result
            .into_iter()
            .find(|l| l.name == self.cfg.list_name && l.kind == "ip")
            .map(|l| l.id))
    }

    /// List the items of an IP List (cursor-paginated).
    pub(crate) async fn list_items(&self, account: &str, list_id: &str) -> Result<Vec<ListItem>> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_ITEM_PAGES {
            let url = format!("{}/{list_id}/items", self.account_lists_url(account));
            let mut req = self
                .http
                .get(&url)
                .bearer_auth(&self.cfg.token)
                .query(&[("per_page", ITEMS_PER_PAGE.to_string())]);
            if let Some(c) = &cursor {
                req = req.query(&[("cursor", c)]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| CoreError::Challenge(format!("list ip list items: {e}")))?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(CoreError::Challenge(format!(
                    "list ip list items: HTTP {status}: {body}"
                )));
            }
            let body: ItemsResponse = resp.json().await.unwrap_or_default();
            let got = body.result.len();
            all.extend(body.result);
            cursor = body
                .result_info
                .and_then(|i| i.cursors)
                .and_then(|c| c.after)
                .filter(|c| !c.is_empty());
            if cursor.is_none() || got == 0 {
                break;
            }
        }
        Ok(all)
    }

    /// Add (or refresh the comment of) a single item. The API replaces
    /// duplicates and overwrites their comment, so this is idempotent.
    pub(crate) async fn add_item(
        &self,
        account: &str,
        list_id: &str,
        cidr: &str,
        comment: &str,
    ) -> Result<()> {
        let url = format!("{}/{list_id}/items", self.account_lists_url(account));
        let body = json!([{ "ip": cidr, "comment": comment }]);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.cfg.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("add ip list item: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CoreError::Challenge(format!(
                "add ip list item {cidr}: HTTP {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Delete items by id (batch, asynchronous at the API).
    pub(crate) async fn delete_items(
        &self,
        account: &str,
        list_id: &str,
        ids: &[String],
    ) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let url = format!("{}/{list_id}/items", self.account_lists_url(account));
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.cfg.token)
            .json(&delete_items_body(ids))
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("delete ip list items: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CoreError::Challenge(format!(
                "delete ip list items: HTTP {status}: {text}"
            )));
        }
        Ok(())
    }

    /// Ensure the zone's custom firewall rule referencing the list exists
    /// (and carries our expression/action), preserving any other rules the
    /// zone may have. Works on raw JSON so unknown rule fields survive the
    /// round-trip.
    pub(crate) async fn ensure_custom_rule(&self) -> Result<()> {
        let url = format!(
            "{}/rulesets/phases/http_request_firewall_custom/entrypoint",
            self.zones_url()
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.cfg.token)
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("get custom rules entrypoint: {e}")))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        // 404 = phase entrypoint not deployed yet; other errors surface via
        // the PUT below.
        let mut rules: Vec<Value> = if status.is_success() {
            serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("result")?.get("rules")?.as_array().cloned())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        if !merge_custom_rule(&mut rules, custom_rule_json(&self.cfg.list_name)) {
            return Ok(());
        }

        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.cfg.token)
            .json(&json!({ "rules": rules }))
            .send()
            .await
            .map_err(|e| CoreError::Challenge(format!("put custom rules entrypoint: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(CoreError::Challenge(format!(
                "put custom rules entrypoint: HTTP {status}: {text}"
            )));
        }
        info!(list = %self.cfg.list_name, "cloudflare custom rule ensured");
        Ok(())
    }
}

/// A Cloudflare rules list (subset of fields).
#[derive(Debug, Deserialize)]
struct IpList {
    id: String,
    name: String,
    #[serde(default)]
    kind: String,
}

#[derive(Debug, Default, Deserialize)]
struct ListsResponse {
    #[serde(default)]
    result: Vec<IpList>,
}

/// A single IP List item (subset of fields).
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ListItem {
    pub id: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ItemsResponse {
    #[serde(default)]
    result: Vec<ListItem>,
    #[serde(default)]
    result_info: Option<ItemsPageInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct ItemsPageInfo {
    #[serde(default)]
    cursors: Option<ItemsCursors>,
}

#[derive(Debug, Default, Deserialize)]
struct ItemsCursors {
    #[serde(default)]
    after: Option<String>,
}

/// The custom rule Sentry provisions, referencing the managed list.
pub(crate) fn custom_rule_json(list_name: &str) -> Value {
    json!({
        "description": CUSTOM_RULE_DESCRIPTION,
        "expression": format!("ip.src in ${list_name}"),
        "action": "block",
        "enabled": true,
    })
}

/// Insert or update our custom rule in `rules`, preserving everything else
/// (and the id of an existing Sentry rule). Returns whether `rules` changed.
pub(crate) fn merge_custom_rule(rules: &mut Vec<Value>, ours: Value) -> bool {
    let ours_expr = ours.get("expression").and_then(Value::as_str);
    for rule in rules.iter_mut() {
        let desc = rule.get("description").and_then(Value::as_str);
        let expr = rule.get("expression").and_then(Value::as_str);
        let is_ours = desc == Some(CUSTOM_RULE_DESCRIPTION) || expr == ours_expr;
        if !is_ours {
            continue;
        }
        if rule_matches_ours(rule, &ours) {
            return false;
        }
        let mut next = ours.clone();
        if let Some(id) = rule.get("id").cloned() {
            next["id"] = id;
        }
        *rule = next;
        return true;
    }
    rules.push(ours);
    true
}

fn rule_matches_ours(rule: &Value, ours: &Value) -> bool {
    ["description", "expression", "action", "enabled"]
        .iter()
        .all(|field| rule.get(field) == ours.get(field))
}

/// Body for the bulk item DELETE call.
pub(crate) fn delete_items_body(ids: &[String]) -> Value {
    json!({ "items": ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>() })
}

/// Mask an IPv6 address down to its /<prefix> network address, used as the
/// dedupe cache key (an `IpAddr` representing the whole prefix). Falls back
/// to the unmasked address on an impossible prefix length.
pub(crate) fn normalize_v6(v6: Ipv6Addr, prefix: u8) -> IpAddr {
    match ipnet::Ipv6Net::new(v6, prefix) {
        Ok(net) => IpAddr::V6(net.network()),
        Err(_) => IpAddr::V6(v6),
    }
}

/// Parse a list item's `ip` field (`"2001:db8::/64"` or a bare address)
/// into the network address used as the dedupe cache key.
pub(crate) fn parse_list_item_net(ip: &str) -> Option<IpAddr> {
    match ip.split_once('/') {
        Some((addr, len)) => {
            let addr: IpAddr = addr.parse().ok()?;
            let len: u8 = len.parse().ok()?;
            match addr {
                IpAddr::V4(a) => ipnet::Ipv4Net::new(a, len)
                    .ok()
                    .map(|n| IpAddr::V4(n.network())),
                IpAddr::V6(a) => ipnet::Ipv6Net::new(a, len)
                    .ok()
                    .map(|n| IpAddr::V6(n.network())),
            }
        }
        None => ip.parse().ok(),
    }
}

/// Whether an IPv6 verdict goes to the IP List (block semantics) instead of
/// an exact-address access rule.
pub(crate) fn v6_uses_list(verdict: Verdict) -> bool {
    matches!(verdict, Verdict::Block | Verdict::RateLimit)
}

/// Extract `(zone_name, account_id)` from a `GET /zones/{id}` response body.
pub(crate) fn parse_zone_lookup(body: &Value) -> (String, Option<String>) {
    let result = body.get("result");
    let zone = result
        .and_then(|r| r.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let account = result
        .and_then(|r| r.get("account"))
        .and_then(|a| a.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string);
    (zone, account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_v6_masks_host_bits() {
        let ip: Ipv6Addr = "2001:db8:abcd:12:1:2:3:4".parse().unwrap();
        assert_eq!(
            normalize_v6(ip, 64),
            "2001:db8:abcd:12::".parse::<IpAddr>().unwrap()
        );
        // Rotation inside the /64 collapses to the same key.
        let rotated: Ipv6Addr = "2001:db8:abcd:12:ffff::dead".parse().unwrap();
        assert_eq!(normalize_v6(ip, 64), normalize_v6(rotated, 64));
        assert_eq!(
            normalize_v6(ip, 48),
            "2001:db8:abcd::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn normalize_v6_identity_on_invalid_prefix() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_v6(ip, 200), IpAddr::V6(ip));
    }

    #[test]
    fn parse_list_item_net_variants() {
        assert_eq!(
            parse_list_item_net("2001:db8:abcd:12::1/64"),
            Some("2001:db8:abcd:12::".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_list_item_net("10.0.0.5/24"),
            Some("10.0.0.0".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_list_item_net("198.51.100.7"),
            Some("198.51.100.7".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parse_list_item_net("not-an-ip"), None);
        assert_eq!(parse_list_item_net("10.0.0.5/99"), None);
    }

    #[test]
    fn v6_uses_list_routes_block_verdicts_only() {
        assert!(v6_uses_list(Verdict::Block));
        assert!(v6_uses_list(Verdict::RateLimit));
        assert!(!v6_uses_list(Verdict::Challenge));
        assert!(!v6_uses_list(Verdict::Allow));
    }

    #[test]
    fn custom_rule_json_shape() {
        let rule = custom_rule_json("sentry_blocks");
        assert_eq!(
            rule.get("expression").and_then(Value::as_str),
            Some("ip.src in $sentry_blocks")
        );
        assert_eq!(rule.get("action").and_then(Value::as_str), Some("block"));
        assert_eq!(
            rule.get("description").and_then(Value::as_str),
            Some(CUSTOM_RULE_DESCRIPTION)
        );
        assert_eq!(rule.get("enabled").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn merge_custom_rule_appends_when_absent() {
        let user_rule = json!({
            "description": "my own rule",
            "expression": "ip.geoip.country eq \"XX\"",
            "action": "managed_challenge",
        });
        let mut rules = vec![user_rule.clone()];
        assert!(merge_custom_rule(
            &mut rules,
            custom_rule_json("sentry_blocks")
        ));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], user_rule);
        assert_eq!(
            rules[1].get("expression").and_then(Value::as_str),
            Some("ip.src in $sentry_blocks")
        );
    }

    #[test]
    fn merge_custom_rule_preserves_id_and_noops_when_current() {
        let mut existing = custom_rule_json("sentry_blocks");
        existing["id"] = json!("abc123");
        let user_rule = json!({ "description": "other", "expression": "true", "action": "log" });
        let mut rules = vec![user_rule.clone(), existing.clone()];
        // Identical managed fields → no change.
        assert!(!merge_custom_rule(
            &mut rules,
            custom_rule_json("sentry_blocks")
        ));
        assert_eq!(rules, vec![user_rule.clone(), existing.clone()]);

        // Stale expression → updated in place, id preserved, user rule intact.
        existing["expression"] = json!("ip.src in $old_name");
        let mut rules = vec![user_rule.clone(), existing];
        assert!(merge_custom_rule(
            &mut rules,
            custom_rule_json("sentry_blocks")
        ));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], user_rule);
        assert_eq!(rules[1].get("id").and_then(Value::as_str), Some("abc123"));
        assert_eq!(
            rules[1].get("expression").and_then(Value::as_str),
            Some("ip.src in $sentry_blocks")
        );
    }

    #[test]
    fn merge_custom_rule_replaces_sentry_expression_rule() {
        // A rule with our expression but a foreign description is still ours
        // (the expression uniquely references our list).
        let stale = json!({
            "description": "renamed by someone",
            "expression": "ip.src in $sentry_blocks",
            "action": "log",
        });
        let mut rules = vec![stale.clone()];
        assert!(merge_custom_rule(
            &mut rules,
            custom_rule_json("sentry_blocks")
        ));
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("description").and_then(Value::as_str),
            Some(CUSTOM_RULE_DESCRIPTION)
        );
        assert_eq!(
            rules[0].get("action").and_then(Value::as_str),
            Some("block")
        );
    }

    #[test]
    fn delete_items_body_shape() {
        let body = delete_items_body(&["a".into(), "b".into()]);
        let items = body.get("items").and_then(Value::as_array).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].get("id").and_then(Value::as_str), Some("a"));
    }

    #[test]
    fn parse_zone_lookup_extracts_account() {
        let body = json!({
            "success": true,
            "result": {
                "name": "example.com",
                "account": { "id": "01a2b3c4d5", "name": "Example Inc" }
            }
        });
        assert_eq!(
            parse_zone_lookup(&body),
            ("example.com".to_string(), Some("01a2b3c4d5".to_string()))
        );

        let missing = json!({ "success": true, "result": { "name": "x.test" } });
        assert_eq!(parse_zone_lookup(&missing), ("x.test".to_string(), None));

        let broken = json!({ "success": false });
        assert_eq!(parse_zone_lookup(&broken), (String::new(), None));
    }
}
