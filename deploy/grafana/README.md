# Grafana dashboard for Sentry

Ready-made dashboard (`sentry-dashboard.json`) combining the Prometheus
aggregates with the per-event log exposed by the daemon's `[metrics]`
HTTP server.

| Panel | Source |
| --- | --- |
| Events / sec, blocks / sec, fast-path denials, block table size | Prometheus |
| Events by risk level, top signal kinds, actions, verdict latency | Prometheus |
| **Recent events (live log)** — ip, method, path, status, verdict, level, score, country, ASN, signals | `GET /api/events` (Infinity datasource) |

## Setup

1. **Prometheus scrape**: point your Prometheus (or Grafana Agent/Alloy) at
   the daemon's `[metrics]` address (`host:port`, default `0.0.0.0:9100`),
   e.g.:

   ```yaml
   scrape_configs:
     - job_name: sentry
       static_configs:
         - targets: ["sentry-host:9100"]
   ```

2. **Prometheus datasource** in Grafana (the dashboard asks for it on
   import — pick yours in the `Prometheus` variable).

3. **Infinity datasource** for the event log panel: install the
   [yesoreyeram-infinity-datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/)
   plugin, create a datasource, and select it in the `Infinity` variable
   on import. The panel queries:

   ```
   http://sentry-host:9100/api/events?limit=100
   ```

4. Import `sentry-dashboard.json` (Dashboards → New → Import).

## `/api/events` reference

Served by the daemon's metrics server, alongside `/metrics`.

| Param | Meaning |
| --- | --- |
| `limit` | Max events returned (1–1024, default 100), newest first |
| `level` | Filter by risk level: `info` `low` `medium` `high` `critical` |
| `verdict` | Filter by verdict: `allow` `rate_limit` `challenge` `block` `quarantine` |

> The dashboard's Infinity panel uses plain JSON auto-detect — no
> `root_selector` / explicit `columns` in the query. Infinity ≥ 4 dropped
> JSONPath root selectors and ignores explicit column lists on `json`
> queries; auto-detect plus the stable row schema below is version-proof.

Each row: `ts` (RFC 3339), `ip`, `source`, `protocol`, `method`, `path`,
`host`, `status`, `user_agent`, `verdict`, `risk_level`, `score`,
`country`, `asn`, `rule_hit`, `signals[]` (`kind`, `weight`, `detail`).
Every key is always present (`null` when not applicable — the schema is
stable across protocols, so consumers that infer columns from the first
row, like the Grafana Infinity datasource, see all 16 fields). Fields
absent for the queried protocol are `null` (e.g. `path`/`status` on TCP
SYN events).
The buffer holds the **last 1024 events in memory** — for full history use
the `events` table in Postgres (Grafana Postgres datasource) or `sentry
export siem`.

## Security notes

- The `[metrics]` server has **no authentication** (same trust domain as
  `/metrics`); `/api/events` exposes client IPs and request paths. Keep the
  port on an internal network — the default bind is fine for LAN/VPC
  setups, but do not expose it to the internet.
- For authenticated access to the same data, `sentry serve` exposes
  `/api/events` behind `[server.auth]` (token/password) — an Infinity
  datasource with a custom header (`Authorization: Bearer <token>`) works
  against that endpoint too.
- Longer-term retention of per-event logs belongs in Loki/Postgres, not in
  this ring buffer.
