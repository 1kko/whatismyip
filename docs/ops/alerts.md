# Production alerts

Two layers tell someone when ip.1kko.com is unhealthy:

1. **`healthz-probe` workflow** (in this repo, active once merged). It checks
   `/healthz` from outside every 15 minutes, and a failing run emails the owner.
2. **Three SigNoz alerts**, defined below and **not created yet**. They are
   kept here so the queries can be reviewed before anyone creates them in
   SigNoz by hand.

Both exist because, before them, nothing told anyone about a problem.
`/healthz` answered `"ok"` unconditionally, and SigNoz had no alert rules and
no notification channels. GeoIP stuck on its 2026-06-05 build, PTR timeouts and
AFRINIC RDAP timeouts all showed up in telemetry, and no one was notified.

## 1. External probe: `.github/workflows/healthz-probe.yml`

| | |
|---|---|
| Runs | cron `7,22,37,52 * * * *`, plus manual dispatch |
| Where | GitHub-hosted `ubuntu-latest`. Not the self-hosted runner, which sits on the Coolify host: it would still reach a service the internet cannot, and it would go down with the host it watches. |
| Checks | `GET https://ip.1kko.com/healthz` |
| A check fails when | there is no HTTP answer, the status is not 200, the body has no `status`, or `status` is not `"ok"` (so `degraded` fails it too) |
| The run fails when | all 4 checks fail, spaced 4 minutes apart (12 minutes in all) |
| Who is told | whoever last changed the workflow's cron line. GitHub emails them about failed scheduled runs under its default Actions notification settings (Settings → Notifications → Actions). |
| Token | none (`permissions: {}`). It uses no actions, so there is nothing to pin. |

**Why `degraded` fails the run.** The SigNoz alerts below don't exist yet, so
this probe is the only thing that can report a GeoIP feed going stale or an RDAP
registry going down. The container's own `HEALTHCHECK` deliberately ignores
`degraded`, because a restart fixes neither problem.

**Why 4 checks over 12 minutes.** The RDAP circuit breaker skips a failing
server for 10 minutes and then clears. A run that lasts longer than that
cooldown doesn't send email over one blip, and it rides out the container swap
during a deploy. A real outage still fails every check.

**Limits.**

- GitHub delays scheduled runs under load and sometimes drops them, so a
  15-minute cron is a best effort.
- Detection takes 12 to 27 minutes: the 12-minute run, plus up to 15 minutes
  until the next run.
- In a public repository, GitHub disables scheduled workflows after 60 days
  without repository activity. Re-enable the workflow from the Actions tab if
  that happens.
- A failing run sends one email per run, up to 4 an hour. During a long
  `degraded` episode, either fix the cause or disable the workflow until it is
  fixed.

The `reasons` codes the probe prints are listed in README → `GET /healthz`.

## 2. SigNoz alerts (create by hand)

### Before you start

- **Notification channel.** SigNoz had no notification channels on
  2026-10-09. Create one first (Settings → Alert Channels, e.g. email to the
  owner) and select it on every alert below. The JSON blocks call it
  `<channel>`.
- **Alert 1 depends on this change.** "No server spans" only works once the
  container `HEALTHCHECK` calls `GET /healthz` every 30 seconds, which this
  change adds. Before it, real traffic alone (about 260 server spans a day as
  of 2026-10-09) routinely went more than 15 minutes without a span. Deploy first. Then check
  that `GET /healthz` shows about 30 spans per 15 minutes before you create
  alert 1.
- The JSON blocks follow the SigNoz v2alpha1 rule shape that the SigNoz MCP
  `signoz_create_alert` tool takes. They have not been submitted to SigNoz, so
  check each saved rule in the UI against the table above it.

### What the queries rely on

Every name below was checked against production with read-only queries on
2026-10-09.

- **Resource attributes.** Every span and log carries
  `service.name = 'whatismyip-backend'` and
  `deployment.environment = 'production'`. Every alert filters on both.
- **HTTP attribute names.** The OTel instrumentation (`opentelemetry-*`
  0.62b0) emits the older HTTP semantic conventions, so the attributes are
  `http.method`, `http.route`, `http.status_code`, `http.url` and
  `http.target`. They are not `http.request.method` or
  `http.response.status_code`.
- **Query strings.** `http.url` includes the query string (`?subdomains=...`).
  `http.target` is the path alone.
- **Server spans** are named after the route: `GET /{domain_ip}`, `GET /`,
  `POST /mcp`, `GET /healthz`, `GET /static`.
- **Client spans** come only from `requests`, which whoisit uses. That covers
  the RDAP servers and the IANA bootstrap host `data.iana.org`. crt.sh, the
  GeoLite2 downloads and the public suffix list all go through `urllib`, which
  has no instrumentation, so they produce no spans. SigNoz's derived column
  `external_http_url` holds a client span's host, e.g. `rdap.arin.net` or
  `rdap.verisign.com`.
- **What counts as an RDAP failure.** An RDAP `404`, which means "not
  registered", sets `hasError = true` on its client span, but it is a
  successful answer. So the RDAP alert counts failures by status code instead,
  the same way the breaker does in `rdap._is_server_failure`: no status at all
  (a timeout, a refused connection, a TLS or DNS error), `429`, or `5xx`.
- **Why the alerts use spans, not logs.** Log records carry only the message
  body, with no `code.*` attributes, so a log-based alert would have to match
  message text.

### Alert 1: no server spans for 15 minutes

Fires when the process is dead or hung, the container is stopped, or the OTLP
export path (exporter, collector, ingestion) is broken. It does not fire when
the container is fine but unreachable from the internet. The probe covers that
case.

| Field | Value |
|---|---|
| Type | Traces-based, threshold rule |
| Query A | `count()` |
| Filter | `service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Server'` |
| Group by | none |
| Condition | **Missing data**: "Notify when data is missing for **15 min**" (alert on absent) |
| Evaluation | rolling window 15m, every 1m |
| Severity | critical |

Use the missing-data option, not a `count() < 1` threshold. A window with no
matching spans returns no series at all rather than a 0, so a below-threshold
condition never gets anything to compare.

```json
{
  "alert": "whatismyip: no server spans for 15 minutes",
  "alertType": "TRACES_BASED_ALERT",
  "ruleType": "threshold_rule",
  "description": "No server span from whatismyip-backend (production) in 15 minutes. The container HEALTHCHECK alone produces one every 30s, so the process, the container, or the telemetry pipeline is down.",
  "labels": {"severity": "critical", "service": "whatismyip-backend", "environment": "production"},
  "annotations": {
    "summary": "whatismyip-backend sent no server spans for 15 minutes",
    "description": "Check https://ip.1kko.com/healthz and the Coolify container. If /healthz answers, the OTLP export path is broken."
  },
  "evaluation": {"kind": "rolling", "spec": {"evalWindow": "15m0s", "frequency": "1m0s"}},
  "condition": {
    "compositeQuery": {
      "queryType": "builder",
      "panelType": "graph",
      "queries": [
        {
          "type": "builder_query",
          "spec": {
            "name": "A",
            "signal": "traces",
            "stepInterval": 60,
            "aggregations": [{"expression": "count()"}],
            "filter": {"expression": "service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Server'"}
          }
        }
      ]
    },
    "selectedQueryName": "A",
    "alertOnAbsent": true,
    "absentFor": 15
  },
  "preferredChannels": ["<channel>"]
}
```

Check `absentFor` in the saved rule. SigNoz's UI takes it in minutes (15), but
the MCP tool documents the field in milliseconds (900000). Whichever unit the
server stores, the saved rule must read "15 minutes".

### Alert 2: successful lookups slower than 8 s at p95

Fires when the lookups that succeed get slow: a resolver, an RDAP server or a
TLS handshake eating its whole budget.

| Field | Value |
|---|---|
| Type | Traces-based, threshold rule |
| Query A | `p95(durationNano)` |
| Filter | `service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Server' AND http.method = 'GET' AND http.route IN ('/', '/{domain_ip}') AND http.status_code = 200 AND http.url NOT LIKE '%subdomains=%'` |
| Step | 3600 s, so each point is one hour's p95 |
| Y unit | nanoseconds (`ns`) |
| Condition | above **8 s**, at least once |
| Evaluation | rolling window 1h, every 5m |
| Severity | warning |

The filter leaves out the following:

- **`?subdomains=` requests.** On a cache miss they wait 3-20 s for crt.sh, so
  they would set the p95 by themselves.
- **`HEAD`.** It runs no lookup.
- **Rejected lookups (400, 403, 429).** They return fast and say nothing about
  lookup latency.
- **MCP `tools/call`.** It runs the same `gather()` path. Add it later if MCP
  traffic grows.

Baseline: in the 7 days to 2026-10-09, the p95 of successful lookups was
5.4 s for `GET /`, which waits for the visitor's own RDAP, and 1.5 s for
`GET /{domain_ip}`. No successful lookup took over 8 s, so this alert would
have stayed quiet. Traffic is low (about 5 lookups an hour), so an hour's p95 is
close to its slowest lookup. Expect it to fire on a single pathological lookup
now and then. Raise the threshold before you lengthen the window.

```json
{
  "alert": "whatismyip: successful-lookup p95 above 8s",
  "alertType": "TRACES_BASED_ALERT",
  "ruleType": "threshold_rule",
  "description": "Hourly p95 of successful GET / and GET /{domain_ip} (excluding ?subdomains=) is above 8 seconds.",
  "labels": {"severity": "warning", "service": "whatismyip-backend", "environment": "production"},
  "annotations": {
    "summary": "Successful lookups are slow: p95 {{$value}}",
    "description": "Look at the slowest GET /{domain_ip} traces in SigNoz: which leg (DNS, RDAP, WHOIS, TLS) ate the time."
  },
  "evaluation": {"kind": "rolling", "spec": {"evalWindow": "1h0m0s", "frequency": "5m0s"}},
  "condition": {
    "compositeQuery": {
      "queryType": "builder",
      "panelType": "graph",
      "unit": "ns",
      "queries": [
        {
          "type": "builder_query",
          "spec": {
            "name": "A",
            "signal": "traces",
            "stepInterval": 3600,
            "aggregations": [{"expression": "p95(durationNano)"}],
            "filter": {"expression": "service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Server' AND http.method = 'GET' AND http.route IN ('/', '/{domain_ip}') AND http.status_code = 200 AND http.url NOT LIKE '%subdomains=%'"}
          }
        }
      ]
    },
    "selectedQueryName": "A",
    "thresholds": {
      "kind": "basic",
      "spec": [
        {"name": "warning", "target": 8, "targetUnit": "s", "matchType": "1", "op": "1", "recoveryTarget": null, "channels": ["<channel>"]}
      ]
    }
  }
}
```

### Alert 3: RDAP error rate above 30% over an hour

Fires when the RDAP servers this service queries are failing. This is the
AFRINIC-timeout case that was visible only in telemetry.

| Field | Value |
|---|---|
| Type | Traces-based, threshold rule with a formula |
| Query A (failures) | `count()` where `service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Client' AND external_http_url != 'data.iana.org' AND hasError = true AND (http.status_code >= 500 OR http.status_code = 429 OR http.status_code NOT EXISTS)` |
| Query B (all RDAP requests) | `count()` where `service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Client' AND external_http_url != 'data.iana.org'` |
| Formula F1 | `A * 100 / B` (alert on F1; hide A and B) |
| Step | 3600 s |
| Y unit | percent |
| Condition | above **30**, at least once |
| Evaluation | rolling window 1h, every 5m |
| Severity | warning |

- **`data.iana.org` is excluded.** It is the bootstrap registry, not an RDAP
  server.
- **No RDAP requests means no alert.** An hour with no requests leaves B
  empty, so F1 has no value.
- **An open breaker sends no requests.** While a host is skipped, its
  failures stop adding to A. `/healthz` reports that state as
  `rdap_breaker_open`, which the probe picks up.
- **Low volume makes the ratio jumpy.** There were 115 RDAP requests in the
  30 days to 2026-10-09: 100 × `200`, 14 × `404` and 1 × `400`. None matched
  query A, so this alert would have stayed quiet. At a few requests an hour,
  though, one timeout among three requests is 33%. If that proves noisy,
  switch to a count alert, `A >= 3` per hour, which needs more than one
  failure to fire.

```json
{
  "alert": "whatismyip: RDAP error rate above 30%",
  "alertType": "TRACES_BASED_ALERT",
  "ruleType": "threshold_rule",
  "description": "Over the last hour, more than 30% of RDAP requests failed at the server: transport error, 429 or 5xx. 404 (not registered) and 400 are answers, not failures.",
  "labels": {"severity": "warning", "service": "whatismyip-backend", "environment": "production"},
  "annotations": {
    "summary": "RDAP error rate {{$value}} over the last hour",
    "description": "Group query A by external_http_url in SigNoz to see which registry; /healthz lists breakers that are open."
  },
  "evaluation": {"kind": "rolling", "spec": {"evalWindow": "1h0m0s", "frequency": "5m0s"}},
  "condition": {
    "compositeQuery": {
      "queryType": "builder",
      "panelType": "graph",
      "unit": "percent",
      "queries": [
        {
          "type": "builder_query",
          "spec": {
            "name": "A",
            "signal": "traces",
            "stepInterval": 3600,
            "disabled": true,
            "aggregations": [{"expression": "count()"}],
            "filter": {"expression": "service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Client' AND external_http_url != 'data.iana.org' AND hasError = true AND (http.status_code >= 500 OR http.status_code = 429 OR http.status_code NOT EXISTS)"}
          }
        },
        {
          "type": "builder_query",
          "spec": {
            "name": "B",
            "signal": "traces",
            "stepInterval": 3600,
            "disabled": true,
            "aggregations": [{"expression": "count()"}],
            "filter": {"expression": "service.name = 'whatismyip-backend' AND deployment.environment = 'production' AND kind_string = 'Client' AND external_http_url != 'data.iana.org'"}
          }
        },
        {
          "type": "builder_formula",
          "spec": {"name": "F1", "expression": "A * 100 / B"}
        }
      ]
    },
    "selectedQueryName": "F1",
    "thresholds": {
      "kind": "basic",
      "spec": [
        {"name": "warning", "target": 30, "targetUnit": "percent", "matchType": "1", "op": "1", "recoveryTarget": null, "channels": ["<channel>"]}
      ]
    }
  }
}
```

### Not alerted on yet

- **GeoIP build age is not a SigNoz alert.** Nothing exports the age as
  telemetry. `/healthz` reports it as `geoip_build_stale` once a build is older
  than `GEOIP_MAX_BUILD_AGE_DAYS` (21), and the probe catches that.
  Production's builds were 1 and 3 days old on 2026-10-09.
- **Docker DNS PTR timeouts are not alerted on.** They are logged at WARNING
  (`Reverse lookup failed for IP ...`) on purpose, so error metrics stay clean.
  A log-based alert on that text is possible, but per-target timeouts are
  normal, so it would need a rate threshold tuned against real data first.
