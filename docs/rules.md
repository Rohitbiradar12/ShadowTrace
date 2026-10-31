# Detection rules

Each `rules/*.yaml` file defines one rule. Validate with `python -m app.cli validate-rules`
from `server/`, then restart the server to load changes. Paths can be overridden with
`ST_RULES_DIR` and `ST_INTEL_FILE`. Use absolute paths when overriding them.

```yaml
id: CUSTOM-AUTH-001
title: Repeated failed logins
severity: high
category: auth
mitre: [T1110]
match:
  action: logon_failed
exclude:
  - data.target_user: LAB-PC\approved-test-user
threshold:
  count: 5
  within: 120s
  group_by: [device_id, data.target_user]
response:
  notify: [telegram, email]
```

`match` conditions are ANDed. A bare value means equality. Dotted fields address event
metadata (`data.remote_ip`, `data.parent.name`). Any matching `exclude` block suppresses a
firing; `enabled: false` disables a rule. Missing grouping values do not form a threshold group.
Every threshold is scoped to one device, including when `device_id` is omitted from `group_by`.

Supported operators:

| Kind | Operators |
|---|---|
| Values | `eq`, `ne`, `in`, `not_in`, `exists` |
| Numbers/comparable values | `gt`, `ge`, `lt`, `le` |
| Text | `contains`, `icontains`, `contains_any`, `icontains_any` |
| Prefix/suffix | `startswith`, `istartswith`, `endswith`, `iendswith` |
| Patterns | `regex`, `iregex` |
| Local lists | `in_list`, `not_in_list` |

Examples: `data.remote_port: {in: [4444, 6667]}` and
`data.domain: {in_list: bad_domains}`. `exists` takes a boolean; regexes and unknown
operators/list names are checked when rules load. Write regexes as YAML single-quoted
strings when they contain backslashes. Rules are trusted administrator configuration.
Missing fields never match text/list lookups; `ne` and `not_in` do match missing values.

Without `threshold`, every matching event fires. Thresholds count distinct stored events
inside an inclusive event-time window, including late arrivals; they do not use upload time.
`within` accepts `s`, `m`, or `h`, or use numeric `window_seconds` instead. Windows are bounded
to 24 hours and counts to 10,000. MongoDB supplies window history so process restarts preserve it.

Firings for the same rule/device/group update the same alert within a rolling ten-minute
receipt-time interval (`ST_ALERT_DEDUP_SECONDS`). A resolved/false-positive alert does not
absorb a new firing. Each later qualifying event increments occurrence count once. Replaying
the same uploaded event ID does not increment it. Rule changes apply to new/pending events;
they do not automatically re-evaluate events whose detection cursor has already advanced.

Local lists in `intel/lists.yaml` have `kind` and `values`. Kinds are `domain` (including
subdomains), `ip` (addresses/CIDRs), `sha256`, `url` (exact), `text` (case sensitive), and `path`
(Windows-style case-insensitive subtree matching). The starter pack uses 9 lists, including
USB, Wi-Fi, hash, domain and IP allowlists. Empty allowlists suppress nothing, so tune them
for the lab before enabling external notifications.

Severity is `low`, `medium`, `high`, or `critical`. Omitted `response.notify` sends
high/critical alerts to Telegram and email; other severities remain in the database.
Set `notify: []` for database-only alerts. Each channel's delivery state is retained in the
outbox and visible through `show-alert`/`list-notifications`. Digest messages combine up to
10 pending alerts from one device/channel.

`response.auto_action` can be `lock_workstation` or `kill_process`. It remains a suggestion
unless `ST_AUTO_RESPONSE_ENABLED=true`; endpoint `responses.enabled` and `allowed_actions`
also control execution. The starter rules do not enable automatic actions. Events older than
60 seconds (`ST_AUTO_RESPONSE_MAX_EVENT_AGE_SECONDS`) or more than five seconds in the future
cannot trigger commands. One automatic command is created per deduplicated alert/action;
repeated firings do not repeatedly lock a workstation or kill subsequent processes.

Automatic kill requires the triggering event to be `process/process_started` with
`data.pid`, an absolute `data.exe`, and timezone-aware `data.create_time`. Other event types
cannot supply a kill target. Configure automatic rules narrowly and synchronize endpoint and
server clocks. See [response operation](operations.md#response-commands) for result semantics.
