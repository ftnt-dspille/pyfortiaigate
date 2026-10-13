# Usage, cost & logs

## Pricing a run in one call

Instead of looking up every request's log record, ask the cost API:

```python
import datetime as dt

today = dt.date.today()
spend = faig.cost_summary(today, today, workspace_id=ws_id)
print(spend["totals"]["chargebackSpend"], spend["volume"])

# Who or what spent it
for row in rank_items(faig.cost_rankings(today, today, by="key", limit=10, workspace_id=ws_id)):
    print(row["name"], row["chargebackSpend"])
```

Dates are `date` objects or `"YYYY-MM-DD"`; omitted, the window is the last 30
days. `by` is `key`, `user`, `workspace` or `model`; `usage_*` calls report
requests and tokens, `cost_*` calls report spend. Use `rank_items()` to read
ranking rows: the API answers `items`, `top`/`bottom` lists (`end="both"`), or
only `meta` when nothing was used in the window.

Usage and cost figures are aggregated, so a request can take a little while to
appear in them. The traffic log is immediate.

## Traffic logs

```python
for row in faig.traffic_logs(range="24h", filters={"virtual_key": "student04-key"}):
    detail = faig.traffic_log(row["uuid"])
    print(detail["model"], detail["verdict"], detail["cost"], detail["detector"])
```

`traffic_logs()` is an iterator that follows the API's cursor; stop early with
`max_items=`. Rows are summaries; `traffic_log(uuid)` returns the full record
(prompt, cost, latency, detector, guardrail, policy, http status).

Time is `range=` `24h` (default), `7d`, `month` or `all`, or a custom window
with `start=`/`end=` (`datetime` or epoch milliseconds).

Filters map a field to a value, a list of values, or an operator:

```python
filters = {
    "model": ["openai-gpt-4.1-mini", "openai-gpt-4o"],  # is any of
    "verdict": {"operator": "is not", "value": "Log"},
    "virtual_key": {"operator": "contains", "value": "student"},
}
```

!!! warning "The API ignores filters it does not understand"
    A misspelled filter name or operator is silently dropped and every row
    comes back. The client checks both against the known lists and raises
    `ValueError` instead. Valid values per field: `traffic_log_filter_options()`.

ICAP logs (FortiGate-inspected traffic) work the same way through `icap_logs()`,
with their own filter fields. An appliance with ICAP turned off answers 404.

## Which models can a key call?

A request for a model the key is not granted fails with 404 "model not available
to this API key". Check first:

```python
faig.available_models(secret)  # names the key may call
faig.can_use_model(secret, "openai-gpt-4.1-mini")
```

To see why a model is missing: `workspace_models(ws_id)` (what the workspace
allows), `grantable_providers(ws_id)` (what a key there can be granted) and
`attachable_policies(ws_id)`.

## Natural Language detectors and the Playground

```python
body = ai_detector_body(
    "dark-side",
    [("sith-recruiting", ["Urging someone to join the dark side"], ["Film plot discussion"])],
)
faig.playground("Join the dark side, apprentice.", body, ws_id)  # test it unsaved
det = faig.create_detector(ws_id, body)
faig.submit(ws_id, "detectors", det["uuid"])  # or approve_new() as org admin
```

Each rule is `(name, violate_if, exempt_if)`; the builder fills both the
editor's `aiRules` and the flat `rules` list the engine evaluates.
`withdraw(ws_id, kind, id)` cancels a pending submission.
