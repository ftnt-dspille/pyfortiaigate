# Record types

`TypedDict`s for the records the client returns, with the fields FortiAIGate
8.0.2 sends. They exist for editor completion and type checking: at runtime
every record is a plain `dict`. All fields are optional (`total=False`).

| Type | Returned by |
|---|---|
| `Workspace` | `workspaces()`, `my_workspaces()`, `workspace_by_name()` |
| `Detector` | `detectors()`, `detector_by_name()` |
| `Guardrail` | `guardrails()`, `guardrail()`, `guardrail_by_name()` |
| `Policy` | `policies()`, `policy()`, `policy_by_name()` |
| `VirtualKey` | `virtual_keys()`, `virtual_key()` |
| `TrafficLogRow` | `traffic_logs()`, `wait_for_traffic()` |
| `TrafficLog` | `traffic_log()` |
| `AuditLogRow` | `iter_audit_logs()` |

::: pyfortiaigate.Workspace

::: pyfortiaigate.Detector

::: pyfortiaigate.Guardrail

::: pyfortiaigate.Policy

::: pyfortiaigate.VirtualKey

::: pyfortiaigate.TrafficLogRow

::: pyfortiaigate.TrafficLog

::: pyfortiaigate.AuditLogRow
