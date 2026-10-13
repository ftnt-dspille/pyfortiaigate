# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.1] - 2026-10-13

### Security

- The command line prints text from the server (traffic-log prompts and
  answers, detector, guardrail and workspace names) as text: control
  characters are shown escaped (`\x1b`) instead of reaching the terminal as
  escape sequences, and rich markup in a name (`[red]...`) is shown, not
  applied. 0.3.0 passed both through.

### Added

- Terminal screenshots in the command-line guide and the README, made by
  `scripts/cli_screenshots.py` from made-up data.

## [0.3.0] - 2026-10-13

### Added

- `pip install "pyfortiaigate[cli]"`: with rich installed, the command line
  draws coloured tables, panels and bar charts in a terminal. Pipes, and
  `--plain` or `FAIG_CLI_STYLE=plain`, get plain aligned text; the library
  itself still needs nothing.
- New commands: `dashboard` (traffic, blocks, blocks per detector, spend by
  model and a daily trend on one screen), `trend usage|cost` (a bar per hour,
  day, week or month), `try-regex` (a regex detector in the Playground, matches
  highlighted, nothing saved), `check-key`, `builtins` and `members`.
- `logs --follow` prints new traffic as it arrives.
- `FAIG_WS` is the default `--ws` (`--ws ''` for org-wide), and `--json` /
  `--plain` work after the command as well as before it.

### Changed

- Every command's output is easier to read: plain-English headers, names
  instead of ids (a guardrail's detectors, a deleted key), money as `$`, times
  as local time or "3h ago", verdicts and statuses coloured, and a share bar in
  `usage` / `cost` rankings.
- `log` shows a summary (verdict, prompt, answer, tokens, cost and what matched)
  instead of the raw record; `--json` still prints the record.
- `whoami` shows a summary instead of JSON (`--json` for the raw user).
- `scan` starts with `Verdict: BLOCK` (was `finalDisposition: block`).

### Fixed

- `workspaces --mine` printed columns the endpoint does not return (all `-`);
  it now shows your role, your key count and your budget.

## [0.2.2] - 2026-10-13

### Added

- The command line reads `~/.config/pyfortiaigate/.env` (or `FAIG_ENV_FILE`)
  when `--env-file` is not given, so settings live in one place and every
  command finds them. A `.env` in the current directory is still never read, and
  a settings file other users can read gets a warning.
- Tests and docs: a URL with any path (the console's `/ui`, the gateway's
  `/ai/openai/v1/chat/completions`) is reduced to its host, as it always was.
- `builtin_detectors(ws_id)`: the workspace path, which a workspace member can
  call.
- `pyfortiaigate scan` names each detector instead of printing its id.
- `examples/workshop/`: six short scripts for a hands-on lab (red-team a key,
  scan without a model call, blocks per detector, spend by model, a regex
  detector in the Playground), five with a FIXME to finish.

### Fixed

- Docs: `traffic_log()` names the matching detector in `violation`;
  `detector`, `guardrail` and `policy` come back empty on 8.0.2.

- Docs: types in method signatures (`-> User`, `list[Invitation]`, `WsRef`, ...)
  link to their entries; the docs build now fails on any reference that does
  not resolve.

## [0.2.1] - 2026-10-13

### Added

- Every method now declares what it returns: about 80 `TypedDict` response
  types (`UsageSummary`, `Rankings`, `Breakdown`, `Analytics`,
  `TrafficLogPage`, `DetectorTest`, `GuardrailTest`, `NewVirtualKey`,
  `ChatCompletion`, ...), recorded from a live 8.0.2 appliance and exported from
  the package. The docs list every field with its type and meaning, and the
  Actions page links each method to the type it returns.
- A live conformance test fails when the appliance returns a field the
  declared type lacks, so the documented fields stay complete.
- `invitations()`, `invitation_by_email()` and `revoke_invitation()`.
- Org-level calls verified live and typed: `invite` (`Invitation`),
  `accept_invite` (`AcceptedInvite`), `make_workspace_admin` (`User`),
  `create_workspace` (`Workspace`); an opt-in live test
  (`FAIG_ORG_WRITES`, `FAIG_TEST_INVITEE`) runs the whole invite, account and
  workspace lifecycle and cleans up.

### Changed

- `delete_detector`, `delete_guardrail`, `delete_policy`, `delete_virtual_key`,
  `delete_user`, `delete_workspace` and `withdraw` return None (the appliance
  answers with an empty body); `accept_invite` returns `{}` rather than None
  for an empty body.
- `create_workspace` and `delete_workspace` keep the workspace-name cache
  current.
- `my_workspaces()` is annotated as `list[MyWorkspace]` (its real shape),
  not `list[Workspace]`.

## [0.2.0] - 2026-10-13

### Added

- Usage, cost and analytics reports, org-wide or per workspace:
  `usage_summary/trend/rankings/breakdown`, `cost_summary/trend/rankings/breakdown`,
  `analytics`; `rank_items` and `breakdown_items` read the rows whatever shape
  the API answers in. Allowed values are checked before sending.
- Traffic logs: `traffic_logs()` iterator over the API cursor, `traffic_logs_page`,
  `traffic_log(uuid)` (cost, prompt, verdict, detector) and filter options; ICAP
  logs the same way. Filters are validated, since the API silently ignores
  unknown names and operators and returns every row.
- Workspace-path writes: `delete_detector(..., ws_id)`, `update_policy`,
  `withdraw` (cancel a pending submission), and `ws_id=` on every virtual-key
  call. `workspace()`.
- `test_guardrail(..., ws_id=)` and `guardrail(gid, ws_id=)`: the guardrail tester on
  the workspace path, usable by workspace members.
- The Playground (`playground()`: test an unsaved detector body) and
  `ai_detector_body()` for Natural Language detectors.
- What a key can call: `available_models()`, `can_use_model()`, plus `models()`,
  `workspace_models()`, `grantable_providers()`, `attachable_policies()` and
  workspace `model_groups()`.
- Workspaces by name: every `ws_id` argument accepts a workspace's id, its
  unique name, or its record; `resolve_workspace()` does the lookup (cached,
  refreshed on a miss; org admins and members alike). An unknown name raises
  `LookupError`.
- Detectors, guardrails, policies and virtual keys by name too, everywhere one
  is taken (including the detector list of a guardrail, a policy's guardrails
  and a key's policies). A detector name may be a built-in's name or slug; a
  key may also be given by its `faig_...` secret; `approve`/`reject` take a
  name with `ws_id`. A custom detector that shares a built-in's name or slug is
  refused as ambiguous. `resolve_detector/guardrail/policy/virtual_key()`.
- Re-runnable setup: `ensure_detector`, `ensure_guardrail`, `ensure_policy` and
  `ensure_virtual_key` create what is missing, update what differs, approve it,
  and leave a match alone; they return `Ensured(record, action, secret)`.
- Typed errors, all subclasses of `FaigError`: `AuthError`, `NotFound`,
  `ModelNotAvailable`, `Conflict`, `ValidationError`, `RateLimited`,
  `ServerError`; each carries the decoded `data`, the gateway's `code` and the
  `field` a 409/422 names. `error_for()` picks the class.
- `rate_limit_wait=`: wait out HTTP 429s for up to that many seconds
  (honouring `Retry-After` when sent) instead of raising.
- Streaming: `chat_completion_stream()` yields chunks, including a block's
  `content_filter` chunk; `collect_stream()` joins them.
- `wait_for_traffic()`: poll until a request's traffic log rows have landed.
- Audit log: `iter_audit_logs()` and `audit_logs_page()` with time windows and
  user/role/action/message/workspace filters; `licenses()`.
- `TypedDict` record types (`Workspace`, `Detector`, `Guardrail`, `Policy`,
  `VirtualKey`, `TrafficLogRow`, `TrafficLog`, `AuditLogRow`) on the methods
  that return them, for editor completion. Records are still plain dicts.
- A `pyfortiaigate` command (`python -m pyfortiaigate`): workspaces, objects,
  keys, models, usage and cost, traffic and audit logs, guardrail scans and a
  test chat, as tables or `--json`. Reads `FAIG_*` from the environment, or
  from a settings file only when `--env-file` names one.
- `pyfortiaigate.__version__`.
- `create_guardrail`/`update_guardrail` take `deny_suspicious_characters`;
  `update_virtual_key` takes `provider_ids`.

### Changed

- `workspace_analytics()` takes an optional date window.
- `approve_new()` also approves an active object's pending change.
- List and record methods are annotated with the record types above instead of
  `dict[str, Any]`; strict type checkers may need a `dict(...)` where a plain
  dict is expected.

## [0.1.0] - 2026-10-12

### Added

- `FortiAIGate` client for the 8.x management API and OpenAI-compatible
  gateway: users and invitations, workspaces, detectors, guardrails, policies,
  the approval workflow, virtual keys, providers, model groups, DLP labels,
  audit logs, `check_key` and `chat_completion`.
- Session login with re-login on expiry, a CSRF token per mutation, bearer
  token auth, and `verify` as a CA bundle path.
- Transport retries that never resend a mutation that may have landed, on one
  keep-alive connection.
- Body builders (`regex_detector_body`, `dlp_detector_body`, `guardrail_body`)
  and `approve_new`.
- `delete_detector`, `delete_guardrail`, `delete_policy`; `key_update_body`.
- Live test suites: read-only, and opt-in writes confined to one workspace
  (`FAIG_WRITE_WORKSPACE`) that delete everything they create. Settings load
  from a gitignored `.env` (template: `.env.example`).

### Verified live on FortiAIGate 8.0.2

- `me()` reads `GET /api/v1/user` (`/api/v1/me` does not exist).
- `create_policy` takes `provider_ids`: a policy that grants no model is
  refused with HTTP 422.
- `update_virtual_key` sends only the fields a key PUT accepts, with
  `policyIds` as plain strings; resending the whole record is refused.
- `revoke_virtual_key` sends the `reason` the API requires.
