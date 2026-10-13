# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-13

### Added

- Usage, cost and analytics reports, org-wide or per workspace:
  `usage_summary/trend/rankings/breakdown`, `cost_summary/trend/rankings/breakdown`,
  `analytics`; `rank_items` reads ranking rows. Allowed values are checked
  before sending.
- Traffic logs: `traffic_logs()` iterator over the API cursor, `traffic_logs_page`,
  `traffic_log(uuid)` (cost, prompt, verdict, detector) and filter options; ICAP
  logs the same way. Filters are validated, since the API silently ignores
  unknown names and operators and returns every row.
- Workspace-path writes: `delete_detector(..., ws_id)`, `update_policy`,
  `withdraw` (cancel a pending submission), and `ws_id=` on every virtual-key
  call. `workspace()`.
- The Playground (`playground()`: test an unsaved detector body) and
  `ai_detector_body()` for Natural Language detectors.
- What a key can call: `available_models()`, `can_use_model()`, plus `models()`,
  `workspace_models()`, `grantable_providers()`, `attachable_policies()` and
  workspace `model_groups()`.

### Changed

- `workspace_analytics()` takes an optional date window.

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
