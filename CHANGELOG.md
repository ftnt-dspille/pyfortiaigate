# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
