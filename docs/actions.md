# Actions

Every client method and the API call it makes. `{ws}` is a workspace id; list
methods return the records (unwrapped from `{"items": [...]}`), the rest return
the decoded JSON response.

**Names work everywhere.** A workspace, detector, guardrail, policy or virtual
key argument takes its id, its name, or its record. Detector, guardrail and
policy names are unique in a workspace (8.0.2 refuses a duplicate with 409), so
a name is looked up in the method's `ws_id` (org-wide without one). A detector
name may also be a built-in detector's name or slug (a custom detector sharing
one is refused as ambiguous). Key names are NOT unique:
two keys with one name raise `ValueError`; a key can also be given by its
`faig_...` secret. An unknown name raises `LookupError`.

## Session & raw calls

| Method | HTTP | Notes |
|---|---|---|
| `login(username, password)` | `POST /api/v1/login` | Optional: the client logs in on its first call. Falls back to the legacy `/api/login`. |
| `close()` | `POST /api/v1/logout` | Also runs on leaving a `with` block. |
| `me()` | `GET /api/v1/user` | The logged-in user: `email`, `role`, `memberships`, ... |
| `request(method, path, body, params)` | any | Raw management call with auth, CSRF and retries. |
| `get(path, params)` | `GET` | |
| `post(path, body)` | `POST` | Sends `{}` when there is no body. |
| `put(path, body)` | `PUT` | |
| `patch(path, body)` | `PATCH` | |
| `delete(path)` | `DELETE` | |

## Users & invitations

| Method | HTTP | Notes |
|---|---|---|
| `users()` | `GET /api/v1/admin/users` | |
| `user(user_id)` | `GET /api/v1/admin/users/{id}` | |
| `user_by_email(email)` | `GET /api/v1/admin/users` | Case-insensitive match; `None` if absent. |
| `invite(email, role)` | `POST /api/v1/admin/user-invitations` | Users exist only via invitation; no email is sent. |
| `accept_invite(invitation_id, email, password, display_name)` | `POST /api/v1/invitations/{id}/accept` | Unauthenticated; sets the password. |
| `delete_user(user_id)` | `DELETE /api/v1/admin/users/{id}` | |
| `make_workspace_admin(user_id, ws_id)` | `GET` + `PUT /api/v1/admin/users/{id}` | Keeps the user's other memberships. |

## Workspaces

Every method that takes a workspace (`ws_id`) accepts its **id**, its **name**
(names are unique), or its **record** from `workspaces()` / `workspace_by_name()`.
Names are resolved once and cached; an unknown name raises `LookupError`.


| Method | HTTP | Notes |
|---|---|---|
| `resolve_workspace(ws)` | `GET /api/v1/admin/workspaces` (or `/api/v1/me/workspaces`) | A workspace's id from its id, name or record; cached. |
| `workspaces()` | `GET /api/v1/admin/workspaces` | Every workspace (org admin). |
| `my_workspaces()` | `GET /api/v1/me/workspaces` | Workspaces the caller belongs to. |
| `workspace_by_name(name)` | `GET /api/v1/admin/workspaces` | |
| `create_workspace(name, admin_ids, provider_ids, description)` | `POST /api/v1/admin/workspaces` | Admins must be existing users. |
| `delete_workspace(ws_id)` | `DELETE /api/v1/admin/workspaces/{ws}` | |
| `workspace(ws_id)` | `GET /api/v1/workspaces/{ws}` | Settings: `allowedModels`, `allowedPolicies`, budgets, member defaults. |
| `workspace_members(ws_id)` | `GET /api/v1/workspaces/{ws}/members` | |
| `workspace_budget(ws_id)` | `GET /api/v1/workspaces/{ws}/budget` | |
| `workspace_analytics(ws_id, frm, to, limit)` | `GET /api/v1/workspaces/{ws}/analytics` | Same as `analytics(..., ws_id=)`. |

## Detectors

| Method | HTTP | Notes |
|---|---|---|
| `detectors(ws_id=None)` | `GET /api/v1/workspaces/{ws}/detectors` or `GET /api/v1/admin/detectors` | Custom detectors. |
| `builtin_detectors()` | `GET /api/v1/admin/built-in-detectors` | Identified by slug id. |
| `detector_by_name(ws_id, name)` | `GET /api/v1/workspaces/{ws}/detectors` | |
| `create_detector(ws_id, body)` | `POST /api/v1/workspaces/{ws}/detectors` | Build `body` with `regex_detector_body` / `dlp_detector_body`. |
| `update_detector(ws_id, uuid, body)` | `PUT /api/v1/workspaces/{ws}/detectors/{uuid}` | An active detector changes at once. |
| `delete_detector(uuid, ws_id=None)` | `DELETE /api/v1/workspaces/{ws}/detectors/{uuid}` or `DELETE /api/v1/admin/detectors/{uuid}` | |
| `playground(text, body, ws_id=None)` | `POST /api/v1/workspaces/{ws}/detectors/test` or `POST /api/v1/admin/detectors/test` | Scan text with an UNSAVED detector body (the console Playground). |
| `test_detector(ws_id, uuid, text)` | `POST /api/v1/workspaces/{ws}/detectors/{uuid}/test` | Scan with a SAVED detector: `matched`, `score`, `spans`. |
| `resolve_detector(ref, ws_id=None)` | `GET .../detectors` (+ built-ins, cached) | A detector's uuid from its uuid, name, slug or record. |
| `ensure_detector(ws_id, body, approve=True)` | list, then `POST` or `PUT`, then approval | Create, update or leave alone, by `body["name"]`. Returns `Ensured`. |

## Guardrails

| Method | HTTP | Notes |
|---|---|---|
| `guardrails(ws_id=None)` | `GET /api/v1/workspaces/{ws}/guardrails` or `GET /api/v1/admin/guardrails` | |
| `guardrail(gid, ws_id=None)` | `GET /api/v1/workspaces/{ws}/guardrails/{id}` or `GET /api/v1/admin/guardrails/{id}` | |
| `guardrail_by_name(ws_id, name)` | as `guardrails` | `ws_id=None` searches org guardrails. |
| `create_guardrail(ws_id, name, detector_ids, description, deny_suspicious_characters=)` | `POST /api/v1/workspaces/{ws}/guardrails` | Needs at least one detector (ids or names). |
| `update_guardrail(ws_id, gid, name, detector_ids, description, deny_suspicious_characters=)` | `PUT /api/v1/workspaces/{ws}/guardrails/{id}` | |
| `delete_guardrail(gid, ws_id=None)` | `DELETE /api/v1/workspaces/{ws}/guardrails/{id}` or `DELETE /api/v1/admin/guardrails/{id}` | |
| `test_guardrail(text, detector_ids, guardrail_id=, deny_suspicious_characters=, ws_id=)` | `POST /api/v1/workspaces/{ws}/guardrails/test` or `POST /api/v1/admin/guardrails/test` | The guardrail tester: scans text without an LLM; `finalDisposition` plus a result per detector. |
| `resolve_guardrail(ref, ws_id=None)` | `GET .../guardrails` | A guardrail's id from its id, name or record. |
| `ensure_guardrail(ws_id, name, detector_ids, description, deny_suspicious_characters=, approve=True)` | list, then `POST` or `PUT`, then approval | Returns `Ensured`. |

## Policies

| Method | HTTP | Notes |
|---|---|---|
| `policies(ws_id=None)` | `GET /api/v1/workspaces/{ws}/policies` or `GET /api/v1/admin/policies` | |
| `policy(pid, ws_id=None)` | `GET /api/v1/admin/policies/{id}` | `ws_id` scopes a name lookup. |
| `policy_by_name(ws_id, name)` | as `policies` | |
| `create_policy(ws_id, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=)` | `POST /api/v1/workspaces/{ws}/policies` | `provider_ids` grants all of those providers' models; some builds require at least one. |
| `update_policy(ws_id, pid, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=)` | `PUT /api/v1/workspaces/{ws}/policies/{id}` | By an org admin, an edit to an active policy applies at once. |
| `delete_policy(pid, ws_id=None)` | `DELETE /api/v1/workspaces/{ws}/policies/{id}` or `DELETE /api/v1/admin/policies/{id}` | |
| `resolve_policy(ref, ws_id=None)` | `GET .../policies` | A policy's id from its id, name or record. |
| `ensure_policy(ws_id, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=, approve=True)` | list, then `POST` or `PUT`, then approval | Guardrails by id or name. Returns `Ensured`. |

## Approval workflow

| Method | HTTP | Notes |
|---|---|---|
| `submit(ws_id, kind, obj_id)` | `POST /api/v1/workspaces/{ws}/{kind}/{id}/submit` | `kind`: `detectors`, `guardrails`, `policies`. |
| `withdraw(ws_id, kind, obj_id)` | `DELETE /api/v1/workspaces/{ws}/{kind}/{id}/pending` | Cancel a pending submission or change. |
| `approve(kind, obj_id, ws_id=None)` | `POST /api/v1/admin/{kind}/{id}/approve` | By name only with `ws_id` (a name can be pending in several workspaces). |
| `reject(kind, obj_id, reason, ws_id=None)` | `POST /api/v1/admin/{kind}/{id}/reject` | As `approve`. |
| `review_queue()` | `GET /api/v1/admin/review-queue` | Map an item's `type` with `QUEUE_KIND`. |

See also [`approve_new`](reference/helpers.md#pyfortiaigate.approve_new).

## Virtual keys

| Method | HTTP | Notes |
|---|---|---|
| `virtual_keys(ws_id=None, status=)` | `GET /api/v1/workspaces/{ws}/virtual-keys` or `GET /api/v1/admin/virtual-keys` | |
| `virtual_key(key_id, ws_id=None)` | `GET /api/v1/workspaces/{ws}/virtual-keys/{id}` or `GET /api/v1/admin/virtual-keys/{id}` | Every key call takes `ws_id=` for the workspace path. |
| `create_virtual_key(ws_id, name, policy_ids=, provider_ids=, expires_at=, tpm=, rpm=)` | `POST /api/v1/workspaces/{ws}/virtual-keys` | The secret is returned once. |
| `update_virtual_key(key_id, expires_at=, tpm=, rpm=, policy_ids=, provider_ids=, ws_id=)` | `GET` + `PUT .../virtual-keys/{id}` | Resends the record's writable fields with your changes. |
| `rotate_virtual_key(key_id, ws_id=None)` | `POST .../virtual-keys/{id}/rotate` | New secret, once. |
| `revoke_virtual_key(key_id, reason, ws_id=None)` | `POST .../virtual-keys/{id}/revoke` | The secret stops working; a reason is required. |
| `delete_virtual_key(key_id, ws_id=None)` | `DELETE .../virtual-keys/{id}` | |
| `resolve_virtual_key(ref, ws_id=None)` | `GET .../virtual-keys` | A key's id from its id, name, record or `faig_...` secret. |
| `ensure_virtual_key(ws_id, name, policy_ids=, provider_ids=, expires_at=, tpm=, rpm=)` | list, then `POST` or `GET` + `PUT` | Create the active key `name` (secret in `Ensured.secret`) or bring it in line. |

## Models & what a key can use

| Method | HTTP | Notes |
|---|---|---|
| `ai_providers()` | `GET /api/v1/admin/ai-providers` | |
| `models()` | `GET /api/v1/admin/models` | Every model: costs, health, provider. |
| `model_groups(ws_id=None)` | `GET /api/v1/workspaces/{ws}/model-groups` or `GET /api/v1/model-groups` | |
| `workspace_models(ws_id)` | `GET /api/v1/workspaces/{ws}` | The workspace's `allowedModels`. |
| `grantable_providers(ws_id=None)` | `GET /api/v1/workspaces/{ws}/grantable-providers` or `GET /api/v1/admin/grantable-providers` | Providers, models and upstream keys a key can be granted. |
| `attachable_policies(ws_id)` | `GET /api/v1/workspaces/{ws}/attachable-policies` | Policies a key in the workspace can attach. |
| `dlp_labels()` | `GET /api/v1/admin/dlp-labels` | Category names for `dlp_detector_body`. |

## Usage, cost & analytics

Dates are `date` objects or `"YYYY-MM-DD"`; omitted, the window is the last 30
days. `ws_id=` switches every call to the workspace path. Values are
checked before sending: `by` workspace | user | key | model; `interval` hourly |
daily | weekly | monthly; `end` top | bottom | both. Read ranking rows with
`rank_items(result, end)`: the API answers `items`, `top`/`bottom` lists, or
only `meta` when nothing was used.

| Method | HTTP | Notes |
|---|---|---|
| `usage_summary(frm, to, ws_id=)` | `GET .../usage/summary` | Requests, tokens, previous window, key/user adoption. |
| `usage_trend(frm, to, interval, ws_id=)` | `GET .../usage/trend` | `points: [{at, requests, tokens}]`. |
| `usage_rankings(frm, to, by, limit, end=, order_by=, interval=, ws_id=)` | `GET .../usage/rankings` | `order_by`: tokens \| requests. |
| `usage_breakdown(by, item_id, frm, to, ws_id=)` | `GET .../usage/breakdown` | A key/user/workspace by model; a model by who used it. Rows: `breakdown_items()`. 404 for a deleted key. |
| `cost_summary(frm, to, ws_id=)` | `GET .../cost/summary` | `totals.chargebackSpend`, volume, unit costs. |
| `cost_trend(frm, to, interval, ws_id=)` | `GET .../cost/trend` | |
| `cost_rankings(frm, to, by, limit, end=, order_by=, interval=, ws_id=)` | `GET .../cost/rankings` | `order_by`: providerSpend \| chargebackSpend \| per1kTokens \| perRequest. |
| `cost_breakdown(by, item_id, frm, to, ws_id=)` | `GET .../cost/breakdown` | As `usage_breakdown`, with spend. Rows: `breakdown_items()`. |
| `analytics(frm, to, limit, ws_id=)` | `GET /api/v1/admin/analytics` or `.../workspaces/{ws}/analytics` | Guardrail violations, severity, trend, scanner latency. |

## Traffic & ICAP logs

Time: `range=` 24h (default) \| 7d \| month \| all, or `start=`/`end=`
(`datetime` or epoch ms). `filters=` maps a field to a value, a list (`is`), or
`{"operator": "is" | "is not" | "contains" | "does not contain", "value": [...]}`.
Unknown fields or operators raise `ValueError`: the API would silently ignore
them and return every row.

| Method | HTTP | Notes |
|---|---|---|
| `traffic_logs(range=, start=, end=, filters=, max_items=, page_size=, ws_id=)` | `GET .../traffic-logs` | Iterator; follows `nextCursor`. Filters: verdict, user, workspace, virtual_key, model, traffic_type, request_path. |
| `traffic_logs_page(cursor, ...)` | `GET .../traffic-logs` | One page with `nextCursor`, `hasNext`, `total` (first page). |
| `traffic_log(uuid, ws_id=)` | `GET .../traffic-logs/{uuid}` | Full record: verdict, action, detector, guardrail, policy, prompt, cost, latency. |
| `traffic_log_filter_options(range=, start=, end=, ws_id=)` | `GET .../traffic-logs/filter-options` | Values each filter can take. |
| `wait_for_traffic(since, filters=, count=1, timeout=60, interval=2, ws_id=)` | `GET .../traffic-logs` (polled) | Rows land seconds after a request: wait for `count` rows from `since` on. `TimeoutError` otherwise. |
| `icap_logs(...)` | `GET .../icap-logs` | Iterator (offset paging). Filters: verdict, direction, user, application, fortigate, shadow_ai, inspection. 404 when ICAP is off. |
| `icap_logs_page(offset, ...)` | `GET .../icap-logs` | |
| `icap_log(uuid, ws_id=)` | `GET .../icap-logs/{uuid}` | |
| `icap_log_filter_options(...)` | `GET .../icap-logs/filter-options` | |

## Audit log & licenses

The audit log takes the same `range=` / `start=` / `end=` and `filters=` as the
traffic log. Filters: user, role, action, message, workspace; spell actions as
`audit_log_filter_options()` lists them (`Approve`, `Create`, ...).

| Method | HTTP | Notes |
|---|---|---|
| `iter_audit_logs(range=, start=, end=, filters=, max_items=, page_size=, ws_id=)` | `GET .../audit-logs` | Iterator; follows `nextCursor`. |
| `audit_logs_page(cursor, ...)` | `GET .../audit-logs` | One page. |
| `audit_logs(offset, limit)` | `GET /api/v1/admin/audit-logs` | One page by offset, no filters. |
| `audit_log_filter_options(range=, start=, end=, ws_id=)` | `GET .../audit-logs/filter-options` | Users, roles, actions, workspaces seen. |
| `licenses()` | `GET /api/v1/licenses` | Serial, status, end date, GPU mapping. |

## Gateway (data plane)

Authenticated with a virtual key secret, never the session.

| Method | HTTP | Notes |
|---|---|---|
| `check_key(api_key)` | `GET /ai/openai/v1/models` | `{"valid", "model_count", "http_status"}`. |
| `available_models(api_key)` | `GET /ai/openai/v1/models` | Model names the key may call. A model missing here 404s with "model not available to this API key". |
| `can_use_model(api_key, model)` | `GET /ai/openai/v1/models` | `model in available_models(api_key)`. |
| `chat_completion(api_key, model, messages, max_tokens=, temperature=, **extra)` | `POST /ai/openai/v1/chat/completions` | A guardrail block is a 200; test it with `blocked()`. A model the key lacks raises `ModelNotAvailable`. |
| `chat_completion_stream(api_key, model, messages, max_tokens=, temperature=, **extra)` | `POST /ai/openai/v1/chat/completions` (`stream: true`) | Yields chunks; a block arrives as a `content_filter` chunk. `collect_stream()` joins them. |
