# Actions

Every client method, the API call it makes, and what it returns. Click a method
for its full signature; click a type in **Returns** for every field it carries
(see [Response types](reference/types.md)). `{ws}` is a workspace id. List
methods return the records already unwrapped from `{"items": [...]}`.

**Names work everywhere.** A workspace, detector, guardrail, policy or virtual
key argument takes its id, its name, or its record. Detector, guardrail and
policy names are unique in a workspace (8.0.2 refuses a duplicate with 409), so
a name is looked up in the method's `ws_id` (org-wide without one). A detector
name may also be a built-in detector's name or slug (a custom detector sharing
one is refused as ambiguous). Key names are NOT unique:
two keys with one name raise `ValueError`; a key can also be given by its
`faig_...` secret. An unknown name raises `LookupError`.

## Session & raw calls

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`login(username, password)`](reference/client.md#pyfortiaigate.FortiAIGate.login) | `POST /api/v1/login` | None | Optional: the client logs in on its first call. Falls back to the legacy `/api/login`. |
| [`close()`](reference/client.md#pyfortiaigate.FortiAIGate.close) | `POST /api/v1/logout` | None | Also runs on leaving a `with` block. |
| [`me()`](reference/client.md#pyfortiaigate.FortiAIGate.me) | `GET /api/v1/user` | [Me](reference/types.md#me) | The logged-in user: `email`, `role`, `memberships`, ... |
| [`request(method, path, body, params)`](reference/client.md#pyfortiaigate.FortiAIGate.request) | any | JSON (untyped) | Raw management call with auth, CSRF and retries. |
| [`get(path, params)`](reference/client.md#pyfortiaigate.FortiAIGate.get) | `GET` | JSON (untyped) |  |
| [`post(path, body)`](reference/client.md#pyfortiaigate.FortiAIGate.post) | `POST` | JSON (untyped) | Sends `{}` when there is no body. |
| [`put(path, body)`](reference/client.md#pyfortiaigate.FortiAIGate.put) | `PUT` | JSON (untyped) |  |
| [`patch(path, body)`](reference/client.md#pyfortiaigate.FortiAIGate.patch) | `PATCH` | JSON (untyped) |  |
| [`delete(path)`](reference/client.md#pyfortiaigate.FortiAIGate.delete) | `DELETE` | JSON (untyped) |  |

## Users & invitations

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`users()`](reference/client.md#pyfortiaigate.FortiAIGate.users) | `GET /api/v1/admin/users` | list\[[User](reference/types.md#user)\] |  |
| [`user(user_id)`](reference/client.md#pyfortiaigate.FortiAIGate.user) | `GET /api/v1/admin/users/{id}` | [User](reference/types.md#user) |  |
| [`user_by_email(email)`](reference/client.md#pyfortiaigate.FortiAIGate.user_by_email) | `GET /api/v1/admin/users` | [User](reference/types.md#user) \| None | Case-insensitive match; `None` if absent. |
| [`invite(email, role)`](reference/client.md#pyfortiaigate.FortiAIGate.invite) | `POST /api/v1/admin/user-invitations` | [Invitation](reference/types.md#invitation) | Users exist only via invitation; no email is sent. A second invite while one is pending is refused (422). |
| [`invitations()`](reference/client.md#pyfortiaigate.FortiAIGate.invitations) | `GET /api/v1/admin/user-invitations` | list\[[Invitation](reference/types.md#invitation)\] | Pending invitations. |
| [`invitation_by_email(email)`](reference/client.md#pyfortiaigate.FortiAIGate.invitation_by_email) | `GET /api/v1/admin/user-invitations` | [Invitation](reference/types.md#invitation) \| None | Case-insensitive; `None` if there is none. |
| [`revoke_invitation(invitation_id)`](reference/client.md#pyfortiaigate.FortiAIGate.revoke_invitation) | `DELETE /api/v1/admin/user-invitations/{id}` | None | Needed before re-inviting an address with one pending. |
| [`accept_invite(invitation_id, email, password, display_name)`](reference/client.md#pyfortiaigate.FortiAIGate.accept_invite) | `POST /api/v1/invitations/{id}/accept` | [AcceptedInvite](reference/types.md#acceptedinvite) | Unauthenticated; sets the password. |
| [`delete_user(user_id)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_user) | `DELETE /api/v1/admin/users/{id}` | None |  |
| [`make_workspace_admin(user_id, ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.make_workspace_admin) | `GET` + `PUT /api/v1/admin/users/{id}` | [User](reference/types.md#user) | Keeps the user's other memberships. |

## Workspaces

Every method that takes a workspace (`ws_id`) accepts its **id**, its **name**
(names are unique), or its **record** from `workspaces()` / `workspace_by_name()`.
Names are resolved once and cached; an unknown name raises `LookupError`.


| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`resolve_workspace(ws)`](reference/client.md#pyfortiaigate.FortiAIGate.resolve_workspace) | `GET /api/v1/admin/workspaces` (or `/api/v1/me/workspaces`) | str | A workspace's id from its id, name or record; cached. |
| [`workspaces()`](reference/client.md#pyfortiaigate.FortiAIGate.workspaces) | `GET /api/v1/admin/workspaces` | list\[[Workspace](reference/types.md#workspace)\] | Every workspace (org admin). |
| [`my_workspaces()`](reference/client.md#pyfortiaigate.FortiAIGate.my_workspaces) | `GET /api/v1/me/workspaces` | list\[[MyWorkspace](reference/types.md#myworkspace)\] | Workspaces the caller belongs to. |
| [`workspace_by_name(name)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace_by_name) | `GET /api/v1/admin/workspaces` | [Workspace](reference/types.md#workspace) \| None |  |
| [`create_workspace(name, admin_ids, provider_ids, description)`](reference/client.md#pyfortiaigate.FortiAIGate.create_workspace) | `POST /api/v1/admin/workspaces` | [Workspace](reference/types.md#workspace) | Admins must be existing users. |
| [`delete_workspace(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_workspace) | `DELETE /api/v1/admin/workspaces/{ws}` | None |  |
| [`workspace(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace) | `GET /api/v1/workspaces/{ws}` | [WorkspaceSettings](reference/types.md#workspacesettings) | Settings: `allowedModels`, `allowedPolicies`, budgets, member defaults. |
| [`workspace_members(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace_members) | `GET /api/v1/workspaces/{ws}/members` | [WorkspaceMembers](reference/types.md#workspacemembers) |  |
| [`workspace_budget(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace_budget) | `GET /api/v1/workspaces/{ws}/budget` | [WorkspaceBudget](reference/types.md#workspacebudget) |  |
| [`workspace_analytics(ws_id, frm, to, limit)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace_analytics) | `GET /api/v1/workspaces/{ws}/analytics` | [Analytics](reference/types.md#analytics) | Same as `analytics(..., ws_id=)`. |

## Detectors

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`detectors(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.detectors) | `GET /api/v1/workspaces/{ws}/detectors` or `GET /api/v1/admin/detectors` | list\[[Detector](reference/types.md#detector)\] | Custom detectors. |
| [`builtin_detectors(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.builtin_detectors) | `GET /api/v1/workspaces/{ws}/built-in-detectors` or `GET /api/v1/admin/built-in-detectors` | list\[[BuiltinDetector](reference/types.md#builtindetector)\] | Identified by slug id. |
| [`detector_by_name(ws_id, name)`](reference/client.md#pyfortiaigate.FortiAIGate.detector_by_name) | `GET /api/v1/workspaces/{ws}/detectors` | [Detector](reference/types.md#detector) \| None |  |
| [`create_detector(ws_id, body)`](reference/client.md#pyfortiaigate.FortiAIGate.create_detector) | `POST /api/v1/workspaces/{ws}/detectors` | [Detector](reference/types.md#detector) | Build `body` with [`regex_detector_body`](reference/helpers.md#pyfortiaigate.regex_detector_body) / [`dlp_detector_body`](reference/helpers.md#pyfortiaigate.dlp_detector_body). |
| [`update_detector(ws_id, uuid, body)`](reference/client.md#pyfortiaigate.FortiAIGate.update_detector) | `PUT /api/v1/workspaces/{ws}/detectors/{uuid}` | [Detector](reference/types.md#detector) | An active detector changes at once. |
| [`delete_detector(uuid, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_detector) | `DELETE /api/v1/workspaces/{ws}/detectors/{uuid}` or `DELETE /api/v1/admin/detectors/{uuid}` | None |  |
| [`playground(text, body, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.playground) | `POST /api/v1/workspaces/{ws}/detectors/test` or `POST /api/v1/admin/detectors/test` | [DetectorTest](reference/types.md#detectortest) | Scan text with an UNSAVED detector body (the console Playground). |
| [`test_detector(ws_id, uuid, text)`](reference/client.md#pyfortiaigate.FortiAIGate.test_detector) | `POST /api/v1/workspaces/{ws}/detectors/{uuid}/test` | [DetectorTest](reference/types.md#detectortest) | Scan with a SAVED detector: `matched`, `score`, `spans`. |
| [`resolve_detector(ref, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.resolve_detector) | `GET .../detectors` (+ built-ins, cached) | str | A detector's uuid from its uuid, name, slug or record. |
| [`ensure_detector(ws_id, body, approve=True)`](reference/client.md#pyfortiaigate.FortiAIGate.ensure_detector) | list, then `POST` or `PUT`, then approval | [Ensured](reference/helpers.md#pyfortiaigate.Ensured) | Create, update or leave alone, by `body["name"]`. Returns `Ensured`. |

## Guardrails

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`guardrails(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.guardrails) | `GET /api/v1/workspaces/{ws}/guardrails` or `GET /api/v1/admin/guardrails` | list\[[Guardrail](reference/types.md#guardrail)\] |  |
| [`guardrail(gid, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.guardrail) | `GET /api/v1/workspaces/{ws}/guardrails/{id}` or `GET /api/v1/admin/guardrails/{id}` | [Guardrail](reference/types.md#guardrail) |  |
| [`guardrail_by_name(ws_id, name)`](reference/client.md#pyfortiaigate.FortiAIGate.guardrail_by_name) | as `guardrails` | [Guardrail](reference/types.md#guardrail) \| None | `ws_id=None` searches org guardrails. |
| [`create_guardrail(ws_id, name, detector_ids, description, deny_suspicious_characters=)`](reference/client.md#pyfortiaigate.FortiAIGate.create_guardrail) | `POST /api/v1/workspaces/{ws}/guardrails` | [Guardrail](reference/types.md#guardrail) | Needs at least one detector (ids or names). |
| [`update_guardrail(ws_id, gid, name, detector_ids, description, deny_suspicious_characters=)`](reference/client.md#pyfortiaigate.FortiAIGate.update_guardrail) | `PUT /api/v1/workspaces/{ws}/guardrails/{id}` | [Guardrail](reference/types.md#guardrail) |  |
| [`delete_guardrail(gid, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_guardrail) | `DELETE /api/v1/workspaces/{ws}/guardrails/{id}` or `DELETE /api/v1/admin/guardrails/{id}` | None |  |
| [`test_guardrail(text, detector_ids, guardrail_id=, deny_suspicious_characters=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.test_guardrail) | `POST /api/v1/workspaces/{ws}/guardrails/test` or `POST /api/v1/admin/guardrails/test` | [GuardrailTest](reference/types.md#guardrailtest) | The guardrail tester: scans text without an LLM; `finalDisposition` plus a result per detector. |
| [`resolve_guardrail(ref, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.resolve_guardrail) | `GET .../guardrails` | str | A guardrail's id from its id, name or record. |
| [`ensure_guardrail(ws_id, name, detector_ids, description, deny_suspicious_characters=, approve=True)`](reference/client.md#pyfortiaigate.FortiAIGate.ensure_guardrail) | list, then `POST` or `PUT`, then approval | [Ensured](reference/helpers.md#pyfortiaigate.Ensured) | Returns `Ensured`. |

## Policies

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`policies(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.policies) | `GET /api/v1/workspaces/{ws}/policies` or `GET /api/v1/admin/policies` | list\[[Policy](reference/types.md#policy)\] |  |
| [`policy(pid, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.policy) | `GET /api/v1/admin/policies/{id}` | [Policy](reference/types.md#policy) | `ws_id` scopes a name lookup. |
| [`policy_by_name(ws_id, name)`](reference/client.md#pyfortiaigate.FortiAIGate.policy_by_name) | as `policies` | [Policy](reference/types.md#policy) \| None |  |
| [`create_policy(ws_id, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=)`](reference/client.md#pyfortiaigate.FortiAIGate.create_policy) | `POST /api/v1/workspaces/{ws}/policies` | [Policy](reference/types.md#policy) | `provider_ids` grants all of those providers' models; some builds require at least one. |
| [`update_policy(ws_id, pid, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=)`](reference/client.md#pyfortiaigate.FortiAIGate.update_policy) | `PUT /api/v1/workspaces/{ws}/policies/{id}` | [Policy](reference/types.md#policy) | By an org admin, an edit to an active policy applies at once. |
| [`delete_policy(pid, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_policy) | `DELETE /api/v1/workspaces/{ws}/policies/{id}` or `DELETE /api/v1/admin/policies/{id}` | None |  |
| [`resolve_policy(ref, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.resolve_policy) | `GET .../policies` | str | A policy's id from its id, name or record. |
| [`ensure_policy(ws_id, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=, approve=True)`](reference/client.md#pyfortiaigate.FortiAIGate.ensure_policy) | list, then `POST` or `PUT`, then approval | [Ensured](reference/helpers.md#pyfortiaigate.Ensured) | Guardrails by id or name. Returns `Ensured`. |

## Approval workflow

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`submit(ws_id, kind, obj_id)`](reference/client.md#pyfortiaigate.FortiAIGate.submit) | `POST /api/v1/workspaces/{ws}/{kind}/{id}/submit` | [Detector](reference/types.md#detector) \| [Guardrail](reference/types.md#guardrail) \| [Policy](reference/types.md#policy) | `kind`: `detectors`, `guardrails`, `policies`. |
| [`withdraw(ws_id, kind, obj_id)`](reference/client.md#pyfortiaigate.FortiAIGate.withdraw) | `DELETE /api/v1/workspaces/{ws}/{kind}/{id}/pending` | None | Cancel a pending submission or change. |
| [`approve(kind, obj_id, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.approve) | `POST /api/v1/admin/{kind}/{id}/approve` | [Detector](reference/types.md#detector) \| [Guardrail](reference/types.md#guardrail) \| [Policy](reference/types.md#policy) | By name only with `ws_id` (a name can be pending in several workspaces). |
| [`reject(kind, obj_id, reason, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.reject) | `POST /api/v1/admin/{kind}/{id}/reject` | [Detector](reference/types.md#detector) \| [Guardrail](reference/types.md#guardrail) \| [Policy](reference/types.md#policy) | As `approve`. |
| [`review_queue()`](reference/client.md#pyfortiaigate.FortiAIGate.review_queue) | `GET /api/v1/admin/review-queue` | list\[[ReviewItem](reference/types.md#reviewitem)\] | Map an item's `type` with `QUEUE_KIND`. |

See also [`approve_new`](reference/helpers.md#pyfortiaigate.approve_new).

## Virtual keys

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`virtual_keys(ws_id=None, status=)`](reference/client.md#pyfortiaigate.FortiAIGate.virtual_keys) | `GET /api/v1/workspaces/{ws}/virtual-keys` or `GET /api/v1/admin/virtual-keys` | list\[[VirtualKey](reference/types.md#virtualkey)\] |  |
| [`virtual_key(key_id, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.virtual_key) | `GET /api/v1/workspaces/{ws}/virtual-keys/{id}` or `GET /api/v1/admin/virtual-keys/{id}` | [VirtualKey](reference/types.md#virtualkey) | Every key call takes `ws_id=` for the workspace path. |
| [`create_virtual_key(ws_id, name, policy_ids=, provider_ids=, expires_at=, tpm=, rpm=)`](reference/client.md#pyfortiaigate.FortiAIGate.create_virtual_key) | `POST /api/v1/workspaces/{ws}/virtual-keys` | [NewVirtualKey](reference/types.md#newvirtualkey) | The secret is returned once. |
| [`update_virtual_key(key_id, expires_at=, tpm=, rpm=, policy_ids=, provider_ids=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.update_virtual_key) | `GET` + `PUT .../virtual-keys/{id}` | [VirtualKey](reference/types.md#virtualkey) | Resends the record's writable fields with your changes. |
| [`rotate_virtual_key(key_id, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.rotate_virtual_key) | `POST .../virtual-keys/{id}/rotate` | [NewVirtualKey](reference/types.md#newvirtualkey) | New secret, once. |
| [`replace_virtual_key(key_id, name=, expires_in_days=, revoke_old=, allow_revoked=, allow_uncopied=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.replace_virtual_key) | `GET`, then `POST .../rotate` or `POST` a new key | Replaced | A working replacement and its new secret: rotates an active key, else issues a new key with the same name, limits and policies. Refuses a revoked key, or one with model limits it cannot copy, unless allowed. |
| [`revoke_virtual_key(key_id, reason, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.revoke_virtual_key) | `POST .../virtual-keys/{id}/revoke` | [VirtualKey](reference/types.md#virtualkey) | The secret stops working; a reason is required. |
| [`delete_virtual_key(key_id, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.delete_virtual_key) | `DELETE .../virtual-keys/{id}` | None |  |
| [`resolve_virtual_key(ref, ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.resolve_virtual_key) | `GET .../virtual-keys` | str | A key's id from its id, name, record or `faig_...` secret. |
| [`ensure_virtual_key(ws_id, name, policy_ids=, provider_ids=, expires_at=, tpm=, rpm=)`](reference/client.md#pyfortiaigate.FortiAIGate.ensure_virtual_key) | list, then `POST` or `GET` + `PUT` | [Ensured](reference/helpers.md#pyfortiaigate.Ensured) | Create the active key `name` (secret in `Ensured.secret`) or bring it in line. |

## Models & what a key can use

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`ai_providers()`](reference/client.md#pyfortiaigate.FortiAIGate.ai_providers) | `GET /api/v1/admin/ai-providers` | list\[[AiProvider](reference/types.md#aiprovider)\] |  |
| [`models()`](reference/client.md#pyfortiaigate.FortiAIGate.models) | `GET /api/v1/admin/models` | list\[[Model](reference/types.md#model)\] | Every model: costs, health, provider. |
| [`model_groups(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.model_groups) | `GET /api/v1/workspaces/{ws}/model-groups` or `GET /api/v1/model-groups` | list\[[ModelGroup](reference/types.md#modelgroup)\] |  |
| [`workspace_models(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.workspace_models) | `GET /api/v1/workspaces/{ws}` | list\[str\] | The workspace's `allowedModels`. |
| [`grantable_providers(ws_id=None)`](reference/client.md#pyfortiaigate.FortiAIGate.grantable_providers) | `GET /api/v1/workspaces/{ws}/grantable-providers` or `GET /api/v1/admin/grantable-providers` | list\[[GrantableProvider](reference/types.md#grantableprovider)\] | Providers, models and upstream keys a key can be granted. |
| [`attachable_policies(ws_id)`](reference/client.md#pyfortiaigate.FortiAIGate.attachable_policies) | `GET /api/v1/workspaces/{ws}/attachable-policies` | list\[[Policy](reference/types.md#policy)\] | Policies a key in the workspace can attach. |
| [`dlp_labels()`](reference/client.md#pyfortiaigate.FortiAIGate.dlp_labels) | `GET /api/v1/admin/dlp-labels` | list\[[DlpLabel](reference/types.md#dlplabel)\] | Category names for [`dlp_detector_body`](reference/helpers.md#pyfortiaigate.dlp_detector_body). |

## Usage, cost & analytics

Dates are `date` objects or `"YYYY-MM-DD"`; omitted, the window is the last 30
days. `ws_id=` switches every call to the workspace path. Values are
checked before sending: `by` workspace | user | key | model; `interval` hourly |
daily | weekly | monthly; `end` top | bottom | both. Read ranking rows with
`rank_items(result, end)`: the API answers `items`, `top`/`bottom` lists, or
only `meta` when nothing was used.

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`usage_summary(frm, to, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.usage_summary) | `GET .../usage/summary` | [UsageSummary](reference/types.md#usagesummary) | Requests, tokens, previous window, key/user adoption. |
| [`usage_trend(frm, to, interval, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.usage_trend) | `GET .../usage/trend` | [UsageTrend](reference/types.md#usagetrend) | `points: [{at, requests, tokens}]`. |
| [`usage_rankings(frm, to, by, limit, end=, order_by=, interval=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.usage_rankings) | `GET .../usage/rankings` | [Rankings](reference/types.md#rankings) | `order_by`: tokens \| requests. |
| [`usage_breakdown(by, item_id, frm, to, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.usage_breakdown) | `GET .../usage/breakdown` | [Breakdown](reference/types.md#breakdown) | A key/user/workspace by model; a model by who used it. Rows: [`breakdown_items()`](reference/helpers.md#pyfortiaigate.breakdown_items). 404 for a deleted key. |
| [`cost_summary(frm, to, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.cost_summary) | `GET .../cost/summary` | [CostSummary](reference/types.md#costsummary) | `totals.chargebackSpend`, volume, unit costs. |
| [`cost_trend(frm, to, interval, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.cost_trend) | `GET .../cost/trend` | [CostTrend](reference/types.md#costtrend) |  |
| [`cost_rankings(frm, to, by, limit, end=, order_by=, interval=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.cost_rankings) | `GET .../cost/rankings` | [Rankings](reference/types.md#rankings) | `order_by`: providerSpend \| chargebackSpend \| per1kTokens \| perRequest. |
| [`cost_breakdown(by, item_id, frm, to, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.cost_breakdown) | `GET .../cost/breakdown` | [Breakdown](reference/types.md#breakdown) | As `usage_breakdown`, with spend. Rows: [`breakdown_items()`](reference/helpers.md#pyfortiaigate.breakdown_items). |
| [`analytics(frm, to, limit, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.analytics) | `GET /api/v1/admin/analytics` or `.../workspaces/{ws}/analytics` | [Analytics](reference/types.md#analytics) | Guardrail violations, severity, trend, scanner latency. |

## Traffic & ICAP logs

Time: `range=` 24h (default) \| 7d \| month \| all, or `start=`/`end=`
(`datetime` or epoch ms). `filters=` maps a field to a value, a list (`is`), or
`{"operator": "is" | "is not" | "contains" | "does not contain", "value": [...]}`.
Unknown fields or operators raise `ValueError`: the API would silently ignore
them and return every row.

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`traffic_logs(range=, start=, end=, filters=, max_items=, page_size=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.traffic_logs) | `GET .../traffic-logs` | Iterator\[[TrafficLogRow](reference/types.md#trafficlogrow)\] | Iterator; follows `nextCursor`. Filters: verdict, user, workspace, virtual_key, model, traffic_type, request_path. |
| [`traffic_logs_page(cursor, ...)`](reference/client.md#pyfortiaigate.FortiAIGate.traffic_logs_page) | `GET .../traffic-logs` | [TrafficLogPage](reference/types.md#trafficlogpage) | One page with `nextCursor`, `hasNext`, `total` (first page). |
| [`traffic_log(uuid, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.traffic_log) | `GET .../traffic-logs/{uuid}` | [TrafficLog](reference/types.md#trafficlog) | Full record: verdict, action, detector, guardrail, policy, prompt, cost, latency. |
| [`traffic_log_filter_options(range=, start=, end=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.traffic_log_filter_options) | `GET .../traffic-logs/filter-options` | [TrafficFilterOptions](reference/types.md#trafficfilteroptions) | Values each filter can take. |
| [`wait_for_traffic(since, filters=, count=1, timeout=60, interval=2, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.wait_for_traffic) | `GET .../traffic-logs` (polled) | list\[[TrafficLogRow](reference/types.md#trafficlogrow)\] | Rows land seconds after a request: wait for `count` rows from `since` on. `TimeoutError` otherwise. |
| [`icap_logs(...)`](reference/client.md#pyfortiaigate.FortiAIGate.icap_logs) | `GET .../icap-logs` | Iterator\[dict\[str, Any\]\] | Iterator (offset paging). Filters: verdict, direction, user, application, fortigate, shadow_ai, inspection. 404 when ICAP is off. |
| [`icap_logs_page(offset, ...)`](reference/client.md#pyfortiaigate.FortiAIGate.icap_logs_page) | `GET .../icap-logs` | [IcapLogPage](reference/types.md#icaplogpage) |  |
| [`icap_log(uuid, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.icap_log) | `GET .../icap-logs/{uuid}` | dict\[str, Any\] |  |
| [`icap_log_filter_options(...)`](reference/client.md#pyfortiaigate.FortiAIGate.icap_log_filter_options) | `GET .../icap-logs/filter-options` | dict\[str, Any\] |  |

## Audit log & licenses

The audit log takes the same `range=` / `start=` / `end=` and `filters=` as the
traffic log. Filters: user, role, action, message, workspace; spell actions as
`audit_log_filter_options()` lists them (`Approve`, `Create`, ...).

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`iter_audit_logs(range=, start=, end=, filters=, max_items=, page_size=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.iter_audit_logs) | `GET .../audit-logs` | Iterator\[[AuditLogRow](reference/types.md#auditlogrow)\] | Iterator; follows `nextCursor`. |
| [`audit_logs_page(cursor, ...)`](reference/client.md#pyfortiaigate.FortiAIGate.audit_logs_page) | `GET .../audit-logs` | [AuditLogPage](reference/types.md#auditlogpage) | One page. |
| [`audit_logs(offset, limit)`](reference/client.md#pyfortiaigate.FortiAIGate.audit_logs) | `GET /api/v1/admin/audit-logs` | [AuditLogPage](reference/types.md#auditlogpage) | One page by offset, no filters. |
| [`audit_log_filter_options(range=, start=, end=, ws_id=)`](reference/client.md#pyfortiaigate.FortiAIGate.audit_log_filter_options) | `GET .../audit-logs/filter-options` | [AuditFilterOptions](reference/types.md#auditfilteroptions) | Users, roles, actions, workspaces seen. |
| [`licenses()`](reference/client.md#pyfortiaigate.FortiAIGate.licenses) | `GET /api/v1/licenses` | [Licenses](reference/types.md#licenses) | Serial, status, end date, GPU mapping. |

## Gateway (data plane)

Authenticated with a virtual key secret, never the session.

| Method | HTTP | Returns | Notes |
|---|---|---|---|
| [`check_key(api_key)`](reference/client.md#pyfortiaigate.FortiAIGate.check_key) | `GET /ai/openai/v1/models` | [KeyCheck](reference/types.md#keycheck) | `{"valid", "model_count", "http_status"}`. |
| [`available_models(api_key)`](reference/client.md#pyfortiaigate.FortiAIGate.available_models) | `GET /ai/openai/v1/models` | list\[str\] | Model names the key may call. A model missing here 404s with "model not available to this API key". |
| [`can_use_model(api_key, model)`](reference/client.md#pyfortiaigate.FortiAIGate.can_use_model) | `GET /ai/openai/v1/models` | bool | `model in available_models(api_key)`. |
| [`chat_completion(api_key, model, messages, max_tokens=, temperature=, **extra)`](reference/client.md#pyfortiaigate.FortiAIGate.chat_completion) | `POST /ai/openai/v1/chat/completions` | [ChatCompletion](reference/types.md#chatcompletion) | A guardrail block is a 200; test it with [`blocked()`](reference/helpers.md#pyfortiaigate.blocked). A model the key lacks raises `ModelNotAvailable`. |
| [`chat_completion_stream(api_key, model, messages, max_tokens=, temperature=, **extra)`](reference/client.md#pyfortiaigate.FortiAIGate.chat_completion_stream) | `POST /ai/openai/v1/chat/completions` (`stream: true`) | Iterator\[dict\[str, Any\]\] | Yields chunks; a block arrives as a `content_filter` chunk. [`collect_stream()`](reference/helpers.md#pyfortiaigate.collect_stream) joins them. |
