# Actions

Every client method and the API call it makes. `{ws}` is a workspace id; list
methods return the records (unwrapped from `{"items": [...]}`), the rest return
the decoded JSON response.

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

| Method | HTTP | Notes |
|---|---|---|
| `workspaces()` | `GET /api/v1/admin/workspaces` | Every workspace (org admin). |
| `my_workspaces()` | `GET /api/v1/me/workspaces` | Workspaces the caller belongs to. |
| `workspace_by_name(name)` | `GET /api/v1/admin/workspaces` | |
| `create_workspace(name, admin_ids, provider_ids, description)` | `POST /api/v1/admin/workspaces` | Admins must be existing users. |
| `delete_workspace(ws_id)` | `DELETE /api/v1/admin/workspaces/{ws}` | |
| `workspace_members(ws_id)` | `GET /api/v1/workspaces/{ws}/members` | |
| `workspace_budget(ws_id)` | `GET /api/v1/workspaces/{ws}/budget` | |
| `workspace_analytics(ws_id)` | `GET /api/v1/workspaces/{ws}/analytics` | |

## Detectors

| Method | HTTP | Notes |
|---|---|---|
| `detectors(ws_id=None)` | `GET /api/v1/workspaces/{ws}/detectors` or `GET /api/v1/admin/detectors` | Custom detectors. |
| `builtin_detectors()` | `GET /api/v1/admin/built-in-detectors` | Identified by slug id. |
| `detector_by_name(ws_id, name)` | `GET /api/v1/workspaces/{ws}/detectors` | |
| `create_detector(ws_id, body)` | `POST /api/v1/workspaces/{ws}/detectors` | Build `body` with `regex_detector_body` / `dlp_detector_body`. |
| `update_detector(ws_id, uuid, body)` | `PUT /api/v1/workspaces/{ws}/detectors/{uuid}` | An active detector changes at once. |
| `delete_detector(uuid)` | `DELETE /api/v1/admin/detectors/{uuid}` | |
| `test_detector(ws_id, uuid, text)` | `POST /api/v1/workspaces/{ws}/detectors/{uuid}/test` | |

## Guardrails

| Method | HTTP | Notes |
|---|---|---|
| `guardrails(ws_id=None)` | `GET /api/v1/workspaces/{ws}/guardrails` or `GET /api/v1/admin/guardrails` | |
| `guardrail(gid)` | `GET /api/v1/admin/guardrails/{id}` | |
| `guardrail_by_name(ws_id, name)` | as `guardrails` | `ws_id=None` searches org guardrails. |
| `create_guardrail(ws_id, name, detector_ids, description)` | `POST /api/v1/workspaces/{ws}/guardrails` | Needs at least one detector. |
| `update_guardrail(ws_id, gid, name, detector_ids, description)` | `PUT /api/v1/workspaces/{ws}/guardrails/{id}` | |
| `delete_guardrail(gid, ws_id=None)` | `DELETE /api/v1/workspaces/{ws}/guardrails/{id}` or `DELETE /api/v1/admin/guardrails/{id}` | |
| `test_guardrail(text, detector_ids, guardrail_id=, deny_suspicious_characters=)` | `POST /api/v1/admin/guardrails/test` | Scans text without an LLM. |

## Policies

| Method | HTTP | Notes |
|---|---|---|
| `policies(ws_id=None)` | `GET /api/v1/workspaces/{ws}/policies` or `GET /api/v1/admin/policies` | |
| `policy(pid)` | `GET /api/v1/admin/policies/{id}` | |
| `policy_by_name(ws_id, name)` | as `policies` | |
| `create_policy(ws_id, name, input_guardrail_ids, output_guardrail_ids, provider_ids=, description=, response_scan_mode=)` | `POST /api/v1/workspaces/{ws}/policies` | `provider_ids` grants all of those providers' models; some builds require at least one. |

| `delete_policy(pid, ws_id=None)` | `DELETE /api/v1/workspaces/{ws}/policies/{id}` or `DELETE /api/v1/admin/policies/{id}` | |

## Approval workflow

| Method | HTTP | Notes |
|---|---|---|
| `submit(ws_id, kind, obj_id)` | `POST /api/v1/workspaces/{ws}/{kind}/{id}/submit` | `kind`: `detectors`, `guardrails`, `policies`. |
| `approve(kind, obj_id)` | `POST /api/v1/admin/{kind}/{id}/approve` | |
| `reject(kind, obj_id, reason)` | `POST /api/v1/admin/{kind}/{id}/reject` | |
| `review_queue()` | `GET /api/v1/admin/review-queue` | Map an item's `type` with `QUEUE_KIND`. |

See also [`approve_new`](reference/helpers.md#pyfortiaigate.approve_new).

## Virtual keys

| Method | HTTP | Notes |
|---|---|---|
| `virtual_keys(ws_id=None, status=)` | `GET /api/v1/workspaces/{ws}/virtual-keys` or `GET /api/v1/admin/virtual-keys` | |
| `virtual_key(key_id)` | `GET /api/v1/admin/virtual-keys/{id}` | |
| `create_virtual_key(ws_id, name, policy_ids=, provider_ids=, expires_at=, tpm=, rpm=)` | `POST /api/v1/workspaces/{ws}/virtual-keys` | The secret is returned once. |
| `update_virtual_key(key_id, expires_at=, tpm=, rpm=, policy_ids=)` | `GET` + `PUT /api/v1/admin/virtual-keys/{id}` | Resends the record's writable fields with your changes. |
| `rotate_virtual_key(key_id)` | `POST /api/v1/admin/virtual-keys/{id}/rotate` | New secret, once. |
| `revoke_virtual_key(key_id, reason)` | `POST /api/v1/admin/virtual-keys/{id}/revoke` | The secret stops working; a reason is required. |
| `delete_virtual_key(key_id)` | `DELETE /api/v1/admin/virtual-keys/{id}` | |

## Providers, models & audit

| Method | HTTP | Notes |
|---|---|---|
| `ai_providers()` | `GET /api/v1/admin/ai-providers` | |
| `model_groups()` | `GET /api/v1/model-groups` | Member public names are what `chat_completion` takes as `model`. |
| `dlp_labels()` | `GET /api/v1/admin/dlp-labels` | Category names for `dlp_detector_body`. |
| `audit_logs(offset, limit)` | `GET /api/v1/admin/audit-logs` | |
| `audit_log_filter_options()` | `GET /api/v1/admin/audit-logs/filter-options` | |

## Gateway (data plane)

Authenticated with a virtual key secret, never the session.

| Method | HTTP | Notes |
|---|---|---|
| `check_key(api_key)` | `GET /ai/openai/v1/models` | `{"valid", "model_count", "http_status"}`. |
| `chat_completion(api_key, model, messages, max_tokens=, temperature=, **extra)` | `POST /ai/openai/v1/chat/completions` | A guardrail block is a 200; test it with `blocked()`. |
