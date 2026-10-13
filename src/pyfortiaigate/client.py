"""FortiAIGate 8.x client: management API (/api/v1/...) and the OpenAI-compatible
gateway (/ai/openai/v1/...).

Standard library only, and self-contained: this one file can be copied onto a
host that cannot pip install (a lab VM, a student pod) and imported as-is.

There is no published OpenAPI document. The endpoints are the ones the console
(a Next.js app) calls; behaviour noted here was verified live on 8.0.2:

* Auth is a session (``POST /api/v1/login`` -> ``session_id`` cookie) or a
  bearer token. Every mutation on a session needs a fresh ``X-CSRF-Token`` from
  ``GET /api/csrf-token``. Virtual keys are for the gateway, never /api/v1/*.
* The session expires (~24 min on 8.0.2). A 401 means nothing was applied, so
  the client logs in again and resends.
* Workspace objects go ``draft`` -> ``submit`` -> ``pending`` -> org-admin
  ``approve`` -> ``active``. Editing an ACTIVE guardrail or detector applies at
  once, with no re-approval.
* A guardrail needs at least one detector.
* A regex detector matches on the flat ``rules`` list; ``regexRules`` is only the
  editor's grouping. ``rules: []`` stores fine and silently matches nothing.
* A DLP rule's field is ``disposition``, not ``action``.
* Users exist only via invitation; ``POST /api/v1/invitations/{id}/accept`` is
  unauthenticated and sets the password. FortiAIGate sends no email.
* A virtual key's secret is returned once, at create or rotate, and embeds the
  key's id: ``faig_<uuid without dashes>_...``.
* A guardrail block on the gateway is HTTP 200 with ``finish_reason``
  ``content_filter``, not an error status.
* Bodiless mutations are rejected ("request body is required"): POST/PUT/PATCH
  send ``{}`` when there is no body.
* A policy must grant at least one model (HTTP 422 otherwise): pass
  ``provider_ids`` to ``create_policy``.
* A virtual key's GET returns ``policyIds`` as ``{"id", "assignedByOrg"}``
  objects and many read-only fields; its PUT takes only the writable fields,
  with plain id strings (``key_update_body``). Revoking requires a ``reason``.
* The current user is ``GET /api/v1/user``; there is no ``/api/v1/me``.
"""

from __future__ import annotations

import contextlib
import http.client
import http.cookiejar
import io
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from typing import Any

log = logging.getLogger("pyfortiaigate")

JSON = Any

# Invitable org roles (8.0.2 rejects plain "member").
ROLE_MEMBER = "org_member"
ROLE_ADMIN = "org_admin"

# Review-queue ``type`` -> the approve/reject path segment.
QUEUE_KIND = {"guardrail": "guardrails", "detector": "detectors", "policy": "policies"}

# Where a create/rotate response may carry a virtual key's one-time secret.
SECRET_FIELDS = ("secretKey", "secret_key", "apiKey", "api_key", "newKey", "new_key", "key")

_BODY_METHODS = {"POST", "PUT", "PATCH"}


class FaigError(RuntimeError):
    """An HTTP status >= 400 from FortiAIGate. ``body`` is the raw response text."""

    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"{method} {path} -> HTTP {status}: {_message(body)}")
        self.method = method
        self.path = path
        self.status = status
        self.body = body


def _message(body: str) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return body[:400]
    if isinstance(data, dict):
        for key in ("error", "message", "detail"):
            if data.get(key):
                return str(data[key])[:400]
    return body[:400]


def origin(url: str) -> str:
    """``host``, ``https://host``, ``https://host/api`` -> ``https://host``."""
    url = url.strip()
    if not url:
        raise ValueError("FortiAIGate URL is required")
    if "://" not in url:
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        raise ValueError(f"not a URL: {url!r}")
    return f"{parts.scheme}://{parts.netloc}"


def items(data: JSON) -> list[dict[str, Any]]:
    """A list endpoint's records, whether it answers a bare list or ``{"items": [...]}``."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "results"):
            if isinstance(data.get(key), list):
                return list(data[key])
    return []


def key_id_from_secret(secret: str) -> str:
    """A virtual key secret embeds its record id: ``faig_<uuid-no-dashes>_...``."""
    bare = secret.split("_")[1]
    return "-".join((bare[:8], bare[8:12], bare[12:16], bare[16:20], bare[20:]))


def secret_from_response(data: JSON) -> str | None:
    """The one-time ``faig_...`` secret in a create or rotate response, if any."""
    if not isinstance(data, dict):
        return None
    for record in (data, data.get("key") or {}):
        for name in SECRET_FIELDS:
            value = record.get(name) if isinstance(record, dict) else None
            if isinstance(value, str) and value.startswith("faig_"):
                return value
    return None


# -- transport -----------------------------------------------------------------
class _Resp(io.BytesIO):
    def __init__(self, status: int, body: bytes):
        super().__init__(body)
        self.status = status

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _KeepAliveOpener:
    """urllib's ``opener.open(req, timeout)`` contract on ONE reused HTTPS connection.

    urllib opens a new connection per request. Through a tunnel a new connect
    can cost 1.5-2s while a request on an open connection is ~0.1s, and every
    mutation is two requests (CSRF token, then the call). Errors keep urllib's
    shape for the retry rules: a failed connect or send is a URLError (never
    answered), a drop while waiting for the response is raised as-is (it may
    have landed), and a status >= 400 is an HTTPError carrying the body."""

    IDLE = 30.0  # reopen rather than reuse a connection the server may have idled out

    def __init__(self, ctx: ssl.SSLContext, jar: http.cookiejar.CookieJar):
        self._ctx, self._jar = ctx, jar
        self._conn: http.client.HTTPConnection | None = None
        self._key: tuple[str, str, int] | None = None
        self._last = 0.0

    def close(self) -> None:
        if self._conn:
            self._conn.close()
        self._conn = None

    def open(self, req: urllib.request.Request, timeout: float = 60) -> _Resp:
        u = urllib.parse.urlsplit(req.full_url)
        key = (u.scheme, u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
        if self._conn and (key != self._key or time.monotonic() - self._last > self.IDLE):
            self.close()
        try:
            if not self._conn:
                if u.scheme == "https":
                    self._conn = http.client.HTTPSConnection(
                        key[1], key[2], context=self._ctx, timeout=timeout
                    )
                else:
                    self._conn = http.client.HTTPConnection(key[1], key[2], timeout=timeout)
                self._key = key
                self._conn.connect()
            self._conn.timeout = timeout
            self._jar.add_cookie_header(req)
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            self._conn.request(
                req.get_method(), path, body=req.data, headers=dict(req.header_items())
            )
        except (OSError, http.client.HTTPException) as e:
            self.close()
            raise urllib.error.URLError(e) from e
        try:
            resp = self._conn.getresponse()
            body = resp.read()
        except BaseException:
            self.close()
            raise
        self._last = time.monotonic()
        self._jar.extract_cookies(resp, req)
        if resp.will_close:
            self.close()
        if resp.status >= 400:
            raise urllib.error.HTTPError(
                req.full_url, resp.status, resp.reason, resp.msg, io.BytesIO(body)
            )
        return _Resp(resp.status, body)


class FortiAIGate:
    """FortiAIGate 8.x client.

    ``FortiAIGate(url, username, password)`` logs in on the first call (the
    login name is the account's EMAIL, or ``admin`` for the built-in admin).
    ``FortiAIGate(url, token=...)`` uses a bearer token instead. ``verify`` is
    True (system trust store), a CA bundle path (trust a self-signed appliance
    certificate), or False (no verification; lab use only). ``gateway_url`` is
    the data plane's base when it differs from the management URL.

    Transport failures are retried with backoff (1, 2, 4, ... s): a request that
    was never answered is retried for every method; a connection dropped AFTER
    the request went out is retried only for GET, since a mutation may already
    have landed. HTTP errors are never retried, except one re-login on 401 and
    one fresh CSRF token on a CSRF 403."""

    def __init__(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
        *,
        token: str | None = None,
        verify: bool | str = True,
        timeout: float = 60,
        retries: int = 5,
        gateway_url: str | None = None,
    ):
        self.url = origin(url)
        self.gateway_url = origin(gateway_url) if gateway_url else self.url
        self.timeout = timeout
        self.retries = retries
        self._token = token
        self._creds = (username, password or "") if username else None
        self._logged_in = False
        self._ctx = _ssl_context(verify)
        self._jar = http.cookiejar.CookieJar()
        self._opener = _KeepAliveOpener(self._ctx, self._jar)

    @classmethod
    def from_env(cls, **kw: Any) -> FortiAIGate:
        """FAIG_URL plus FAIG_TOKEN or FAIG_USERNAME/FAIG_PASSWORD. FAIG_CA_BUNDLE
        trusts a CA file; FAIG_VERIFY_TLS=false turns verification off."""
        env = os.environ
        verify: bool | str = env.get("FAIG_CA_BUNDLE") or True
        if env.get("FAIG_VERIFY_TLS", "true").strip().lower() in ("0", "false", "no"):
            verify = False
        return cls(
            env["FAIG_URL"],
            env.get("FAIG_USERNAME"),
            env.get("FAIG_PASSWORD"),
            token=env.get("FAIG_TOKEN") or None,
            verify=verify,
            **kw,
        )

    def __enter__(self) -> FortiAIGate:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Log out (best effort) and drop the connection."""
        if self._logged_in:
            with contextlib.suppress(FaigError, OSError, http.client.HTTPException):
                self.post("/api/v1/logout")
            self._logged_in = False
        self._opener.close()

    # -- raw transport ---------------------------------------------------------
    def _raw(
        self,
        method: str,
        url: str,
        body: JSON = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        """One request with transport retries. Returns (status, text) for every
        HTTP answer, error statuses included."""
        data = None if body is None else json.dumps(body).encode()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        hdrs.update(headers or {})
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            try:
                with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                    return resp.status, resp.read().decode(errors="replace")
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode(errors="replace")
            except urllib.error.URLError as e:
                err: Exception = e
            except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as e:
                if method != "GET":
                    raise
                err = e
            if attempt == self.retries:
                raise err
            wait = 2**attempt
            log.warning(
                "%s %s: %s; retry %d/%d in %ds", method, url, err, attempt + 1, self.retries, wait
            )
            time.sleep(wait)
        raise AssertionError("unreachable")

    def _path(self, path: str, params: Mapping[str, Any] | None = None) -> str:
        if not path.startswith("/"):
            path = "/" + path
        if path.startswith("/v1/"):  # tolerate paths written relative to /api
            path = "/api" + path
        if params:
            q = {k: v for k, v in params.items() if v is not None}
            if q:
                path += ("&" if "?" in path else "?") + urllib.parse.urlencode(q, doseq=True)
        return path

    # -- auth --------------------------------------------------------------------
    def login(self, username: str | None = None, password: str | None = None) -> None:
        """Log in now (the client otherwise logs in on its first call)."""
        if username:
            self._creds = (username, password or "")
        if not self._creds:
            raise ValueError("login needs a username and password")
        user, pw = self._creds
        body = {"username": user, "password": pw}
        st, txt = self._raw("POST", self.url + "/api/v1/login", body)
        if st != 200:
            # The legacy /api/login takes only the built-in admin by its bare name.
            st2, _ = self._raw("POST", self.url + "/api/login", body)
            if st2 != 200:
                raise FaigError("POST", "/api/v1/login", st, txt)
        self._logged_in = True

    def _auth_headers(self, method: str) -> tuple[int, str, dict[str, str]]:
        """(status, text, headers): status != 200 means the CSRF fetch failed."""
        if self._token:
            return 200, "", {"Authorization": f"Bearer {self._token}"}
        if method == "GET":
            return 200, "", {}
        # CSRF tokens are short-lived: one per mutation rather than a cached one.
        st, txt = self._raw("GET", self.url + "/api/csrf-token")
        if st != 200:
            return st, txt, {}
        return 200, "", {"X-CSRF-Token": str(json.loads(txt).get("csrf_token", ""))}

    def _send(self, method: str, path: str, body: JSON) -> tuple[int, str]:
        st, txt, headers = self._auth_headers(method)
        if st != 200:
            return st, txt
        return self._raw(method, self.url + path, body, headers)

    def request(
        self,
        method: str,
        path: str,
        body: JSON = None,
        params: Mapping[str, Any] | None = None,
    ) -> JSON:
        """Call the management API. ``path`` is ``/api/v1/...`` (or ``/v1/...``).
        Returns the decoded JSON, or None for an empty body."""
        method = method.upper()
        path = self._path(path, params)
        if body is None and method in _BODY_METHODS:
            body = {}
        if self._creds and not self._token and not self._logged_in:
            self.login()
        st, txt = self._send(method, path, body)
        if st == 401 and self._creds and not self._token:
            # Session expired: a 401 means nothing was applied, so log in and resend.
            self._logged_in = False
            self.login()
            st, txt = self._send(method, path, body)
        elif st == 403 and method != "GET" and "csrf" in txt.lower():
            st, txt = self._send(method, path, body)  # a token that went stale in flight
        if st >= 400:
            raise FaigError(method, path, st, txt)
        return json.loads(txt) if txt.strip() else None

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> JSON:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: JSON = None) -> JSON:
        return self.request("POST", path, body)

    def put(self, path: str, body: JSON) -> JSON:
        return self.request("PUT", path, body)

    def patch(self, path: str, body: JSON) -> JSON:
        return self.request("PATCH", path, body)

    def delete(self, path: str) -> JSON:
        return self.request("DELETE", path)

    def _list(self, path: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        return items(self.get(path, params))

    def me(self) -> JSON:
        """The logged-in user (``email``, ``role``, ``memberships``, ...)."""
        return self.get("/api/v1/user")

    # -- users & invitations (org admin) -----------------------------------------
    def users(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/admin/users")

    def user(self, user_id: str) -> JSON:
        return self.get(f"/api/v1/admin/users/{_q(user_id)}")

    def user_by_email(self, email: str) -> dict[str, Any] | None:
        e = email.lower()
        return next((u for u in self.users() if str(u.get("email", "")).lower() == e), None)

    def invite(self, email: str, role: str = ROLE_MEMBER) -> JSON:
        return self.post("/api/v1/admin/user-invitations", {"emails": [email], "orgRole": role})

    def accept_invite(
        self, invitation_id: str, email: str, password: str, display_name: str = ""
    ) -> JSON:
        """Unauthenticated in the product, so sent with no session cookie."""
        body: dict[str, Any] = {"email": email, "password": password}
        if display_name:
            body["displayName"] = display_name
        path = f"/api/v1/invitations/{_q(invitation_id)}/accept"
        anon = FortiAIGate(self.url, timeout=self.timeout, retries=self.retries)
        anon._ctx = self._ctx
        anon._opener = _KeepAliveOpener(self._ctx, anon._jar)
        try:
            st, txt = anon._raw("POST", self.url + path, body)
        finally:
            anon._opener.close()
        if st >= 400:
            raise FaigError("POST", path, st, txt)
        return json.loads(txt) if txt.strip() else None

    def delete_user(self, user_id: str) -> JSON:
        return self.delete(f"/api/v1/admin/users/{_q(user_id)}")

    def make_workspace_admin(self, user_id: str, ws_id: str) -> JSON:
        """The user update REPLACES the user's workspace list, so the existing
        memberships are kept and this one added."""
        u = self.user(user_id)
        keep = [
            {"workspaceId": w["workspaceId"], "role": w.get("membershipRole", "workspace_member")}
            for w in u.get("workspaces") or []
            if w["workspaceId"] != ws_id
        ]
        # A GET's `orgRole` is the EFFECTIVE role (workspace_admin once they admin
        # a workspace); `orgRoleStored` is the real org role -- send that back.
        return self.put(
            f"/api/v1/admin/users/{_q(user_id)}",
            {
                "email": u["email"],
                "fullName": u.get("fullName") or u["email"],
                "orgRole": u.get("orgRoleStored") or u["orgRole"],
                "workspaces": [*keep, {"workspaceId": ws_id, "role": "workspace_admin"}],
            },
        )

    # -- workspaces ----------------------------------------------------------------
    def workspaces(self) -> list[dict[str, Any]]:
        """Every workspace (org admin)."""
        return self._list("/api/v1/admin/workspaces")

    def my_workspaces(self) -> list[dict[str, Any]]:
        """The workspaces the logged-in user is a member of."""
        return self._list("/api/v1/me/workspaces")

    def workspace_by_name(self, name: str) -> dict[str, Any] | None:
        return next((w for w in self.workspaces() if w.get("workspaceName") == name), None)

    def create_workspace(
        self,
        name: str,
        admin_ids: Iterable[str],
        provider_ids: Iterable[str],
        description: str = "",
    ) -> JSON:
        """``admin_ids`` must be EXISTING user ids (a pending invitation is not one)."""
        return self.post(
            "/api/v1/admin/workspaces",
            {
                "workspaceName": name,
                "description": description,
                "admins": [{"id": i} for i in admin_ids],
                "budget": None,
                "budgetCycle": "monthly",
                "providerAccess": [
                    {"providerId": p, "allKeys": True, "allModels": True} for p in provider_ids
                ],
            },
        )

    def delete_workspace(self, ws_id: str) -> JSON:
        return self.delete(f"/api/v1/admin/workspaces/{_q(ws_id)}")

    def workspace_members(self, ws_id: str) -> JSON:
        return self.get(f"/api/v1/workspaces/{_q(ws_id)}/members")

    def workspace_budget(self, ws_id: str) -> JSON:
        return self.get(f"/api/v1/workspaces/{_q(ws_id)}/budget")

    def workspace_analytics(self, ws_id: str) -> JSON:
        return self.get(f"/api/v1/workspaces/{_q(ws_id)}/analytics")

    # -- detectors -----------------------------------------------------------------
    def detectors(self, ws_id: str | None = None) -> list[dict[str, Any]]:
        """Custom detectors in a workspace, or (no ``ws_id``) every custom detector."""
        if ws_id:
            return self._list(f"/api/v1/workspaces/{_q(ws_id)}/detectors")
        return self._list("/api/v1/admin/detectors")

    def builtin_detectors(self) -> list[dict[str, Any]]:
        """Built-in detectors, identified by a slug id; a guardrail can use either kind."""
        return self._list("/api/v1/admin/built-in-detectors")

    def detector_by_name(self, ws_id: str, name: str) -> dict[str, Any] | None:
        return next((d for d in self.detectors(ws_id) if d.get("name") == name), None)

    def create_detector(self, ws_id: str, body: Mapping[str, Any]) -> JSON:
        """See ``regex_detector_body`` and ``dlp_detector_body``."""
        return self.post(f"/api/v1/workspaces/{_q(ws_id)}/detectors", dict(body))

    def update_detector(self, ws_id: str, uuid: str, body: Mapping[str, Any]) -> JSON:
        return self.put(f"/api/v1/workspaces/{_q(ws_id)}/detectors/{_q(uuid)}", dict(body))

    def delete_detector(self, uuid: str) -> JSON:
        return self.delete(f"/api/v1/admin/detectors/{_q(uuid)}")

    def test_detector(self, ws_id: str, uuid: str, text: str) -> JSON:
        return self.post(
            f"/api/v1/workspaces/{_q(ws_id)}/detectors/{_q(uuid)}/test", {"input": text}
        )

    # -- guardrails ----------------------------------------------------------------
    def guardrails(self, ws_id: str | None = None) -> list[dict[str, Any]]:
        """A workspace's guardrails, or (no ``ws_id``) the org's."""
        if ws_id:
            return self._list(f"/api/v1/workspaces/{_q(ws_id)}/guardrails")
        return self._list("/api/v1/admin/guardrails")

    def guardrail(self, gid: str) -> dict[str, Any]:
        data = self.get(f"/api/v1/admin/guardrails/{_q(gid)}")
        return dict(data.get("guardrail", data)) if isinstance(data, dict) else {}

    def guardrail_by_name(self, ws_id: str | None, name: str) -> dict[str, Any] | None:
        return next((g for g in self.guardrails(ws_id) if g.get("name") == name), None)

    def create_guardrail(
        self, ws_id: str, name: str, detector_ids: list[str], description: str = ""
    ) -> JSON:
        return self.post(
            f"/api/v1/workspaces/{_q(ws_id)}/guardrails",
            guardrail_body(name, detector_ids, description),
        )

    def update_guardrail(
        self, ws_id: str, gid: str, name: str, detector_ids: list[str], description: str = ""
    ) -> JSON:
        return self.put(
            f"/api/v1/workspaces/{_q(ws_id)}/guardrails/{_q(gid)}",
            guardrail_body(name, detector_ids, description),
        )

    def delete_guardrail(self, gid: str, ws_id: str | None = None) -> JSON:
        """Delete a workspace guardrail (``ws_id``) or an org guardrail."""
        if ws_id:
            return self.delete(f"/api/v1/workspaces/{_q(ws_id)}/guardrails/{_q(gid)}")
        return self.delete(f"/api/v1/admin/guardrails/{_q(gid)}")

    def test_guardrail(
        self,
        text: str,
        detector_ids: list[str] | None = None,
        *,
        guardrail_id: str | None = None,
        deny_suspicious_characters: bool = False,
    ) -> JSON:
        """Scan text with detectors (no LLM involved). Pass ``detector_ids``, or
        ``guardrail_id`` to reuse a guardrail's detectors and its
        denySuspiciousCharacters setting."""
        if not detector_ids and not guardrail_id:
            raise ValueError("detector_ids or guardrail_id is required")
        if guardrail_id and not detector_ids:
            g = self.guardrail(guardrail_id)
            detector_ids = list(g.get("detectorIds") or [])
            deny_suspicious_characters = bool(
                g.get("denySuspiciousCharacters", deny_suspicious_characters)
            )
        return self.post(
            "/api/v1/admin/guardrails/test",
            {
                "input": text,
                "detectorIds": detector_ids,
                "denySuspiciousCharacters": deny_suspicious_characters,
            },
        )

    # -- policies --------------------------------------------------------------------
    def policies(self, ws_id: str | None = None) -> list[dict[str, Any]]:
        """A workspace's policies, or (no ``ws_id``) the org's."""
        if ws_id:
            return self._list(f"/api/v1/workspaces/{_q(ws_id)}/policies")
        return self._list("/api/v1/admin/policies")

    def policy(self, pid: str) -> dict[str, Any]:
        data = self.get(f"/api/v1/admin/policies/{_q(pid)}")
        return dict(data.get("policy", data)) if isinstance(data, dict) else {}

    def policy_by_name(self, ws_id: str | None, name: str) -> dict[str, Any] | None:
        return next((p for p in self.policies(ws_id) if p.get("name") == name), None)

    def create_policy(
        self,
        ws_id: str,
        name: str,
        input_guardrail_ids: list[str],
        output_guardrail_ids: list[str],
        *,
        provider_ids: list[str] | None = None,
        description: str = "",
        response_scan_mode: str = "post_stream",
    ) -> JSON:
        """``provider_ids`` grants every model of those providers. Some 8.0.2
        builds refuse a policy that grants no model (HTTP 422 "a policy must
        grant at least one model")."""
        body: dict[str, Any] = {
            "name": name,
            "description": description or name,
            "inputGuardrailIds": input_guardrail_ids,
            "outputGuardrailIds": output_guardrail_ids,
            "responseScanMode": response_scan_mode,
        }
        if provider_ids is not None:
            body["providerAccess"] = [{"providerId": p, "allModels": True} for p in provider_ids]
        return self.post(f"/api/v1/workspaces/{_q(ws_id)}/policies", body)

    def delete_policy(self, pid: str, ws_id: str | None = None) -> JSON:
        """Delete a workspace policy (``ws_id``) or an org policy."""
        if ws_id:
            return self.delete(f"/api/v1/workspaces/{_q(ws_id)}/policies/{_q(pid)}")
        return self.delete(f"/api/v1/admin/policies/{_q(pid)}")

    # -- approval (org admin) ----------------------------------------------------------
    def submit(self, ws_id: str, kind: str, obj_id: str) -> JSON:
        """kind: detectors | guardrails | policies"""
        return self.post(f"/api/v1/workspaces/{_q(ws_id)}/{kind}/{_q(obj_id)}/submit")

    def approve(self, kind: str, obj_id: str) -> JSON:
        return self.post(f"/api/v1/admin/{kind}/{_q(obj_id)}/approve")

    def reject(self, kind: str, obj_id: str, reason: str = "rejected") -> JSON:
        return self.post(f"/api/v1/admin/{kind}/{_q(obj_id)}/reject", {"reason": reason})

    def review_queue(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/admin/review-queue")

    # -- virtual keys ----------------------------------------------------------------------
    def virtual_keys(
        self, ws_id: str | None = None, *, status: str | None = None
    ) -> list[dict[str, Any]]:
        """A workspace's keys, or (no ``ws_id``) every key; ``status`` filters."""
        if ws_id:
            keys = self._list(f"/api/v1/workspaces/{_q(ws_id)}/virtual-keys")
        else:
            keys = self._list("/api/v1/admin/virtual-keys")
        return [k for k in keys if not status or k.get("status") == status]

    def virtual_key(self, key_id: str) -> dict[str, Any]:
        data = self.get(f"/api/v1/admin/virtual-keys/{_q(key_id)}")
        return dict(data.get("key", data)) if isinstance(data, dict) else {}

    def create_virtual_key(
        self,
        ws_id: str,
        name: str,
        *,
        policy_ids: list[str] | None = None,
        provider_ids: list[str] | None = None,
        expires_at: str | None = None,
        tpm: int | str | None = None,
        rpm: int | str | None = None,
    ) -> JSON:
        """Create a key in a workspace. The secret is in the response ONCE
        (``secret_from_response``) and never readable again."""
        body: dict[str, Any] = {"keyName": name}
        if policy_ids is not None:
            body["policyIds"] = policy_ids
        if provider_ids is not None:
            body["providerAccess"] = [
                {"providerId": p, "allKeys": True, "allModels": True} for p in provider_ids
            ]
        for field, value in (("expiresAt", expires_at), ("tpm", tpm), ("rpm", rpm)):
            if value is not None and value != "":
                body[field] = value
        return self.post(f"/api/v1/workspaces/{_q(ws_id)}/virtual-keys", body)

    def update_virtual_key(
        self,
        key_id: str,
        *,
        expires_at: str | None = None,
        tpm: int | str | None = None,
        rpm: int | str | None = None,
        policy_ids: list[str] | None = None,
    ) -> JSON:
        """The update REPLACES the record, so the current one is read and its
        writable fields resent with the changes (8.0.2 rejects read-only fields
        such as ``status`` or ``spend``). ``policy_ids`` replaces the attached
        policies (org-assigned policies stay forced onto the key regardless)."""
        body = key_update_body(self.virtual_key(key_id))
        for field, value in (("expiresAt", expires_at), ("tpm", tpm), ("rpm", rpm)):
            if value is not None and value != "":
                body[field] = value
        if policy_ids is not None:
            body["policyIds"] = [str(p) for p in policy_ids]
        return self.put(f"/api/v1/admin/virtual-keys/{_q(key_id)}", body)

    def rotate_virtual_key(self, key_id: str) -> JSON:
        """New secret, once, in the response (``secret_from_response``)."""
        return self.post(f"/api/v1/admin/virtual-keys/{_q(key_id)}/rotate")

    def revoke_virtual_key(self, key_id: str, reason: str = "revoked") -> JSON:
        """The secret stops working; 8.0.2 requires a ``reason``."""
        return self.post(f"/api/v1/admin/virtual-keys/{_q(key_id)}/revoke", {"reason": reason})

    def delete_virtual_key(self, key_id: str) -> JSON:
        return self.delete(f"/api/v1/admin/virtual-keys/{_q(key_id)}")

    # -- providers, models, audit ----------------------------------------------------------
    def ai_providers(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/admin/ai-providers")

    def model_groups(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/model-groups")

    def dlp_labels(self) -> list[dict[str, Any]]:
        """The DLP category names ``dlp_detector_body`` takes."""
        return self._list("/api/v1/admin/dlp-labels")

    def audit_logs(self, offset: int = 0, limit: int = 25) -> JSON:
        return self.get("/api/v1/admin/audit-logs", {"offset": int(offset), "limit": int(limit)})

    def audit_log_filter_options(self) -> JSON:
        return self.get("/api/v1/admin/audit-logs/filter-options")

    # -- gateway (data plane) ----------------------------------------------------------------
    def _gateway(
        self, method: str, path: str, api_key: str, body: JSON = None, timeout: float | None = None
    ) -> tuple[int, str]:
        return self._raw(
            method,
            self.gateway_url + path,
            body,
            {"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def check_key(self, api_key: str) -> dict[str, Any]:
        """Is a virtual key secret accepted by the gateway? Returns ``valid`` and
        ``model_count``; only an unexpected status raises."""
        path = "/ai/openai/v1/models"
        st, txt = self._gateway("GET", path, api_key)
        if st == 200:
            return {"valid": True, "model_count": len(items(json.loads(txt))), "http_status": st}
        if st in (401, 403):
            return {"valid": False, "model_count": 0, "http_status": st}
        raise FaigError("GET", path, st, txt)

    def chat_completion(
        self,
        api_key: str,
        model: str,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        timeout: float = 120,
        **extra: Any,
    ) -> JSON:
        """One OpenAI-compatible chat completion through the gateway; the key's
        policies apply. A guardrail block is HTTP 200 with ``finish_reason``
        ``content_filter`` (see ``blocked``), not an exception."""
        if not messages:
            raise ValueError("messages must be a non-empty list")
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False, **extra}
        if max_tokens:
            body["max_tokens"] = int(max_tokens)
        if temperature is not None:
            body["temperature"] = float(temperature)
        path = "/ai/openai/v1/chat/completions"
        st, txt = self._gateway("POST", path, api_key, body, timeout=max(self.timeout, timeout))
        if st != 200:
            raise FaigError("POST", path, st, txt)
        return json.loads(txt)


def _ssl_context(verify: bool | str) -> ssl.SSLContext:
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _q(segment: str) -> str:
    return urllib.parse.quote(str(segment), safe="")


def blocked(completion: JSON) -> bool:
    """Did a guardrail block this chat completion?"""
    choices = completion.get("choices") if isinstance(completion, dict) else None
    if not isinstance(choices, list):
        return False
    return any(c.get("finish_reason") == "content_filter" for c in choices if isinstance(c, dict))


# Fields a virtual-key PUT accepts; every other field of the GET is read-only.
KEY_WRITABLE = (
    "keyName",
    "expiresAt",
    "tpm",
    "rpm",
    "policyIds",
    "providerAccess",
    "modelGroups",
    "budgetWindows",
)


def key_update_body(record: Mapping[str, Any]) -> dict[str, Any]:
    """A virtual-key record (as read) reduced to what an update may send. A
    read returns ``policyIds`` as ``{"id", "assignedByOrg"}`` objects; the
    update takes plain id strings."""
    body = {k: record[k] for k in KEY_WRITABLE if k in record}
    if "policyIds" in body:
        body["policyIds"] = [
            str(p["id"]) if isinstance(p, dict) else str(p) for p in body["policyIds"] or []
        ]
    return body


# -- body builders ------------------------------------------------------------------------
def guardrail_body(name: str, detector_ids: list[str], description: str = "") -> dict[str, Any]:
    if not detector_ids:
        raise ValueError("a guardrail needs at least one detector")
    return {
        "name": name,
        "description": description or name,
        "detectorIds": list(detector_ids),
        "denySuspiciousCharacters": False,
    }


def regex_detector_body(
    name: str, rules: Iterable[tuple[str, str, str]], description: str = ""
) -> dict[str, Any]:
    """rules: ``[(rule_name, pattern, disposition)]``. Fills BOTH ``regexRules``
    (the editor's grouping) and the flat ``rules`` list the engine matches on."""
    regex_rules: list[dict[str, Any]] = [
        {
            "id": f"r{i}",
            "name": rn,
            "enabled": True,
            "description": rn,
            "conditions": [{"id": f"c{i}", "pattern": pat, "disposition": disp}],
        }
        for i, (rn, pat, disp) in enumerate(rules, 1)
    ]
    if not regex_rules:
        raise ValueError("a regex detector with no rules matches nothing")
    return {
        "name": name,
        "description": description or name,
        "inputGuards": ["Regex patterns"],
        "outputGuards": ["Regex patterns"],
        "sensitivity": None,
        "detectorType": "regex",
        "managedEngine": None,
        "action": None,
        "aiRules": None,
        "regexRules": regex_rules,
        "rules": [c for r in regex_rules for c in r["conditions"]],
    }


def dlp_detector_body(
    name: str,
    categories: Iterable[str],
    disposition: str = "block",
    threshold: float = 0.7,
    description: str = "",
) -> dict[str, Any]:
    """categories: DLP label names as ``dlp_labels()`` spells them."""
    cats = list(categories)
    return {
        "name": name,
        "description": description or name,
        "inputGuards": cats,
        "outputGuards": cats,
        "sensitivity": None,
        "detectorType": "managed",
        "managedEngine": "dlp",
        "action": None,
        "regexRules": None,
        "aiRules": None,
        "rules": [
            {"id": f"d{i}", "category": c, "disposition": disposition, "threshold": threshold}
            for i, c in enumerate(cats)
        ],
    }


def approve_new(admin: FortiAIGate, ws_id: str, kind: str, obj: Mapping[str, Any]) -> JSON:
    """Walk a freshly created workspace object draft -> pending -> active. Losing
    the race to another approver (it is no longer pending) is not an error."""
    oid = obj.get("uuid") or obj["id"]
    status = obj.get("approvalStatus") or obj.get("status")
    if status == "draft":
        admin.submit(ws_id, kind, oid)
        status = "pending"
    if status == "pending":
        try:
            return admin.approve(kind, oid)
        except FaigError as e:
            if e.status != 409 or "pending submission" not in e.body:
                raise
    return obj
