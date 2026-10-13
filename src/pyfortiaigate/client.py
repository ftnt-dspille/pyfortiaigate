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
* Traffic-log filters are ``<field>Filters`` holding JSON
  ``{"operator", "value": [...]}``; an unknown name or operator is IGNORED and
  every row returned. Time is ``range`` (24h | 7d | month | all | custom) with
  ``startTime``/``endTime`` in epoch ms; paging is ``cursor`` + ``direction``.
* A Natural Language detector (``detectorType: "ai"``) mirrors a regex one:
  ``aiRules`` for the editor, flat ``rules`` that the engine evaluates.
* A request for a model the key is not granted is HTTP 404.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import email.utils
import http.client
import http.cookiejar
import io
import json
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, NamedTuple, TypedDict, cast

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

# Usage/cost reporting: what the API accepts (it 422s on anything else).
INTERVALS = ("hourly", "daily", "weekly", "monthly")
RANK_BY = ("workspace", "user", "key", "model")
RANK_END = ("top", "bottom", "both")
USAGE_ORDER = ("tokens", "requests")
COST_ORDER = ("providerSpend", "chargebackSpend", "per1kTokens", "perRequest")

# Log time windows; "custom" takes start/end.
LOG_RANGES = ("24h", "7d", "month", "all", "custom")
# Filter operators. The API IGNORES an unknown operator or filter name and
# returns everything, so both are checked here.
FILTER_OPERATORS = ("is", "is not", "contains", "does not contain")
TRAFFIC_FILTERS = {
    "verdict": "verdictFilters",
    "user": "userFilters",
    "workspace": "workspaceFilters",
    "virtual_key": "virtualKeyFilters",
    "model": "modelFilters",
    "traffic_type": "trafficTypeFilters",
    "request_path": "requestPathFilters",
}
ICAP_FILTERS = {
    "verdict": "verdictFilters",
    "direction": "directionFilters",
    "user": "userFilters",
    "application": "applicationFilters",
    "fortigate": "fortigateFilters",
    "shadow_ai": "shadowAiFilters",
    "inspection": "inspectionFilters",
}
LOG_PAGE = 50  # the console's page size

# A workspace argument: its id, its (unique) name, or its record as returned by
# workspaces() / workspace_by_name().
WsRef = str | Mapping[str, Any]
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# A detector, guardrail, policy or virtual key argument: its id, its name, or
# its record. A key may also be given by its ``faig_...`` secret.
Ref = str | Mapping[str, Any]

AUDIT_FILTERS = {
    "user": "userFilters",
    "role": "roleFilters",
    "action": "actionFilters",
    "message": "messageFilters",
    "workspace": "workspaceFilters",
}


# -- record types ------------------------------------------------------------------
# The fields 8.0.2 returns, for editor completion and type checking. They are
# ``total=False``: a field the appliance leaves out is simply absent. Records
# are plain dicts at runtime.
class Workspace(TypedDict, total=False):
    id: str
    workspaceName: str
    organizationId: str
    organization: str
    spend: float
    budget: float | None
    budgetCycle: str
    tpm: int | None
    rpm: int | None
    memberCount: int
    admins: list[dict[str, Any]]
    providerAccess: list[dict[str, Any]]
    modelGroups: list[dict[str, Any]]
    createdAt: str
    createdBy: str
    grantedModelCount: int
    credentialGaps: list[Any]


class _Reviewed(TypedDict, total=False):
    """Fields shared by objects that go through approval."""

    name: str
    description: str
    ownerWorkspaceId: str | None
    scope: str
    submittedBy: Any
    submittedAt: str | None
    rejectionReason: str | None
    createdAt: str
    updatedAt: str
    activatedAt: str | None
    contentUpdatedAt: str | None
    hasPendingChange: bool
    pendingDeletion: bool
    pendingChangeKind: str | None


class Detector(_Reviewed, total=False):
    uuid: str
    inputGuards: list[str]
    outputGuards: list[str]
    ruleCount: int
    sensitivity: Any
    engine: str
    detectorType: str
    managedEngine: str | None
    action: str | None
    rules: list[dict[str, Any]]
    regexRules: list[dict[str, Any]] | None
    aiRules: list[dict[str, Any]] | None
    approvalStatus: str


class Guardrail(_Reviewed, total=False):
    id: str
    detectorIds: list[str]
    status: str
    usedByPolicyCount: int
    denySuspiciousCharacters: bool


class Policy(_Reviewed, total=False):
    id: str
    inputGuardrailIds: list[str]
    outputGuardrailIds: list[str]
    responseScanMode: str
    providerAccess: list[dict[str, Any]]
    status: str
    assignedWorkspaceIds: list[str]
    applyToOrganization: bool


class VirtualKey(TypedDict, total=False):
    id: str
    keyName: str
    keyType: str
    scope: str
    keyPreview: str
    status: str
    createdBy: dict[str, Any]
    owner: dict[str, Any]
    workspace: dict[str, Any]
    project: Any
    policyIds: list[dict[str, Any]]
    providerAccess: list[dict[str, Any]]
    modelGroups: list[Any]
    budgetWindows: dict[str, Any]
    windowSpend: dict[str, Any]
    workspaceSpend: float
    suspension: Any
    spend: float
    tpm: int | None
    rpm: int | None
    expiresAt: str | None
    lastUsedAt: str | None
    revokedAt: str | None
    revokeReason: str | None
    createdAt: str
    updatedAt: str
    updatedBy: dict[str, Any]


class TrafficLogRow(TypedDict, total=False):
    """A row of ``traffic_logs``; ``timeStamp`` is epoch milliseconds."""

    uuid: str
    timeStamp: int
    verdict: bool
    action: str
    verdictLabel: str
    status: str
    user: str
    workspace: str
    isGlobalKey: bool
    keyAlias: str
    keyPrefix: str
    keyType: str
    model: str | None
    modelGroup: str | None
    requestPath: str
    trafficType: str


class TrafficLog(TrafficLogRow, total=False):
    """The full record from ``traffic_log(uuid)``."""

    costBasis: str
    httpStatus: int
    errorCode: str | None
    upstreamMessage: str | None
    outcome: str | None
    aiFlow: Any
    guardName: str | None
    guardType: str
    detector: str | None
    guardrail: str | None
    policy: str | None
    cost: str
    duration: str
    latency: Any
    ipaddress: list[str]
    prompt: dict[str, Any]
    response: dict[str, Any]
    systemPrompt: str
    tokens: dict[str, Any]
    toolCalls: list[Any]
    toolDefinitions: list[Any]
    toolResponses: list[Any]
    violation: dict[str, Any]
    userAgent: str | None
    requestId: str
    sessionId: str | None
    org: Any


class AuditLogRow(TypedDict, total=False):
    uuid: str
    timeStamp: int
    username: str
    sourceIp: str
    type: str
    action: str
    actionLabel: str
    message: str
    role: str
    workspace: str | None


class Ensured(NamedTuple):
    """What an ``ensure_*`` call did. ``action`` is ``created``, ``updated`` or
    ``unchanged``; ``record`` is the object as it now stands; ``secret`` is a
    new virtual key's one-time secret (None otherwise)."""

    record: dict[str, Any]
    action: str
    secret: str | None = None

    @property
    def id(self) -> str:
        return str(self.record.get("uuid") or self.record.get("id"))

    @property
    def changed(self) -> bool:
        return self.action != "unchanged"


class FaigError(RuntimeError):
    """An HTTP status >= 400 from FortiAIGate. ``body`` is the raw response text,
    ``data`` its decoded JSON (None if it is not JSON), ``code`` the gateway's
    OpenAI-style ``error.code`` and ``field`` the field a 409/422 names.

    Raised as the subclass for its status (``NotFound``, ``Conflict``, ...), so
    ``except FaigError`` still catches every one."""

    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"{method} {path} -> HTTP {status}: {_message(body)}")
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        self.data: Any = _json_or_none(body)
        err = self.data.get("error") if isinstance(self.data, dict) else None
        self.code: str | None = (
            str(err["code"]) if isinstance(err, dict) and err.get("code") else None
        )
        field = self.data.get("field") if isinstance(self.data, dict) else None
        self.field: str | None = str(field) if field else None


class AuthError(FaigError):
    """401 or 403: bad credentials, an expired session that would not renew, a
    rejected virtual key, or a call the account's role may not make."""


class NotFound(FaigError):
    """404: no such object (or path)."""


class ModelNotAvailable(NotFound):
    """The gateway's 404 for a model the virtual key is not granted
    (``code: model_not_found``). ``available_models(key)`` lists what it may call."""


class Conflict(FaigError):
    """409: a name already used in the workspace (``field`` names it), or an
    approval that lost a race."""


class ValidationError(FaigError):
    """400 or 422: the body was refused; the message usually lists what is allowed."""


class RateLimited(FaigError):
    """429: a key's rpm/tpm limit. 8.0.2 sends no ``Retry-After``; set
    ``rate_limit_wait`` on the client to wait and retry instead of raising."""


class ServerError(FaigError):
    """5xx from the appliance or an upstream provider."""


def error_for(method: str, path: str, status: int, body: str) -> FaigError:
    """The ``FaigError`` subclass for an HTTP status (and gateway error code)."""
    cls: type[FaigError] = FaigError
    if status in (401, 403):
        cls = AuthError
    elif status == 404:
        cls = NotFound
        data = _json_or_none(body)
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict) and err.get("code") == "model_not_found":
            cls = ModelNotAvailable
    elif status == 409:
        cls = Conflict
    elif status in (400, 422):
        cls = ValidationError
    elif status == 429:
        cls = RateLimited
    elif status >= 500:
        cls = ServerError
    return cls(method, path, status, body)


def _json_or_none(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


def _message(body: str) -> str:
    data = _json_or_none(body)
    if isinstance(data, dict):
        for key in ("error", "message", "detail"):
            value = data.get(key)
            if isinstance(value, dict) and value.get("message"):
                value = value["message"]
            if value:
                return str(value)[:400]
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


def rank_items(data: JSON, end: str = "top") -> list[dict[str, Any]]:
    """The rows of a ``usage_rankings``/``cost_rankings`` result. The API answers
    ``items``, or ``top`` and ``bottom`` lists for ``end="both"``, or only
    ``meta`` when nothing was used in the window."""
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("items"), list):
        return list(data["items"])
    return list(data.get("bottom" if end == "bottom" else "top") or [])


def breakdown_items(data: JSON) -> list[dict[str, Any]]:
    """The rows of a ``usage_breakdown``/``cost_breakdown`` result. A key, user
    or workspace splits by ``models``; a model splits by ``consumers`` (usage)
    or ``spenders`` (cost), each ``{"count", "items"}``."""
    if not isinstance(data, dict):
        return []
    for part in ("models", "consumers", "spenders"):
        block = data.get(part)
        if isinstance(block, dict):
            return list(block.get("items") or [])
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
    ``rate_limit_wait`` is how many seconds in total to spend waiting out HTTP
    429s before raising ``RateLimited`` (0, the default, raises at once).

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
        rate_limit_wait: float = 0,
    ):
        self.url = origin(url)
        self.gateway_url = origin(gateway_url) if gateway_url else self.url
        self.timeout = timeout
        self.retries = retries
        self.rate_limit_wait = rate_limit_wait
        self._token = token
        self._creds = (username, password or "") if username else None
        self._logged_in = False
        self._ctx = _ssl_context(verify)
        self._jar = http.cookiejar.CookieJar()
        self._opener = _KeepAliveOpener(self._ctx, self._jar)
        self._ws_ids: dict[str, str] = {}  # workspace name -> id
        self._builtin_cache: list[dict[str, Any]] | None = None

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
        attempt = limited = 0
        waited = 0.0
        while True:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            try:
                with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                    return resp.status, resp.read().decode(errors="replace")
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if e.code != 429 or waited >= self.rate_limit_wait:
                    return e.code, text
                # Rate limited: nothing was processed, so any method may resend.
                wait = min(_retry_after(e.headers) or 2.0**limited, self.rate_limit_wait - waited)
                limited += 1
                waited += wait
                log.warning("%s %s: HTTP 429; waiting %.1fs", method, url, wait)
                time.sleep(wait)
                continue
            except urllib.error.URLError as e:
                err: Exception = e
            except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as e:
                if method != "GET":
                    raise
                err = e
            if attempt == self.retries:
                raise err
            wait = 2**attempt
            attempt += 1
            log.warning(
                "%s %s: %s; retry %d/%d in %ds", method, url, err, attempt, self.retries, wait
            )
            time.sleep(wait)

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
                raise error_for("POST", "/api/v1/login", st, txt)
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
            raise error_for(method, path, st, txt)
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
            raise error_for("POST", path, st, txt)
        return json.loads(txt) if txt.strip() else None

    def delete_user(self, user_id: str) -> JSON:
        return self.delete(f"/api/v1/admin/users/{_q(user_id)}")

    def make_workspace_admin(self, user_id: str, ws_id: WsRef) -> JSON:
        """The user update REPLACES the user's workspace list, so the existing
        memberships are kept and this one added."""
        ws_id = self.resolve_workspace(ws_id)
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

    # -- workspaces ----
    def resolve_workspace(self, ws: WsRef) -> str:
        """A workspace's id from its id, its name, or its record. Every method
        that takes ``ws_id`` accepts all three, so ``faig.guardrails("team-a")``
        works. Names are looked up once and cached (refreshed on a miss); an
        org admin reads every workspace, anyone else the ones they belong to."""
        if isinstance(ws, Mapping):
            return str(ws["id"])
        if _UUID.match(ws):
            return ws
        if ws not in self._ws_ids:
            self._load_workspace_names()
        if ws not in self._ws_ids:
            raise LookupError(f"no workspace named {ws!r} visible to this account")
        return self._ws_ids[ws]

    def _load_workspace_names(self) -> None:
        try:
            records = self.workspaces()
        except FaigError as e:
            if e.status not in (401, 403):
                raise
            records = self.my_workspaces()
        names: dict[str, str] = {}
        for w in records:
            name, wid = w.get("workspaceName"), w.get("id")
            if not name or not wid:
                continue
            if name in names and names[name] != wid:
                raise ValueError(f"two workspaces are named {name!r}; pass the id")
            names[str(name)] = str(wid)
        self._ws_ids = names

    def _ws(self, ws: WsRef) -> str:
        """The URL segment for a workspace argument."""
        return _q(self.resolve_workspace(ws))

    def workspaces(self) -> list[Workspace]:
        """Every workspace (org admin)."""
        return cast("list[Workspace]", self._list("/api/v1/admin/workspaces"))

    def my_workspaces(self) -> list[Workspace]:
        """The workspaces the logged-in user is a member of."""
        return cast("list[Workspace]", self._list("/api/v1/me/workspaces"))

    def workspace_by_name(self, name: str) -> Workspace | None:
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

    def delete_workspace(self, ws_id: WsRef) -> JSON:
        return self.delete(f"/api/v1/admin/workspaces/{self._ws(ws_id)}")

    def workspace_members(self, ws_id: WsRef) -> JSON:
        return self.get(f"/api/v1/workspaces/{self._ws(ws_id)}/members")

    def workspace_budget(self, ws_id: WsRef) -> JSON:
        return self.get(f"/api/v1/workspaces/{self._ws(ws_id)}/budget")

    def workspace(self, ws_id: WsRef) -> dict[str, Any]:
        """A workspace's settings: ``allowedModels``, ``allowedPolicies``,
        ``allowedGuardrails``, budgets and member defaults."""
        data = self.get(f"/api/v1/workspaces/{self._ws(ws_id)}")
        return dict(data) if isinstance(data, dict) else {}

    def workspace_analytics(
        self, ws_id: WsRef, frm: Day | None = None, to: Day | None = None, limit: int = 10
    ) -> JSON:
        """Guardrail analytics for a workspace; see ``analytics``."""
        return self.analytics(frm, to, limit=limit, ws_id=ws_id)

    # -- names -> ids -------------------------------------------------------------------
    def _resolve(self, kind: str, ref: Ref, ws_id: WsRef | None) -> str:
        """The id of a detector/guardrail/policy/key from its id, name or record.
        Names are unique per workspace for detectors, guardrails and policies
        (a duplicate create is a 409); key names are not, so two keys with one
        name are refused as ambiguous."""
        if isinstance(ref, Mapping):
            return str(ref.get("uuid") or ref["id"])
        if _UUID.match(ref):
            return ref
        if kind == "virtual-keys" and ref.startswith("faig_"):
            return key_id_from_secret(ref)
        records: list[Any]
        if kind == "detectors":
            records = self.detectors(ws_id)
        elif kind == "guardrails":
            records = self.guardrails(ws_id)
        elif kind == "policies":
            records = self.policies(ws_id)
        else:
            records = self.virtual_keys(ws_id)
        field = "keyName" if kind == "virtual-keys" else "name"
        found = {str(r.get("uuid") or r.get("id")) for r in records if r.get(field) == ref}
        if kind == "detectors":
            # A built-in detector's id is a slug ("prompt-injection"), not a UUID.
            # A custom detector may carry a built-in's name or slug: refuse to
            # guess which one is meant.
            builtin = {
                str(b["id"]) for b in self._builtins() if ref in (b.get("id"), b.get("name"))
            }
            if found and builtin:
                raise ValueError(
                    f"{ref!r} names both a custom and a built-in detector; pass the custom"
                    f" detector's uuid, or {{'id': {next(iter(builtin))!r}}} for the built-in"
                )
            found = found or builtin
        where = "this account" if ws_id is None else f"workspace {ws_id!r}"
        if not found:
            raise LookupError(f"no {_SINGULAR[kind]} named {ref!r} in {where}")
        if len(found) > 1:
            raise ValueError(
                f"{len(found)} {kind.replace('-', ' ')} are named {ref!r}; pass the id"
            )
        return found.pop()

    def _builtins(self) -> list[dict[str, Any]]:
        if self._builtin_cache is None:
            self._builtin_cache = self.builtin_detectors()
        return self._builtin_cache

    def resolve_detector(self, ref: Ref, ws_id: WsRef | None = None) -> str:
        """A detector's uuid from its uuid, name (custom or built-in) or record.
        Every method that takes a detector accepts all three."""
        return self._resolve("detectors", ref, ws_id)

    def resolve_guardrail(self, ref: Ref, ws_id: WsRef | None = None) -> str:
        """A guardrail's id from its id, name or record."""
        return self._resolve("guardrails", ref, ws_id)

    def resolve_policy(self, ref: Ref, ws_id: WsRef | None = None) -> str:
        """A policy's id from its id, name or record."""
        return self._resolve("policies", ref, ws_id)

    def resolve_virtual_key(self, ref: Ref, ws_id: WsRef | None = None) -> str:
        """A virtual key's id from its id, name, record or ``faig_...`` secret."""
        return self._resolve("virtual-keys", ref, ws_id)

    def _ids(self, kind: str, refs: Iterable[Ref], ws_id: WsRef | None) -> list[str]:
        return [self._resolve(kind, r, ws_id) for r in refs]

    # -- detectors -----------------------------------------------------------------
    def detectors(self, ws_id: WsRef | None = None) -> list[Detector]:
        """Custom detectors in a workspace, or (no ``ws_id``) every custom detector."""
        if ws_id:
            return cast(
                "list[Detector]", self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/detectors")
            )
        return cast("list[Detector]", self._list("/api/v1/admin/detectors"))

    def builtin_detectors(self) -> list[dict[str, Any]]:
        """Built-in detectors, identified by a slug id; a guardrail can use either kind."""
        return self._list("/api/v1/admin/built-in-detectors")

    def detector_by_name(self, ws_id: WsRef, name: str) -> Detector | None:
        return next((d for d in self.detectors(ws_id) if d.get("name") == name), None)

    def create_detector(self, ws_id: WsRef, body: Mapping[str, Any]) -> JSON:
        """See ``regex_detector_body``, ``dlp_detector_body`` and ``ai_detector_body``.
        A name already used in the workspace is a ``Conflict``."""
        return self.post(f"/api/v1/workspaces/{self._ws(ws_id)}/detectors", dict(body))

    def update_detector(self, ws_id: WsRef, uuid: Ref, body: Mapping[str, Any]) -> JSON:
        did = _q(self.resolve_detector(uuid, ws_id))
        return self.put(f"/api/v1/workspaces/{self._ws(ws_id)}/detectors/{did}", dict(body))

    def delete_detector(self, uuid: Ref, ws_id: WsRef | None = None) -> JSON:
        """Delete a workspace detector (``ws_id``) or, as org admin, any detector."""
        did = _q(self.resolve_detector(uuid, ws_id))
        if ws_id:
            return self.delete(f"/api/v1/workspaces/{self._ws(ws_id)}/detectors/{did}")
        return self.delete(f"/api/v1/admin/detectors/{did}")

    def playground(self, text: str, body: Mapping[str, Any], ws_id: WsRef | None = None) -> JSON:
        """Scan ``text`` with a detector BODY that need not be saved (the
        console's Playground): build it with ``regex_detector_body``,
        ``dlp_detector_body`` or ``ai_detector_body``."""
        detector = {k: v for k, v in body.items() if k not in ("name", "description")}
        payload = {"input": text, "detector": detector}
        if ws_id:
            return self.post(f"/api/v1/workspaces/{self._ws(ws_id)}/detectors/test", payload)
        return self.post("/api/v1/admin/detectors/test", payload)

    def test_detector(self, ws_id: WsRef, uuid: Ref, text: str) -> JSON:
        """Scan text with a SAVED detector: ``matched``, ``finalDisposition``,
        ``score``, ``spans``. For an unsaved body use ``playground``."""
        did = _q(self.resolve_detector(uuid, ws_id))
        return self.post(
            f"/api/v1/workspaces/{self._ws(ws_id)}/detectors/{did}/test", {"input": text}
        )

    def ensure_detector(
        self, ws_id: WsRef, body: Mapping[str, Any], *, approve: bool = True
    ) -> Ensured:
        """Make the workspace's detector named ``body["name"]`` match ``body``:
        create it if missing, update it if any field in ``body`` differs, leave
        it alone otherwise. ``approve`` (org admin) walks a new or still-draft
        detector to ``active``. Safe to re-run."""
        ws = self.resolve_workspace(ws_id)
        name = str(body["name"])
        current = self.detector_by_name(ws, name)
        if current is None:
            created = self.create_detector(ws, body)
            action = "created"
            current = cast(Detector, created)
        elif _differs(body, current):
            self.update_detector(ws, current["uuid"], body)
            action = "updated"
        else:
            action = "unchanged"
        if approve:
            approve_new(self, ws, "detectors", self.detector_by_name(ws, name) or current)
        return Ensured(dict(self.detector_by_name(ws, name) or current), action)

    # -- guardrails ----------------------------------------------------------------
    def guardrails(self, ws_id: WsRef | None = None) -> list[Guardrail]:
        """A workspace's guardrails, or (no ``ws_id``) the org's."""
        if ws_id:
            return cast(
                "list[Guardrail]", self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails")
            )
        return cast("list[Guardrail]", self._list("/api/v1/admin/guardrails"))

    def guardrail(self, gid: Ref, ws_id: WsRef | None = None) -> Guardrail:
        """One guardrail, by the workspace path (``ws_id``) or the org-admin path."""
        g = _q(self.resolve_guardrail(gid, ws_id))
        if ws_id:
            data = self.get(f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails/{g}")
        else:
            data = self.get(f"/api/v1/admin/guardrails/{g}")
        return cast(Guardrail, dict(data.get("guardrail", data)) if isinstance(data, dict) else {})

    def guardrail_by_name(self, ws_id: WsRef | None, name: str) -> Guardrail | None:
        return next((g for g in self.guardrails(ws_id) if g.get("name") == name), None)

    def create_guardrail(
        self,
        ws_id: WsRef,
        name: str,
        detector_ids: Sequence[Ref],
        description: str = "",
        *,
        deny_suspicious_characters: bool = False,
    ) -> JSON:
        """``detector_ids`` may be detector names (custom or built-in)."""
        return self.post(
            f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails",
            guardrail_body(
                name,
                self._ids("detectors", detector_ids, ws_id),
                description,
                deny_suspicious_characters=deny_suspicious_characters,
            ),
        )

    def update_guardrail(
        self,
        ws_id: WsRef,
        gid: Ref,
        name: str,
        detector_ids: Sequence[Ref],
        description: str = "",
        *,
        deny_suspicious_characters: bool = False,
    ) -> JSON:
        g = _q(self.resolve_guardrail(gid, ws_id))
        return self.put(
            f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails/{g}",
            guardrail_body(
                name,
                self._ids("detectors", detector_ids, ws_id),
                description,
                deny_suspicious_characters=deny_suspicious_characters,
            ),
        )

    def delete_guardrail(self, gid: Ref, ws_id: WsRef | None = None) -> JSON:
        """Delete a workspace guardrail (``ws_id``) or an org guardrail."""
        g = _q(self.resolve_guardrail(gid, ws_id))
        if ws_id:
            return self.delete(f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails/{g}")
        return self.delete(f"/api/v1/admin/guardrails/{g}")

    def test_guardrail(
        self,
        text: str,
        detector_ids: Sequence[Ref] | None = None,
        *,
        guardrail_id: Ref | None = None,
        deny_suspicious_characters: bool = False,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """Scan text through a guardrail without an LLM (the console's guardrail
        tester). Pass ``detector_ids``, or ``guardrail_id`` to reuse a saved
        guardrail's detectors and its denySuspiciousCharacters setting.
        ``ws_id`` uses the workspace path, which a workspace member can call.
        Returns ``finalDisposition`` plus a ``results`` row per detector."""
        if not detector_ids and not guardrail_id:
            raise ValueError("detector_ids or guardrail_id is required")
        ids: list[str] = []
        if detector_ids:
            ids = self._ids("detectors", detector_ids, ws_id)
        elif guardrail_id:
            g = self.guardrail(guardrail_id, ws_id)
            ids = list(g.get("detectorIds") or [])
            deny_suspicious_characters = bool(
                g.get("denySuspiciousCharacters", deny_suspicious_characters)
            )
        path = (
            f"/api/v1/workspaces/{self._ws(ws_id)}/guardrails/test"
            if ws_id
            else "/api/v1/admin/guardrails/test"
        )
        return self.post(
            path,
            {
                "input": text,
                "detectorIds": ids,
                "denySuspiciousCharacters": deny_suspicious_characters,
            },
        )

    def ensure_guardrail(
        self,
        ws_id: WsRef,
        name: str,
        detector_ids: Sequence[Ref],
        description: str = "",
        *,
        deny_suspicious_characters: bool = False,
        approve: bool = True,
    ) -> Ensured:
        """Create or update the workspace guardrail ``name`` to use exactly these
        detectors (ids or names); see ``ensure_detector``."""
        ws = self.resolve_workspace(ws_id)
        body = guardrail_body(
            name,
            self._ids("detectors", detector_ids, ws),
            description,
            deny_suspicious_characters=deny_suspicious_characters,
        )
        current = self.guardrail_by_name(ws, name)
        if current is None:
            current = cast(Guardrail, self.post(f"/api/v1/workspaces/{_q(ws)}/guardrails", body))
            action = "created"
        elif _differs(body, current):
            self.put(f"/api/v1/workspaces/{_q(ws)}/guardrails/{_q(current['id'])}", body)
            action = "updated"
        else:
            action = "unchanged"
        if approve:
            approve_new(self, ws, "guardrails", self.guardrail_by_name(ws, name) or current)
        return Ensured(dict(self.guardrail_by_name(ws, name) or current), action)

    # -- policies --------------------------------------------------------------------
    def policies(self, ws_id: WsRef | None = None) -> list[Policy]:
        """A workspace's policies, or (no ``ws_id``) the org's."""
        if ws_id:
            return cast(
                "list[Policy]", self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/policies")
            )
        return cast("list[Policy]", self._list("/api/v1/admin/policies"))

    def policy(self, pid: Ref, ws_id: WsRef | None = None) -> Policy:
        """One policy (org-admin path). ``ws_id`` scopes a name lookup."""
        data = self.get(f"/api/v1/admin/policies/{_q(self.resolve_policy(pid, ws_id))}")
        return cast(Policy, dict(data.get("policy", data)) if isinstance(data, dict) else {})

    def policy_by_name(self, ws_id: WsRef | None, name: str) -> Policy | None:
        return next((p for p in self.policies(ws_id) if p.get("name") == name), None)

    def _policy(
        self,
        ws_id: WsRef,
        name: str,
        inputs: Sequence[Ref],
        outputs: Sequence[Ref],
        provider_ids: list[str] | None,
        description: str,
        response_scan_mode: str,
    ) -> dict[str, Any]:
        return _policy_body(
            name,
            self._ids("guardrails", inputs, ws_id),
            self._ids("guardrails", outputs, ws_id),
            provider_ids,
            description,
            response_scan_mode,
        )

    def create_policy(
        self,
        ws_id: WsRef,
        name: str,
        input_guardrail_ids: Sequence[Ref],
        output_guardrail_ids: Sequence[Ref],
        *,
        provider_ids: list[str] | None = None,
        description: str = "",
        response_scan_mode: str = "post_stream",
    ) -> JSON:
        """Guardrails may be given by name. ``provider_ids`` grants every model
        of those providers. Some 8.0.2 builds refuse a policy that grants no
        model (HTTP 422 "a policy must grant at least one model")."""
        body = self._policy(
            ws_id,
            name,
            input_guardrail_ids,
            output_guardrail_ids,
            provider_ids,
            description,
            response_scan_mode,
        )
        return self.post(f"/api/v1/workspaces/{self._ws(ws_id)}/policies", body)

    def update_policy(
        self,
        ws_id: WsRef,
        pid: Ref,
        name: str,
        input_guardrail_ids: Sequence[Ref],
        output_guardrail_ids: Sequence[Ref],
        *,
        provider_ids: list[str] | None = None,
        description: str = "",
        response_scan_mode: str = "post_stream",
    ) -> JSON:
        """Replace a workspace policy. Made by an org admin, an edit to an ACTIVE
        policy applies at once (verified on 8.0.2); otherwise check
        ``hasPendingChange`` for an edit held for review."""
        body = self._policy(
            ws_id,
            name,
            input_guardrail_ids,
            output_guardrail_ids,
            provider_ids,
            description,
            response_scan_mode,
        )
        p = _q(self.resolve_policy(pid, ws_id))
        return self.put(f"/api/v1/workspaces/{self._ws(ws_id)}/policies/{p}", body)

    def delete_policy(self, pid: Ref, ws_id: WsRef | None = None) -> JSON:
        """Delete a workspace policy (``ws_id``) or an org policy."""
        p = _q(self.resolve_policy(pid, ws_id))
        if ws_id:
            return self.delete(f"/api/v1/workspaces/{self._ws(ws_id)}/policies/{p}")
        return self.delete(f"/api/v1/admin/policies/{p}")

    def ensure_policy(
        self,
        ws_id: WsRef,
        name: str,
        input_guardrail_ids: Sequence[Ref],
        output_guardrail_ids: Sequence[Ref],
        *,
        provider_ids: list[str] | None = None,
        description: str = "",
        response_scan_mode: str = "post_stream",
        approve: bool = True,
    ) -> Ensured:
        """Create or update the workspace policy ``name``; see ``ensure_detector``."""
        ws = self.resolve_workspace(ws_id)
        body = self._policy(
            ws,
            name,
            input_guardrail_ids,
            output_guardrail_ids,
            provider_ids,
            description,
            response_scan_mode,
        )
        current = self.policy_by_name(ws, name)
        if current is None:
            current = cast(Policy, self.post(f"/api/v1/workspaces/{_q(ws)}/policies", body))
            action = "created"
        elif _differs(body, current):
            self.put(f"/api/v1/workspaces/{_q(ws)}/policies/{_q(current['id'])}", body)
            action = "updated"
        else:
            action = "unchanged"
        if approve:
            approve_new(self, ws, "policies", self.policy_by_name(ws, name) or current)
        return Ensured(dict(self.policy_by_name(ws, name) or current), action)

    # -- approval (org admin) ----------------------------------------------------------
    def submit(self, ws_id: WsRef, kind: str, obj_id: Ref) -> JSON:
        """kind: detectors | guardrails | policies. The object may be given by name."""
        oid = _q(self._resolve(_kind(kind), obj_id, ws_id))
        return self.post(f"/api/v1/workspaces/{self._ws(ws_id)}/{kind}/{oid}/submit")

    def withdraw(self, ws_id: WsRef, kind: str, obj_id: Ref) -> JSON:
        """Cancel a pending submission or pending change (kind as for ``submit``)."""
        oid = _q(self._resolve(_kind(kind), obj_id, ws_id))
        return self.delete(f"/api/v1/workspaces/{self._ws(ws_id)}/{kind}/{oid}/pending")

    def _queued(self, kind: str, obj_id: Ref, ws_id: WsRef | None) -> str:
        """An id for approve/reject. A name is looked up ONLY in ``ws_id``: the
        same name can be pending in several workspaces, and approving another
        workspace's object by mistake is not undoable."""
        if isinstance(obj_id, Mapping) or _UUID.match(obj_id):
            return self._resolve(_kind(kind), obj_id, None)
        if ws_id is None:
            raise ValueError(f"approving or rejecting {obj_id!r} by name needs ws_id")
        return self._resolve(_kind(kind), obj_id, ws_id)

    def approve(self, kind: str, obj_id: Ref, ws_id: WsRef | None = None) -> JSON:
        """Approve a submitted object, by id, record, or (with ``ws_id``) name."""
        return self.post(f"/api/v1/admin/{kind}/{_q(self._queued(kind, obj_id, ws_id))}/approve")

    def reject(
        self, kind: str, obj_id: Ref, reason: str = "rejected", ws_id: WsRef | None = None
    ) -> JSON:
        oid = _q(self._queued(kind, obj_id, ws_id))
        return self.post(f"/api/v1/admin/{kind}/{oid}/reject", {"reason": reason})

    def review_queue(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/admin/review-queue")

    # -- virtual keys ----------------------------------------------------------------------
    def virtual_keys(
        self, ws_id: WsRef | None = None, *, status: str | None = None
    ) -> list[VirtualKey]:
        """A workspace's keys, or (no ``ws_id``) every key; ``status`` filters."""
        if ws_id:
            keys = self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/virtual-keys")
        else:
            keys = self._list("/api/v1/admin/virtual-keys")
        return cast(
            "list[VirtualKey]", [k for k in keys if not status or k.get("status") == status]
        )

    def _key_path(self, key_id: Ref, ws_id: WsRef | None) -> str:
        kid = _q(self.resolve_virtual_key(key_id, ws_id))
        if ws_id:
            return f"/api/v1/workspaces/{self._ws(ws_id)}/virtual-keys/{kid}"
        return f"/api/v1/admin/virtual-keys/{kid}"

    def virtual_key(self, key_id: Ref, ws_id: WsRef | None = None) -> VirtualKey:
        """One key, by the workspace path (``ws_id``) or the org-admin path. The
        key may be given by id, name, record or its ``faig_...`` secret."""
        data = self.get(self._key_path(key_id, ws_id))
        return cast(VirtualKey, dict(data.get("key", data)) if isinstance(data, dict) else {})

    def create_virtual_key(
        self,
        ws_id: WsRef,
        name: str,
        *,
        policy_ids: Sequence[Ref] | None = None,
        provider_ids: list[str] | None = None,
        expires_at: str | None = None,
        tpm: int | str | None = None,
        rpm: int | str | None = None,
    ) -> JSON:
        """Create a key in a workspace; policies may be given by name. The
        secret is in the response ONCE (``secret_from_response``) and never
        readable again. Key names need not be unique."""
        body: dict[str, Any] = {"keyName": name}
        if policy_ids is not None:
            body["policyIds"] = self._ids("policies", policy_ids, ws_id)
        if provider_ids is not None:
            body["providerAccess"] = _provider_access(provider_ids)
        for field, value in (("expiresAt", expires_at), ("tpm", tpm), ("rpm", rpm)):
            if value is not None and value != "":
                body[field] = value
        return self.post(f"/api/v1/workspaces/{self._ws(ws_id)}/virtual-keys", body)

    def update_virtual_key(
        self,
        key_id: Ref,
        *,
        expires_at: str | None = None,
        tpm: int | str | None = None,
        rpm: int | str | None = None,
        policy_ids: Sequence[Ref] | None = None,
        provider_ids: list[str] | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """The update REPLACES the record, so the current one is read and its
        writable fields resent with the changes (8.0.2 rejects read-only fields
        such as ``status`` or ``spend``). ``policy_ids`` replaces the attached
        policies (org-assigned policies stay forced onto the key regardless);
        ``provider_ids`` replaces the providers granted."""
        path = self._key_path(key_id, ws_id)
        data = self.get(path)
        body = key_update_body(dict(data.get("key", data)) if isinstance(data, dict) else {})
        for field, value in (("expiresAt", expires_at), ("tpm", tpm), ("rpm", rpm)):
            if value is not None and value != "":
                body[field] = value
        if policy_ids is not None:
            body["policyIds"] = self._ids("policies", policy_ids, ws_id)
        if provider_ids is not None:
            body["providerAccess"] = _provider_access(provider_ids)
        return self.put(path, body)

    def rotate_virtual_key(self, key_id: Ref, ws_id: WsRef | None = None) -> JSON:
        """New secret, once, in the response (``secret_from_response``)."""
        return self.post(self._key_path(key_id, ws_id) + "/rotate")

    def revoke_virtual_key(
        self, key_id: Ref, reason: str = "revoked", ws_id: WsRef | None = None
    ) -> JSON:
        """The secret stops working; 8.0.2 requires a ``reason``."""
        return self.post(self._key_path(key_id, ws_id) + "/revoke", {"reason": reason})

    def delete_virtual_key(self, key_id: Ref, ws_id: WsRef | None = None) -> JSON:
        return self.delete(self._key_path(key_id, ws_id))

    def ensure_virtual_key(
        self,
        ws_id: WsRef,
        name: str,
        *,
        policy_ids: Sequence[Ref] | None = None,
        provider_ids: list[str] | None = None,
        expires_at: str | None = None,
        tpm: int | str | None = None,
        rpm: int | str | None = None,
    ) -> Ensured:
        """Create the workspace's active key ``name``, or bring an existing one's
        policies, providers and limits in line (only the arguments given are
        checked). A created key's secret is in ``Ensured.secret``; an existing
        key's secret cannot be read again (rotate it if you need one). Revoked
        keys are ignored; two active keys with the name are refused."""
        ws = self.resolve_workspace(ws_id)
        active = [k for k in self.virtual_keys(ws) if k.get("keyName") == name]
        active = [k for k in active if k.get("status") != "revoked"]
        if len(active) > 1:
            raise ValueError(f"{len(active)} active keys are named {name!r}; pass the id")
        policies = None if policy_ids is None else self._ids("policies", policy_ids, ws)
        if not active:
            created = self.create_virtual_key(
                ws,
                name,
                policy_ids=policies,
                provider_ids=provider_ids,
                expires_at=expires_at,
                tpm=tpm,
                rpm=rpm,
            )
            secret = secret_from_response(created)
            record = self.virtual_key(key_id_from_secret(secret)) if secret else created
            return Ensured(dict(record), "created", secret)
        current = self.virtual_key(active[0]["id"], ws)
        have = key_update_body(current)
        want: dict[str, Any] = {}
        if policies is not None and sorted(policies) != sorted(have.get("policyIds") or []):
            want["policy_ids"] = policies
        if provider_ids is not None and sorted(provider_ids) != sorted(
            str(a.get("providerId")) for a in have.get("providerAccess") or []
        ):
            want["provider_ids"] = provider_ids
        for arg, field, value in (
            ("expires_at", "expiresAt", expires_at),
            ("tpm", "tpm", tpm),
            ("rpm", "rpm", rpm),
        ):
            if value not in (None, "") and str(value) != str(have.get(field)):
                want[arg] = value
        if not want:
            return Ensured(dict(current), "unchanged")
        self.update_virtual_key(current["id"], ws_id=ws, **want)
        return Ensured(dict(self.virtual_key(current["id"], ws)), "updated")

    # -- providers, models, audit ----------------------------------------------------------
    def ai_providers(self) -> list[dict[str, Any]]:
        return self._list("/api/v1/admin/ai-providers")

    def model_groups(self, ws_id: WsRef | None = None) -> list[dict[str, Any]]:
        """Model groups: the org's, or those a workspace can use."""
        if ws_id:
            return self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/model-groups")
        return self._list("/api/v1/model-groups")

    def models(self) -> list[dict[str, Any]]:
        """Every model the org knows: costs, health, provider (org admin)."""
        return self._list("/api/v1/admin/models")

    def workspace_models(self, ws_id: WsRef) -> list[Any]:
        """The models a workspace allows (its ``allowedModels``)."""
        return list(self.workspace(ws_id).get("allowedModels") or [])

    def grantable_providers(self, ws_id: WsRef | None = None) -> list[dict[str, Any]]:
        """Providers, models and upstream keys that can be granted: to keys in a
        workspace (``ws_id``), or org-wide."""
        if ws_id:
            data = self.get(f"/api/v1/workspaces/{self._ws(ws_id)}/grantable-providers")
            return list(data.get("providers") or []) if isinstance(data, dict) else []
        return self._list("/api/v1/admin/grantable-providers")

    def attachable_policies(self, ws_id: WsRef) -> list[dict[str, Any]]:
        """Policies a key in this workspace can attach."""
        return self._list(f"/api/v1/workspaces/{self._ws(ws_id)}/attachable-policies")

    def dlp_labels(self) -> list[dict[str, Any]]:
        """The DLP category names ``dlp_detector_body`` takes."""
        return self._list("/api/v1/admin/dlp-labels")

    def audit_logs(self, offset: int = 0, limit: int = 25) -> JSON:
        """One page of the org audit log, newest first. ``iter_audit_logs``
        filters by time, user, role, action and workspace, and follows pages."""
        return self.get("/api/v1/admin/audit-logs", {"offset": int(offset), "limit": int(limit)})

    def audit_logs_page(
        self,
        cursor: str | None = None,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        limit: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """One page of audit log rows, cursor-paged like ``traffic_logs_page``.
        ``filters`` fields: user, role, action, message, workspace (spell
        actions as ``audit_log_filter_options`` lists them: ``Approve``, ...)."""
        q = _log_window(range, start, end)
        q.update(_log_filters(filters, AUDIT_FILTERS))
        return self.get(self._logs_base("audit-logs", ws_id), _cursor_query(q, cursor, limit))

    def iter_audit_logs(
        self,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        max_items: int | None = None,
        page_size: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> Iterator[AuditLogRow]:
        """Every matching audit log row, newest first, following ``nextCursor``."""
        rows = _follow(
            lambda cursor: self.audit_logs_page(
                cursor,
                range=range,
                start=start,
                end=end,
                filters=filters,
                limit=page_size,
                ws_id=ws_id,
            ),
            max_items,
        )
        return cast("Iterator[AuditLogRow]", rows)

    def audit_log_filter_options(
        self,
        *,
        range: str | None = None,
        start: When | None = None,
        end: When | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """The values each audit filter can take (users, roles, actions, ...)."""
        q = (
            _log_window(range or "24h", start, end)
            if range or start is not None or end is not None
            else {}
        )
        return self.get(f"{self._logs_base('audit-logs', ws_id)}/filter-options", q or None)

    def licenses(self) -> JSON:
        """The appliance's licenses (serial, status, end date, GPU mapping)."""
        return self.get("/api/v1/licenses")

    # -- usage, cost and analytics ---------------------------------------------------------
    def _report(
        self, kind: str, view: str, frm: Day | None, to: Day | None, ws_id: WsRef | None, **q: Any
    ) -> JSON:
        query = {**_window(frm, to), **{k: v for k, v in q.items() if v is not None}}
        if ws_id:
            return self.get(f"/api/v1/workspaces/{self._ws(ws_id)}/{kind}/{view}", query)
        return self.get(f"/api/v1/admin/{kind}/{view}", query)

    def usage_summary(
        self, frm: Day | None = None, to: Day | None = None, ws_id: WsRef | None = None
    ) -> JSON:
        """Requests and tokens in the window, the previous window, and key/user
        adoption. Dates are ``date`` objects or ``"YYYY-MM-DD"``; the default
        window is the last 30 days. ``ws_id`` scopes it to a workspace."""
        return self._report("usage", "summary", frm, to, ws_id)

    def usage_trend(
        self,
        frm: Day | None = None,
        to: Day | None = None,
        interval: str = "daily",
        ws_id: WsRef | None = None,
    ) -> JSON:
        """``{"interval", "points": [{"at", "requests", "tokens"}]}``."""
        return self._report(
            "usage",
            "trend",
            frm,
            to,
            ws_id,
            interval=_one_of("interval", interval, INTERVALS),
        )

    def usage_rankings(
        self,
        frm: Day | None = None,
        to: Day | None = None,
        by: str = "key",
        limit: int = 5,
        *,
        end: str | None = None,
        order_by: str | None = None,
        interval: str | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """Top (or ``end="bottom"``) keys, users, workspaces or models by usage:
        ``{"items": [...], "meta": {...}}``. ``order_by``: tokens | requests."""
        return self._report(
            "usage",
            "rankings",
            frm,
            to,
            ws_id,
            **_rank_query(by, limit, end, order_by, interval, USAGE_ORDER),
        )

    def usage_breakdown(
        self,
        by: str,
        item_id: str,
        frm: Day | None = None,
        to: Day | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """One ranked item broken down: a key, user or workspace by model, a
        model by who used it. Read the rows with ``breakdown_items()``.
        Rankings still list deleted keys (``deleted: true``); their breakdown
        is a 404."""
        return self._report(
            "usage", "breakdown", frm, to, ws_id, by=_one_of("by", by, RANK_BY), id=item_id
        )

    def cost_summary(
        self, frm: Day | None = None, to: Day | None = None, ws_id: WsRef | None = None
    ) -> JSON:
        """Spend (``totals.chargebackSpend``), volume and unit costs in the window."""
        return self._report("cost", "summary", frm, to, ws_id)

    def cost_trend(
        self,
        frm: Day | None = None,
        to: Day | None = None,
        interval: str = "daily",
        ws_id: WsRef | None = None,
    ) -> JSON:
        return self._report(
            "cost",
            "trend",
            frm,
            to,
            ws_id,
            interval=_one_of("interval", interval, INTERVALS),
        )

    def cost_rankings(
        self,
        frm: Day | None = None,
        to: Day | None = None,
        by: str = "key",
        limit: int = 5,
        *,
        end: str | None = None,
        order_by: str | None = None,
        interval: str | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """Top spenders by key, user, workspace or model. ``order_by``:
        providerSpend | chargebackSpend | per1kTokens | perRequest."""
        return self._report(
            "cost",
            "rankings",
            frm,
            to,
            ws_id,
            **_rank_query(by, limit, end, order_by, interval, COST_ORDER),
        )

    def cost_breakdown(
        self,
        by: str,
        item_id: str,
        frm: Day | None = None,
        to: Day | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        return self._report(
            "cost", "breakdown", frm, to, ws_id, by=_one_of("by", by, RANK_BY), id=item_id
        )

    def analytics(
        self,
        frm: Day | None = None,
        to: Day | None = None,
        limit: int = 10,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """Guardrail analytics: violations by detector, key, user and workspace,
        severity, trend and scanner latency."""
        if ws_id:
            return self.get(
                f"/api/v1/workspaces/{self._ws(ws_id)}/analytics",
                {**_window(frm, to), "limit": int(limit)},
            )
        return self.get("/api/v1/admin/analytics", {**_window(frm, to), "limit": int(limit)})

    # -- traffic and ICAP logs --------------------------------------------------------------
    def _logs_base(self, kind: str, ws_id: WsRef | None) -> str:
        if ws_id:
            return f"/api/v1/workspaces/{self._ws(ws_id)}/{kind}"
        return f"/api/v1/admin/{kind}"

    def traffic_logs_page(
        self,
        cursor: str | None = None,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        limit: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """One page: ``{"items", "nextCursor", "hasNext", "total"}`` (``total``
        on the first page only). Pass the previous ``nextCursor`` to go on."""
        q = _log_window(range, start, end)
        q.update(_log_filters(filters, TRAFFIC_FILTERS))
        return self.get(self._logs_base("traffic-logs", ws_id), _cursor_query(q, cursor, limit))

    def traffic_logs(
        self,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        max_items: int | None = None,
        page_size: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> Iterator[TrafficLogRow]:
        """Every matching traffic log row, newest first, following ``nextCursor``.

        ``range``: 24h | 7d | month | all, or pass ``start``/``end``
        (``datetime`` or epoch milliseconds) for a custom window. ``filters``
        maps a field (verdict, user, workspace, virtual_key, model,
        traffic_type, request_path) to a value, a list of values (``is``), or
        ``{"operator": ..., "value": [...]}``. ``virtual_key`` takes the key's
        NAME. Rows are summaries; the full record (tokens, cost, prompt,
        detector) is ``traffic_log(uuid)``."""
        rows = _follow(
            lambda cursor: self.traffic_logs_page(
                cursor,
                range=range,
                start=start,
                end=end,
                filters=filters,
                limit=page_size,
                ws_id=ws_id,
            ),
            max_items,
        )
        return cast("Iterator[TrafficLogRow]", rows)

    def wait_for_traffic(
        self,
        since: When,
        *,
        filters: Mapping[str, Any] | None = None,
        count: int = 1,
        timeout: float = 60,
        interval: float = 2,
        ws_id: WsRef | None = None,
    ) -> list[TrafficLogRow]:
        """Poll until ``count`` traffic log rows matching ``filters`` exist from
        ``since`` (a ``datetime`` or epoch ms, taken BEFORE sending the request)
        on; rows land a few seconds after the request. Returns them, newest
        first; raises ``TimeoutError`` after ``timeout`` seconds."""
        start = _ms(since) - 2000  # tolerate a little clock skew with the appliance
        deadline = time.monotonic() + timeout
        while True:
            end = int(time.time() * 1000) + 60_000
            rows = list(self.traffic_logs(start=start, end=end, filters=filters, ws_id=ws_id))
            if len(rows) >= count:
                return rows
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"{len(rows)} of {count} traffic log rows after {timeout:g}s"
                    f" (filters: {filters})"
                )
            time.sleep(interval)

    def traffic_log(self, uuid: str, ws_id: WsRef | None = None) -> TrafficLog:
        """The full record: model, verdict, action, detector, guardrail, policy,
        prompt, cost, latency, http status, request id."""
        data = self.get(f"{self._logs_base('traffic-logs', ws_id)}/{_q(uuid)}")
        return cast(TrafficLog, dict(data) if isinstance(data, dict) else {})

    def traffic_log_filter_options(
        self,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """The values each filter can take in the window (models, users, keys, ...)."""
        return self.get(
            f"{self._logs_base('traffic-logs', ws_id)}/filter-options",
            _log_window(range, start, end),
        )

    def icap_logs_page(
        self,
        offset: int = 0,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        limit: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> JSON:
        """One page of ICAP logs (FortiGate-inspected traffic; offset paging).
        404 when the appliance has ICAP turned off."""
        q = _log_window(range, start, end)
        q.update(_log_filters(filters, ICAP_FILTERS))
        q.update({"offset": int(offset), "limit": int(limit)})
        return self.get(self._logs_base("icap-logs", ws_id), q)

    def icap_logs(
        self,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        filters: Mapping[str, Any] | None = None,
        max_items: int | None = None,
        page_size: int = LOG_PAGE,
        ws_id: WsRef | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Every matching ICAP log row. ``filters`` fields: verdict, direction,
        user, application, fortigate, shadow_ai, inspection."""
        offset = 0
        seen = 0
        while True:
            page = self.icap_logs_page(
                offset,
                range=range,
                start=start,
                end=end,
                filters=filters,
                limit=page_size,
                ws_id=ws_id,
            )
            rows = items(page)
            for row in rows:
                yield row
                seen += 1
                if max_items is not None and seen >= max_items:
                    return
            offset += len(rows)
            if not rows or not page.get("hasNext", len(rows) == page_size):
                return

    def icap_log(self, uuid: str, ws_id: WsRef | None = None) -> dict[str, Any]:
        data = self.get(f"{self._logs_base('icap-logs', ws_id)}/{_q(uuid)}")
        return dict(data) if isinstance(data, dict) else {}

    def icap_log_filter_options(
        self,
        *,
        range: str = "24h",
        start: When | None = None,
        end: When | None = None,
        ws_id: WsRef | None = None,
    ) -> JSON:
        return self.get(
            f"{self._logs_base('icap-logs', ws_id)}/filter-options",
            _log_window(range, start, end),
        )

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
        raise error_for("GET", path, st, txt)

    def available_models(self, api_key: str) -> list[str]:
        """The model names a virtual key may call (what ``chat_completion``
        takes as ``model``). A model missing here fails with 404 "model not
        available to this API key"."""
        path = "/ai/openai/v1/models"
        st, txt = self._gateway("GET", path, api_key)
        if st != 200:
            raise error_for("GET", path, st, txt)
        return [str(m.get("id")) for m in items(json.loads(txt)) if m.get("id")]

    def can_use_model(self, api_key: str, model: str) -> bool:
        return model in self.available_models(api_key)

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
            raise error_for("POST", path, st, txt)
        return json.loads(txt)

    def chat_completion_stream(
        self,
        api_key: str,
        model: str,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        timeout: float = 120,
        **extra: Any,
    ) -> Iterator[dict[str, Any]]:
        """A streamed chat completion: yields each ``chat.completion.chunk`` as
        it arrives. A guardrail block arrives as chunks too (the block message,
        then ``finish_reason: content_filter``), including one raised by
        ``in_stream`` response scanning mid-answer. ``collect_stream`` joins
        the chunks into one completion that ``blocked`` understands.

        Runs on its own connection and is never retried (it is a POST)."""
        if not messages:
            raise ValueError("messages must be a non-empty list")
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": True, **extra}
        if max_tokens:
            body["max_tokens"] = int(max_tokens)
        if temperature is not None:
            body["temperature"] = float(temperature)
        path = "/ai/openai/v1/chat/completions"
        u = urllib.parse.urlsplit(self.gateway_url)
        conn: http.client.HTTPConnection
        t = max(self.timeout, timeout)
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(
                u.hostname or "", u.port or 443, context=self._ctx, timeout=t
            )
        else:
            conn = http.client.HTTPConnection(u.hostname or "", u.port or 80, timeout=t)
        try:
            conn.request(
                "POST",
                path,
                body=json.dumps(body).encode(),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
            )
            resp = conn.getresponse()
            if resp.status != 200:
                raise error_for("POST", path, resp.status, resp.read().decode(errors="replace"))
            if "event-stream" not in (resp.getheader("Content-Type") or ""):
                yield json.loads(resp.read() or b"{}")  # answered without streaming
                return
            for raw in resp:
                line = raw.decode(errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    return
                if data:
                    yield json.loads(data)
        finally:
            conn.close()


Day = dt.date | str
When = dt.datetime | int


def _day(d: Day) -> str:
    return d.isoformat()[:10] if isinstance(d, dt.date) else str(d)


def _window(frm: Day | None, to: Day | None) -> dict[str, str]:
    """``from``/``to`` as YYYY-MM-DD; the default is the 30 days up to today."""
    end = to if to is not None else dt.date.today()
    if frm is None:
        base = end if isinstance(end, dt.date) else dt.date.fromisoformat(str(end)[:10])
        frm = base - dt.timedelta(days=29)
    return {"from": _day(frm), "to": _day(end)}


def _one_of(name: str, value: str, allowed: Iterable[str]) -> str:
    allowed = tuple(allowed)
    if value not in allowed:
        raise ValueError(f"{name} must be one of {', '.join(allowed)}; got {value!r}")
    return value


def _rank_query(
    by: str,
    limit: int,
    end: str | None,
    order_by: str | None,
    interval: str | None,
    orders: Iterable[str],
) -> dict[str, Any]:
    q: dict[str, Any] = {"by": _one_of("by", by, RANK_BY), "limit": int(limit)}
    if end is not None:
        q["end"] = _one_of("end", end, RANK_END)
    if order_by is not None:
        q["orderBy"] = _one_of("order_by", order_by, orders)
    if interval is not None:
        q["interval"] = _one_of("interval", interval, INTERVALS)
    return q


def _cursor_query(q: dict[str, Any], cursor: str | None, limit: int) -> dict[str, Any]:
    q.update({"limit": int(limit), "direction": "next"})
    if cursor:
        q["cursor"] = cursor
    else:
        q["includeTotal"] = "true"
    return q


def _follow(page: Any, max_items: int | None) -> Iterator[dict[str, Any]]:
    """Rows from ``page(cursor)`` calls, following ``nextCursor``."""
    cursor: str | None = None
    seen = 0
    while True:
        data = page(cursor)
        for row in items(data):
            yield row
            seen += 1
            if max_items is not None and seen >= max_items:
                return
        cursor = data.get("nextCursor") if isinstance(data, dict) else None
        if not cursor or not data.get("hasNext", True):
            return


_SINGULAR = {
    "detectors": "detector",
    "guardrails": "guardrail",
    "policies": "policy",
    "virtual-keys": "virtual key",
}


def _kind(kind: str) -> str:
    return _one_of("kind", kind, ("detectors", "guardrails", "policies"))


def _provider_access(provider_ids: Iterable[str]) -> list[dict[str, Any]]:
    return [{"providerId": p, "allKeys": True, "allModels": True} for p in provider_ids]


def _differs(want: Any, have: Any) -> bool:
    """Does the stored record ``have`` differ from ``want`` in any field
    ``want`` sets? Fields the appliance adds are ignored, ``None`` in ``want``
    means "not set", and lists of plain ids compare as sets."""
    if want is None:
        return False
    if isinstance(want, Mapping):
        if not isinstance(have, Mapping):
            return True
        return any(_differs(v, have.get(k)) for k, v in want.items())
    if isinstance(want, (list, tuple)):
        if not isinstance(have, (list, tuple)) or len(want) != len(have):
            return True
        if all(isinstance(x, str) for x in want) and all(isinstance(x, str) for x in have):
            return sorted(want) != sorted(have)
        return any(_differs(w, h) for w, h in zip(want, have, strict=True))
    return bool(want != have)


def _retry_after(headers: Any) -> float | None:
    """A ``Retry-After`` header as seconds (it may be a delay or an HTTP date)."""
    value = headers.get("Retry-After") if headers is not None else None
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, (when - dt.datetime.now(dt.timezone.utc)).total_seconds())


def _ms(t: When) -> int:
    if isinstance(t, dt.datetime):
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return int(t.timestamp() * 1000)
    return int(t)


def _log_window(range: str, start: When | None, end: When | None) -> dict[str, Any]:
    if start is not None or end is not None:
        if start is None or end is None:
            raise ValueError("a custom window needs both start and end")
        return {"range": "custom", "startTime": _ms(start), "endTime": _ms(end)}
    return {"range": _one_of("range", range, LOG_RANGES)}


def _log_filters(filters: Mapping[str, Any] | None, fields: Mapping[str, str]) -> dict[str, str]:
    """``{"model": "gpt", "verdict": ["Block"]}`` -> the API's
    ``<field>Filters`` JSON. Unknown fields and operators raise: the API
    would silently ignore them and return every row."""
    out: dict[str, str] = {}
    for field, spec in (filters or {}).items():
        if field not in fields:
            raise ValueError(f"unknown filter {field!r}; one of {', '.join(fields)}")
        if isinstance(spec, Mapping):
            op = _one_of("operator", str(spec.get("operator", "is")), FILTER_OPERATORS)
            value = spec.get("value")
        else:
            op, value = "is", spec
        values = [str(v) for v in (value if isinstance(value, (list, tuple, set)) else [value])]
        values = [v for v in values if v not in ("", "None")]
        if values:
            out[fields[field]] = json.dumps({"operator": op, "value": values})
    return out


def _policy_body(
    name: str,
    input_ids: list[str],
    output_ids: list[str],
    provider_ids: list[str] | None,
    description: str,
    response_scan_mode: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "description": description or name,
        "inputGuardrailIds": input_ids,
        "outputGuardrailIds": output_ids,
        "responseScanMode": response_scan_mode,
    }
    if provider_ids is not None:
        body["providerAccess"] = [{"providerId": p, "allModels": True} for p in provider_ids]
    return body


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


def collect_stream(chunks: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Join ``chat_completion_stream`` chunks into one ``chat.completion``:
    each choice's ``message.content`` is its deltas joined, ``finish_reason``
    the last one given. A non-streamed completion passes through unchanged."""
    out: dict[str, Any] = {"object": "chat.completion", "choices": []}
    choices: dict[int, dict[str, Any]] = {}
    for chunk in chunks:
        if any("message" in c for c in chunk.get("choices") or []):
            return dict(chunk)
        for key in ("id", "model", "created", "usage"):
            if chunk.get(key) is not None:
                out[key] = chunk[key]
        for c in chunk.get("choices") or []:
            slot = choices.setdefault(
                int(c.get("index", 0)),
                {
                    "index": int(c.get("index", 0)),
                    "message": {"role": "assistant", "content": ""},
                    "finish_reason": None,
                },
            )
            delta = c.get("delta") or {}
            if delta.get("role"):
                slot["message"]["role"] = delta["role"]
            if delta.get("content"):
                slot["message"]["content"] += delta["content"]
            if c.get("finish_reason"):
                slot["finish_reason"] = c["finish_reason"]
    out["choices"] = [choices[i] for i in sorted(choices)]
    return out


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
def guardrail_body(
    name: str,
    detector_ids: list[str],
    description: str = "",
    *,
    deny_suspicious_characters: bool = False,
) -> dict[str, Any]:
    if not detector_ids:
        raise ValueError("a guardrail needs at least one detector")
    return {
        "name": name,
        "description": description or name,
        "detectorIds": list(detector_ids),
        "denySuspiciousCharacters": deny_suspicious_characters,
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


def ai_detector_body(
    name: str,
    rules: Iterable[tuple[Any, ...]],
    action: str = "block",
    description: str = "",
) -> dict[str, Any]:
    """A Natural Language detector: the engine judges text against plain-language
    descriptions. rules: ``[(rule_name, violate_if)]`` or
    ``[(rule_name, violate_if, exempt_if)]``, where each is a string or a list of
    strings. Like a regex detector it fills BOTH ``aiRules`` (the editor's
    grouping) and the flat ``rules`` list the engine matches on."""
    ai_rules: list[dict[str, Any]] = []
    for i, rule in enumerate(rules, 1):
        rule_name, violate = rule[0], rule[1]
        exempt = rule[2] if len(rule) > 2 else []
        violate_if = [violate] if isinstance(violate, str) else list(violate)
        exempt_if = [exempt] if isinstance(exempt, str) else list(exempt)
        if not violate_if:
            raise ValueError(f"rule {rule_name!r} needs at least one violate_if description")
        ai_rules.append(
            {
                "id": f"r{i}",
                "name": rule_name,
                "enabled": True,
                "description": rule_name,
                "violateIf": violate_if,
                "exemptIf": exempt_if,
                "conditions": [
                    {"id": f"c{i}-{j}", "description": text} for j, text in enumerate(violate_if, 1)
                ],
            }
        )
    if not ai_rules:
        raise ValueError("a natural-language detector with no rules matches nothing")
    return {
        "name": name,
        "description": description or name,
        "inputGuards": ["AI descriptions"],
        "outputGuards": ["AI descriptions"],
        "sensitivity": None,
        "detectorType": "ai",
        "managedEngine": None,
        "action": action,
        "regexRules": None,
        "aiRules": ai_rules,
        "rules": [c for r in ai_rules for c in r["conditions"]],
    }


def approve_new(admin: FortiAIGate, ws_id: WsRef, kind: str, obj: Mapping[str, Any]) -> JSON:
    """Walk a workspace object draft -> pending -> active, or approve an
    active one's pending change. Losing the race to another approver (it is no
    longer pending) is not an error."""
    oid = str(obj.get("uuid") or obj["id"])
    status = obj.get("approvalStatus") or obj.get("status")
    if status == "draft":
        admin.submit(ws_id, kind, oid)
        status = "pending"
    if status == "pending" or (status == "active" and obj.get("hasPendingChange")):
        try:
            return admin.approve(kind, oid)
        except FaigError as e:
            if e.status != 409 or "pending submission" not in e.body:
                raise
    return obj
