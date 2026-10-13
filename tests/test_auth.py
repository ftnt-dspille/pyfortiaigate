"""Login, session expiry, CSRF and bearer-token auth."""

from __future__ import annotations

import ssl

import pytest

from pyfortiaigate import FaigError, FortiAIGate

from .conftest import FakeFaig

EXPIRED = (401, {"error": "Invalid authentication credentials"})


def test_logs_in_lazily_on_first_call(fake: FakeFaig) -> None:
    c = FortiAIGate(fake.url, "admin", "pw")
    assert fake.seen == []
    c.workspaces()
    assert [s.key for s in fake.seen] == [
        ("POST", "/api/v1/login"),
        ("GET", "/api/v1/admin/workspaces"),
    ]
    assert fake.seen[0].body == {"username": "admin", "password": "pw"}


def test_session_cookie_is_sent_after_login(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.me()
    assert "session_id=s1" in fake.calls("GET", "/api/v1/user")[0].headers["cookie"]


def test_falls_back_to_legacy_login(fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/login", (401, {"error": "nope"}))
    c = FortiAIGate(fake.url, "admin", "pw")
    c.me()
    assert [s.path for s in fake.seen[:2]] == ["/api/v1/login", "/api/login"]


def test_login_failure_raises_the_v1_error(fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/login", (401, {"error": "bad password"}))
    fake.answer("POST", "/api/login", (401, {}))
    with pytest.raises(FaigError, match="bad password") as e:
        FortiAIGate(fake.url, "admin", "pw").me()
    assert e.value.status == 401


def test_explicit_login_sets_credentials(fake: FakeFaig) -> None:
    c = FortiAIGate(fake.url)
    c.login("a@example.com", "pw2")
    c.me()
    assert len(fake.calls("POST", "/api/v1/login")) == 1


def test_login_without_credentials_is_a_value_error(fake: FakeFaig) -> None:
    with pytest.raises(ValueError, match="username"):
        FortiAIGate(fake.url).login()


def test_expired_session_logs_in_again_and_resends(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/workspaces", EXPIRED, (200, {"items": [{"id": "w"}]}))
    assert faig.workspaces() == [{"id": "w"}]
    assert len(fake.calls("POST", "/api/v1/login")) == 2


def test_resent_mutation_gets_a_fresh_csrf_token(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/admin/detectors/d1/approve", EXPIRED, (200, {}))
    faig.approve("detectors", "d1")
    tokens = [
        s.headers["x-csrf-token"] for s in fake.calls("POST", "/api/v1/admin/detectors/d1/approve")
    ]
    assert len(tokens) == 2
    assert tokens[0] != tokens[1]


def test_still_401_after_relogin_raises(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/workspaces", EXPIRED)
    with pytest.raises(FaigError) as e:
        faig.workspaces()
    assert e.value.status == 401
    assert len(fake.calls("POST", "/api/v1/login")) == 2


def test_anonymous_client_does_not_log_in(fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/user", EXPIRED)
    with pytest.raises(FaigError):
        FortiAIGate(fake.url).me()
    assert fake.calls("POST", "/api/v1/login") == []


def test_every_mutation_fetches_its_own_csrf_token(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.post("/api/v1/x")
    faig.put("/api/v1/x", {"a": 1})
    faig.delete("/api/v1/x")
    sent = [s.headers.get("x-csrf-token") for s in fake.app_calls()]
    assert sent == ["csrf-1", "csrf-2", "csrf-3"]


def test_get_sends_no_csrf_token(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.get("/api/v1/x")
    assert "x-csrf-token" not in fake.app_calls()[0].headers
    assert fake.calls(path="/api/csrf-token") == []


def test_stale_csrf_403_is_retried_once(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/x", (403, {"error": "CSRF token invalid"}), (200, {"ok": 1}))
    assert faig.post("/api/v1/x") == {"ok": 1}
    assert len(fake.calls("POST", "/api/v1/x")) == 2


def test_other_403_is_not_retried(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/x", (403, {"error": "forbidden"}))
    with pytest.raises(FaigError, match="forbidden"):
        faig.post("/api/v1/x")
    assert len(fake.calls("POST", "/api/v1/x")) == 1


def test_csrf_fetch_failure_surfaces_as_the_error(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/csrf-token", (500, {"error": "csrf down"}))
    with pytest.raises(FaigError, match="csrf down"):
        faig.post("/api/v1/x")
    assert fake.calls("POST", "/api/v1/x") == []


def test_bearer_token_skips_login_and_csrf(fake: FakeFaig) -> None:
    c = FortiAIGate(fake.url, token="tok")
    c.post("/api/v1/x")
    assert [s.key for s in fake.seen] == [("POST", "/api/v1/x")]
    assert fake.seen[0].headers["authorization"] == "Bearer tok"


def test_bearer_token_401_is_not_a_relogin(fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/user", EXPIRED)
    with pytest.raises(FaigError):
        FortiAIGate(fake.url, "admin", "pw", token="tok").me()
    assert fake.calls("POST", "/api/v1/login") == []


def test_close_logs_out_once(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.me()
    faig.close()
    faig.close()
    assert len(fake.calls("POST", "/api/v1/logout")) == 1


def test_close_swallows_a_failed_logout(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/logout", (500, {}))
    faig.me()
    faig.close()


def test_context_manager_closes(fake: FakeFaig) -> None:
    with FortiAIGate(fake.url, "admin", "pw") as c:
        c.me()
    assert len(fake.calls("POST", "/api/v1/logout")) == 1


def test_from_env(monkeypatch: pytest.MonkeyPatch, fake: FakeFaig) -> None:
    monkeypatch.setenv("FAIG_URL", fake.url)
    monkeypatch.setenv("FAIG_USERNAME", "admin")
    monkeypatch.setenv("FAIG_PASSWORD", "pw")
    monkeypatch.delenv("FAIG_TOKEN", raising=False)
    monkeypatch.delenv("FAIG_CA_BUNDLE", raising=False)
    monkeypatch.setenv("FAIG_VERIFY_TLS", "false")
    c = FortiAIGate.from_env(retries=1)
    c.me()
    assert c.retries == 1
    assert c._ctx.verify_mode == ssl.CERT_NONE
    assert fake.calls("POST", "/api/v1/login")[0].body["username"] == "admin"


def test_from_env_token_and_default_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAIG_URL", "faig.example.com")
    monkeypatch.setenv("FAIG_TOKEN", "tok")
    monkeypatch.delenv("FAIG_VERIFY_TLS", raising=False)
    monkeypatch.delenv("FAIG_CA_BUNDLE", raising=False)
    c = FortiAIGate.from_env()
    assert c._token == "tok"
    assert c._ctx.verify_mode == ssl.CERT_REQUIRED
    assert c._ctx.check_hostname


def test_verify_accepts_a_ca_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def fake_ctx(cafile: str | None = None) -> ssl.SSLContext:
        seen["cafile"] = cafile
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr("pyfortiaigate.client.ssl.create_default_context", fake_ctx)
    FortiAIGate("faig.example.com", verify="/tmp/ca.pem")
    assert seen["cafile"] == "/tmp/ca.pem"
