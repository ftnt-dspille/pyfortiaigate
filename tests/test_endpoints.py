"""Every client method hits the right method + path with the right body."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from pyfortiaigate import FortiAIGate

from .conftest import FakeFaig

ANY = object()  # body not checked

# (call, method, path, expected body)
CASES: list[tuple[Callable[[FortiAIGate], Any], str, str, Any]] = [
    (lambda c: c.me(), "GET", "/api/v1/user", None),
    (lambda c: c.users(), "GET", "/api/v1/admin/users", None),
    (lambda c: c.user("u/1"), "GET", "/api/v1/admin/users/u%2F1", None),
    (
        lambda c: c.invite("a@example.com"),
        "POST",
        "/api/v1/admin/user-invitations",
        {"emails": ["a@example.com"], "orgRole": "org_member"},
    ),
    (lambda c: c.delete_user("u1"), "DELETE", "/api/v1/admin/users/u1", None),
    (lambda c: c.workspaces(), "GET", "/api/v1/admin/workspaces", None),
    (lambda c: c.my_workspaces(), "GET", "/api/v1/me/workspaces", None),
    (
        lambda c: c.create_workspace("ws", ["u1"], ["openai"], "d"),
        "POST",
        "/api/v1/admin/workspaces",
        {
            "workspaceName": "ws",
            "description": "d",
            "admins": [{"id": "u1"}],
            "budget": None,
            "budgetCycle": "monthly",
            "providerAccess": [{"providerId": "openai", "allKeys": True, "allModels": True}],
        },
    ),
    (lambda c: c.delete_workspace("w1"), "DELETE", "/api/v1/admin/workspaces/w1", None),
    (lambda c: c.workspace_members("w1"), "GET", "/api/v1/workspaces/w1/members", None),
    (lambda c: c.workspace_budget("w1"), "GET", "/api/v1/workspaces/w1/budget", None),
    (lambda c: c.workspace_analytics("w1"), "GET", "/api/v1/workspaces/w1/analytics", None),
    (lambda c: c.detectors("w1"), "GET", "/api/v1/workspaces/w1/detectors", None),
    (lambda c: c.detectors(), "GET", "/api/v1/admin/detectors", None),
    (lambda c: c.builtin_detectors(), "GET", "/api/v1/admin/built-in-detectors", None),
    (
        lambda c: c.create_detector("w1", {"name": "d"}),
        "POST",
        "/api/v1/workspaces/w1/detectors",
        {"name": "d"},
    ),
    (
        lambda c: c.update_detector("w1", "d1", {"name": "d"}),
        "PUT",
        "/api/v1/workspaces/w1/detectors/d1",
        {"name": "d"},
    ),
    (
        lambda c: c.test_detector("w1", "d1", "hi"),
        "POST",
        "/api/v1/workspaces/w1/detectors/d1/test",
        {"input": "hi"},
    ),
    (lambda c: c.delete_detector("d1"), "DELETE", "/api/v1/admin/detectors/d1", None),
    (
        lambda c: c.delete_guardrail("g1", "w1"),
        "DELETE",
        "/api/v1/workspaces/w1/guardrails/g1",
        None,
    ),
    (lambda c: c.delete_guardrail("g1"), "DELETE", "/api/v1/admin/guardrails/g1", None),
    (lambda c: c.delete_policy("p1", "w1"), "DELETE", "/api/v1/workspaces/w1/policies/p1", None),
    (lambda c: c.delete_policy("p1"), "DELETE", "/api/v1/admin/policies/p1", None),
    (lambda c: c.guardrails("w1"), "GET", "/api/v1/workspaces/w1/guardrails", None),
    (lambda c: c.guardrails(), "GET", "/api/v1/admin/guardrails", None),
    (lambda c: c.guardrail("g1"), "GET", "/api/v1/admin/guardrails/g1", None),
    (
        lambda c: c.create_guardrail("w1", "g", ["d1"]),
        "POST",
        "/api/v1/workspaces/w1/guardrails",
        {"name": "g", "description": "g", "detectorIds": ["d1"], "denySuspiciousCharacters": False},
    ),
    (
        lambda c: c.update_guardrail("w1", "g1", "g", ["d1"], "desc"),
        "PUT",
        "/api/v1/workspaces/w1/guardrails/g1",
        {
            "name": "g",
            "description": "desc",
            "detectorIds": ["d1"],
            "denySuspiciousCharacters": False,
        },
    ),
    (
        lambda c: c.test_guardrail("text", ["d1"]),
        "POST",
        "/api/v1/admin/guardrails/test",
        {"input": "text", "detectorIds": ["d1"], "denySuspiciousCharacters": False},
    ),
    (lambda c: c.policies("w1"), "GET", "/api/v1/workspaces/w1/policies", None),
    (lambda c: c.policies(), "GET", "/api/v1/admin/policies", None),
    (lambda c: c.policy("p1"), "GET", "/api/v1/admin/policies/p1", None),
    (
        lambda c: c.create_policy("w1", "p", ["gi"], ["go"]),
        "POST",
        "/api/v1/workspaces/w1/policies",
        {
            "name": "p",
            "description": "p",
            "inputGuardrailIds": ["gi"],
            "outputGuardrailIds": ["go"],
            "responseScanMode": "post_stream",
        },
    ),
    (
        lambda c: c.submit("w1", "guardrails", "g1"),
        "POST",
        "/api/v1/workspaces/w1/guardrails/g1/submit",
        {},
    ),
    (lambda c: c.approve("detectors", "d1"), "POST", "/api/v1/admin/detectors/d1/approve", {}),
    (
        lambda c: c.reject("policies", "p1", "no"),
        "POST",
        "/api/v1/admin/policies/p1/reject",
        {"reason": "no"},
    ),
    (lambda c: c.review_queue(), "GET", "/api/v1/admin/review-queue", None),
    (lambda c: c.virtual_keys("w1"), "GET", "/api/v1/workspaces/w1/virtual-keys", None),
    (lambda c: c.virtual_keys(), "GET", "/api/v1/admin/virtual-keys", None),
    (lambda c: c.virtual_key("k1"), "GET", "/api/v1/admin/virtual-keys/k1", None),
    (
        lambda c: c.create_virtual_key("w1", "k"),
        "POST",
        "/api/v1/workspaces/w1/virtual-keys",
        {"keyName": "k"},
    ),
    (
        lambda c: c.create_virtual_key(
            "w1",
            "k",
            policy_ids=["p1"],
            provider_ids=["openai"],
            expires_at="2030-01-01",
            tpm=10,
            rpm="",
        ),
        "POST",
        "/api/v1/workspaces/w1/virtual-keys",
        {
            "keyName": "k",
            "policyIds": ["p1"],
            "providerAccess": [{"providerId": "openai", "allKeys": True, "allModels": True}],
            "expiresAt": "2030-01-01",
            "tpm": 10,
        },
    ),
    (lambda c: c.rotate_virtual_key("k1"), "POST", "/api/v1/admin/virtual-keys/k1/rotate", {}),
    (
        lambda c: c.revoke_virtual_key("k1"),
        "POST",
        "/api/v1/admin/virtual-keys/k1/revoke",
        {"reason": "revoked"},
    ),
    (lambda c: c.delete_virtual_key("k1"), "DELETE", "/api/v1/admin/virtual-keys/k1", None),
    (lambda c: c.patch("/api/v1/x", {"a": 1}), "PATCH", "/api/v1/x", {"a": 1}),
    (lambda c: c.ai_providers(), "GET", "/api/v1/admin/ai-providers", None),
    (lambda c: c.model_groups(), "GET", "/api/v1/model-groups", None),
    (lambda c: c.dlp_labels(), "GET", "/api/v1/admin/dlp-labels", None),
    (lambda c: c.audit_logs(10, 50), "GET", "/api/v1/admin/audit-logs", None),
    (
        lambda c: c.audit_log_filter_options(),
        "GET",
        "/api/v1/admin/audit-logs/filter-options",
        None,
    ),
]


@pytest.mark.parametrize(
    ("call", "method", "path", "body"), CASES, ids=[c[2] + " " + c[1] for c in CASES]
)
def test_endpoint(
    faig: FortiAIGate, fake: FakeFaig, call: Any, method: str, path: str, body: Any
) -> None:
    call(faig)
    sent = fake.app_calls()
    assert [s.key for s in sent] == [(method, path)]
    if body is not ANY:
        assert sent[0].body == body


def test_audit_logs_paging_query(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.audit_logs(10, 50)
    assert fake.app_calls()[0].query == "offset=10&limit=50"


def test_lists_unwrap_items(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/users", (200, {"items": [{"id": 1}], "total": 1}))
    assert faig.users() == [{"id": 1}]


def test_by_name_lookups(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/users", (200, [{"email": "A@Example.com"}]))
    fake.answer("GET", "/api/v1/admin/workspaces", (200, [{"workspaceName": "ws", "id": "w1"}]))
    fake.answer("GET", "/api/v1/workspaces/w1/detectors", (200, [{"name": "d"}]))
    fake.answer("GET", "/api/v1/workspaces/w1/guardrails", (200, [{"name": "g"}]))
    fake.answer("GET", "/api/v1/workspaces/w1/policies", (200, [{"name": "p"}]))
    assert faig.user_by_email("a@example.com") == {"email": "A@Example.com"}
    assert faig.user_by_email("b@example.com") is None
    assert faig.workspace_by_name("ws") == {"workspaceName": "ws", "id": "w1"}
    assert faig.detector_by_name("w1", "d") == {"name": "d"}
    assert faig.guardrail_by_name("w1", "g") == {"name": "g"}
    assert faig.policy_by_name("w1", "missing") is None


def test_single_record_unwraps_its_envelope(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/guardrails/g1", (200, {"guardrail": {"id": "g1"}}))
    fake.answer("GET", "/api/v1/admin/policies/p1", (200, {"id": "p1"}))
    fake.answer("GET", "/api/v1/admin/virtual-keys/k1", (200, []))
    assert faig.guardrail("g1") == {"id": "g1"}
    assert faig.policy("p1") == {"id": "p1"}
    assert faig.virtual_key("k1") == {}


def test_virtual_keys_status_filter(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/virtual-keys",
        (200, [{"id": "a", "status": "active"}, {"id": "b", "status": "revoked"}]),
    )
    assert [k["id"] for k in faig.virtual_keys(status="active")] == ["a"]


def test_update_virtual_key_merges_into_the_current_record(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/virtual-keys/k1",
        (
            200,
            {
                "key": {
                    "id": "k1",
                    "keyName": "k",
                    "rpm": 5,
                    "status": "active",
                    "spend": 1.5,
                    "policyIds": [{"id": "p0", "assignedByOrg": True}],
                }
            },
        ),
    )
    faig.update_virtual_key("k1", tpm=100, policy_ids=["p1"])
    put = fake.calls("PUT", "/api/v1/admin/virtual-keys/k1")[0]
    assert put.body == {"keyName": "k", "rpm": 5, "tpm": 100, "policyIds": ["p1"]}


def test_make_workspace_admin_keeps_other_memberships(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/users/u1",
        (
            200,
            {
                "email": "a@example.com",
                "orgRole": "workspace_admin",
                "orgRoleStored": "org_member",
                "workspaces": [
                    {"workspaceId": "w0", "membershipRole": "workspace_member"},
                    {"workspaceId": "w1"},
                ],
            },
        ),
    )
    faig.make_workspace_admin("u1", "w1")
    assert fake.calls("PUT", "/api/v1/admin/users/u1")[0].body == {
        "email": "a@example.com",
        "fullName": "a@example.com",
        "orgRole": "org_member",
        "workspaces": [
            {"workspaceId": "w0", "role": "workspace_member"},
            {"workspaceId": "w1", "role": "workspace_admin"},
        ],
    }


def test_test_guardrail_by_guardrail_id(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/guardrails/g1",
        (200, {"id": "g1", "detectorIds": ["d1", "d2"], "denySuspiciousCharacters": True}),
    )
    faig.test_guardrail("hi", guardrail_id="g1")
    assert fake.calls("POST", "/api/v1/admin/guardrails/test")[0].body == {
        "input": "hi",
        "detectorIds": ["d1", "d2"],
        "denySuspiciousCharacters": True,
    }


def test_test_guardrail_needs_detectors_or_a_guardrail(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="detector_ids or guardrail_id"):
        faig.test_guardrail("hi")


def test_accept_invite_is_sent_without_the_session(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.me()  # logged in: the session cookie exists
    faig.accept_invite("i1", "a@example.com", "pw", "Ann")
    call = fake.calls("POST", "/api/v1/invitations/i1/accept")[0]
    assert call.body == {"email": "a@example.com", "password": "pw", "displayName": "Ann"}
    assert "cookie" not in call.headers
    assert "x-csrf-token" not in call.headers


def test_accept_invite_error(faig: FortiAIGate, fake: FakeFaig) -> None:
    from pyfortiaigate import FaigError

    fake.answer("POST", "/api/v1/invitations/i1/accept", (410, {"error": "expired"}))
    with pytest.raises(FaigError, match="expired"):
        faig.accept_invite("i1", "a@example.com", "pw")
    fake.answer("POST", "/api/v1/invitations/i2/accept", (200, None))
    assert faig.accept_invite("i2", "a@example.com", "pw") is None
