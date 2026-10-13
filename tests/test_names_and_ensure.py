"""Detectors, guardrails, policies and keys by name, and the ensure_* helpers."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest

from pyfortiaigate import Ensured, FortiAIGate, approve_new, regex_detector_body
from pyfortiaigate.client import _differs

from .conftest import FakeFaig, Seen

WS = "/api/v1/workspaces/w1"


def _id() -> str:
    return str(uuid.uuid4())


# -- resolution --------------------------------------------------------------------
def test_detector_by_name_custom_and_builtin(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", f"{WS}/detectors", (200, [{"uuid": "d1", "name": "secrets"}]))
    fake.answer(
        "GET", "/api/v1/admin/built-in-detectors", (200, [{"id": "pii", "name": "PII Guard"}])
    )
    assert faig.resolve_detector("secrets", "w1") == "d1"
    assert faig.resolve_detector("PII Guard", "w1") == "pii"
    assert faig.resolve_detector("pii", "w1") == "pii"
    assert len(fake.calls("GET", "/api/v1/admin/built-in-detectors")) == 1  # cached
    with pytest.raises(LookupError, match="no detector named 'nope' in workspace 'w1'"):
        faig.resolve_detector("nope", "w1")


def test_refs_that_need_no_lookup(faig: FortiAIGate, fake: FakeFaig) -> None:
    real = _id()
    assert faig.resolve_guardrail(real) == real
    assert faig.resolve_guardrail({"id": "g9", "name": "x"}) == "g9"
    assert faig.resolve_detector({"uuid": "d9"}) == "d9"
    secret = "faig_" + real.replace("-", "") + "_tail"
    assert faig.resolve_virtual_key(secret) == real
    assert fake.app_calls() == []


def test_org_wide_lookup_and_ambiguity(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/virtual-keys",
        (200, [{"id": "k1", "keyName": "dup"}, {"id": "k2", "keyName": "dup"}]),
    )
    with pytest.raises(ValueError, match="2 virtual keys are named 'dup'"):
        faig.resolve_virtual_key("dup")
    fake.answer("GET", "/api/v1/admin/policies", (200, []))
    with pytest.raises(LookupError, match="in this account"):
        faig.resolve_policy("missing")


def test_names_in_create_calls(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", f"{WS}/detectors", (200, [{"uuid": "d1", "name": "secrets"}]))
    fake.answer("GET", f"{WS}/guardrails", (200, [{"id": "g1", "name": "block-secrets"}]))
    fake.answer("GET", f"{WS}/policies", (200, [{"id": "p1", "name": "strict"}]))
    faig.create_guardrail("w1", "block-secrets", ["secrets"], deny_suspicious_characters=True)
    faig.create_policy("w1", "strict", ["block-secrets"], ["block-secrets"])
    faig.create_virtual_key("w1", "student-key", policy_ids=["strict"])
    g = fake.calls("POST", f"{WS}/guardrails")[0].body
    assert g["detectorIds"] == ["d1"]
    assert g["denySuspiciousCharacters"] is True
    p = fake.calls("POST", f"{WS}/policies")[0].body
    assert (p["inputGuardrailIds"], p["outputGuardrailIds"]) == (["g1"], ["g1"])
    assert fake.calls("POST", f"{WS}/virtual-keys")[0].body["policyIds"] == ["p1"]


@pytest.mark.parametrize(
    ("call", "method", "path"),
    [
        (lambda c: c.update_detector("w1", "secrets", {}), "PUT", f"{WS}/detectors/d1"),
        (lambda c: c.test_detector("w1", "secrets", "t"), "POST", f"{WS}/detectors/d1/test"),
        (lambda c: c.delete_detector("secrets", "w1"), "DELETE", f"{WS}/detectors/d1"),
        (lambda c: c.guardrail("gr", "w1"), "GET", f"{WS}/guardrails/g1"),
        (lambda c: c.delete_guardrail("gr", "w1"), "DELETE", f"{WS}/guardrails/g1"),
        (lambda c: c.delete_policy("pol", "w1"), "DELETE", f"{WS}/policies/p1"),
        (lambda c: c.virtual_key("key", "w1"), "GET", f"{WS}/virtual-keys/k1"),
        (lambda c: c.rotate_virtual_key("key", "w1"), "POST", f"{WS}/virtual-keys/k1/rotate"),
        (lambda c: c.submit("w1", "guardrails", "gr"), "POST", f"{WS}/guardrails/g1/submit"),
        (lambda c: c.withdraw("w1", "policies", "pol"), "DELETE", f"{WS}/policies/p1/pending"),
        (
            lambda c: c.approve("detectors", "secrets", "w1"),
            "POST",
            "/api/v1/admin/detectors/d1/approve",
        ),
    ],
)
def test_names_in_object_calls(
    faig: FortiAIGate,
    fake: FakeFaig,
    call: Callable[[FortiAIGate], Any],
    method: str,
    path: str,
) -> None:
    fake.answer("GET", f"{WS}/detectors", (200, [{"uuid": "d1", "name": "secrets"}]))
    fake.answer("GET", f"{WS}/guardrails", (200, [{"id": "g1", "name": "gr"}]))
    fake.answer("GET", f"{WS}/policies", (200, [{"id": "p1", "name": "pol"}]))
    fake.answer("GET", f"{WS}/virtual-keys", (200, [{"id": "k1", "keyName": "key"}]))
    call(faig)
    assert fake.calls(method, path)


def test_policy_by_name_in_a_workspace(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", f"{WS}/policies", (200, [{"id": "p1", "name": "pol"}]))
    fake.answer("GET", "/api/v1/admin/policies/p1", (200, {"policy": {"id": "p1"}}))
    assert faig.policy("pol", "w1") == {"id": "p1"}


def test_test_guardrail_by_names(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", f"{WS}/detectors", (200, [{"uuid": "d1", "name": "secrets"}]))
    faig.test_guardrail("text", ["secrets"], ws_id="w1")
    assert fake.calls("POST", f"{WS}/guardrails/test")[0].body["detectorIds"] == ["d1"]


def test_approve_by_name_from_the_review_queue(faig: FortiAIGate, fake: FakeFaig) -> None:
    queue = [
        {"id": "g1", "name": "gr", "type": "guardrail"},
        {"id": "p1", "name": "gr", "type": "policy"},
    ]
    fake.answer("GET", "/api/v1/admin/review-queue", (200, queue))
    faig.approve("guardrails", "gr")
    faig.reject("policies", "gr", "no")
    assert fake.calls("POST", "/api/v1/admin/guardrails/g1/approve")
    assert fake.calls("POST", "/api/v1/admin/policies/p1/reject")[0].body == {"reason": "no"}
    with pytest.raises(LookupError, match="0 detectors named 'gr' in the review queue"):
        faig.approve("detectors", "gr")


def test_submit_rejects_an_unknown_kind(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="kind must be one of"):
        faig.submit("w1", "keys", "k1")


def test_update_virtual_key_org_wide_by_name(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/policies", (200, [{"id": "p2", "name": "loose"}]))
    fake.answer("GET", "/api/v1/admin/virtual-keys", (200, [{"id": "k1", "keyName": "bot"}]))
    fake.answer("GET", "/api/v1/admin/virtual-keys/k1", (200, {"key": {"keyName": "bot"}}))
    faig.update_virtual_key("bot", policy_ids=["loose"])
    assert fake.calls("PUT", "/api/v1/admin/virtual-keys/k1")[0].body["policyIds"] == ["p2"]
    with pytest.raises(LookupError, match="no policy named 'tight' in this account"):
        faig.update_virtual_key("bot", policy_ids=["tight"])


def test_update_virtual_key_in_a_workspace(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", f"{WS}/policies", (200, [{"id": "p2", "name": "loose"}]))
    fake.answer("GET", f"{WS}/virtual-keys/k1", (200, {"key": {"keyName": "k", "rpm": 5}}))
    faig.update_virtual_key("k1", policy_ids=["loose"], provider_ids=["openai"], ws_id="w1")
    body = fake.calls("PUT", f"{WS}/virtual-keys/k1")[0].body
    assert body["policyIds"] == ["p2"]
    assert body["providerAccess"] == [{"providerId": "openai", "allKeys": True, "allModels": True}]
    assert body["rpm"] == 5


# -- _differs ----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("want", "have", "differs"),
    [
        ({"a": 1}, {"a": 1, "extra": 2}, False),
        ({"a": 1}, {"a": 2}, True),
        ({"a": None}, {"a": 5}, False),
        ({"a": {"b": 1}}, {"a": "x"}, True),
        ({"ids": ["x", "y"]}, {"ids": ["y", "x"]}, False),
        ({"ids": ["x"]}, {"ids": ["x", "y"]}, True),
        ({"rules": [{"p": 1}]}, {"rules": [{"p": 1, "id": "srv"}]}, False),
        ({"rules": [{"p": 1}]}, {"rules": [{"p": 2}]}, True),
        ({"rules": [{"p": 1}]}, {"rules": None}, True),
    ],
)
def test_differs(want: Any, have: Any, differs: bool) -> None:
    assert _differs(want, have) is differs


# -- ensure_* against a small stateful workspace -----------------------------------------------
class Store:
    """Just enough of a workspace to run ensure_* against: list, create, update,
    submit and approve, for one kind of object."""

    def __init__(self, fake: FakeFaig, kind: str, id_field: str, status_field: str):
        self.records: dict[str, dict[str, Any]] = {}
        self.kind, self.id_field, self.status_field = kind, id_field, status_field
        base = f"{WS}/{kind}"
        fake.answer("GET", base, lambda s: (200, list(self.records.values())))
        fake.answer("POST", base, self.create)
        self.fake = fake

    def create(self, seen: Seen) -> tuple[int, Any]:
        oid = f"{self.kind[0]}{len(self.records) + 1}"
        rec = {**seen.body, self.id_field: oid, self.status_field: "draft"}
        self.records[oid] = rec
        base = f"{WS}/{self.kind}/{oid}"
        self.fake.answer("PUT", base, lambda s, oid=oid: self.update(oid, s))
        self.fake.answer("POST", f"{base}/submit", lambda s, oid=oid: self.set(oid, "pending"))
        self.fake.answer(
            "POST",
            f"/api/v1/admin/{self.kind}/{oid}/approve",
            lambda s, oid=oid: self.set(oid, "active"),
        )
        return 201, rec

    def update(self, oid: str, seen: Seen) -> tuple[int, Any]:
        self.records[oid].update(seen.body)
        return 200, self.records[oid]

    def set(self, oid: str, status: str) -> tuple[int, Any]:
        self.records[oid][self.status_field] = status
        return 200, self.records[oid]


def test_ensure_detector_create_then_unchanged_then_update(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    store = Store(fake, "detectors", "uuid", "approvalStatus")
    body = regex_detector_body("secrets", [("code", r"Z-\d+", "block")])
    first = faig.ensure_detector("w1", body)
    assert first.action == "created"
    assert first.changed
    assert first.id == "d1"
    assert first.record["approvalStatus"] == "active"
    again = faig.ensure_detector("w1", body)
    assert (again.action, again.changed) == ("unchanged", False)
    changed = regex_detector_body("secrets", [("code", r"Z-\d{4}", "block")])
    assert faig.ensure_detector("w1", changed).action == "updated"
    assert store.records["d1"]["rules"][0]["pattern"] == r"Z-\d{4}"
    assert len(fake.calls("POST", f"{WS}/detectors")) == 1


def test_ensure_detector_without_approval(faig: FortiAIGate, fake: FakeFaig) -> None:
    Store(fake, "detectors", "uuid", "approvalStatus")
    out = faig.ensure_detector("w1", regex_detector_body("s", [("c", "x", "block")]), approve=False)
    assert out.record["approvalStatus"] == "draft"


def test_ensure_guardrail(faig: FortiAIGate, fake: FakeFaig) -> None:
    store = Store(fake, "guardrails", "id", "status")
    fake.answer(
        "GET", f"{WS}/detectors", (200, [{"uuid": "d1", "name": "a"}, {"uuid": "d2", "name": "b"}])
    )
    assert faig.ensure_guardrail("w1", "gr", ["a"]).action == "created"
    assert faig.ensure_guardrail("w1", "gr", ["d1"]).action == "unchanged"
    out = faig.ensure_guardrail("w1", "gr", ["a", "b"])
    assert out.action == "updated"
    assert store.records["g1"]["detectorIds"] == ["d1", "d2"]
    assert out.record["status"] == "active"


def test_ensure_policy(faig: FortiAIGate, fake: FakeFaig) -> None:
    Store(fake, "policies", "id", "status")
    fake.answer("GET", f"{WS}/guardrails", (200, [{"id": "g1", "name": "gr"}]))
    first = faig.ensure_policy("w1", "pol", ["gr"], ["gr"], provider_ids=["openai"])
    assert first.action == "created"
    assert (
        faig.ensure_policy("w1", "pol", ["gr"], ["gr"], provider_ids=["openai"]).action
        == "unchanged"
    )
    assert faig.ensure_policy("w1", "pol", ["gr"], [], provider_ids=["openai"]).action == "updated"


def test_approve_new_approves_a_pending_change(faig: FortiAIGate, fake: FakeFaig) -> None:
    approve_new(
        faig, "w1", "guardrails", {"id": "g1", "status": "active", "hasPendingChange": True}
    )
    approve_new(faig, "w1", "guardrails", {"id": "g2", "status": "active"})
    assert fake.calls("POST", "/api/v1/admin/guardrails/g1/approve")
    assert not fake.calls("POST", "/api/v1/admin/guardrails/g2/approve")


KEY_ID = "0b6b5c1e-1111-4222-8333-944455556666"
SECRET = "faig_" + KEY_ID.replace("-", "") + "_s"


def test_ensure_virtual_key_creates_with_secret(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET", f"{WS}/virtual-keys", (200, [{"id": "k0", "keyName": "s1", "status": "revoked"}])
    )
    fake.answer("GET", f"{WS}/policies", (200, [{"id": "p1", "name": "pol"}]))
    fake.answer("POST", f"{WS}/virtual-keys", (201, {"secretKey": SECRET}))
    fake.answer(
        "GET",
        f"/api/v1/admin/virtual-keys/{KEY_ID}",
        (200, {"key": {"id": KEY_ID, "keyName": "s1"}}),
    )
    out = faig.ensure_virtual_key("w1", "s1", policy_ids=["pol"], rpm=10)
    assert out == Ensured({"id": KEY_ID, "keyName": "s1"}, "created", SECRET)
    assert out.id == KEY_ID
    body = fake.calls("POST", f"{WS}/virtual-keys")[0].body
    assert body == {"keyName": "s1", "policyIds": ["p1"], "rpm": 10}


def test_ensure_virtual_key_create_without_a_secret_in_the_answer(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer("GET", f"{WS}/virtual-keys", (200, []))
    fake.answer("POST", f"{WS}/virtual-keys", (201, {"id": "k1", "keyName": "s1"}))
    out = faig.ensure_virtual_key("w1", "s1")
    assert (out.action, out.secret, out.id) == ("created", None, "k1")


def test_ensure_virtual_key_unchanged_and_updated(faig: FortiAIGate, fake: FakeFaig) -> None:
    rec = {
        "id": "k1",
        "keyName": "s1",
        "status": "active",
        "rpm": 10,
        "policyIds": [{"id": "p1", "assignedByOrg": False}],
        "providerAccess": [{"providerId": "openai"}],
    }
    fake.answer("GET", f"{WS}/virtual-keys", (200, [rec]))
    fake.answer("GET", f"{WS}/virtual-keys/k1", (200, {"key": rec}))
    same = faig.ensure_virtual_key("w1", "s1", policy_ids=["p1"], provider_ids=["openai"], rpm=10)
    assert same.action == "unchanged"
    assert fake.calls("PUT", f"{WS}/virtual-keys/k1") == []
    out = faig.ensure_virtual_key(
        "w1",
        "s1",
        policy_ids=["p2"],
        provider_ids=["anthropic"],
        rpm=20,
        tpm=5,
        expires_at="2030-01-01",
    )
    assert out.action == "updated"
    body = fake.calls("PUT", f"{WS}/virtual-keys/k1")[0].body
    assert body["policyIds"] == ["p2"]
    assert body["rpm"] == 20
    assert body["tpm"] == 5
    assert body["expiresAt"] == "2030-01-01"
    assert body["providerAccess"][0]["providerId"] == "anthropic"


def test_ensure_virtual_key_refuses_two_active_keys(faig: FortiAIGate, fake: FakeFaig) -> None:
    keys = [{"id": "k1", "keyName": "s1", "status": "active"}, {"id": "k2", "keyName": "s1"}]
    fake.answer("GET", f"{WS}/virtual-keys", (200, keys))
    with pytest.raises(ValueError, match="2 active keys are named 's1'"):
        faig.ensure_virtual_key("w1", "s1")
