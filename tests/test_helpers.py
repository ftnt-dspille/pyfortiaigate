"""Module-level helpers and body builders."""

from __future__ import annotations

from typing import Any

import pytest

from pyfortiaigate import (
    FaigError,
    approve_new,
    blocked,
    dlp_detector_body,
    guardrail_body,
    items,
    key_id_from_secret,
    origin,
    regex_detector_body,
    secret_from_response,
)


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("faig.example.com", "https://faig.example.com"),
        ("https://faig.example.com/", "https://faig.example.com"),
        ("https://faig.example.com/api", "https://faig.example.com"),
        ("http://faig.example.com:8443/api/v1", "http://faig.example.com:8443"),
    ],
)
def test_origin(url: str, want: str) -> None:
    assert origin(url) == want


@pytest.mark.parametrize("bad", ["", "   ", "https://"])
def test_origin_rejects(bad: str) -> None:
    with pytest.raises(ValueError, match="URL"):
        origin(bad)


@pytest.mark.parametrize(
    ("data", "want"),
    [
        ([{"a": 1}], [{"a": 1}]),
        ({"items": [{"a": 1}]}, [{"a": 1}]),
        ({"data": [{"a": 1}]}, [{"a": 1}]),
        ({"results": []}, []),
        ({"total": 0}, []),
        (None, []),
    ],
)
def test_items(data: Any, want: Any) -> None:
    assert items(data) == want


def test_key_id_from_secret() -> None:
    secret = "faig_0123456789abcdef0123456789abcdef_tail"
    assert key_id_from_secret(secret) == "01234567-89ab-cdef-0123-456789abcdef"


@pytest.mark.parametrize(
    ("data", "want"),
    [
        ({"secretKey": "faig_abc"}, "faig_abc"),
        ({"key": {"apiKey": "faig_nested"}}, "faig_nested"),
        ({"newKey": "not-a-secret"}, None),
        ({"key": "faig_flat"}, "faig_flat"),
        ([], None),
    ],
)
def test_secret_from_response(data: Any, want: Any) -> None:
    assert secret_from_response(data) == want


@pytest.mark.parametrize(
    ("completion", "want"),
    [
        ({"choices": [{"finish_reason": "content_filter"}]}, True),
        ({"choices": [{"finish_reason": "stop"}]}, False),
        ({"choices": None}, False),
        ({"choices": ["junk"]}, False),
        ("text", False),
    ],
)
def test_blocked(completion: Any, want: bool) -> None:
    assert blocked(completion) is want


def test_guardrail_body_needs_a_detector() -> None:
    with pytest.raises(ValueError, match="at least one detector"):
        guardrail_body("g", [])


def test_regex_detector_body_fills_the_flat_rules_the_engine_matches() -> None:
    body = regex_detector_body(
        "no-ssn", [("ssn", r"\d{3}-\d{2}-\d{4}", "block"), ("x", "x", "log")]
    )
    assert body["detectorType"] == "regex"
    assert body["description"] == "no-ssn"
    assert body["rules"] == [
        {"id": "c1", "pattern": r"\d{3}-\d{2}-\d{4}", "disposition": "block"},
        {"id": "c2", "pattern": "x", "disposition": "log"},
    ]
    assert [r["name"] for r in body["regexRules"]] == ["ssn", "x"]


def test_regex_detector_body_refuses_no_rules() -> None:
    with pytest.raises(ValueError, match="matches nothing"):
        regex_detector_body("empty", [])


def test_dlp_detector_body_uses_disposition() -> None:
    body = dlp_detector_body("dlp", ["Credit Card", "SSN"], threshold=0.5, description="pii")
    assert body["managedEngine"] == "dlp"
    assert body["description"] == "pii"
    assert body["inputGuards"] == ["Credit Card", "SSN"]
    assert body["rules"][1] == {
        "id": "d1",
        "category": "SSN",
        "disposition": "block",
        "threshold": 0.5,
    }


class FakeAdmin:
    def __init__(self, error: FaigError | None = None):
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def submit(self, ws: str, kind: str, oid: str) -> None:
        self.calls.append(("submit", oid))

    def approve(self, kind: str, oid: str) -> dict[str, str]:
        self.calls.append(("approve", oid))
        if self.error:
            raise self.error
        return {"uuid": oid, "status": "active"}


RACE = '{"error":"only a workspace\'s pending submission can be approved or rejected"}'


def test_approve_new_walks_draft_to_active() -> None:
    a = FakeAdmin()
    assert (
        approve_new(a, "w1", "guardrails", {"uuid": "g1", "status": "draft"})["status"] == "active"
    )  # type: ignore[arg-type,index]
    assert a.calls == [("submit", "g1"), ("approve", "g1")]


def test_approve_new_uses_approval_status_and_id() -> None:
    a = FakeAdmin()
    approve_new(a, "w1", "detectors", {"id": "d1", "approvalStatus": "pending"})  # type: ignore[arg-type]
    assert a.calls == [("approve", "d1")]


def test_approve_new_leaves_active_objects_alone() -> None:
    a = FakeAdmin()
    obj = {"uuid": "g1", "status": "active"}
    assert approve_new(a, "w1", "guardrails", obj) is obj  # type: ignore[arg-type]
    assert a.calls == []


def test_approve_new_tolerates_losing_the_race() -> None:
    a = FakeAdmin(FaigError("POST", "/approve", 409, RACE))
    obj = {"uuid": "g1", "status": "pending"}
    assert approve_new(a, "w1", "guardrails", obj) is obj  # type: ignore[arg-type]


def test_approve_new_other_errors_raise() -> None:
    a = FakeAdmin(FaigError("POST", "/approve", 409, '{"error":"something else"}'))
    with pytest.raises(FaigError):
        approve_new(a, "w1", "guardrails", {"uuid": "g1", "status": "pending"})  # type: ignore[arg-type]


def test_key_update_body_keeps_writable_fields_and_flattens_policy_ids() -> None:
    from pyfortiaigate import key_update_body

    rec = {
        "id": "k1",
        "keyName": "k",
        "status": "active",
        "spend": 2,
        "rpm": 5,
        "policyIds": [{"id": "p0", "assignedByOrg": True}, "p1"],
    }
    assert key_update_body(rec) == {"keyName": "k", "rpm": 5, "policyIds": ["p0", "p1"]}
    assert key_update_body({"policyIds": None}) == {"policyIds": []}
