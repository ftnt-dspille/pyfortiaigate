"""renew_virtual_key: a new secret for the same key, extending an expired one first."""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from pyfortiaigate import FortiAIGate, Renewed, key_id_from_secret

from .conftest import FakeFaig

WS = str(uuid.uuid4())
OLD = str(uuid.uuid4())
OLD_PATH = f"/api/v1/admin/virtual-keys/{OLD}"
OWN_POL = str(uuid.uuid4())


def _old(**over: object) -> dict[str, object]:
    return {
        "id": OLD,
        "keyName": "svc-key",
        "status": "expired",
        "createdAt": "2026-01-01T00:00:00.000Z",
        "expiresAt": "2026-01-31T00:00:00.000Z",
        "workspace": {"id": WS, "name": "Default"},
        "tpm": 1000,
        "rpm": None,
        "policyIds": [
            {"id": str(uuid.uuid4()), "assignedByOrg": True},
            {"id": OWN_POL, "assignedByOrg": False},
        ],
        "providerAccess": [{"providerId": "openai", "allModels": True}],
        "modelGroups": [],
        "spend": 0,
        **over,
    }


def _serve(fake: FakeFaig, record: dict[str, object]) -> None:
    fake.answer("GET", OLD_PATH, (200, record))
    fake.answer("PUT", OLD_PATH, (200, dict(record, status="active")))
    fake.answer("POST", f"{OLD_PATH}/rotate", (200, {"id": OLD, "secretKey": "faig_rotated_x"}))


def test_an_active_key_is_rotated_in_place(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old(status="active", expiresAt=None))
    out = faig.renew_virtual_key(OLD)
    assert isinstance(out, Renewed)
    assert (out.method, out.secret, out.id, out.expires_at) == (
        "rotated",
        "faig_rotated_x",
        OLD,
        None,
    )
    assert fake.calls("PUT", OLD_PATH) == []


def test_an_expired_key_is_extended_then_rotated(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old())
    out = faig.renew_virtual_key(OLD, expires_in_days=90)
    assert out.method == "extended_and_rotated"
    assert out.old_status == "expired"
    assert out.secret == "faig_rotated_x"
    assert out.id == OLD  # same key: nothing is created, nothing to copy
    order = [(c.method, c.path) for c in fake.app_calls() if c.method in ("PUT", "POST")]
    assert order == [("PUT", OLD_PATH), ("POST", f"{OLD_PATH}/rotate")]
    put = fake.calls("PUT", OLD_PATH)[0].body
    assert put["expiresAt"] == out.expires_at
    new_expiry = dt.datetime.fromisoformat(put["expiresAt"].replace("Z", "+00:00"))
    days = (new_expiry - dt.datetime.now(dt.timezone.utc)).days
    assert 88 <= days <= 90
    assert "status" not in put  # 8.0.2 rejects read-only fields
    assert "spend" not in put
    assert put["policyIds"]
    assert all(isinstance(p, str) for p in put["policyIds"])


def test_an_active_key_past_its_expiry_counts_as_expired(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old(status="active"))
    assert faig.renew_virtual_key(OLD).method == "extended_and_rotated"


@pytest.mark.parametrize("status", ["revoked", "suspended"])
def test_a_revoked_or_suspended_key_is_left_alone(
    faig: FortiAIGate, fake: FakeFaig, status: str
) -> None:
    _serve(fake, _old(status=status))
    with pytest.raises(ValueError, match=f"is {status}"):
        faig.renew_virtual_key(OLD)
    assert fake.calls("PUT", OLD_PATH) == []
    assert fake.calls("POST", f"{OLD_PATH}/rotate") == []


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "nope",
        "faig_short_x",
        "other_" + "a" * 32 + "_x",
        "faig_" + "z" * 32 + "_x",
        "faig_" + "a" * 32,
    ],
)
def test_a_malformed_secret_is_not_turned_into_an_id(secret: str) -> None:
    with pytest.raises(ValueError, match="not a FortiAIGate virtual key secret"):
        key_id_from_secret(secret)


def test_a_renewed_key_keeps_its_name_and_the_active_one_is_chosen(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/virtual-keys",
        (
            200,
            [
                {"id": "k1", "keyName": "dup", "status": "expired"},
                {"id": "k2", "keyName": "dup", "status": "active"},
            ],
        ),
    )
    assert faig.resolve_virtual_key("dup") == "k2"
    fake.routes.clear()
    fake.answer(
        "GET",
        "/api/v1/admin/virtual-keys",
        (
            200,
            [
                {"id": "k1", "keyName": "dup", "status": "active"},
                {"id": "k2", "keyName": "dup", "status": "active"},
            ],
        ),
    )
    with pytest.raises(ValueError, match="2 virtual keys are named 'dup'"):
        faig.resolve_virtual_key("dup")
