"""replace_virtual_key: rotate what can be rotated, reissue what cannot, and fail closed."""

from __future__ import annotations

import uuid

import pytest

from pyfortiaigate import FortiAIGate, Replaced, key_id_from_secret

from .conftest import FakeFaig

WS = str(uuid.uuid4())
OLD = str(uuid.uuid4())
NEW = str(uuid.uuid4())
OLD_PATH = f"/api/v1/admin/virtual-keys/{OLD}"
CREATE = f"/api/v1/workspaces/{WS}/virtual-keys"
OWN_POL = str(uuid.uuid4())
NEW_SECRET = "faig_" + NEW.replace("-", "") + "_s3cret"


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
        "providerAccess": [],
        "modelGroups": [],
        **over,
    }


def _serve(fake: FakeFaig, record: dict[str, object]) -> None:
    fake.answer("GET", OLD_PATH, (200, record))
    fake.answer(
        "POST", CREATE, (200, {"id": NEW, "keyName": record["keyName"], "secretKey": NEW_SECRET})
    )
    fake.answer("POST", f"{OLD_PATH}/revoke", (200, {"id": OLD, "status": "revoked"}))


def test_an_active_key_is_rotated_in_place(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", OLD_PATH, (200, _old(status="active", expiresAt=None)))
    fake.answer("POST", f"{OLD_PATH}/rotate", (200, {"id": OLD, "secretKey": "faig_rotated_x"}))
    out = faig.replace_virtual_key(OLD)
    assert isinstance(out, Replaced)
    assert out.method == "rotated"
    assert out.secret == "faig_rotated_x"
    assert fake.calls("POST", CREATE) == []


def test_an_expired_key_is_reissued_with_its_shape(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old())
    out = faig.replace_virtual_key(OLD)
    assert out.method == "reissued"
    assert out.old_status == "expired"
    assert out.secret == NEW_SECRET
    assert out.old_revoked is False
    assert out.not_copied == ()
    assert out.id == NEW
    body = fake.calls("POST", CREATE)[0].body
    assert body["keyName"] == "svc-key"
    assert body["tpm"] == 1000
    assert "rpm" not in body
    assert body["policyIds"] == [OWN_POL]  # the org policy attaches itself
    assert body["expiresAt"]  # the same 30 days again, from now
    assert fake.calls("POST", f"{OLD_PATH}/revoke") == []


def test_new_name_and_lifetime(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old())
    faig.replace_virtual_key(OLD, name="svc-key-2", expires_in_days=90)
    body = fake.calls("POST", CREATE)[0].body
    assert body["keyName"] == "svc-key-2"
    assert body["expiresAt"].startswith("20")


def test_a_suspended_key_is_revoked_after_its_replacement_exists(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    _serve(fake, _old(status="suspended", expiresAt=None))
    out = faig.replace_virtual_key(OLD)
    assert out.old_revoked is True
    order = [(s.method, s.path) for s in fake.app_calls() if s.method == "POST"]
    assert order.index(("POST", CREATE)) < order.index(("POST", f"{OLD_PATH}/revoke"))
    assert fake.calls("POST", f"{OLD_PATH}/revoke")[0].body["reason"] == f"Replaced by key {NEW}"
    assert "expiresAt" not in fake.calls("POST", CREATE)[0].body
    out = faig.replace_virtual_key(OLD, revoke_old=False)
    assert out.old_revoked is False


def test_a_revoked_key_is_never_revived_unasked(faig: FortiAIGate, fake: FakeFaig) -> None:
    _serve(fake, _old(status="revoked"))
    with pytest.raises(ValueError, match="deliberate"):
        faig.replace_virtual_key(OLD)
    assert fake.calls("POST", CREATE) == []
    assert faig.replace_virtual_key(OLD, allow_revoked=True).method == "reissued"


def test_limits_that_cannot_be_copied_stop_the_replacement(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    _serve(fake, _old(modelGroups=[{"id": "mg"}]))
    with pytest.raises(ValueError, match="could reach more than the original"):
        faig.replace_virtual_key(OLD)
    assert fake.calls("POST", CREATE) == []
    out = faig.replace_virtual_key(OLD, allow_uncopied=True)
    assert out.not_copied == ("modelGroups",)


def test_whole_provider_access_is_copied_but_per_model_limits_are_not(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    _serve(fake, _old(providerAccess=[{"providerId": "p1", "allModels": True}]))
    faig.replace_virtual_key(OLD)
    assert fake.calls("POST", CREATE)[0].body["providerAccess"] == [
        {"providerId": "p1", "allKeys": True, "allModels": True}
    ]
    fake.seen.clear()
    fake.routes.clear()
    _serve(fake, _old(providerAccess=[{"providerId": "p1", "allModels": False, "models": ["m"]}]))
    with pytest.raises(ValueError, match="providerAccess"):
        faig.replace_virtual_key(OLD)


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
