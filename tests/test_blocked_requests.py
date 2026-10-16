"""blocked_requests(): blocked traffic joined with the key that sent it, and the
default workspace a call without ws_id goes to."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import pytest

from pyfortiaigate import FortiAIGate

from .conftest import FakeFaig

WS = "w1"
LOGS = f"/api/v1/workspaces/{WS}/traffic-logs"
KEYS = f"/api/v1/workspaces/{WS}/virtual-keys"
OWNER = {"id": "u1", "fullName": "Ada Student", "email": "ada@example.com"}


def _row(uuid: str, alias: str, prefix: str) -> dict:
    return {"uuid": uuid, "verdictLabel": "Block", "keyAlias": alias, "keyPrefix": prefix}


def _log(uuid: str, alias: str, prefix: str) -> dict:
    return {
        "uuid": uuid,
        "timeStamp": 1792173205875,
        "action": "DENY",
        "user": "Ada Student",
        "workspace": "ada-ws",
        "model": "openai-gpt-4.1-mini",
        "keyAlias": alias,
        "keyPrefix": prefix,
        "prompt": {"original": "the launch code is ZEBRA-7731", "modified": "None"},
        "response": {"original": "", "modified": "None"},
        "violation": {
            "input": [
                {
                    "type": "REGEX",
                    "details": "Matched rules: launch-code (block)",
                    "detectorId": "d1",
                    "detectorName": "ada Launch Codes",
                }
            ],
            "output": [],
        },
    }


def _key(kid: str, name: str, preview: str) -> dict:
    return {"id": kid, "keyName": name, "keyPreview": preview, "status": "active", "owner": OWNER}


def test_a_blocked_request_carries_its_key_and_owner(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET", LOGS, (200, {"items": [_row("t1", "ada-key", "faig_…7a43")], "hasNext": False})
    )
    fake.answer("GET", f"{LOGS}/t1", (200, _log("t1", "ada-key", "faig_…7a43")))
    fake.answer("GET", KEYS, (200, {"items": [_key("k1", "ada-key", "faig_…7a43")]}))
    [b] = faig.blocked_requests(since=1792173000000, ws_id=WS)
    assert b["uuid"] == "t1"
    assert b["time"] == "2026-10-16T17:53:25.875000Z"
    assert (b["keyId"], b["keyStatus"], b["ownerEmail"]) == ("k1", "active", "ada@example.com")
    assert b["prompt"] == "the launch code is ZEBRA-7731"
    assert b["reason"] == "Matched rules: launch-code (block)"
    assert b["detectors"] == [
        {
            "name": "ada Launch Codes",
            "type": "REGEX",
            "details": "Matched rules: launch-code (block)",
            "side": "input",
            "id": "d1",
        }
    ]
    q = parse_qs(fake.calls("GET", LOGS)[0].query)
    assert q["range"] == ["custom"]
    assert q["startTime"] == ["1792173000000"]
    assert json.loads(q["verdictFilters"][0]) == {"operator": "is", "value": ["Block"]}


def test_two_keys_with_one_name_are_told_apart_by_preview(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer("GET", LOGS, (200, {"items": [_row("t1", "dup", "faig_…bbbb")], "hasNext": False}))
    fake.answer("GET", f"{LOGS}/t1", (200, _log("t1", "dup", "faig_…bbbb")))
    keys = [_key("k1", "dup", "faig_…aaaa"), _key("k2", "dup", "faig_…bbbb")]
    fake.answer("GET", KEYS, (200, {"items": keys}))
    assert faig.blocked_requests(ws_id=WS)[0]["keyId"] == "k2"


def test_a_deleted_key_leaves_the_key_fields_empty(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", LOGS, (200, {"items": [_row("t1", "gone", "faig_…0000")], "hasNext": False}))
    fake.answer("GET", f"{LOGS}/t1", (200, _log("t1", "gone", "faig_…0000")))
    fake.answer("GET", KEYS, (200, {"items": []}))
    b = faig.blocked_requests(ws_id=WS)[0]
    assert (b["keyId"], b["ownerEmail"]) == (None, None)
    assert b["keyName"] == "gone"


def test_nothing_blocked_makes_no_further_calls(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", LOGS, (200, {"items": [], "hasNext": False}))
    assert faig.blocked_requests(ws_id=WS) == []
    assert fake.calls("GET", KEYS) == []


def _login(fake: FakeFaig, role: str, workspaces: list[dict]) -> FortiAIGate:
    fake.answer("GET", "/api/v1/user", (200, {"role": role}))
    fake.answer("GET", "/api/v1/me/workspaces", (200, {"items": workspaces}))
    c = FortiAIGate(fake.url, "ada", "pw")
    c._ws_ids.update({"w1": "w1", "w2": "w2"})
    return c


def test_a_workspace_login_defaults_to_its_only_workspace(fake: FakeFaig) -> None:
    c = _login(fake, "workspace_member", [{"id": "w1", "workspaceName": "ada-ws"}])
    fake.answer("GET", KEYS, (200, {"items": []}))
    assert c.virtual_keys() == []
    assert fake.calls("GET", KEYS)
    assert not fake.calls("GET", "/api/v1/admin/virtual-keys")
    c.virtual_keys()
    assert len(fake.calls("GET", "/api/v1/user")) == 1  # the role is read once


def test_a_workspace_login_in_two_workspaces_must_name_one(fake: FakeFaig) -> None:
    ws = [{"id": "w1", "workspaceName": "a"}, {"id": "w2", "workspaceName": "b"}]
    with pytest.raises(ValueError, match="2 workspaces"):
        _login(fake, "workspace_member", ws).virtual_keys()
    c = _login(fake, "workspace_member", ws)
    c._workspace = "b"
    fake.answer("GET", "/api/v1/workspaces/w2/virtual-keys", (200, {"items": []}))
    c.virtual_keys()
    assert fake.calls("GET", "/api/v1/workspaces/w2/virtual-keys")


def test_an_org_admin_keeps_the_admin_paths(fake: FakeFaig) -> None:
    c = _login(fake, "org_admin", [])
    fake.answer("GET", "/api/v1/admin/virtual-keys", (200, {"items": []}))
    c.virtual_keys()
    assert fake.calls("GET", "/api/v1/admin/virtual-keys")
    assert c.default_workspace() is None


def test_an_explicit_ws_id_wins(fake: FakeFaig) -> None:
    c = _login(fake, "workspace_member", [{"id": "w1", "workspaceName": "ada-ws"}])
    fake.answer("GET", "/api/v1/workspaces/w2/virtual-keys", (200, {"items": []}))
    c.virtual_keys("w2")
    assert fake.calls("GET", "/api/v1/workspaces/w2/virtual-keys")
    assert fake.calls("GET", "/api/v1/me/workspaces") == []


def test_a_workspace_login_reads_one_policy_by_the_workspace_path(fake: FakeFaig) -> None:
    c = _login(fake, "workspace_member", [{"id": "w1", "workspaceName": "ada-ws"}])
    fake.answer("GET", "/api/v1/workspaces/w1/policies/p1", (200, {"id": "p1", "name": "P"}))
    assert c.policy("p1")["name"] == "P"
    assert not fake.calls("GET", "/api/v1/admin/policies/p1")
