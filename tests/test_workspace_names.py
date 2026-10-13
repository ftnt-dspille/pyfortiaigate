"""A workspace argument may be its id, its unique name, or its record."""

from __future__ import annotations

import pytest

from pyfortiaigate import FaigError, FortiAIGate

from .conftest import FakeFaig

WS_A = "11111111-2222-3333-4444-555555555555"
WS_B = "66666666-7777-8888-9999-000000000000"
LIST = [{"id": WS_A, "workspaceName": "team-a"}, {"id": WS_B, "workspaceName": "team-b"}]


@pytest.fixture
def client(fake: FakeFaig) -> FortiAIGate:
    fake.answer("GET", "/api/v1/admin/workspaces", (200, {"items": LIST}))
    return FortiAIGate(fake.url, "admin", "pw")


def test_an_id_needs_no_lookup(client: FortiAIGate, fake: FakeFaig) -> None:
    client.guardrails(WS_A)
    assert [c.path for c in fake.app_calls()] == [f"/api/v1/workspaces/{WS_A}/guardrails"]


def test_a_name_resolves_once_then_comes_from_the_cache(
    client: FortiAIGate, fake: FakeFaig
) -> None:
    client.guardrails("team-a")
    client.policies("team-b")
    client.cost_summary("2026-01-01", "2026-01-31", ws_id="team-a")
    assert [c.path for c in fake.app_calls()] == [
        "/api/v1/admin/workspaces",
        f"/api/v1/workspaces/{WS_A}/guardrails",
        f"/api/v1/workspaces/{WS_B}/policies",
        f"/api/v1/workspaces/{WS_A}/cost/summary",
    ]


def test_a_record_works_too(client: FortiAIGate, fake: FakeFaig) -> None:
    client.detectors({"id": WS_B, "workspaceName": "team-b"})
    assert fake.app_calls()[0].path == f"/api/v1/workspaces/{WS_B}/detectors"


def test_a_new_workspace_is_found_by_refreshing(client: FortiAIGate, fake: FakeFaig) -> None:
    assert client.resolve_workspace("team-a") == WS_A
    fake.routes[("GET", "/api/v1/admin/workspaces")].clear()
    fake.answer(
        "GET",
        "/api/v1/admin/workspaces",
        (200, [*LIST, {"id": "77777777-7777-7777-7777-777777777777", "workspaceName": "new"}]),
    )
    assert client.resolve_workspace("new") == "77777777-7777-7777-7777-777777777777"


def test_unknown_name_raises_before_any_workspace_call(client: FortiAIGate, fake: FakeFaig) -> None:
    with pytest.raises(LookupError, match="no workspace named 'nope'"):
        client.guardrails("nope")
    assert [c.path for c in fake.app_calls()] == ["/api/v1/admin/workspaces"]


def test_a_member_resolves_through_their_own_workspaces(fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/workspaces", (403, {"error": "forbidden"}))
    fake.answer("GET", "/api/v1/me/workspaces", (200, LIST[:1]))
    member = FortiAIGate(fake.url, "student@example.com", "pw")
    assert member.resolve_workspace("team-a") == WS_A


def test_other_lookup_errors_are_not_swallowed(fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/workspaces", (500, {"error": "boom"}))
    with pytest.raises(FaigError, match="boom"):
        FortiAIGate(fake.url, "admin", "pw").resolve_workspace("team-a")


def test_duplicate_names_refuse_to_guess(fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/workspaces",
        (200, [*LIST, {"id": WS_B.replace("6", "5"), "workspaceName": "team-a"}]),
    )
    with pytest.raises(ValueError, match="two workspaces are named 'team-a'"):
        FortiAIGate(fake.url, "admin", "pw").resolve_workspace("team-a")


def test_records_without_a_name_are_skipped(fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/workspaces", (200, [{"id": WS_A}, *LIST[1:]]))
    assert FortiAIGate(fake.url, "admin", "pw").resolve_workspace("team-b") == WS_B


def test_make_workspace_admin_by_name_keeps_other_memberships(
    client: FortiAIGate, fake: FakeFaig
) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/users/u1",
        (
            200,
            {
                "email": "a@example.com",
                "orgRole": "org_member",
                "workspaces": [{"workspaceId": WS_A}, {"workspaceId": WS_B}],
            },
        ),
    )
    client.make_workspace_admin("u1", "team-a")
    put = fake.calls("PUT", "/api/v1/admin/users/u1")[0]
    assert put.body["workspaces"] == [
        {"workspaceId": WS_B, "role": "workspace_member"},
        {"workspaceId": WS_A, "role": "workspace_admin"},
    ]
