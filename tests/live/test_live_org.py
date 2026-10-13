"""Org-level writes against a real FortiAIGate: invitations, accounts and
workspaces. Doubly opt-in, since these touch the whole org:

    FAIG_LIVE=1 FAIG_ORG_WRITES=1 FAIG_TEST_INVITEE=<an address you own> pytest tests/live

The invitee must NOT already have an account or a pending invitation (the test
skips rather than touch one). It invites the address, revokes and re-invites,
accepts the invitation with a random password (creating the account), creates a
``pytest-org-`` workspace, makes the new user its admin, then deletes the
workspace and the account. Every response is checked against its declared
type."""

from __future__ import annotations

import os
import secrets
import typing
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

import pyfortiaigate as P
from pyfortiaigate import FortiAIGate, ValidationError

from ..shapes import assert_declared

INVITEE = os.environ.get("FAIG_TEST_INVITEE", "")
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not (os.environ.get("FAIG_LIVE") and os.environ.get("FAIG_ORG_WRITES") and INVITEE),
        reason="set FAIG_LIVE=1, FAIG_ORG_WRITES=1 and FAIG_TEST_INVITEE=<address> to run",
    ),
]


def returns(method: str) -> Any:
    return typing.get_type_hints(getattr(FortiAIGate, method), vars(P.client))["return"]


@pytest.fixture(scope="module")
def faig() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        if c.user_by_email(INVITEE) or c.invitation_by_email(INVITEE):
            pytest.skip(f"{INVITEE} already has an account or invitation; not touching it")
        yield c


def test_invite_account_and_workspace_lifecycle(faig: FortiAIGate) -> None:
    ws_name = "pytest-org-" + uuid.uuid4().hex[:8]
    user_id = ws_id = None
    try:
        inv = faig.invite(INVITEE)
        assert_declared(inv, returns("invite"))
        assert_declared(faig.invitations(), returns("invitations"))
        with pytest.raises(ValidationError, match="pending invitation"):
            faig.invite(INVITEE)  # one pending invitation per address
        faig.revoke_invitation(inv["id"])
        assert faig.invitation_by_email(INVITEE) is None

        inv = faig.invite(INVITEE)
        accepted = faig.accept_invite(
            inv["id"], INVITEE, secrets.token_urlsafe(18) + "aA1!", "pytest org user"
        )
        assert_declared(accepted, returns("accept_invite"))
        assert accepted["createdAccount"]
        user = faig.user_by_email(INVITEE)
        assert user
        user_id = user["id"]
        assert_declared(faig.user(user_id), returns("user"))

        ws = faig.create_workspace(ws_name, [faig.me()["id"]], ["openai"], "pytest org test")
        assert_declared(ws, returns("create_workspace"))
        ws_id = ws["id"]
        updated = faig.make_workspace_admin(user_id, ws_name)
        assert_declared(updated, returns("make_workspace_admin"))
        assert any(
            w["workspaceId"] == ws_id and w["membershipRole"] == "workspace_admin"
            for w in updated["workspaces"]
        )
        roles = [m["role"] for m in faig.workspace_members(ws_name)["items"]]
        assert roles.count("workspace_admin") == 2

        faig.delete_workspace(ws_name)
        ws_id = None
        assert not any(w.get("workspaceName") == ws_name for w in faig.workspaces())
        faig.delete_user(user_id)
        user_id = None
        assert faig.user_by_email(INVITEE) is None
    finally:
        if ws_id:
            faig.delete_workspace(ws_id)
        if user_id:
            faig.delete_user(user_id)
        pending = faig.invitation_by_email(INVITEE)
        if pending:
            faig.revoke_invitation(pending["id"])
