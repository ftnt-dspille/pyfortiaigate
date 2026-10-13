"""Read-only checks against a real FortiAIGate. Opt-in:

    FAIG_LIVE=1 FAIG_URL=... FAIG_USERNAME=... FAIG_PASSWORD=... pytest tests/live -v

Nothing here creates, changes or deletes anything."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from pyfortiaigate import FortiAIGate

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("FAIG_LIVE"), reason="set FAIG_LIVE=1 to run"),
]


@pytest.fixture(scope="module")
def live() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        yield c


def test_login_and_me(live: FortiAIGate) -> None:
    assert {"id", "email", "role"} <= live.me().keys()


@pytest.mark.parametrize(
    "method",
    [
        "users",
        "workspaces",
        "my_workspaces",
        "detectors",
        "builtin_detectors",
        "guardrails",
        "policies",
        "virtual_keys",
        "review_queue",
        "ai_providers",
        "model_groups",
        "dlp_labels",
    ],
)
def test_lists_are_lists(live: FortiAIGate, method: str) -> None:
    assert isinstance(getattr(live, method)(), list)


def test_workspace_records_have_the_fields_the_client_reads(live: FortiAIGate) -> None:
    for ws in live.workspaces():
        assert {"id", "workspaceName"} <= ws.keys()


def test_audit_logs_page(live: FortiAIGate) -> None:
    assert live.audit_logs(0, 1) is not None
