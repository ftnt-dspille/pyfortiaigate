"""The class auto-approver example approves only the class's changes and survives races."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from pyfortiaigate import FaigError

SPEC = importlib.util.spec_from_file_location(
    "auto_approver", Path(__file__).resolve().parents[1] / "examples/workshop/auto_approver.py"
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class FakeFaig:
    def __init__(self, queue, lost=()):
        self.queue, self.lost, self.approved = queue, set(lost), []

    def workspaces(self):
        return [
            {"id": "w1", "workspaceName": "student01"},
            {"id": "w2", "workspaceName": "student02"},
            {"id": "w9", "workspaceName": "instructors"},
        ]

    def review_queue(self):
        return self.queue

    def approve(self, kind, oid):
        if oid in self.lost:
            raise FaigError("POST", "/approve", 409, "no longer pending")
        self.approved.append((kind, oid))


def item(oid, ws, typ="guardrail"):
    return {"id": oid, "name": oid, "type": typ, "ownerWorkspaceId": ws, "changeKind": "create"}


def test_workspace_ids_match_by_prefix():
    assert mod.class_workspace_ids(FakeFaig([]), ["student"]) == {"w1", "w2"}


def test_only_class_workspaces_are_approved():
    f = FakeFaig([item("a", "w1"), item("b", "w9"), item("c", "w2", "policy")])
    assert mod.approve_pending(f, {"w1", "w2"}) == 2
    assert f.approved == [("guardrails", "a"), ("policies", "c")]


def test_a_lost_race_is_not_an_error():
    f = FakeFaig([item("a", "w1"), item("b", "w1")], lost={"a"})
    assert mod.approve_pending(f, {"w1"}) == 1
    assert f.approved == [("guardrails", "b")]
