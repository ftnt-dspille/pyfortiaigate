"""A method that takes ``ws_id`` must have a workspace path to send it to.

``policy()`` once took ``ws_id`` but always read ``/api/v1/admin/...``, which a
workspace login cannot call (403). Its test asserted the admin path, and live
tests run as an org admin, so nothing caught it. This guards the pattern."""

from __future__ import annotations

import ast
from pathlib import Path

import pyfortiaigate.client as client

# Org-admin actions where ws_id NAMES the workspace acted on rather than scoping
# the call: no workspace path exists for them.
ORG_ONLY = {"make_workspace_admin", "delete_workspace", "approve", "reject"}

# Helpers that build a workspace path from ws_id.
WS_PATH_MARKERS = ("/api/v1/workspaces", "_logs_base", "_key_path", "_base(")


def test_every_ws_id_method_can_reach_a_workspace_path() -> None:
    src = Path(client.__file__).read_text()
    cls = next(
        n for n in ast.parse(src).body if isinstance(n, ast.ClassDef) and n.name == "FortiAIGate"
    )
    admin_only = []
    for f in cls.body:
        if not isinstance(f, ast.FunctionDef):
            continue
        if "ws_id" not in [a.arg for a in f.args.args + f.args.kwonlyargs]:
            continue
        body = ast.get_source_segment(src, f) or ""
        if "/api/v1/admin" in body and not any(m in body for m in WS_PATH_MARKERS):
            admin_only.append(f.name)
    assert set(admin_only) == ORG_ONLY, (
        "takes ws_id but only calls /api/v1/admin (a workspace login gets 403): "
        f"{sorted(set(admin_only) - ORG_ONLY)}; no longer admin-only: "
        f"{sorted(ORG_ONLY - set(admin_only))}"
    )
