"""The shape checker the live type tests use, and generated-docs freshness."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pyfortiaigate import Detector, Rankings, TrafficLogPage, VirtualKey

from .shapes import assert_declared, undeclared

ROOT = Path(__file__).resolve().parents[1]


def test_declared_keys_pass() -> None:
    page = {"items": [{"uuid": "t", "verdict": True}], "nextCursor": None, "hasNext": False}
    assert undeclared(page, TrafficLogPage) == []


def test_unknown_keys_are_reported_with_their_path() -> None:
    det = {"uuid": "d", "rules": [{"id": "r", "newRuleField": 1}], "brandNew": 2}
    assert undeclared(det, Detector) == ["$.brandNew", "$.rules[0].newRuleField"]
    with pytest.raises(AssertionError, match=r"\$\.rules\[\]\.newRuleField"):
        assert_declared(det, Detector)


def test_unions_nested_types_and_none() -> None:
    key = {"owner": None, "workspace": {"id": "w", "name": "n"}, "policyIds": [{"id": "p"}]}
    assert undeclared(key, VirtualKey) == []
    assert undeclared({"meta": {"oops": 1}}, Rankings) == ["$.meta.oops"]
    assert undeclared({"anything": 1}, dict) == []


def test_generated_docs_are_current() -> None:
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_docs.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
