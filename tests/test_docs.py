"""The Actions page lists every public client method, so the docs cannot drift."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from pyfortiaigate import FortiAIGate

ACTIONS = Path(__file__).resolve().parents[1] / "docs" / "actions.md"


def test_every_public_method_is_on_the_actions_page() -> None:
    documented = set(re.findall(r"^\| `(\w+)\(", ACTIONS.read_text(), re.MULTILINE))
    public = {
        n for n, _ in inspect.getmembers(FortiAIGate, inspect.isfunction) if not n.startswith("_")
    }
    public.discard("from_env")  # documented on the home page
    assert public - documented == set(), "add these to docs/actions.md"
    assert documented - public == set(), "these are on docs/actions.md but not on the client"
