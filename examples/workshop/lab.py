"""Shared setup for the workshop scripts: read your settings and connect.

Every script starts with

    from lab import KEY, WS, connect, model

and reads the same settings as the ``pyfortiaigate`` command line. Write them
once with ``pyfortiaigate config init``; ``pyfortiaigate config`` shows them.
"""

from __future__ import annotations

import sys

from pyfortiaigate import FortiAIGate
from pyfortiaigate.settings import load_settings

SETTINGS = load_settings()
_missing = [
    n
    for n in ("FAIG_URL", "FAIG_USERNAME", "FAIG_PASSWORD", "FAIG_WS", "FAIG_KEY")
    if not SETTINGS.get(n)
]
if _missing:
    sys.exit(f"Not set: {', '.join(_missing)}. Run: pyfortiaigate config init")

WS = SETTINGS["FAIG_WS"]
"""Your workspace, e.g. student03."""
KEY = SETTINGS["FAIG_KEY"]
"""Your virtual key's secret (faig_...)."""
KEY_NAME = SETTINGS.get("FAIG_KEY_NAME") or f"{WS}-key"
"""Your virtual key's NAME, as the logs show it."""
STUDENT = SETTINGS.get("FAIG_STUDENT") or WS
"""The prefix on your detectors and guardrails ("student03 Input")."""


def connect() -> FortiAIGate:
    """A client logged in as you. Use it in a ``with`` block so it closes."""
    return FortiAIGate.from_env(SETTINGS)


def model(faig: FortiAIGate) -> str:
    """FAIG_MODEL, or the first model your key may call."""
    return SETTINGS.get("FAIG_MODEL") or faig.available_models(KEY)[0]
