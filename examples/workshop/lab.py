"""Shared setup for the workshop scripts: read your settings and connect.

Every script starts with

    from lab import KEY, WS, connect, model

and reads the same settings file as the ``pyfortiaigate`` command line,
~/.config/pyfortiaigate/.env (or a .env next to this file, if there is one).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from pyfortiaigate import FortiAIGate
from pyfortiaigate.cli import default_env_file, load_env

ENV_FILE = Path(__file__).with_name(".env")
if not ENV_FILE.is_file():
    ENV_FILE = default_env_file()
if not ENV_FILE.is_file():
    sys.exit(f"No {ENV_FILE}: copy env.example there and fill it in.")
load_env(ENV_FILE)

for name in ("FAIG_URL", "FAIG_USERNAME", "FAIG_PASSWORD", "FAIG_WS", "FAIG_KEY"):
    if not os.environ.get(name):
        sys.exit(f"{name} is empty in {ENV_FILE}")

WS = os.environ["FAIG_WS"]
"""Your workspace, e.g. student03."""
KEY = os.environ["FAIG_KEY"]
"""Your virtual key's secret (faig_...), the one in ~/.faig-lab.env."""
KEY_NAME = os.environ.get("FAIG_KEY_NAME") or f"{WS}-key"
"""Your virtual key's NAME, as the logs show it."""
STUDENT = os.environ.get("FAIG_STUDENT") or WS
"""The prefix on your detectors and guardrails ("student03 Input")."""


def connect() -> FortiAIGate:
    """A client logged in as you. Use it in a ``with`` block so it closes."""
    return FortiAIGate.from_env()


def model(faig: FortiAIGate) -> str:
    """FAIG_MODEL, or the first model your key may call."""
    return os.environ.get("FAIG_MODEL") or faig.available_models(KEY)[0]
