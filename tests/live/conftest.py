"""Load the repo's .env for live tests (the shell's env wins)."""

from __future__ import annotations

import os
from pathlib import Path

from pyfortiaigate.settings import read_env_file

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def load_env(path: Path = ENV_FILE) -> None:
    """The repo's .env into os.environ for the live tests; the shell wins and
    blank values are skipped."""
    if not path.is_file():
        return
    for name, value in read_env_file(path).items():
        if value and name not in os.environ:
            os.environ[name] = value


load_env()
