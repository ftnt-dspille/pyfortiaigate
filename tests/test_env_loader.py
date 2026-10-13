"""tests/live/conftest.load_env: the .env loader for live tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from .live.conftest import load_env


def test_load_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / ".env"
    f.write_text(
        "# comment\n\nFAIG_T_A=plain\nexport FAIG_T_B='quoted value'\nFAIG_T_C=\n"
        "FAIG_T_D=from-file\nnot a pair\n"
    )
    for k in ("FAIG_T_A", "FAIG_T_B", "FAIG_T_C"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FAIG_T_D", "from-shell")
    load_env(f)
    assert os.environ["FAIG_T_A"] == "plain"
    assert os.environ["FAIG_T_B"] == "quoted value"
    assert "FAIG_T_C" not in os.environ  # blank values are left unset
    assert os.environ["FAIG_T_D"] == "from-shell"  # the shell wins
    for k in ("FAIG_T_A", "FAIG_T_B"):
        monkeypatch.delenv(k)


def test_missing_file_is_fine(tmp_path: Path) -> None:
    load_env(tmp_path / "absent")
