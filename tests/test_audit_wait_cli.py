"""Audit log paging, waiting for traffic, licenses, and the command-line tool."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest

from pyfortiaigate import FortiAIGate
from pyfortiaigate.cli import load_env, main, table

from .conftest import FakeFaig, Seen


def _q(seen: Seen) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(seen.query).items()}


# -- audit logs ----------------------------------------------------------------------
def test_iter_audit_logs_follows_cursor_with_filters(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/admin/audit-logs",
        (200, {"items": [{"uuid": "a1"}, {"uuid": "a2"}], "nextCursor": "c2", "hasNext": True}),
        (200, {"items": [{"uuid": "a3"}], "nextCursor": None, "hasNext": False}),
    )
    rows = list(faig.iter_audit_logs(range="7d", filters={"action": "Approve"}, page_size=2))
    assert [r["uuid"] for r in rows] == ["a1", "a2", "a3"]
    first, second = (_q(s) for s in fake.calls("GET", "/api/v1/admin/audit-logs"))
    assert first["range"] == "7d"
    assert first["includeTotal"] == "true"
    assert json.loads(first["actionFilters"]) == {"operator": "is", "value": ["Approve"]}
    assert second["cursor"] == "c2"


def test_iter_audit_logs_max_items_and_workspace(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer(
        "GET",
        "/api/v1/workspaces/w1/audit-logs",
        (200, {"items": [{"uuid": "a1"}, {"uuid": "a2"}], "nextCursor": "c2"}),
    )
    assert len(list(faig.iter_audit_logs(max_items=1, ws_id="w1"))) == 1


def test_audit_unknown_filter_raises(faig: FortiAIGate) -> None:
    with pytest.raises(ValueError, match="unknown filter 'verdict'"):
        faig.audit_logs_page(filters={"verdict": "Block"})


def test_audit_filter_options(faig: FortiAIGate, fake: FakeFaig) -> None:
    faig.audit_log_filter_options()
    faig.audit_log_filter_options(range="7d", ws_id="w1")
    plain = fake.calls("GET", "/api/v1/admin/audit-logs/filter-options")[0]
    scoped = fake.calls("GET", "/api/v1/workspaces/w1/audit-logs/filter-options")[0]
    assert plain.query == ""
    assert _q(scoped) == {"range": "7d"}


def test_licenses(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/licenses", (200, {"licenses": [{"status": "Active"}]}))
    assert faig.licenses() == {"licenses": [{"status": "Active"}]}


# -- wait_for_traffic ----------------------------------------------------------------------
def test_wait_for_traffic_polls_until_rows(
    faig: FortiAIGate, fake: FakeFaig, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr("pyfortiaigate.client.time.sleep", sleeps.append)
    fake.answer(
        "GET",
        "/api/v1/admin/traffic-logs",
        (200, {"items": []}),
        (200, {"items": [{"uuid": "t1"}]}),
    )
    rows = faig.wait_for_traffic(10_000, filters={"virtual_key": "bot"}, interval=0.5)
    assert rows == [{"uuid": "t1"}]
    assert sleeps == [0.5]
    q = _q(fake.calls("GET", "/api/v1/admin/traffic-logs")[0])
    assert q["range"] == "custom"
    assert q["startTime"] == "8000"  # two seconds of clock-skew slack
    assert json.loads(q["virtualKeyFilters"])["value"] == ["bot"]


def test_wait_for_traffic_times_out(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("GET", "/api/v1/admin/traffic-logs", (200, {"items": [{"uuid": "t1"}]}))
    with pytest.raises(TimeoutError, match="1 of 2 traffic log rows after 0s"):
        faig.wait_for_traffic(0, count=2, timeout=0)


# -- CLI ---------------------------------------------------------------------------------
@pytest.fixture
def cli_env(fake: FakeFaig, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeFaig:
    for var in ("FAIG_TOKEN", "FAIG_KEY", "FAIG_CA_BUNDLE", "FAIG_VERIFY_TLS", "FAIG_ENV_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))  # no real ~/.config
    monkeypatch.setenv("FAIG_URL", fake.url)
    monkeypatch.setenv("FAIG_USERNAME", "admin")
    monkeypatch.setenv("FAIG_PASSWORD", "pw")
    monkeypatch.chdir(tmp_path)  # no stray .env
    return fake


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_table_output(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    cli_env.answer(
        "GET",
        "/api/v1/admin/workspaces",
        (200, [{"workspaceName": "team-a", "id": "w1", "memberCount": 2, "spend": 0.12345678}]),
    )
    code, out, _ = run(capsys, "workspaces")
    assert code == 0
    assert out.splitlines()[0].split() == [
        "workspaceName",
        "id",
        "memberCount",
        "grantedModelCount",
        "spend",
    ]
    assert out.splitlines()[1].split() == ["team-a", "w1", "2", "-", "0.1235"]


def test_cli_json_output(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    cli_env.answer("GET", "/api/v1/me/workspaces", (200, [{"workspaceName": "a"}]))
    code, out, _ = run(capsys, "--json", "workspaces", "--mine")
    assert code == 0
    assert json.loads(out) == [{"workspaceName": "a"}]


def test_cli_whoami_and_empty(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    cli_env.answer("GET", "/api/v1/user", (200, {"email": "a@example.com"}))
    assert json.loads(run(capsys, "whoami")[1]) == {"email": "a@example.com"}
    cli_env.answer("GET", "/api/v1/admin/guardrails", (200, []))
    assert run(capsys, "guardrails")[1].strip() == "(none)"


@pytest.mark.parametrize(
    ("argv", "path"),
    [
        (["detectors", "--ws", "w1"], "/api/v1/workspaces/w1/detectors"),
        (["policies"], "/api/v1/admin/policies"),
        (["keys", "--status", "active"], "/api/v1/admin/virtual-keys"),
        (["models"], "/api/v1/admin/models"),
        (["models", "--ws", "w1"], "/api/v1/workspaces/w1"),
        (["models", "--key", "faig_x"], "/ai/openai/v1/models"),
        (["licenses"], "/api/v1/licenses"),
        (["log", "t1"], "/api/v1/admin/traffic-logs/t1"),
        (["breakdown", "cost", "key", "k1", "--days", "2"], "/api/v1/admin/cost/breakdown"),
        (["breakdown", "usage", "model", "m1"], "/api/v1/admin/usage/breakdown"),
    ],
)
def test_cli_read_commands(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], argv: list[str], path: str
) -> None:
    cli_env.answer("GET", "/api/v1/admin/workspaces", (200, [{"workspaceName": "w1", "id": "w1"}]))
    assert run(capsys, *argv)[0] == 0
    assert cli_env.calls("GET", path)


def test_cli_usage_and_cost(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    cli_env.answer(
        "GET",
        "/api/v1/admin/usage/summary",
        (200, {"window": {"from": "a", "to": "b"}, "totals": {"requests": 3, "tokens": 40}}),
    )
    cli_env.answer(
        "GET", "/api/v1/admin/usage/rankings", (200, {"items": [{"name": "k", "requests": 3}]})
    )
    code, out, _ = run(capsys, "usage", "--days", "1", "--limit", "1")
    assert code == 0
    assert "a .. b: 3 requests, 40 tokens" in out
    q = _q(cli_env.calls("GET", "/api/v1/admin/usage/rankings")[0])
    assert q["from"] == q["to"]
    cli_env.answer(
        "GET",
        "/api/v1/admin/cost/summary",
        (200, {"totals": {"chargebackSpend": {"amount": 1.5}}, "volume": {"requests": 2}}),
    )
    code, out, _ = run(capsys, "cost", "--from", "2026-01-01", "--to", "2026-01-31")
    assert "$1.5000 over 2 requests" in out
    code, out, _ = run(capsys, "--json", "cost")
    assert set(json.loads(out)) == {"summary", "rankings"}


def test_cli_logs_and_audit(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    row = {"uuid": "t1", "timeStamp": 0, "verdictLabel": "Block", "keyAlias": "bot"}
    cli_env.answer("GET", "/api/v1/admin/traffic-logs", (200, {"items": [row]}))
    argv = ["logs", "--key", "bot", "--verdict", "Block", "--user", "u", "--model", "m"]
    code, out, _ = run(capsys, *argv, "--workspace-filter", "team-a")
    assert code == 0
    assert "Block" in out
    q = _q(cli_env.calls("GET", "/api/v1/admin/traffic-logs")[0])
    assert {"virtualKeyFilters", "verdictFilters", "workspaceFilters"} <= set(q)
    cli_env.answer(
        "GET", "/api/v1/admin/audit-logs", (200, {"items": [{"timeStamp": "x", "username": "a"}]})
    )
    code, out, _ = run(capsys, "audit", "--action", "Approve")
    assert code == 0
    assert out.splitlines()[1].startswith("-")  # an unreadable time prints as "-"


def test_cli_scan(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    cli_env.answer("GET", "/api/v1/admin/guardrails/g1", (200, {"detectorIds": ["d1"]}))
    result = {"finalDisposition": "block", "results": [{"detectorId": "d1", "matched": True}]}
    cli_env.answer("POST", "/api/v1/admin/guardrails/test", (200, result))
    code, out, _ = run(capsys, "scan", "--guardrail", "g1", "secret")
    assert code == 0
    assert out.startswith("finalDisposition: block")
    assert out.splitlines()[2].split()[0] == "d1"  # no names readable: the id
    cli_env.answer("GET", "/api/v1/admin/detectors", (200, [{"uuid": "d1", "name": "My DLP"}]))
    cli_env.answer("GET", "/api/v1/admin/built-in-detectors", (200, [{"id": "x", "name": "X"}]))
    code, out, _ = run(capsys, "scan", "--guardrail", "g1", "secret")
    assert out.splitlines()[2].startswith("My DLP")
    code, out, _ = run(capsys, "--json", "scan", "--detector", "d1", "secret")
    assert json.loads(out) == result


def test_cli_chat(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    blocked = {"choices": [{"message": {"content": "no"}, "finish_reason": "content_filter"}]}
    cli_env.answer("POST", "/ai/openai/v1/chat/completions", (200, blocked))
    code, out, _ = run(capsys, "chat", "--key", "faig_x", "--model", "m", "hi")
    assert (code, out.strip()) == (0, "BLOCKED: no")
    monkeypatch.setenv("FAIG_KEY", "faig_env")
    code, out, _ = run(capsys, "--json", "chat", "--model", "m", "hi")
    assert json.loads(out) == blocked
    assert cli_env.calls("POST", "/ai/openai/v1/chat/completions")[-1].headers["authorization"] == (
        "Bearer faig_env"
    )


def test_cli_errors(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    cli_env.answer("GET", "/api/v1/admin/workspaces", (200, []))
    code, _, err = run(capsys, "detectors", "--ws", "nope")
    assert code == 1
    assert "no workspace named 'nope'" in err
    monkeypatch.delenv("FAIG_URL")
    code, _, err = run(capsys, "whoami")
    assert code == 2
    assert "set FAIG_URL" in err


def test_cli_reads_env_file_and_insecure(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FAIG_URL")
    monkeypatch.delenv("PATH_FROM_FILE", raising=False)
    env = tmp_path / "lab.env"
    env.write_text(
        f"# settings\nexport FAIG_URL='{cli_env.url}'\nFAIG_USERNAME=other\n"
        "PATH_FROM_FILE=x\nJUNK\n"
    )
    cli_env.answer("GET", "/api/v1/user", (200, {"ok": True}))
    code, _, _ = run(capsys, "--env-file", str(env), "--insecure", "whoami")
    assert code == 0
    login = cli_env.calls("POST", "/api/v1/login")[0]
    assert login.body["username"] == "admin"  # the shell wins over the file
    assert "PATH_FROM_FILE" not in os.environ  # only FAIG_* keys are read


def test_cli_ignores_a_dotenv_it_was_not_given(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FAIG_URL")
    Path(".env").write_text("FAIG_URL=https://elsewhere.example.com\n")
    code, _, err = run(capsys, "whoami")
    assert code == 2
    assert "set FAIG_URL" in err


def _home_settings(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "config" / "pyfortiaigate" / ".env"
    path.parent.mkdir(parents=True)
    path.write_text(text)
    path.chmod(mode)
    return path


def test_cli_reads_the_home_settings_file(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FAIG_URL")
    _home_settings(tmp_path, f"FAIG_URL={cli_env.url}\n")
    cli_env.answer("GET", "/api/v1/user", (200, {"ok": True}))
    code, _, err = run(capsys, "whoami")
    assert code == 0
    assert err == ""


def test_cli_warns_when_the_settings_file_is_readable_by_others(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _home_settings(tmp_path, "FAIG_KEY=faig_x\n", mode=0o644)
    cli_env.answer("GET", "/api/v1/user", (200, {"ok": True}))
    code, _, err = run(capsys, "whoami")
    assert code == 0
    assert "readable by other users" in err


def test_cli_named_file_replaces_the_home_one(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FAIG_URL")
    _home_settings(tmp_path, "FAIG_URL=https://home.example.com\n")
    named = tmp_path / "named.env"
    named.write_text(f"FAIG_URL={cli_env.url}\n")
    named.chmod(0o600)
    cli_env.answer("GET", "/api/v1/user", (200, {"ok": True}))
    monkeypatch.setenv("FAIG_ENV_FILE", str(named))
    assert run(capsys, "whoami")[0] == 0
    monkeypatch.delenv("FAIG_URL")
    monkeypatch.delenv("FAIG_ENV_FILE")
    assert run(capsys, "--env-file", str(named), "whoami")[0] == 0
    assert os.environ["FAIG_URL"] == cli_env.url


def test_cli_missing_faig_env_file(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAIG_ENV_FILE", "absent.env")
    code, _, err = run(capsys, "whoami")
    assert code == 2
    assert "no settings file absent.env" in err


def test_cli_missing_env_file(cli_env: FakeFaig, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "--env-file", "absent.env", "whoami")
    assert code == 2
    assert "no settings file absent.env" in err


def test_load_env_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_env(tmp_path / "absent.env")


def test_table_formats_values() -> None:
    rows: list[dict[str, Any]] = [{"a": {"b": 1.5}, "c": [1], "d": None}, {"a": "x"}]
    text = table(rows, ["a.b", "c", "d"])
    assert text.splitlines() == ["a.b  c    d", "1.5  [1]  -", "-    -    -"]
