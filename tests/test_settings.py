"""pyfortiaigate.settings and the ``config`` commands: one settings reader,
flag > environment > file > default, and a settings file the CLI writes."""

from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

import pytest

from pyfortiaigate.settings import load_settings, parse_env, read_env_file, write_settings

from .conftest import FakeFaig, run


def test_parse_env_follows_the_dotenv_format() -> None:
    text = "\n".join(
        [
            "# a comment",
            "",
            "FAIG_A=plain",
            "export FAIG_B='single # not a comment'",
            'FAIG_C="tab\\there \\"quoted\\""',
            "FAIG_D=value # trailing comment",
            "FAIG_E = spaced ",
            "FAIG_F=",
            "FAIG_G=a#b",
            "not a pair",
            "9BAD=x",
            "FAIG_H='unclosed",
        ]
    )
    assert parse_env(text) == {
        "FAIG_A": "plain",
        "FAIG_B": "single # not a comment",
        "FAIG_C": 'tab\there "quoted"',
        "FAIG_D": "value",
        "FAIG_E": "spaced",
        "FAIG_F": "",
        "FAIG_G": "a#b",
    }


def test_read_env_file_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="no settings file"):
        read_env_file(tmp_path / "absent.env")


def test_environment_beats_the_file_and_nothing_is_exported(tmp_path: Path) -> None:
    f = tmp_path / "s.env"
    f.write_text("FAIG_URL=https://file.example.com\nFAIG_WS=from-file\nFAIG_KEY=\nOTHER=x\n")
    env = {"FAIG_URL": "https://shell.example.com", "FAIG_ENV_FILE": str(f), "PATH": "/bin"}
    s = load_settings(environ=env)
    assert s["FAIG_URL"] == "https://shell.example.com"
    assert s.source("FAIG_URL") == "environment"
    assert s["FAIG_WS"] == "from-file"
    assert s.source("FAIG_WS") == str(f)
    assert "FAIG_KEY" not in s  # an empty value is the same as no line
    for absent in ("OTHER", "PATH", "FAIG_ENV_FILE"):
        assert absent not in s
    assert s.file == f
    flagged = s.with_flags({"FAIG_WS": "from-flag", "FAIG_KEY": None})
    assert flagged["FAIG_WS"] == "from-flag"
    assert flagged.source("FAIG_WS") == "flag"
    assert "FAIG_KEY" not in flagged


def test_an_empty_environment_variable_still_wins(tmp_path: Path) -> None:
    f = tmp_path / "s.env"
    f.write_text("FAIG_WS=team-a\n")
    s = load_settings(f, environ={"FAIG_WS": ""})
    assert s["FAIG_WS"] == ""  # --ws '' means org-wide


def test_the_default_file_is_optional(tmp_path: Path) -> None:
    s = load_settings(environ={"XDG_CONFIG_HOME": str(tmp_path)})
    assert s.file is None
    assert len(s) == 0


def test_write_settings_keeps_comments_and_is_private(tmp_path: Path) -> None:
    f = tmp_path / "dir" / ".env"
    write_settings(f, {"FAIG_URL": "https://a.example.com", "FAIG_PASSWORD": "p w#'x"})
    f.write_text("# my notes\n" + f.read_text() + "export FAIG_WS=old\n")
    write_settings(f, {"FAIG_WS": "new", "FAIG_URL": None, "FAIG_KEY": "faig_k"})
    text = f.read_text()
    assert text.startswith("# my notes\n")
    assert "FAIG_URL" not in text
    assert read_env_file(f) == {"FAIG_PASSWORD": "p w#'x", "FAIG_WS": "new", "FAIG_KEY": "faig_k"}
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700


def test_a_value_cannot_inject_another_setting(tmp_path: Path) -> None:
    f = tmp_path / ".env"
    sneaky = {"FAIG_MODEL": "m\rFAIG_URL=https://evil.example.com", "FAIG_WS": "a\nb"}
    write_settings(f, sneaky)
    assert read_env_file(f) == sneaky  # the CR and LF stay inside their values
    for sep in ("\x0b", "\x0c", "\x1c", "\x85", "\u2028"):
        with pytest.raises(ValueError, match="separator"):
            write_settings(f, {"FAIG_MODEL": f"m{sep}FAIG_URL=https://evil.example.com"})
    assert "FAIG_URL" not in read_env_file(f)


def test_cli_reads_env_file_in_either_spelling(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FAIG_URL")
    f = tmp_path / "named.env"
    f.write_text(f"FAIG_URL={cli_env.url}\n")
    f.chmod(0o600)
    cli_env.answer("GET", "/api/v1/user", (200, {"email": "me@example.com"}))
    assert run(capsys, f"--env-file={f}", "whoami")[0] == 0
    assert run(capsys, "--env-file", str(f), "whoami")[0] == 0
    assert "FAIG_URL" not in os.environ  # the CLI never exports what it read


def test_url_flag_beats_the_environment(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAIG_URL", "https://wrong.example.com")
    cli_env.answer("GET", "/api/v1/user", (200, {"email": "me@example.com"}))
    assert run(capsys, "--url", cli_env.url, "whoami")[0] == 0


def test_config_list_names_the_source_and_masks_secrets(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "config" / "pyfortiaigate" / ".env"
    write_settings(path, {"FAIG_WS": "team-a", "FAIG_KEY": "faig_0123456789abcd"})
    code, out, _ = run(capsys, "--json", "config")
    assert code == 0
    data = json.loads(out)
    rows = {r["setting"]: r for r in data["settings"]}
    assert data["file"] == str(path)
    assert rows["FAIG_WS"] == {"setting": "FAIG_WS", "value": "team-a", "from": "settings file"}
    assert rows["FAIG_KEY"]["value"] == "****abcd"
    assert rows["FAIG_PASSWORD"]["value"] == "********"  # no characters of a password
    assert rows["FAIG_URL"]["from"] == "environment"
    assert "FAIG_TOKEN" not in rows
    _, out, _ = run(capsys, "--json", "config", "list", "--all")
    assert "FAIG_TOKEN" in {r["setting"] for r in json.loads(out)["settings"]}
    assert not cli_env.calls()  # config never logs in


def _init(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, url: str, *extra: str
) -> tuple[int, str, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO("s3cret pw\n"))
    return run(
        capsys,
        "config",
        "init",
        "--url",
        url,
        "--username",
        "me@example.com",
        "--password-stdin",
        "--ws",
        "team-a",
        "--key",
        "faig_0123456789abcd",
        "--insecure",
        *extra,
    )


def test_config_init_checks_then_saves(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for var in ("FAIG_URL", "FAIG_USERNAME", "FAIG_PASSWORD"):
        monkeypatch.delenv(var)
    cli_env.answer("GET", "/api/v1/user", (200, {"email": "me@example.com"}))
    cli_env.answer("GET", "/api/v1/me/workspaces", (200, [{"workspaceName": "team-a"}]))
    cli_env.answer("GET", "/ai/openai/v1/models", (200, {"data": [{"id": "m1"}]}))
    code, out, err = _init(capsys, monkeypatch, cli_env.url + "/ui/")
    assert code == 0, err
    assert "Saved to" in out
    path = tmp_path / "config" / "pyfortiaigate" / ".env"
    assert read_env_file(path) == {
        "FAIG_URL": cli_env.url,
        "FAIG_USERNAME": "me@example.com",
        "FAIG_PASSWORD": "s3cret pw",
        "FAIG_WS": "team-a",
        "FAIG_KEY": "faig_0123456789abcd",
        "FAIG_VERIFY_TLS": "false",
        "FAIG_MODEL": "m1",  # saved so chat never spends a request on the lookup
    }
    assert cli_env.calls("POST", "/api/v1/login")[0].body["password"] == "s3cret pw"


def test_config_init_never_saves_a_refused_login(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cli_env.answer("POST", "/api/v1/login", (401, {"detail": "Invalid credentials"}))
    cli_env.answer("POST", "/api/login", (401, {"detail": "Invalid credentials"}))
    code, _, err = _init(capsys, monkeypatch, cli_env.url)
    assert code == 1
    assert err.startswith("faig:")
    assert not (tmp_path / "config" / "pyfortiaigate" / ".env").exists()


def test_config_init_no_verify_saves_without_logging_in(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    code, _, _ = _init(capsys, monkeypatch, cli_env.url, "--no-verify")
    assert code == 0
    assert not cli_env.calls()
    assert (tmp_path / "config" / "pyfortiaigate" / ".env").is_file()


def test_config_set_unset_and_path(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "config" / "pyfortiaigate" / ".env"
    assert run(capsys, "config", "set", "faig_ws", "team-b")[0] == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("piped-secret\n"))
    assert run(capsys, "config", "set", "FAIG_PASSWORD")[0] == 0
    assert read_env_file(path) == {"FAIG_WS": "team-b", "FAIG_PASSWORD": "piped-secret"}
    assert run(capsys, "config", "unset", "FAIG_WS")[0] == 0
    assert read_env_file(path) == {"FAIG_PASSWORD": "piped-secret"}
    code, _, err = run(capsys, "config", "set", "PATH", "/tmp")
    assert code == 1
    assert "FAIG_*" in err
    assert run(capsys, "config", "path")[1].strip() == str(path)


def test_chat_defaults_to_the_keys_model(
    cli_env: FakeFaig, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAIG_KEY", "faig_k")
    cli_env.answer("GET", "/ai/openai/v1/models", (200, {"data": [{"id": "llama3.2-1b"}]}))
    answer = {"choices": [{"message": {"content": "hi"}}]}
    cli_env.answer("POST", "/ai/openai/v1/chat/completions", (200, answer))
    code, out, _ = run(capsys, "--plain", "chat", "hello")
    assert code == 0
    assert "hi" in out
    assert cli_env.calls("POST", "/ai/openai/v1/chat/completions")[0].body["model"] == "llama3.2-1b"


def test_config_init_creates_the_file_it_is_named(
    cli_env: FakeFaig,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    new = tmp_path / "new.env"
    code, _, err = _init(capsys, monkeypatch, cli_env.url, "--no-verify")
    assert code == 0, err
    monkeypatch.setattr("sys.stdin", io.StringIO("pw\n"))
    code, _, err = run(
        capsys,
        "--env-file",
        str(new),
        "config",
        "init",
        "--url",
        cli_env.url,
        "--username",
        "u",
        "--password-stdin",
        "--no-verify",
    )
    assert code == 0, err
    assert read_env_file(new)["FAIG_USERNAME"] == "u"
    code, _, err = run(capsys, "--env-file", str(tmp_path / "absent.env"), "whoami")
    assert code == 2  # any other command still needs the file to exist
    assert "no settings file" in err
