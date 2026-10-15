"""Settings for the command line and for scripts: ``FAIG_*`` variables and a
settings file, resolved the way most command-line tools resolve them.

Precedence, highest first:

1. a command-line flag (``--url``, ``--ws``, ``--key``, ``--insecure``);
2. a ``FAIG_*`` environment variable, even an empty one;
3. the settings file;
4. the built-in default.

The settings file is the one ``--env-file`` names, else ``FAIG_ENV_FILE``, else
``$XDG_CONFIG_HOME/pyfortiaigate/.env`` (``~/.config/pyfortiaigate/.env``) when it
exists. A ``.env`` in the current directory is never read, so a stray one cannot
point your credentials at another server.

The file uses the python-dotenv format: ``NAME=value`` lines, an optional
``export`` in front, ``#`` comments (also at the end of an unquoted value), single
quotes for a literal value and double quotes for one with ``\\n``, ``\\t``, ``\\"``
or ``\\\\`` escapes. A value is one line, and ``${VAR}`` is not expanded. An empty
value (``FAIG_WS=``) is the same as leaving the line out. Only ``FAIG_*`` names
are used; any other line is ignored.

Reading settings never changes ``os.environ``::

    from pyfortiaigate import FortiAIGate
    from pyfortiaigate.settings import load_settings

    with FortiAIGate.from_env(load_settings()) as faig:
        ...
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "KNOWN",
    "Setting",
    "Settings",
    "default_settings_file",
    "load_settings",
    "parse_env",
    "read_env_file",
    "settings_file",
    "write_settings",
]

PREFIX = "FAIG_"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


@dataclass(frozen=True)
class Setting:
    """One documented setting: its name, what it is for, whether it is a secret."""

    name: str
    help: str
    secret: bool = False


KNOWN: tuple[Setting, ...] = (
    Setting("FAIG_URL", "FortiAIGate address (anything after the host is ignored)"),
    Setting("FAIG_USERNAME", "console login"),
    Setting("FAIG_PASSWORD", "console password", secret=True),
    Setting("FAIG_TOKEN", "bearer token, instead of a username and password", secret=True),
    Setting("FAIG_WS", "default --ws: your workspace name or id"),
    Setting("FAIG_KEY", "default --key: a virtual key secret (faig_...)", secret=True),
    Setting("FAIG_MODEL", "default --model for chat"),
    Setting("FAIG_CA_BUNDLE", "CA file to trust for a private certificate"),
    Setting("FAIG_VERIFY_TLS", "false skips TLS verification (lab use only)"),
)
_SECRET = {s.name for s in KNOWN if s.secret}


def parse_env(text: str) -> dict[str, str]:
    """``NAME=value`` pairs from settings-file text (python-dotenv format, one
    line per value). Lines that are not a pair are skipped."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[7:].lstrip()
        name, sep, rest = line.partition("=")
        name = name.strip()
        if not sep or not _NAME.fullmatch(name):
            continue
        value = _value(rest.lstrip())
        if value is not None:
            out[name] = value
    return out


def _value(rest: str) -> str | None:
    if rest[:1] == "'":
        end = rest.find("'", 1)
        return rest[1:end] if end > 0 else None
    if rest[:1] == '"':
        chars: list[str] = []
        i = 1
        while i < len(rest):
            ch = rest[i]
            if ch == "\\" and i + 1 < len(rest):
                nxt = rest[i + 1]
                chars.append(_ESCAPES.get(nxt, "\\" + nxt))
                i += 2
                continue
            if ch == '"':
                return "".join(chars)
            chars.append(ch)
            i += 1
        return None  # no closing quote
    # Unquoted: a " #" starts a comment.
    cut = re.search(r"\s#", rest)
    return (rest[: cut.start()] if cut else rest).strip()


def read_env_file(path: str | os.PathLike[str]) -> dict[str, str]:
    """Every pair in a settings file. Raises FileNotFoundError when it is missing."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"no settings file {path}")
    return parse_env(p.read_text())


def default_settings_file(environ: Mapping[str, str] | None = None) -> Path:
    """``FAIG_ENV_FILE``, else ``$XDG_CONFIG_HOME/pyfortiaigate/.env``
    (``~/.config/pyfortiaigate/.env``). The file need not exist."""
    env = os.environ if environ is None else environ
    if env.get("FAIG_ENV_FILE"):
        return Path(env["FAIG_ENV_FILE"]).expanduser()
    base = env.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "pyfortiaigate" / ".env"


def settings_file(
    env_file: str | os.PathLike[str] | None = None, environ: Mapping[str, str] | None = None
) -> Path | None:
    """The file to read: a named one (``env_file``, ``FAIG_ENV_FILE``) even when it
    is missing, so reading it reports the mistake; the default one only when it
    exists; else None."""
    env = os.environ if environ is None else environ
    if env_file:
        return Path(env_file).expanduser()
    path = default_settings_file(env)
    return path if env.get("FAIG_ENV_FILE") or path.is_file() else None


class Settings(Mapping[str, str]):
    """Resolved ``FAIG_*`` settings, and where each one came from: ``flag``,
    ``environment``, or the settings file's path. A read-only mapping, so it can be
    passed straight to ``FortiAIGate.from_env``."""

    def __init__(self, values: Mapping[str, str], sources: Mapping[str, str], file: Path | None):
        self._values = dict(values)
        self._sources = dict(sources)
        self.file = file
        """The settings file that was read, or None."""

    def __getitem__(self, name: str) -> str:
        return self._values[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def source(self, name: str) -> str | None:
        """``flag``, ``environment``, the settings file's path, or None (unset)."""
        return self._sources.get(name)

    def with_flags(self, flags: Mapping[str, str | None]) -> Settings:
        """A copy with command-line values on top (None means the flag was not given)."""
        values, sources = dict(self._values), dict(self._sources)
        for name, value in flags.items():
            if value is not None:
                values[name], sources[name] = value, "flag"
        return Settings(values, sources, self.file)

    def masked(self, name: str) -> str:
        """The value for display: a password shows nothing, a key or token only
        its last four characters, so you can tell two apart."""
        value = self._values.get(name, "")
        if name not in _SECRET or not value:
            return value
        if name == "FAIG_PASSWORD" or len(value) <= 12:
            return "********"
        return "****" + value[-4:]


def load_settings(
    env_file: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    *,
    missing_ok: bool = False,
) -> Settings:
    """``FAIG_*`` settings from the environment, filled in from the settings file
    (see the module docstring for which file and the order). A named file that is
    missing raises FileNotFoundError, unless ``missing_ok`` (for a command that is
    about to create it)."""
    env = os.environ if environ is None else environ
    path = settings_file(env_file, env)
    values: dict[str, str] = {}
    sources: dict[str, str] = {}
    if path is not None and (path.is_file() or not missing_ok):
        for name, value in read_env_file(path).items():
            if name.startswith(PREFIX) and value:
                values[name], sources[name] = value, str(path)
    for name, value in env.items():
        if name.startswith(PREFIX) and name != "FAIG_ENV_FILE":
            values[name], sources[name] = value, "environment"
    return Settings(values, sources, path)


def write_settings(path: str | os.PathLike[str], updates: Mapping[str, str | None]) -> Path:
    """Set (or, for None, remove) ``NAME=value`` lines in a settings file, keeping
    every other line and comment. Creates the file and its folder as needed; the
    file is written atomically and readable only by you (mode 600)."""
    p = Path(path).expanduser()
    lines = p.read_text().splitlines() if p.is_file() else []
    pending = dict(updates)
    out: list[str] = []
    for line in lines:
        bare = line.strip()
        if bare.startswith("export "):
            bare = bare[7:].lstrip()
        name = bare.partition("=")[0].strip() if "=" in bare and not bare.startswith("#") else ""
        if name in pending:
            value = pending.pop(name)
            if value is not None:
                out.append(f"{name}={_quote(value)}")
            continue
        out.append(line)
    out.extend(f"{n}={_quote(v)}" for n, v in pending.items() if v is not None)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".settings-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p


def _quote(value: str) -> str:
    """A value as the file must spell it so ``parse_env`` reads it back unchanged.

    ``parse_env`` splits on every separator ``str.splitlines`` knows, so a raw one
    in a value would start a new ``NAME=`` line (a model id from the server must
    never be able to set FAIG_URL). CR and LF are escaped; the rest are refused."""
    if value and re.fullmatch(r"[A-Za-z0-9_@%+=:,./~-]+", value):
        return value
    odd = set(value) - {"\r", "\n"}
    if any(len(f"a{ch}a".splitlines()) > 1 for ch in odd):
        raise ValueError("a setting cannot contain a line or page separator")
    if "'" not in value and "\n" not in value and "\r" not in value:
        return f"'{value}'"
    escaped = (
        value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    )
    return f'"{escaped}"'
