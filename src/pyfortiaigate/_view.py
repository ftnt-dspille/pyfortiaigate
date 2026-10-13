"""What the command line prints: tables, label/value fields, bar charts and
panels, drawn with `rich <https://rich.readthedocs.io>`_ when it is installed
(``pip install "pyfortiaigate[cli]"``) and stdout is a terminal, as plain
aligned text otherwise. Pipes, ``grep`` and logs always get the plain form.

``FAIG_CLI_STYLE=rich|plain|auto`` (or ``--plain``) overrides the choice.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import IO, Any, TypeAlias

try:
    import rich  # noqa: F401

    HAVE_RICH = True
except ImportError:  # pragma: no cover - the [cli] extra is not installed
    HAVE_RICH = False

# Semantic styles; the plain renderer ignores them.
STYLES = {
    "bad": "bold red",
    "good": "green",
    "warn": "yellow",
    "dim": "dim",
    "id": "dim cyan",
    "num": "cyan",
    "accent": "bold magenta",
    "title": "bold",
    "hit": "bold red underline",
}

Style: TypeAlias = str | None
Getter: TypeAlias = str | Callable[[Mapping[str, Any]], Any]


# -- values --------------------------------------------------------------------------
# C0 and C1 control characters except tab and newline: a prompt in the traffic log
# is attacker-controlled text and must not reach the terminal as escape sequences.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """``text`` with control characters shown as ``\\x1b`` instead of sent to the
    terminal."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def dig(row: Mapping[str, Any], path: str) -> Any:
    """``row["a"]["b"]`` for ``"a.b"``; None when any step is missing."""
    value: Any = row
    for part in path.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def cell(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def money(value: Any, places: int = 4) -> str:
    if not isinstance(value, (int, float)):
        return "-"
    return f"${value:,.{places}f}"


def _parse_time(value: Any) -> dt.datetime | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return dt.datetime.fromtimestamp(value / 1000)
    if isinstance(value, str) and value:
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone().replace(tzinfo=None) if parsed.tzinfo else parsed
    return None


def when(value: Any) -> str:
    """Epoch milliseconds or an ISO string as local ``YYYY-MM-DD HH:MM:SS``."""
    parsed = _parse_time(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else "-"


def ago(value: Any, now: dt.datetime | None = None) -> str:
    """``5m ago``, ``3h ago``, ``2d ago``; ``-`` for nothing."""
    parsed = _parse_time(value)
    if parsed is None:
        return "-"
    seconds = int(((now or dt.datetime.now()) - parsed).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return "just now"


def verdict_style(value: Any) -> Style:
    v = str(value or "").lower()
    if v in ("block", "blocked", "deny", "denied"):
        return "bad"
    if v in ("redact", "redacted", "alert", "warn", "pending", "pending_approval"):
        return "warn"
    if v in ("log", "allow", "allowed", "pass", "passed"):
        return "good"
    return None


def status_style(value: Any) -> Style:
    v = str(value or "").lower()
    if v in ("active", "healthy", "valid", "approved", "enabled"):
        return "good"
    if v in ("pending", "pending_approval", "draft", "degraded", "unknown"):
        return "warn"
    if v in ("rejected", "revoked", "inactive", "expired", "disabled", "unhealthy", "down"):
        return "bad"
    return None


# -- blocks ----------------------------------------------------------------------------
@dataclass
class Col:
    """A table column: ``get`` is a dotted path or a function of the row."""

    header: str
    get: Getter
    fmt: Callable[[Any], str] = cell
    style: Style | Callable[[Any], Style] = None
    right: bool = False
    wrap: bool = True
    """False for ids and other values that must stay on one line."""

    def value(self, row: Mapping[str, Any]) -> Any:
        return self.get(row) if callable(self.get) else dig(row, self.get)

    def text(self, row: Mapping[str, Any], sep: str = ", ") -> tuple[str, Style]:
        """The cell; a list value (a :class:`Many`) is joined with ``sep``."""
        v = self.value(row)
        style = self.style(v) if callable(self.style) else self.style
        if isinstance(v, Many):
            return sep.join(v) or "-", style
        return self.fmt(v), style


class Many(list):  # type: ignore[type-arg]
    """A cell holding several values: comma-separated in plain text, one per
    line in a terminal."""


@dataclass
class Table:
    rows: Sequence[Mapping[str, Any]]
    cols: Sequence[Col]
    title: str | None = None
    empty: str = "(none)"


@dataclass
class Fields:
    """Label/value lines: ``(label, value, style)``."""

    items: Sequence[tuple[str, str, Style]]
    title: str | None = None


@dataclass
class Bars:
    """A horizontal bar chart: ``(label, value, value_text)``."""

    items: Sequence[tuple[str, float, str]]
    title: str | None = None
    style: str = "num"
    empty: str = "(nothing yet)"
    width: int = 24
    """Bar length in a terminal (30 in plain text)."""


@dataclass
class Line:
    """One line of text in styled pieces: ``Line(("Verdict: ", None), ("BLOCK", "bad"))``."""

    parts: Sequence[tuple[str, Style]]

    @classmethod
    def of(cls, text: str, style: Style = None) -> Line:
        return cls([(text, style)])

    @property
    def plain(self) -> str:
        return "".join(t for t, _ in self.parts)


@dataclass
class Lines:
    """Lines printed together, with no blank line between them."""

    lines: Sequence[Line]


@dataclass
class Panel:
    title: str
    blocks: Sequence[Block]
    style: str = "dim"


@dataclass
class Row:
    """Panels side by side (one under the other in plain text)."""

    panels: Sequence[Panel]


Block: TypeAlias = Table | Fields | Bars | Line | Lines | Panel | Row


@dataclass
class Page:
    """What a command shows (``blocks``) and what ``--json`` prints (``data``)."""

    data: Any
    blocks: list[Block] = field(default_factory=list)


def highlight(text: str, spans: Iterable[Mapping[str, Any]]) -> Line:
    """``text`` with the ``{"start", "end"}`` ranges marked: bold red in a terminal,
    ``[bracketed]`` in plain text."""
    parts: list[tuple[str, Style]] = []
    at = 0
    for span in sorted(spans, key=lambda s: int(s.get("start", 0))):
        start, end = int(span.get("start", 0)), int(span.get("end", 0))
        if start < at or end <= start:
            continue
        parts += [(text[at:start], None), (text[start:end], "hit")]
        at = end
    parts.append((text[at:], None))
    return Line([p for p in parts if p[0]])


SPARKS = "▁▂▃▄▅▆▇█"


def spark(values: Sequence[float]) -> str:
    """``▁▃█▅`` for a run of numbers (a flat run is all ``▁``)."""
    top = max(values, default=0)
    if top <= 0:
        return SPARKS[0] * len(values)
    return "".join(SPARKS[min(7, int(v / top * 7.999))] for v in values)


# -- choosing a renderer -----------------------------------------------------------------
def use_rich(stream: IO[str] | None = None, plain: bool = False) -> bool:
    mode = os.environ.get("FAIG_CLI_STYLE", "auto").lower()
    if plain or mode == "plain" or not HAVE_RICH:
        return False
    if mode == "rich":
        return True
    out = stream or sys.stdout
    return bool(getattr(out, "isatty", lambda: False)()) and os.environ.get("TERM") != "dumb"


def render(blocks: Sequence[Block], stream: IO[str] | None = None, plain: bool = False) -> None:
    out = stream or sys.stdout
    if use_rich(out, plain):
        _render_rich(blocks, out)
    else:
        out.write(safe(plain_text(blocks)) + "\n")


# -- plain text -------------------------------------------------------------------------
def _utf8(stream: IO[str] | None = None) -> bool:
    enc = getattr(stream or sys.stdout, "encoding", None) or "utf-8"
    return enc.lower().replace("-", "") in ("utf8", "utf8sig")


def aligned(headers: Sequence[str], rows: Sequence[Sequence[str]], right: Sequence[bool]) -> str:
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]

    def line(values: Sequence[str]) -> str:
        cells = (
            v.rjust(w) if r else v.ljust(w) for v, w, r in zip(values, widths, right, strict=True)
        )
        return "  ".join(cells).rstrip()

    return "\n".join([line(headers)] + [line(r) for r in rows])


def _bar(value: float, top: float, width: int, full: str) -> str:
    n = round(value / top * width) if top > 0 else 0
    return full * max(n, 1 if value > 0 else 0)


def _plain(block: Block) -> list[str]:
    full = "█" if _utf8() else "#"
    if isinstance(block, Table):
        head = [block.title] if block.title else []
        if not block.rows:
            return [*head, block.empty]
        rows = [[c.text(r)[0] for c in block.cols] for r in block.rows]
        table = aligned([c.header for c in block.cols], rows, [c.right for c in block.cols])
        return [*head, table]
    if isinstance(block, Fields):
        width = max((len(label) for label, _, _ in block.items), default=0)
        lines = [f"{label.ljust(width)}  {value}".rstrip() for label, value, _ in block.items]
        return ([block.title] if block.title else []) + lines
    if isinstance(block, Bars):
        head = [block.title] if block.title else []
        if not block.items:
            return [*head, block.empty]
        width = max(len(label) for label, _, _ in block.items)
        top = max(v for _, v, _ in block.items)
        bars = [
            f"{label.ljust(width)}  {_bar(v, top, 30, full).ljust(30)}  {text}".rstrip()
            for label, v, text in block.items
        ]
        return head + bars
    if isinstance(block, Line):
        return [block.plain]
    if isinstance(block, Lines):
        return [line.plain for line in block.lines]
    if isinstance(block, Panel):
        inner = "\n\n".join("\n".join(_plain(b)) for b in block.blocks)
        return [f"== {block.title} ==", inner]
    stacked: list[str] = []  # Row
    for panel in block.panels:
        if stacked:
            stacked.append("")
        stacked += _plain(panel)
    return stacked


def plain_text(blocks: Sequence[Block]) -> str:
    return "\n\n".join("\n".join(_plain(b)) for b in blocks)


# -- rich -----------------------------------------------------------------------------------
def _render_rich(blocks: Sequence[Block], out: IO[str]) -> None:
    from rich.console import Console

    forced = os.environ.get("FAIG_CLI_STYLE", "").lower() == "rich"
    console = Console(
        file=out,
        highlight=False,
        force_terminal=True if forced else None,
        width=int(os.environ.get("COLUMNS", "120")) if forced else None,
    )
    for i, block in enumerate(blocks):
        if i:
            console.print()
        console.print(_rich(block))


def _rich(block: Block) -> Any:
    from rich import box
    from rich.console import Group
    from rich.panel import Panel as RPanel
    from rich.table import Table as RTable
    from rich.text import Text

    def styled(text: str, style: Style) -> Text:
        """Data as plain text: never parsed as rich markup, control characters escaped."""
        return Text(safe(text), style=STYLES.get(style or "", style or ""))

    if isinstance(block, Table):
        if not block.rows:
            return Group(
                *([styled(block.title, "title")] if block.title else []), styled(block.empty, "dim")
            )
        t = RTable(
            box=box.SIMPLE_HEAD,
            header_style="bold",
            title=styled(block.title, "title") if block.title else None,
            title_justify="left",
            pad_edge=False,
            # a blank line between rows when a cell spans several lines
            leading=1
            if any(isinstance(c.value(r), Many) for r in block.rows for c in block.cols)
            else 0,
        )
        for c in block.cols:
            t.add_column(
                styled(c.header, None),
                justify="right" if c.right else "left",
                no_wrap=not c.wrap,
                overflow="fold" if c.wrap else "ellipsis",
            )
        for r in block.rows:
            t.add_row(*(styled(*c.text(r, sep="\n")) for c in block.cols))
        return t
    if isinstance(block, Fields):
        grid = RTable.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column()
        for label, value, style in block.items:
            grid.add_row(styled(label, None), styled(value, style))
        if block.title:
            return Group(styled(block.title, "title"), grid)
        return grid
    if isinstance(block, Bars):
        head = [styled(block.title, "title")] if block.title else []
        if not block.items:
            return Group(*head, styled(block.empty, "dim"))
        grid = RTable.grid(padding=(0, 1))
        grid.add_column(no_wrap=True, overflow="ellipsis", max_width=32)
        grid.add_column(no_wrap=True, min_width=block.width)
        grid.add_column(justify="right", no_wrap=True)
        top = max(v for _, v, _ in block.items)
        for label, v, text in block.items:
            filled = _bar(v, top, block.width, "█")
            bar = Text(filled, style=STYLES.get(block.style, block.style))
            bar.append("·" * (block.width - len(filled)), style="dim")
            grid.add_row(styled(label, None), bar, styled(text, "title"))
        return Group(*head, grid)
    if isinstance(block, Line):
        line = Text()
        for text, style in block.parts:
            line.append(safe(text), style=STYLES.get(style or "", style or ""))
        return line
    if isinstance(block, Lines):
        return Group(*(_rich(line) for line in block.lines))
    if isinstance(block, Panel):
        body: list[Any] = []
        for i, b in enumerate(block.blocks):
            if i:
                body.append(Text(""))
            body.append(_rich(b))
        return RPanel(
            Group(*body),
            title=styled(block.title, "title"),
            title_align="left",
            border_style=STYLES.get(block.style, block.style),
            box=box.ROUNDED,
            padding=(0, 1),
        )
    grid = RTable.grid(expand=True, padding=(0, 1))  # Row
    for _ in block.panels:
        grid.add_column(ratio=1)
    grid.add_row(*(_rich(p) for p in block.panels))
    return grid
