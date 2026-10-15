"""``pyfortiaigate`` on the command line: quick looks at a FortiAIGate without
writing a script. Read-only apart from ``chat`` (one gateway request).

Settings resolve flag > ``FAIG_*`` environment variable > settings file >
default (see ``pyfortiaigate.settings``). ``config init`` writes the settings
file for you, and ``config`` shows each value and where it came from.
``FAIG_WS`` is the default ``--ws`` and ``FAIG_KEY`` the default ``--key``.

With the ``[cli]`` extra (``pip install "pyfortiaigate[cli]"``) a terminal gets
coloured tables, panels and bar charts; pipes always get plain text.

    pyfortiaigate dashboard --ws team-a
    pyfortiaigate guardrails --ws team-a
    pyfortiaigate logs --ws team-a --verdict Block --follow
    pyfortiaigate trend cost --ws team-a --days 14
    pyfortiaigate scan --ws team-a --guardrail pii "my SSN is 123-45-6789"
    pyfortiaigate try-regex --ws team-a '(?i)\\bPA-\\d{3,4}\\b' "order a PA-5450"
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from . import _view as v
from ._view import Bars, Col, Fields, Line, Lines, Many, Page, Panel, Row, Table
from .client import (
    FaigError,
    FortiAIGate,
    blocked,
    breakdown_items,
    items,
    origin,
    rank_items,
    regex_detector_body,
)
from .settings import (
    KNOWN,
    Settings,
    default_settings_file,
    load_settings,
    write_settings,
)

PROG = (
    os.path.basename(sys.argv[0])
    if os.path.basename(sys.argv[0]) in ("faig", "pyfortiaigate")
    else "faig"
)
"""The command's name in messages: what you typed, else ``faig``."""

CATALOG = Path(__file__).with_name("data") / "scenarios.json"
"""The workshop's scenario catalog, shipped with the package: the default for ``scenarios``."""

# How `faig --help` lists the commands: by task, in the order a newcomer needs them.
GROUPS = (
    ("Get started", ("config", "whoami", "check-key", "models")),
    ("Send prompts through the gateway", ("chat", "scenarios")),
    ("Test detectors without a model", ("scan", "try-regex")),
    (
        "Your setup",
        ("guardrails", "detectors", "builtins", "policies", "keys", "workspaces", "members"),
    ),
    (
        "Traffic, blocks and spend",
        ("dashboard", "logs", "log", "usage", "cost", "trend", "breakdown", "audit"),
    ),
    ("Appliance", ("licenses",)),
)


def _version() -> str:
    from . import __version__

    return __version__


def _tilde(path: Path | str) -> str:
    """A path for display: ``~/...`` under your home folder."""
    text, home = str(path), str(Path.home())
    return "~" + text[len(home) :] if text == home or text.startswith(home + os.sep) else text


def table(rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> str:
    """Rows as aligned text columns (a column may be a dotted path)."""
    cells = [[v.cell(v.dig(r, c)) for c in columns] for r in rows]
    return v.aligned(columns, cells, [False] * len(columns))


def _window(args: argparse.Namespace) -> tuple[str | None, str | None]:
    if getattr(args, "days", None):
        today = dt.date.today()
        return (today - dt.timedelta(days=args.days - 1)).isoformat(), today.isoformat()
    return getattr(args, "frm", None), getattr(args, "to", None)


def _ws(args: argparse.Namespace) -> str | None:
    """``--ws`` (default FAIG_WS); an empty value means org-wide."""
    return getattr(args, "ws", None) or None


def _need_ws(args: argparse.Namespace, command: str) -> str:
    ws = _ws(args)
    if not ws:
        raise ValueError(f"{command} needs --ws (or FAIG_WS)")
    return ws


def _count(n: int, plural: str) -> str:
    """``1 policy``, ``2 policies``, ``1 key``."""
    if n == 1:
        plural = plural[:-3] + "y" if plural.endswith("ies") else plural.removesuffix("s")
    return f"{n} {plural}"


def _short(value: Any, n: int = 8) -> str:
    s = str(value or "")
    return s if len(s) <= n + 1 else s[:n] + "…"


def _clip(text: Any, n: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _share(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "-"
    full = "█" if v._utf8() else "#"
    filled = round(value * 10)
    return f"{full * filled}{'·' * (10 - filled)} {value * 100:>3.0f}%"


def _ranked_name(row: Mapping[str, Any]) -> str:
    name = str(row.get("name") or row.get("id") or "-")
    if row.get("deleted"):
        return f"{_short(name)} (deleted)"
    return name


def _detector_names(c: FortiAIGate, ws: str | None) -> dict[Any, Any]:
    """Detector id -> name, custom and built-in; empty when they can't be read."""
    try:
        names = {d.get("uuid"): d.get("name") for d in c.detectors(ws)}
        names |= {d.get("id"): d.get("name") for d in c.builtin_detectors(ws)}
    except FaigError:
        return {}
    return names


def _hits(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every detector match in a traffic log record, with its side."""
    out: list[dict[str, Any]] = []
    for side, hits in (record.get("violation") or {}).items():
        for hit in hits or []:
            if isinstance(hit, Mapping):
                out.append({"side": side, **hit})
    return out


# -- identity and configuration -----------------------------------------------------------
def cmd_whoami(c: FortiAIGate, args: argparse.Namespace) -> Page:
    me = c.me()
    try:
        names = {w.get("id"): w.get("workspaceName") for w in c.my_workspaces()}
    except FaigError:
        names = {}
    spaces = [
        f"{names.get(m.get('workspaceId')) or _short(m.get('workspaceId'))} ({m.get('role')})"
        for m in me.get("memberships") or []
    ]
    fields = [
        ("Name", str(me.get("fullName") or "-"), "title"),
        ("Email", str(me.get("email") or me.get("username") or "-"), None),
        ("Org role", str(me.get("role") or "-"), "accent"),
        ("Workspaces", ", ".join(spaces) or "-", None),
        ("Sign-in", str(me.get("authType") or "-"), "dim"),
        ("User id", str(me.get("id") or "-"), "id"),
    ]
    return Page(me, [Panel("You", [Fields(fields)])])


def cmd_workspaces(c: FortiAIGate, args: argparse.Namespace) -> Page:
    if args.mine:
        rows: list[Any] = list(c.my_workspaces())
        cols = [
            Col("Workspace", "workspaceName", style="title"),
            Col("Your role", "membershipRole", style="accent"),
            Col("Your keys", "myKeyCount", right=True),
            Col("Your budget", "myBudget", fmt=v.money, right=True),
            Col("ID", "id", style="id", wrap=False),
        ]
    else:
        rows = list(c.workspaces())
        cols = [
            Col("Workspace", "workspaceName", style="title"),
            Col("Members", "memberCount", right=True),
            Col("Models", "grantedModelCount", right=True),
            Col("Spend", "spend", fmt=v.money, right=True),
            Col("ID", "id", style="id", wrap=False),
        ]
    return Page(rows, [Table(rows, cols)])


def cmd_members(c: FortiAIGate, args: argparse.Namespace) -> Page:
    ws = _need_ws(args, "members")
    data = c.workspace_members(ws)
    rows = items(data)
    cols = [
        Col("Name", "name", style="title"),
        Col("Email", "email"),
        Col("Role", "role", style="accent"),
        Col("Keys", "keyCount", right=True),
        Col("Spend", "currentSpend", fmt=v.money, right=True),
        Col("Last active", "lastActiveAt", fmt=v.ago, style="dim"),
    ]
    return Page(data, [Table(rows, cols, title=f"Members of {ws}")])


def cmd_detectors(c: FortiAIGate, args: argparse.Namespace) -> Page:
    rows = c.detectors(_ws(args))
    cols = [
        Col("Detector", "name", style="title"),
        Col("Type", "detectorType"),
        Col("Status", "approvalStatus", style=v.status_style),
        Col("Pending", "hasPendingChange", fmt=lambda x: "yes" if x else "", style="warn"),
        Col("ID", "uuid", style="id", wrap=False),
    ]
    return Page(rows, [Table(rows, cols)])


def cmd_builtins(c: FortiAIGate, args: argparse.Namespace) -> Page:
    rows = sorted(c.builtin_detectors(_ws(args)), key=lambda d: (d.get("group") or "", d["name"]))
    cols = [
        Col("Built-in detector", "name", style="title"),
        Col("ID", "id", style="id", wrap=False),
        Col("Group", "group"),
        Col("Category", "category", style="dim"),
        Col("Action", "action", style=v.verdict_style),
        Col("Rules", lambda d: len(d.get("rules") or []), right=True),
    ]
    note = Line.of("Use the ID with  scan --detector <id>  or in a guardrail.", "dim")
    return Page(rows, [Table(rows, cols), note])


def cmd_guardrails(c: FortiAIGate, args: argparse.Namespace) -> Page:
    ws = _ws(args)
    rows = c.guardrails(ws)
    names = _detector_names(c, ws) if rows else {}

    def detectors(g: Mapping[str, Any]) -> Many:
        return Many(str(names.get(i) or _short(i)) for i in g.get("detectorIds") or [])

    cols = [
        Col("Guardrail", "name", style="title"),
        Col("Status", "status", style=v.status_style),
        Col("Detectors", detectors),
        Col("ID", "id", style="id", wrap=False),
    ]
    return Page(rows, [Table(rows, cols)])


def cmd_policies(c: FortiAIGate, args: argparse.Namespace) -> Page:
    rows = c.policies(_ws(args))
    cols = [
        Col("Policy", "name", style="title"),
        Col("Status", "status", style=v.status_style),
        Col("Input", lambda p: len(p.get("inputGuardrailIds") or []), right=True),
        Col("Output", lambda p: len(p.get("outputGuardrailIds") or []), right=True),
        Col("Response scan", "responseScanMode"),
        Col("ID", "id", style="id", wrap=False),
    ]
    return Page(rows, [Table(rows, cols)])


def cmd_keys(c: FortiAIGate, args: argparse.Namespace) -> Page:
    rows = c.virtual_keys(_ws(args), status=args.status)
    cols = [
        Col("Key", "keyName", style="title"),
        Col("Status", "status", style=v.status_style),
        Col("Workspace", "workspace.name"),
        Col("Spend", "spend", fmt=v.money, right=True),
        Col("RPM", "rpm", right=True),
        Col("Last used", "lastUsedAt", fmt=v.ago, style="dim"),
        Col("ID", "id", style="id", wrap=False),
    ]
    return Page(rows, [Table(rows, cols)])


def cmd_check_key(c: FortiAIGate, args: argparse.Namespace) -> Page:
    if not args.key:
        raise ValueError("check-key needs --key (or FAIG_KEY)")
    check = dict(c.check_key(args.key))
    models = c.available_models(args.key) if check.get("valid") else []
    check["models"] = models
    ok = bool(check.get("valid"))
    fields = [
        ("Key", f"{args.key[:9]}…", "id"),
        (
            "Valid",
            f"{'yes' if ok else 'no'} (HTTP {check.get('http_status')})",
            v.status_style("valid" if ok else "rejected"),
        ),
        ("Models", ", ".join(models) or "-", "num" if models else "dim"),
    ]
    return Page(check, [Panel("Virtual key", [Fields(fields)], style="good" if ok else "bad")])


def cmd_models(c: FortiAIGate, args: argparse.Namespace) -> Page:
    ws = _ws(args)
    if args.key or ws:
        names = c.available_models(args.key) if args.key else c.workspace_models(ws or "")
        listed = [{"model": m} for m in names]
        title = "Models your key may call" if args.key else f"Models granted to {ws}"
        return Page(listed, [Table(listed, [Col("Model", "model", style="num")], title=title)])
    rows = c.models()
    cols = [
        Col("Model", "publicName", style="num"),
        Col("Provider", "providerId"),
        Col("Health", "healthStatus", style=v.status_style),
        Col("Last activity", "lastActivityAt", fmt=v.ago, style="dim"),
    ]
    return Page(rows, [Table(rows, cols)])


# -- usage and cost ------------------------------------------------------------------------
def _report(c: FortiAIGate, args: argparse.Namespace, kind: str) -> Page:
    frm, to = _window(args)
    ws = _ws(args)
    summary: Any = (c.usage_summary if kind == "usage" else c.cost_summary)(frm, to, ws_id=ws)
    rankings = (c.usage_rankings if kind == "usage" else c.cost_rankings)(
        frm, to, by=args.by, limit=args.limit, ws_id=ws
    )
    rows = rank_items(rankings)
    if kind == "usage":  # usage rankings carry no share: requests over the window's total
        whole = (summary.get("totals") or {}).get("requests") or 0
        rows = [{"share": (r.get("requests") or 0) / whole if whole else None, **r} for r in rows]
    window = summary.get("window") or {}
    span = f"{window.get('from')} .. {window.get('to')}"
    if kind == "usage":
        totals = summary.get("totals") or {}
        head = f"{span}: {totals.get('requests', 0)} requests, {totals.get('tokens', 0)} tokens"
        cols = [
            Col(args.by.title(), _ranked_name, style="title"),
            Col("Requests", "requests", right=True),
            Col("Tokens", "tokens", right=True),
            Col("Share", "share", fmt=_share, style="num"),
        ]
    else:
        spend = (summary.get("totals") or {}).get("chargebackSpend") or {}
        volume = summary.get("volume") or {}
        head = (
            f"{span}: ${spend.get('amount', 0):.4f}"
            f" over {volume.get('requests', 0)} requests, {volume.get('tokens', 0)} tokens"
        )
        cols = [
            Col(args.by.title(), _ranked_name, style="title"),
            Col("Spend", "chargebackSpend.amount", fmt=v.money, right=True),
            Col("Requests", "volume.requests", right=True),
            Col("Tokens", "volume.tokens", right=True),
            Col("Share", "share", fmt=_share, style="num"),
        ]
    title = f"Top {args.limit} by {args.by}"
    return Page(
        {"summary": summary, "rankings": rows},
        [Line.of(head, "title"), Table(rows, cols, title=title)],
    )


def cmd_usage(c: FortiAIGate, args: argparse.Namespace) -> Page:
    return _report(c, args, "usage")


def cmd_cost(c: FortiAIGate, args: argparse.Namespace) -> Page:
    return _report(c, args, "cost")


def _point_label(at: Any, interval: str) -> str:
    """A trend bucket's label. Day, week and month buckets are dates (midnight
    UTC), so they are read as they are, not moved to local time."""
    text = str(at or "")
    try:
        parsed = v._parse_time(at) if interval == "hourly" else dt.datetime.fromisoformat(text[:10])
    except ValueError:
        parsed = None
    if parsed is None:
        return text
    if interval == "hourly":
        return parsed.strftime("%m-%d %H:00")
    if interval == "monthly":
        return parsed.strftime("%Y-%m")
    if interval == "weekly":
        return "wk " + parsed.strftime("%m-%d")
    return parsed.strftime("%a %m-%d")


def cmd_trend(c: FortiAIGate, args: argparse.Namespace) -> Page:
    frm, to = _window(args)
    if not (frm or to):
        today = dt.date.today()
        frm, to = (today - dt.timedelta(days=6)).isoformat(), today.isoformat()
    ws = _ws(args)
    if args.kind == "usage":
        data: Any = c.usage_trend(frm, to, args.interval, ws_id=ws)
        measure = args.measure
        bars = [
            (
                _point_label(p.get("at"), args.interval),
                float(p.get(measure) or 0),
                f"{int(p.get(measure) or 0):,} {measure}",
            )
            for p in data.get("points") or []
        ]
        total = f"{int(sum(b[1] for b in bars)):,} {measure}"
    else:
        data = c.cost_trend(frm, to, args.interval, ws_id=ws)
        bars = [
            (
                _point_label(p.get("at"), args.interval),
                float(p.get("chargebackSpend") or 0),
                v.money(p.get("chargebackSpend") or 0),
            )
            for p in data.get("points") or []
        ]
        total = v.money(sum(b[1] for b in bars))
    label = (
        "Requests"
        if args.kind == "usage" and args.measure == "requests"
        else ("Tokens" if args.kind == "usage" else "Spend")
    )
    title = f"{label} per {args.interval.removesuffix('ly').replace('dai', 'day')}"
    scope = ws or "organization"
    return Page(
        data,
        [
            Panel(
                f"{title} · {scope} · {frm} .. {to}",
                [Bars(bars), Line.of(f"Total  {total}", "title")],
            )
        ],
    )


def cmd_breakdown(c: FortiAIGate, args: argparse.Namespace) -> Page:
    frm, to = _window(args)
    fn = c.usage_breakdown if args.kind == "usage" else c.cost_breakdown
    data = fn(args.by, args.id, frm, to, ws_id=_ws(args))
    rows = breakdown_items(data)
    cols = [
        Col("Name", "name", style="title"),
        Col("Requests", "requests", right=True),
        Col("Tokens", "tokens", right=True),
    ]
    return Page(data, [Table(rows, cols)])


# -- logs ------------------------------------------------------------------------------------
LOG_COLS = [
    Col("Time", lambda r: v.when(r.get("timeStamp")), style="dim"),
    Col("Verdict", "verdictLabel", style=v.verdict_style),
    Col("Action", "action", style=v.verdict_style),
    Col("Key", "keyAlias"),
    Col("User", "user"),
    Col("Model", "model", style="num"),
    Col("UUID", "uuid", style="id", wrap=False),
]


def _log_filters(args: argparse.Namespace) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    for name in ("verdict", "user", "model"):
        if getattr(args, name):
            filters[name] = getattr(args, name)
    if args.key:
        filters["virtual_key"] = args.key
    if args.workspace_filter:
        filters["workspace"] = args.workspace_filter
    return filters


def _log_line(row: Mapping[str, Any]) -> Line:
    verdict = str(row.get("verdictLabel") or "-")
    return Line(
        [
            (v.when(row.get("timeStamp")) + "  ", "dim"),
            (verdict.ljust(7), v.verdict_style(verdict)),
            (f" {row.get('keyAlias') or '-'}", None),
            (f"  {row.get('model') or '-'}", "num"),
            (f"  {row.get('user') or '-'}", "dim"),
            (f"  {row.get('uuid') or ''}", "id"),
        ]
    )


def _follow(c: FortiAIGate, args: argparse.Namespace, filters: dict[str, Any]) -> None:
    seen: set[Any] = set()
    v.render(
        [Line.of(f"Following traffic (every {args.interval}s, Ctrl+C to stop)", "dim")],
        plain=args.plain,
    )
    try:
        while True:
            rows = list(
                c.traffic_logs(range="24h", filters=filters, max_items=args.limit, ws_id=_ws(args))
            )
            fresh = [r for r in reversed(rows) if r.get("uuid") not in seen]
            for row in fresh:
                seen.add(row.get("uuid"))
                v.render([_log_line(row)], plain=args.plain)
            sys.stdout.flush()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return


def cmd_logs(c: FortiAIGate, args: argparse.Namespace) -> Page | None:
    filters = _log_filters(args)
    if args.follow:
        _follow(c, args, filters)
        return None
    rows = list(
        c.traffic_logs(range=args.range, filters=filters, max_items=args.limit, ws_id=_ws(args))
    )
    return Page(rows, [Table(rows, LOG_COLS)])


def _text_of(value: Any) -> str:
    if isinstance(value, Mapping):
        value = value.get("modified") or value.get("original") or value.get("content")
    if isinstance(value, list):
        value = " ".join(_text_of(x) for x in value)
    return str(value or "")


def cmd_log(c: FortiAIGate, args: argparse.Namespace) -> Page:
    rec = c.traffic_log(args.uuid, _ws(args))
    tokens = rec.get("tokens") or {}
    verdict = str(rec.get("verdictLabel") or "-")
    fields = [
        ("Time", v.when(rec.get("timeStamp")), None),
        ("Verdict", f"{verdict}  {rec.get('action') or ''}".strip(), v.verdict_style(verdict)),
        ("Key", str(rec.get("keyAlias") or "-"), None),
        ("User", str(rec.get("user") or "-"), None),
        ("Workspace", str(rec.get("workspace") or "-"), None),
        ("Model", str(rec.get("model") or "-"), "num"),
        ("Tokens", f"{tokens.get('input', 0)} in / {tokens.get('output', 0)} out", None),
        ("Cost", v.money(_num(rec.get("cost")), 6), None),
        ("Scanned", str(rec.get("guardType") or "-"), "dim"),
    ]
    prompt = rec.get("prompt") or {}
    blocks: list[Any] = [Fields(fields)]
    original = _text_of((prompt or {}).get("original") if isinstance(prompt, Mapping) else prompt)
    blocks.append(Fields([("Prompt", _clip(original, 400), None)]))
    if isinstance(prompt, Mapping) and prompt.get("modified"):
        blocks.append(Fields([("Sent as", _clip(prompt["modified"], 400), "warn")]))
    answer = _text_of(rec.get("response"))
    if answer:
        blocks.append(Fields([("Answer", _clip(answer, 400), "dim")]))
    hits = _hits(rec)
    if hits:
        cols = [
            Col("Side", "side", style="dim"),
            Col("Detector", "detectorName", style="bad"),
            Col("Details", "details"),
        ]
        blocks.append(Table(hits, cols, title="Matched"))
    style = v.verdict_style(verdict) or "dim"
    return Page(rec, [Panel(f"Traffic log {args.uuid}", blocks, style=style)])


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def cmd_audit(c: FortiAIGate, args: argparse.Namespace) -> Page:
    filters = {f: getattr(args, f) for f in ("user", "action") if getattr(args, f)}
    rows = list(
        c.iter_audit_logs(range=args.range, filters=filters, max_items=args.limit, ws_id=_ws(args))
    )
    cols = [
        Col("Time", lambda r: v.when(r.get("timeStamp")), style="dim"),
        Col("User", "username"),
        Col("Action", "actionLabel", style="accent"),
        Col("Type", "type", style="dim"),
        Col("Message", "message"),
    ]
    return Page(rows, [Table(rows, cols)])


# -- trying things -----------------------------------------------------------------------------
def cmd_scan(c: FortiAIGate, args: argparse.Namespace) -> Page:
    ws = _ws(args)
    if args.detector:
        out = c.test_guardrail(args.text, args.detector, ws_id=ws)
    else:
        out = c.test_guardrail(args.text, guardrail_id=args.guardrail, ws_id=ws)
    names = _detector_names(c, ws)
    rows = [
        {
            **r,
            "detector": names.get(r.get("detectorId")) or r.get("detectorId"),
            "match": "untested"
            if r.get("status") == "untested"
            else ("hit" if r.get("matched") else "-"),
        }
        for r in out.get("results") or []
    ]
    verdict = str(out.get("finalDisposition") or "pass")
    cols = [
        Col("Detector", "detector", style="title"),
        Col(
            "Match",
            "match",
            fmt=lambda m: {"hit": "✔", "untested": "untested"}.get(m, "·"),
            style=lambda m: "bad" if m == "hit" else "dim",
        ),
        Col("Action", "finalDisposition", style=v.verdict_style),
        Col("Score", "score", right=True),
        Col("Details", "details", fmt=lambda d: _clip(d, 70) or "-"),
    ]
    head = Line(
        [
            ("Verdict: ", "title"),
            (verdict.upper(), v.verdict_style(verdict) or "good"),
            ("   no model was called, no tokens spent", "dim"),
        ]
    )
    blocks: list[Any] = [head, Table(rows, cols)]
    if any(r["match"] == "untested" for r in rows):
        blocks.append(
            Line.of(
                "Built-in detectors cannot be scanned offline on this FortiAIGate:"
                " send the text through the gateway with `chat` to see what they do.",
                "dim",
            )
        )
    return Page(out, blocks)


def cmd_try_regex(c: FortiAIGate, args: argparse.Namespace) -> Page:
    body = regex_detector_body("pyfortiaigate try-regex", [("pattern", args.pattern, args.action)])
    results = []
    lines: list[Line] = [Line([("Pattern  ", "dim"), (args.pattern, "accent")])]
    for text in args.text:
        out = c.playground(text, body, ws_id=_ws(args))
        results.append({"text": text, **out})
        mark = ("MATCH  ", "bad") if out.get("matched") else ("-      ", "dim")
        lines.append(Line([mark, *_marked(text, out.get("spans") or [], args.plain)]))
    matched = sum(1 for r in results if r.get("matched"))
    where = (
        "matched locally: this FortiAIGate cannot test an unsaved detector"
        if any(r.get("checkedLocally") for r in results)
        else "nothing was saved"
    )
    summary = Line.of(f"{matched} of {len(results)} matched ({where})", "dim")
    return Page(results, [Lines(lines), summary])


def _marked(text: str, spans: Iterable[Mapping[str, Any]], plain: bool) -> list[tuple[str, Any]]:
    """The matches in ``text``: highlighted in a terminal, ``[bracketed]`` in plain text."""
    line = v.highlight(text, spans)
    if v.use_rich(plain=plain):
        return list(line.parts)
    return [(f"[{t}]" if style == "hit" else t, None) for t, style in line.parts]


# -- the gateway: chat and scenarios -------------------------------------------------------
# Exit status of chat and scenarios: 0 = answered / every case matched, 3 = a guardrail
# blocked / a case did not match, 1 = the gateway refused a request (key, rate limit,
# model) or another error, so no guardrail ran.
BLOCKED_EXIT = 3

# Gateway statuses that mean the request never reached a guardrail.
REFUSED_HINTS = {
    401: "the key is wrong or revoked",
    403: "the key may not do this",
    404: "the model is not available to this key",
    429: "rate limited: wait a minute",
    502: "the gateway cannot reach the model",
    503: "the gateway cannot reach the model",
    504: "the gateway timed out waiting for the model",
}


def _send(
    c: FortiAIGate,
    key: str,
    model: str,
    text: str,
    max_tokens: int | None,
    temperature: float | None,
) -> dict[str, Any]:
    """One prompt through the gateway, as a result row: ``result`` is answered,
    blocked or refused; ``status`` the HTTP status; ``text`` the answer, the block
    message or why the gateway refused."""
    msgs = [{"role": "user", "content": text}]
    try:
        out = c.chat_completion(key, model, msgs, max_tokens=max_tokens, temperature=temperature)
    except FaigError as e:
        err = e.data.get("error") if isinstance(e.data, dict) else None
        msg = err.get("message") if isinstance(err, dict) else None
        reason = str(msg or REFUSED_HINTS.get(e.status) or e)
        return {"result": "refused", "status": e.status, "code": e.code, "text": reason}
    choice = (out.get("choices") or [{}])[0]
    content = str((choice.get("message") or {}).get("content") or "")
    usage = out.get("usage") or {}
    return {
        "result": "blocked" if blocked(out) else "answered",
        "status": 200,
        "text": content,
        "tokens": usage.get("total_tokens"),
        "completion": out,
    }


def _model_for(c: FortiAIGate, args: argparse.Namespace) -> str:
    """--model, else FAIG_MODEL, else the first model the key may call."""
    if args.model:
        return str(args.model)
    models = c.available_models(args.key)
    if not models:
        raise ValueError("this key may call no model; pass --model")
    return models[0]


RESULT_STYLE = {"answered": "good", "blocked": "bad", "refused": "warn"}


def cmd_chat(c: FortiAIGate, args: argparse.Namespace) -> Page:
    """Send a prompt (``--repeat N`` times). Exit 0 answered, 3 blocked, 1 refused."""
    model = _model_for(c, args)
    since = int(time.time() * 1000)
    rows = []
    for n in range(1, max(1, args.repeat) + 1):
        row = _send(c, args.key, model, args.text, args.max_tokens, args.temperature)
        rows.append({"n": n, **row})
    results = {r["result"] for r in rows}
    status = 1 if "refused" in results else BLOCKED_EXIT if "blocked" in results else 0
    data: Any = rows if args.repeat > 1 else rows[0]
    if args.repeat > 1:
        counts = Counter(r["result"] for r in rows)
        summary = ", ".join(
            f"{counts[k]} {k}" for k in ("answered", "blocked", "refused") if counts[k]
        )
        cols = [
            Col("#", "n", right=True, style="dim"),
            Col("HTTP", "status", style=lambda s: "good" if s == 200 else "warn"),
            Col("Result", "result", style=lambda r: RESULT_STYLE.get(r)),
            Col("Answer or reason", lambda r: _clip(r["text"], 70)),
        ]
        blocks: list[Any] = [Table(rows, cols, title=f"{model} · {summary}")]
    else:
        r = rows[0]
        head = (
            f"HTTP {r['status']} · {model} · "
            + {
                "answered": "answered",
                "blocked": "BLOCKED by a guardrail",
                "refused": "refused by the gateway",
            }[r["result"]]
        )
        if r.get("tokens"):
            head += f" · {r['tokens']} tokens"
        why = _why(c, args, since) if r["result"] == "blocked" and args.why else []
        if not v.use_rich(plain=args.plain):
            top = Lines([Line.of(head, RESULT_STYLE[r["result"]]), Line.of(r["text"])])
            blocks = [top, *why]
        else:
            blocks = [Panel(head, [Line.of(r["text"]), *why], style=RESULT_STYLE[r["result"]])]
    return Page(data, blocks, exit=status)


def _why(c: FortiAIGate, args: argparse.Namespace, since: int) -> list[Any]:
    """What blocked the prompt, from its traffic log record (it lands a few
    seconds after the request; reading it needs a login and a workspace)."""
    ws = _ws(args)
    if not ws:
        return [Line.of("(--why needs your workspace: set FAIG_WS or pass --ws)", "dim")]
    try:
        name = c.virtual_key(args.key, ws).get("keyName")
        found = c.wait_for_traffic(
            since, filters={"virtual_key": name, "verdict": "Block"}, timeout=45, ws_id=ws
        )
        rec = c.traffic_log(str(found[0].get("uuid")), ws)
    except (FaigError, TimeoutError, ValueError) as e:
        return [Line.of(f"(no traffic log record yet: {e})", "dim")]
    hits = _hits(rec)
    if not hits:
        return [Line.of("(the record names no detector)", "dim")]
    cols = [
        Col("Side", "side", style="dim"),
        Col("Detector", "detectorName", style="bad"),
        Col("Details", "details"),
    ]
    return [Table(hits, cols, title="Blocked by")]


def _load_catalog(path: str) -> list[dict[str, Any]]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"no scenario catalog {path}")
    data = json.loads(p.read_text())
    cases = data.get("scenarios", data) if isinstance(data, dict) else data
    if not isinstance(cases, list) or not all(
        isinstance(x, dict) and x.get("prompt") and x.get("expect") in ("blocked", "allowed")
        for x in cases
    ):
        raise ValueError(f"{path}: want a list of cases with a prompt and expect: blocked|allowed")
    return cases


def cmd_scenarios(c: FortiAIGate, args: argparse.Namespace) -> Page:
    """Send each catalog prompt and compare blocked/allowed with its ``expect``.
    Exit 0 every case matched, 3 a case did not, 1 the gateway refused a request."""
    cases = _load_catalog(args.catalog)
    if args.use_case:
        q = args.use_case.lower()
        cases = [
            x
            for x in cases
            if q in str(x.get("use_case", "")).lower() or q in str(x.get("ui_feature", "")).lower()
        ]
    if args.scanner:
        cases = [x for x in cases if str(x.get("scanner", "")).lower() == args.scanner.lower()]
    if not cases:
        every = _load_catalog(args.catalog)
        names = sorted({str(x.get("use_case")) for x in every if x.get("use_case")})
        raise ValueError(f"no case matches; --use-case is one of: {', '.join(names)}")
    model = _model_for(c, args)
    rows = []
    for x in cases:
        # temperature 0: the same case gets the same answer on every run, so an
        # output rule always has the same text to match.
        r = _send(c, args.key, model, str(x["prompt"]), None, 0.0)
        got = {"answered": "allowed", "blocked": "blocked"}.get(r["result"], "error")
        verdict = "ERROR" if got == "error" else "PASS" if got == x["expect"] else "MISMATCH"
        rows.append(
            {
                "name": x.get("name") or "-",
                "use_case": x.get("use_case") or "-",
                "expect": x["expect"],
                "got": got,
                "verdict": verdict,
                "status": r["status"],
                "detail": r["text"] if got == "error" else "",
                "prompt": x["prompt"],
                "answer": r["text"] if got != "error" else "",
            }
        )
    counts = Counter(r["verdict"] for r in rows)
    status = 1 if counts["ERROR"] else BLOCKED_EXIT if counts["MISMATCH"] else 0
    style = {"PASS": "good", "MISMATCH": "bad", "ERROR": "warn"}
    cols = [
        Col("Case", "name", style="title", wrap=False),
        Col("Use case", "use_case"),
        Col("Expect", "expect", style="dim"),
        Col("Got", "got"),
        Col("Verdict", "verdict", style=lambda x: style.get(x)),
    ]
    if counts["ERROR"]:
        cols.append(Col("Why", lambda r: _clip(r["detail"], 50), style="warn"))
    summary = f"{counts['PASS']}/{len(rows)} PASS"
    if counts["MISMATCH"]:
        summary += f", {counts['MISMATCH']} MISMATCH"
    if counts["ERROR"]:
        summary += f", {counts['ERROR']} ERROR"
    blocks: list[Any] = [Table(rows, cols, title=f"{model} · {summary}")]
    if args.verbose:
        for r in rows:
            blocks.append(
                Fields(
                    [
                        ("Case", str(r["name"]), "title"),
                        ("Sent", _clip(r["prompt"], 300), None),
                        ("Got", _clip(r["answer"] or r["detail"], 300), "dim"),
                    ]
                )
            )
    if counts["ERROR"]:
        blocks.append(
            Line.of(
                "ERROR: the gateway refused the request, so no guardrail ran (key, URL or model).",
                "warn",
            )
        )
    elif counts["MISMATCH"]:
        blocks.append(
            Line.of(
                "MISMATCH: the guardrails are not yet set up the way that use case needs.", "bad"
            )
        )
    return Page({"summary": dict(counts), "cases": rows}, blocks, exit=status)


def cmd_licenses(c: FortiAIGate, args: argparse.Namespace) -> Page:
    data = c.licenses()
    rows = (data.get("licenses") or []) if isinstance(data, dict) else []
    cols = [
        Col("Serial", "serialNumber", style="title"),
        Col("Status", "status", style=v.status_style),
        Col("Ends", "endDate"),
    ]
    return Page(data, [Table(rows, cols)])


# -- dashboard -----------------------------------------------------------------------------------
def cmd_dashboard(c: FortiAIGate, args: argparse.Namespace) -> Page:
    ws = _ws(args)
    days = args.days or 7
    today = dt.date.today()
    frm, to = (today - dt.timedelta(days=days - 1)).isoformat(), today.isoformat()
    log_range = "24h" if days <= 1 else "7d" if days <= 7 else "month"

    me = c.me()
    usage: Any = c.usage_summary(frm, to, ws_id=ws)
    cost: Any = c.cost_summary(frm, to, ws_id=ws)
    by_model = rank_items(c.cost_rankings(frm, to, by="model", limit=5, ws_id=ws))
    trend: Any = c.usage_trend(frm, to, "daily", ws_id=ws)
    total = c.traffic_logs_page(range=log_range, limit=1, ws_id=ws).get("total") or 0
    blocked_rows = list(
        c.traffic_logs(
            range=log_range, filters={"verdict": "Block"}, max_items=args.sample, ws_id=ws
        )
    )
    n_blocked = c.traffic_logs_page(
        range=log_range, filters={"verdict": "Block"}, limit=1, ws_id=ws
    ).get("total") or len(blocked_rows)
    records = [c.traffic_log(r["uuid"], ws) for r in blocked_rows if r.get("uuid")]
    per_detector = Counter(h.get("detectorName") or "?" for rec in records for h in _hits(rec))
    counts = {
        "detectors": len(c.detectors(ws)),
        "guardrails": len(c.guardrails(ws)),
        "policies": len(c.policies(ws)),
        "keys": len(c.virtual_keys(ws)),
    }

    totals = usage.get("totals") or {}
    spend = ((cost.get("totals") or {}).get("chargebackSpend") or {}).get("amount") or 0
    points = trend.get("points") or []
    rate = f"{n_blocked / total * 100:.0f}%" if total else "-"
    header = Fields(
        [
            ("Signed in", f"{me.get('email') or me.get('username')} ({me.get('role')})", None),
            ("Requests", f"{int(totals.get('requests') or 0):,}", "num"),
            ("Tokens", f"{int(totals.get('tokens') or 0):,}", "num"),
            ("Spend", v.money(spend), "num"),
            (
                "Blocked",
                f"{n_blocked:,} of {total:,} logged requests ({rate})",
                "bad" if n_blocked else "good",
            ),
            ("Config", ", ".join(_count(n, k) for k, n in counts.items()), "dim"),
            ("Per day", v.spark([float(p.get("requests") or 0) for p in points]), "num"),
        ]
    )
    spend_bars = Bars(
        [
            (
                str(r.get("name")),
                float(v.dig(r, "chargebackSpend.amount") or 0),
                v.money(v.dig(r, "chargebackSpend.amount")),
            )
            for r in by_model
        ],
        style="num",
        width=14,
    )
    detector_bars = Bars(
        [(name, float(n), str(n)) for name, n in per_detector.most_common(6)],
        style="bad",
        empty="(no blocks)",
        width=14,
    )
    day_bars = Bars(
        [
            (
                _point_label(p.get("at"), "daily"),
                float(p.get("requests") or 0),
                f"{int(p.get('requests') or 0):,}",
            )
            for p in points
        ],
        style="good",
        width=14,
    )
    recent = [
        {
            "time": rec.get("timeStamp"),
            "key": rec.get("keyAlias"),
            "detectors": Many(sorted({str(h.get("detectorName")) for h in _hits(rec)})),
            "prompt": _text_of(
                (rec.get("prompt") or {}).get("original")
                if isinstance(rec.get("prompt"), Mapping)
                else rec.get("prompt")
            ),
        }
        for rec in records[:5]
    ]
    recent_table = Table(
        recent,
        [
            Col("When", lambda r: v.ago(r.get("time")), style="dim", wrap=False),
            Col("Key", "key", wrap=False),
            Col("Stopped by", "detectors", style="bad", wrap=False),
            Col("Prompt", lambda r: _clip(r.get("prompt"), 60)),
        ],
        empty="(no blocks)",
    )
    scope = ws or "organization"
    data = {
        "workspace": ws,
        "from": frm,
        "to": to,
        "me": me,
        "usage": usage,
        "cost": cost,
        "spend_by_model": by_model,
        "trend": trend,
        "logged": total,
        "blocked": n_blocked,
        "blocks_by_detector": dict(per_detector),
        "config": counts,
        "recent_blocks": recent,
    }
    sample = f"last {len(records)} blocked" if records else "blocked requests"
    return Page(
        data,
        [
            Panel(f"FortiAIGate · {scope} · {frm} .. {to}", [header], style="accent"),
            Row(
                [
                    Panel(f"Blocks by detector ({sample})", [detector_bars], style="bad"),
                    Panel("Requests per day", [day_bars], style="good"),
                ]
            ),
            Panel("Spend by model", [spend_bars], style="num"),
            Panel("Recent blocks", [recent_table], style="bad"),
        ],
    )


# -- config: the settings file, written for you ------------------------------------------
def _ask(label: str, current: str | None, secret: bool = False) -> str | None:
    """One prompt; Enter keeps the current value."""
    import getpass

    shown = ("(set)" if secret else current) if current else ""
    prompt = f"{label}{f' [{shown}]' if shown else ''}: "
    answer = (getpass.getpass(prompt) if secret else input(prompt)).strip()
    return answer or current


def _target(args: argparse.Namespace) -> Path:
    """The file config writes: --env-file, else FAIG_ENV_FILE, else the default one."""
    return Path(args.env_file).expanduser() if args.env_file else default_settings_file()


def cmd_config_list(s: Settings, args: argparse.Namespace) -> Page:
    known = [k.name for k in KNOWN]
    names = known + sorted(n for n in s if n not in known)
    path = s.file or _target(args)

    def origin_of(n: str) -> str:
        src = s.source(n) or "-"
        return "settings file" if src == str(path) else src

    rows = [
        {"setting": n, "value": s.masked(n) or "-", "from": origin_of(n)}
        for n in names
        if n in s or getattr(args, "all", False)
    ]
    note = f"Settings file: {_tilde(path)}" + ("" if path.is_file() else " (not created yet)")
    cols = [Col("Setting", "setting", style="title"), Col("Value", "value"), Col("From", "from")]
    blocks: list[Any] = [Line.of(note)]
    if rows:
        blocks.append(Table(rows, cols))
    else:
        blocks.append(Line.of(f"Nothing is set: run `{PROG} config init`."))
    return Page({"file": str(path), "settings": rows}, blocks)


def cmd_config_path(s: Settings, args: argparse.Namespace) -> Page:
    path = s.file or _target(args)
    return Page({"file": str(path), "exists": path.is_file()}, [Line.of(str(path))])


def _setting_name(raw: str) -> str:
    name = raw.upper()
    if not name.startswith("FAIG_") or name == "FAIG_ENV_FILE":
        raise ValueError(f"{raw}: settings are FAIG_* names (see `config list --all`)")
    return name


def cmd_config_set(s: Settings, args: argparse.Namespace) -> Page:
    name = _setting_name(args.name)
    value = args.value
    if value is None:
        if not sys.stdin.isatty():
            value = sys.stdin.readline().rstrip("\r\n")
        else:
            value = _ask(name, None, secret=any(k.name == name and k.secret for k in KNOWN))
    if not value:
        raise ValueError(f"give a value: config set {name} <value> (or config unset {name})")
    path = write_settings(_target(args), {name: value})
    return Page({"file": str(path), "set": name}, [Line.of(f"{name} saved to {_tilde(path)}")])


def cmd_config_unset(s: Settings, args: argparse.Namespace) -> Page:
    name = _setting_name(args.name)
    path = _target(args)
    if path.is_file():
        write_settings(path, {name: None})
    return Page(
        {"file": str(path), "unset": name}, [Line.of(f"{name} removed from {_tilde(path)}")]
    )


_INIT = (
    ("FAIG_URL", "FortiAIGate address, as in your browser (https://...)", "init_url", False),
    ("FAIG_USERNAME", "Username", "init_username", False),
    ("FAIG_PASSWORD", "Password", None, True),
    ("FAIG_WS", "Workspace (Enter for none)", "init_ws", False),
    ("FAIG_KEY", "Virtual key secret, faig_... (Enter for none)", "init_key", True),
)


def cmd_config_init(s: Settings, args: argparse.Namespace) -> Page:
    """Ask for each connection setting (Enter keeps what is there), log in with
    them, and write the settings file (mode 600). Flags answer without asking."""
    tty = sys.stdin.isatty() and not args.password_stdin
    got: dict[str, str | None] = {}
    for name, label, flag, secret in _INIT:
        given = getattr(args, flag) if flag else None
        if name == "FAIG_URL" and given is None:
            given = args.url  # pyfortiaigate --url ... config init
        if given is not None:
            got[name] = given
        elif name == "FAIG_PASSWORD" and args.password_stdin:
            got[name] = sys.stdin.readline().rstrip("\r\n")
        elif tty:
            got[name] = _ask(label, s.get(name), secret=secret)
        else:
            got[name] = s.get(name)
    if args.insecure or args.init_insecure:
        got["FAIG_VERIFY_TLS"] = "false"
    elif tty and "FAIG_VERIFY_TLS" not in s:
        answer = input("Skip TLS verification (a self-signed lab certificate)? [y/N]: ")
        got["FAIG_VERIFY_TLS"] = "false" if answer.strip().lower() in ("y", "yes") else None
    if not got.get("FAIG_URL"):
        raise ValueError("FAIG_URL is required: pass --url, or run config init in a terminal")
    got["FAIG_URL"] = origin(got["FAIG_URL"] or "")  # the browser address minus /ui...
    merged = {**dict(s), **{k: x for k, x in got.items() if x}}
    checks = [] if args.no_verify else _check_settings(merged, got)
    path = write_settings(_target(args), {k: (x or None) for k, x in got.items()})
    blocks: list[Any] = [Fields(checks)] if checks else []
    blocks.append(Line.of(f"Saved to {_tilde(path)} (readable only by you)"))
    return Page({"file": str(path), "checks": [list(c[:2]) for c in checks]}, blocks)


def _check_settings(
    env: Mapping[str, str], got: dict[str, str | None]
) -> list[tuple[str, str, str]]:
    """Log in with the new settings and test the key. A failed login raises, so a
    wrong password is never saved; a refused key or unknown workspace is reported.
    A valid key's model goes into ``got`` as FAIG_MODEL (unless one is set), so
    ``chat`` never spends a rate-limited request looking it up."""
    rows: list[tuple[str, str, str]] = []
    with FortiAIGate.from_env(env) as c:
        if env.get("FAIG_USERNAME") or env.get("FAIG_TOKEN"):
            me = c.me()
            rows.append(("Login", f"ok, {me.get('email') or me.get('username')}", "good"))
            ws = env.get("FAIG_WS")
            if ws:
                mine = c.my_workspaces()
                found = any(ws in (w.get("workspaceName"), w.get("workspaceId")) for w in mine)
                text = ws if found else f"{ws}: not one of your workspaces"
                rows.append(("Workspace", text, "good" if found else "bad"))
        key = env.get("FAIG_KEY")
        if key:
            check = c.check_key(key)
            ok = bool(check.get("valid"))
            text = f"{'valid' if ok else 'refused'} (HTTP {check.get('http_status')})"
            rows.append(("Key", text, "good" if ok else "bad"))
            models = c.available_models(key) if ok else []
            if models and not env.get("FAIG_MODEL"):
                got["FAIG_MODEL"] = models[0]
                rows.append(("Model", models[0], "num"))
    return rows


CONFIG_COMMANDS = {
    "list": cmd_config_list,
    "path": cmd_config_path,
    "set": cmd_config_set,
    "unset": cmd_config_unset,
    "init": cmd_config_init,
}


# -- parser --------------------------------------------------------------------------
def parser(settings: Mapping[str, str] | None = None) -> argparse.ArgumentParser:
    """The argument parser; ``settings`` supply the defaults for --ws and --key."""
    settings = os.environ if settings is None else settings
    p = argparse.ArgumentParser(
        prog=PROG,
        usage=f"{PROG} [options] COMMAND [command options]",
        description="FortiAIGate from the shell: send prompts, test detectors, read"
        " traffic, blocks and spend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--env-file",
        help="settings file to use"
        " (default: FAIG_ENV_FILE, else ~/.config/pyfortiaigate/.env if it exists)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    p.add_argument("--url", help="FortiAIGate address (default: FAIG_URL)")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.add_argument("--plain", action="store_true", help="plain text even in a terminal")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    # The flat list is hidden: the epilog lists the commands grouped by task.
    sub = p.add_subparsers(dest="command", metavar="COMMAND", help=argparse.SUPPRESS)
    helps: dict[str, str] = {}
    ws_default = settings.get("FAIG_WS")
    key_default = settings.get("FAIG_KEY")

    def add(name: str, fn: Any, help: str, ws: bool = True) -> argparse.ArgumentParser:
        helps[name] = help
        sp = sub.add_parser(name, help=help, description=help)
        sp.set_defaults(fn=fn)
        # --json / --plain work after the command too; SUPPRESS keeps the global value.
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="raw JSON")
        sp.add_argument(
            "--plain", action="store_true", default=argparse.SUPPRESS, help="no colours or boxes"
        )
        if ws:
            sp.add_argument(
                "--ws",
                default=ws_default,
                help="workspace name or id (default: FAIG_WS; --ws '' for org-wide)",
            )
        return sp

    def window(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--days", type=int, help="the last N days, today included")
        sp.add_argument("--from", dest="frm", help="YYYY-MM-DD (default: 30 days ago)")
        sp.add_argument("--to", help="YYYY-MM-DD (default: today)")

    def key(sp: argparse.ArgumentParser, required: bool = False) -> None:
        sp.add_argument(
            "--key",
            default=key_default,
            required=required and not key_default,
            help="faig_... secret (default: FAIG_KEY)",
        )

    add("dashboard", cmd_dashboard, "one screen: traffic, blocks, spend and trend").add_argument(
        "--days", type=int, default=7, help="window (default 7)"
    )
    p_dash = sub.choices["dashboard"]
    p_dash.add_argument("--sample", type=int, default=20, help="blocked records to read")
    add("whoami", cmd_whoami, "the logged-in user", ws=False)
    add("workspaces", cmd_workspaces, "workspaces", ws=False).add_argument(
        "--mine", action="store_true", help="only the ones you belong to"
    )
    add("members", cmd_members, "who is in a workspace")
    add("detectors", cmd_detectors, "custom detectors")
    add("builtins", cmd_builtins, "built-in detectors and their ids")
    add("guardrails", cmd_guardrails, "guardrails and the detectors in each")
    add("policies", cmd_policies, "policies")
    add("keys", cmd_keys, "virtual keys").add_argument("--status", help="e.g. active, revoked")
    key(add("check-key", cmd_check_key, "is a key valid, and which models may it call", ws=False))
    sp = add("models", cmd_models, "org models, a workspace's, or what a key may call")
    sp.add_argument("--key", help="faig_... secret: the models this key may call")
    for kind in ("usage", "cost"):
        sp = add(kind, cmd_usage if kind == "usage" else cmd_cost, f"{kind} summary and top items")
        window(sp)
        sp.add_argument("--by", default="key", choices=["key", "user", "workspace", "model"])
        sp.add_argument("--limit", type=int, default=10)
    sp = add("trend", cmd_trend, "usage or cost over time, as a bar chart")
    sp.add_argument("kind", choices=["usage", "cost"])
    sp.add_argument("--interval", default="daily", choices=["hourly", "daily", "weekly", "monthly"])
    sp.add_argument(
        "--measure",
        default="requests",
        choices=["requests", "tokens"],
        help="for usage (default requests)",
    )
    window(sp)
    sp = add("breakdown", cmd_breakdown, "one ranked item split by model (or by consumer)")
    sp.add_argument("kind", choices=["usage", "cost"])
    sp.add_argument("by", choices=["key", "user", "workspace", "model"])
    sp.add_argument("id", help="the item's id, as rankings list it")
    window(sp)
    sp = add("logs", cmd_logs, "recent traffic log rows")
    sp.add_argument("--range", default="24h", choices=["24h", "7d", "month", "all"])
    sp.add_argument("--key", help="virtual key NAME")
    sp.add_argument("--verdict", help="Block or Log")
    sp.add_argument("--user")
    sp.add_argument("--model")
    sp.add_argument("--workspace-filter", help="workspace name, as a filter (with org-wide --ws)")
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--follow", "-f", action="store_true", help="keep printing new rows")
    sp.add_argument("--interval", type=float, default=3.0, help="seconds between polls")
    add("log", cmd_log, "one traffic log record: verdict, prompt, what matched").add_argument(
        "uuid"
    )
    sp = add("audit", cmd_audit, "recent audit log rows")
    sp.add_argument("--range", default="24h", choices=["24h", "7d", "month", "all"])
    sp.add_argument("--user")
    sp.add_argument("--action", help="e.g. Approve, Create, Delete")
    sp.add_argument("--limit", type=int, default=20)
    sp = add("scan", cmd_scan, "scan text with a guardrail or detectors (no LLM call)")
    group = sp.add_mutually_exclusive_group(required=True)
    group.add_argument("--guardrail", help="guardrail name or id")
    group.add_argument("--detector", action="append", help="detector name or id (repeatable)")
    sp.add_argument("text")
    sp = add("try-regex", cmd_try_regex, "try a regex detector on text without saving it")
    sp.add_argument("pattern", help="regular expression ((?i) at the start ignores case)")
    sp.add_argument("text", nargs="+", help="one or more lines to try")
    sp.add_argument("--action", default="block", choices=["block", "redact", "alert", "log"])

    def gateway(sp: argparse.ArgumentParser) -> None:
        key(sp, required=True)
        sp.add_argument(
            "--model",
            default=settings.get("FAIG_MODEL"),
            help="default: FAIG_MODEL, else the first model the key may call",
        )

    sp = add("chat", cmd_chat, "send a prompt through the gateway (exit 3 when blocked)")
    gateway(sp)
    sp.add_argument("--max-tokens", type=int, default=256, metavar="N", help="(default 256)")
    sp.add_argument("--temperature", type=float, metavar="T")
    sp.add_argument(
        "--repeat", type=int, default=1, metavar="N", help="send it N times, one line each"
    )
    sp.add_argument("--why", action="store_true", help="on a block, name what matched (logs in)")
    sp.add_argument("text", help="the prompt (quote it)")
    sp = add("scenarios", cmd_scenarios, "run a catalog of prompts: PASS or MISMATCH per case")
    gateway(sp)
    sp.add_argument(
        "catalog",
        nargs="?",
        default=str(CATALOG),
        help="JSON file of cases: [{name, prompt, expect: blocked|allowed, ...}]"
        " (default: the workshop catalog that comes with pyfortiaigate)",
    )
    sp.add_argument("--use-case", help="only cases whose use case matches (part of the name)")
    sp.add_argument("--scanner", help="only cases for this scanner")
    sp.add_argument("--verbose", "-v", action="store_true", help="show each prompt and answer")
    add("licenses", cmd_licenses, "appliance licenses", ws=False)
    cfg = add("config", None, "show or write your settings file", ws=False)
    csub = cfg.add_subparsers(dest="config", metavar="ACTION")
    c_list = csub.add_parser("list", help="each setting, its value and where it came from")
    c_list.add_argument("--all", action="store_true", help="also the settings that are not set")
    csub.add_parser("path", help="the settings file in use")
    c_init = csub.add_parser("init", help="ask for your settings, check them, save them")
    # Own dests: a subparser default would otherwise overwrite the global --url.
    c_init.add_argument("--url", dest="init_url", help="FortiAIGate address")
    c_init.add_argument("--username", dest="init_username")
    c_init.add_argument("--ws", dest="init_ws", help="your workspace")
    c_init.add_argument("--key", dest="init_key", help="a virtual key secret (faig_...)")
    c_init.add_argument(
        "--insecure", dest="init_insecure", action="store_true", help="skip TLS verification"
    )
    c_init.add_argument(
        "--password-stdin", action="store_true", help="read the password from stdin"
    )
    c_init.add_argument("--no-verify", action="store_true", help="save without logging in")
    c_set = csub.add_parser("set", help="save one setting (no value: prompt, or read stdin)")
    c_set.add_argument("name", help="e.g. FAIG_WS")
    c_set.add_argument("value", nargs="?")
    csub.add_parser("unset", help="remove one setting").add_argument("name")
    width = max(len(n) for n in helps) + 2
    listed = [n for _, names in GROUPS for n in names]
    assert sorted(listed) == sorted(helps), "every command belongs to one help group"
    lines = []
    for title, names in GROUPS:
        lines.append(f"{title}:")
        lines += [f"  {n:<{width}}{helps[n]}" for n in names]
        lines.append("")
    lines.append(
        f"Start with `{PROG} config init`. `{PROG} COMMAND --help` for a command's options."
    )
    p.epilog = "\n".join(lines)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # The settings file supplies parser defaults (--ws, --key), so find it first.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env-file")
    pre.add_argument("--url")
    pre.add_argument("command", nargs="?")
    early = pre.parse_known_args(argv)[0]
    try:  # config init/set may create the file it is given
        settings = load_settings(early.env_file, missing_ok=early.command == "config")
    except FileNotFoundError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 2
    path = settings.file
    if path and path.is_file() and os.name == "posix" and path.stat().st_mode & 0o077:
        print(
            f"{PROG}: warning: {_tilde(path)} is readable by other users"
            f" (chmod 600 {_tilde(path)})",
            file=sys.stderr,
        )
    p = parser(settings)
    args = p.parse_args(argv)
    if not args.command:  # bare `faig`: the grouped command list
        p.print_help()
        return 0
    settings = settings.with_flags(
        {"FAIG_URL": args.url, "FAIG_VERIFY_TLS": "false" if args.insecure else None}
    )
    try:
        if args.command == "config":
            page = CONFIG_COMMANDS[args.config or "list"](settings, args)  # bare `config` lists
        else:
            if not settings.get("FAIG_URL"):
                print(
                    f"{PROG}: no FAIG_URL: run `{PROG} config init`, or set"
                    " FAIG_URL (and FAIG_TOKEN or FAIG_USERNAME/FAIG_PASSWORD)",
                    file=sys.stderr,
                )
                return 2
            with FortiAIGate.from_env(settings) as c:
                page = args.fn(c, args)
    except (FaigError, LookupError, ValueError, TimeoutError, OSError) as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return 130
    if page is None:
        return 0
    if args.json:
        print(json.dumps(page.data, indent=2, default=str))
    else:
        v.render(page.blocks, plain=args.plain)
    return page.exit


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
