"""``pyfortiaigate`` on the command line: quick looks at a FortiAIGate without
writing a script. Read-only apart from ``chat`` (one gateway request).

Connection settings come from the environment (FAIG_URL plus FAIG_TOKEN or
FAIG_USERNAME/FAIG_PASSWORD, FAIG_CA_BUNDLE, FAIG_VERIFY_TLS). ``--env-file``
names a settings file whose FAIG_* lines fill in what the shell does not set;
no file is read unless it is named, so a ``.env`` in whatever directory you
happen to be in cannot redirect your credentials.

    pyfortiaigate workspaces
    pyfortiaigate keys --ws team-a
    pyfortiaigate cost --days 1 --by key
    pyfortiaigate logs --key student04-key --verdict Block
    pyfortiaigate models --key faig_...
    pyfortiaigate scan --ws team-a --guardrail pii "my SSN is 123-45-6789"
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .client import (
    FaigError,
    FortiAIGate,
    blocked,
    breakdown_items,
    rank_items,
)


def load_env(path: Path) -> None:
    """FAIG_*=value lines from ``path`` into the environment; the shell wins
    and other keys are ignored."""
    if not path.is_file():
        raise FileNotFoundError(f"no settings file {path}")
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip().strip("'\"")
        if key.startswith("FAIG_") and value and key not in os.environ:
            os.environ[key] = value


def table(rows: Iterable[Mapping[str, Any]], columns: Sequence[str]) -> str:
    """Rows as aligned text columns (a column may be a dotted path)."""
    cells = [[_cell(_dig(r, c)) for c in columns] for r in rows]
    widths = [max([len(c)] + [len(row[i]) for row in cells]) for i, c in enumerate(columns)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(columns, widths, strict=True)).rstrip()]
    lines += [
        "  ".join(v.ljust(w) for v, w in zip(row, widths, strict=True)).rstrip() for row in cells
    ]
    return "\n".join(lines)


def _dig(row: Mapping[str, Any], path: str) -> Any:
    value: Any = row
    for part in path.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _when(ms: Any) -> str:
    try:
        return dt.datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return "-"


def _window(args: argparse.Namespace) -> tuple[str | None, str | None]:
    if args.days:
        today = dt.date.today()
        return (today - dt.timedelta(days=args.days - 1)).isoformat(), today.isoformat()
    return args.frm, args.to


# -- commands ------------------------------------------------------------------------
def cmd_whoami(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return c.me()


def cmd_workspaces(c: FortiAIGate, args: argparse.Namespace) -> Any:
    rows = c.workspaces() if not args.mine else c.my_workspaces()
    return rows, ["workspaceName", "id", "memberCount", "grantedModelCount", "spend"]


def cmd_detectors(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return c.detectors(args.ws), ["name", "uuid", "detectorType", "approvalStatus"]


def cmd_guardrails(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return c.guardrails(args.ws), ["name", "id", "status", "detectorIds"]


def cmd_policies(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return c.policies(args.ws), ["name", "id", "status", "responseScanMode"]


def cmd_keys(c: FortiAIGate, args: argparse.Namespace) -> Any:
    rows = c.virtual_keys(args.ws, status=args.status)
    return rows, ["keyName", "id", "status", "workspace.name", "spend", "rpm", "lastUsedAt"]


def cmd_models(c: FortiAIGate, args: argparse.Namespace) -> Any:
    if args.key:
        return [{"model": m} for m in c.available_models(args.key)], ["model"]
    if args.ws:
        return [{"model": m} for m in c.workspace_models(args.ws)], ["model"]
    return c.models(), ["publicName", "providerId", "healthStatus"]


def _report(c: FortiAIGate, args: argparse.Namespace, kind: str) -> Any:
    frm, to = _window(args)
    summary: Any = (c.usage_summary if kind == "usage" else c.cost_summary)(frm, to, ws_id=args.ws)
    rankings = (c.usage_rankings if kind == "usage" else c.cost_rankings)(
        frm, to, by=args.by, limit=args.limit, ws_id=args.ws
    )
    if args.json:
        return {"summary": summary, "rankings": rank_items(rankings)}
    window = summary.get("window") or {}
    if kind == "usage":
        totals = summary.get("totals") or {}
        head = (
            f"{window.get('from')} .. {window.get('to')}: {totals.get('requests', 0)} requests,"
            f" {totals.get('tokens', 0)} tokens"
        )
        cols = ["name", "requests", "tokens", "status"]
    else:
        spend = (summary.get("totals") or {}).get("chargebackSpend") or {}
        volume = summary.get("volume") or {}
        head = (
            f"{window.get('from')} .. {window.get('to')}: ${spend.get('amount', 0):.4f}"
            f" over {volume.get('requests', 0)} requests, {volume.get('tokens', 0)} tokens"
        )
        cols = ["name", "chargebackSpend.amount", "volume.requests", "volume.tokens", "status"]
    print(head)
    print(f"\nTop {args.limit} by {args.by}:")
    return rank_items(rankings), cols


def cmd_usage(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return _report(c, args, "usage")


def cmd_cost(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return _report(c, args, "cost")


def cmd_breakdown(c: FortiAIGate, args: argparse.Namespace) -> Any:
    frm, to = _window(args)
    fn = c.usage_breakdown if args.kind == "usage" else c.cost_breakdown
    data = fn(args.by, args.id, frm, to, ws_id=args.ws)
    return (data if args.json else breakdown_items(data)), ["name", "requests", "tokens"]


def cmd_logs(c: FortiAIGate, args: argparse.Namespace) -> Any:
    filters: dict[str, Any] = {}
    for field in ("verdict", "user", "model"):
        if getattr(args, field):
            filters[field] = getattr(args, field)
    if args.key:
        filters["virtual_key"] = args.key
    if args.workspace_filter:
        filters["workspace"] = args.workspace_filter
    rows = [
        {**r, "time": _when(r.get("timeStamp"))}
        for r in c.traffic_logs(
            range=args.range, filters=filters, max_items=args.limit, ws_id=args.ws
        )
    ]
    return rows, ["time", "verdictLabel", "action", "keyAlias", "user", "model", "uuid"]


def cmd_log(c: FortiAIGate, args: argparse.Namespace) -> Any:
    return c.traffic_log(args.uuid, args.ws)


def cmd_audit(c: FortiAIGate, args: argparse.Namespace) -> Any:
    filters = {f: getattr(args, f) for f in ("user", "action") if getattr(args, f)}
    rows = [
        {**r, "time": _when(r.get("timeStamp"))}
        for r in c.iter_audit_logs(
            range=args.range, filters=filters, max_items=args.limit, ws_id=args.ws
        )
    ]
    return rows, ["time", "username", "actionLabel", "type", "message"]


def cmd_scan(c: FortiAIGate, args: argparse.Namespace) -> Any:
    if args.detector:
        out = c.test_guardrail(args.text, args.detector, ws_id=args.ws)
    else:
        out = c.test_guardrail(args.text, guardrail_id=args.guardrail, ws_id=args.ws)
    if args.json:
        return out
    print(f"finalDisposition: {out.get('finalDisposition')}")
    return out.get("results") or [], [
        "detectorId",
        "matched",
        "finalDisposition",
        "score",
        "details",
    ]


def cmd_chat(c: FortiAIGate, args: argparse.Namespace) -> Any:
    out = c.chat_completion(
        args.key, args.model, [{"role": "user", "content": args.text}], max_tokens=args.max_tokens
    )
    if args.json:
        return out
    choice = (out.get("choices") or [{}])[0]
    print(("BLOCKED: " if blocked(out) else "") + str((choice.get("message") or {}).get("content")))
    return None


def cmd_licenses(c: FortiAIGate, args: argparse.Namespace) -> Any:
    data = c.licenses()
    return (data.get("licenses") or []) if isinstance(data, dict) else [], [
        "serialNumber",
        "status",
        "endDate",
    ]


# -- parser --------------------------------------------------------------------------
def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyfortiaigate",
        description="Look at a FortiAIGate from the shell (settings from FAIG_*; see --env-file).",
    )
    p.add_argument("--env-file", help="settings file with FAIG_* lines (e.g. .env)")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, fn: Any, help: str, ws: bool = True) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help, description=help)
        sp.set_defaults(fn=fn)
        if ws:
            sp.add_argument("--ws", help="workspace name or id (default: org-wide)")
        return sp

    def window(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--days", type=int, help="the last N days, today included")
        sp.add_argument("--from", dest="frm", help="YYYY-MM-DD (default: 30 days ago)")
        sp.add_argument("--to", help="YYYY-MM-DD (default: today)")

    add("whoami", cmd_whoami, "the logged-in user", ws=False)
    add("workspaces", cmd_workspaces, "workspaces", ws=False).add_argument(
        "--mine", action="store_true", help="only the ones you belong to"
    )
    add("detectors", cmd_detectors, "custom detectors")
    add("guardrails", cmd_guardrails, "guardrails")
    add("policies", cmd_policies, "policies")
    add("keys", cmd_keys, "virtual keys").add_argument("--status", help="e.g. active, revoked")
    sp = add("models", cmd_models, "org models, a workspace's, or what a key may call")
    sp.add_argument("--key", default=os.environ.get("FAIG_KEY"), help="faig_... secret (FAIG_KEY)")
    for kind in ("usage", "cost"):
        sp = add(kind, cmd_usage if kind == "usage" else cmd_cost, f"{kind} summary and top items")
        window(sp)
        sp.add_argument("--by", default="key", choices=["key", "user", "workspace", "model"])
        sp.add_argument("--limit", type=int, default=10)
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
    add("log", cmd_log, "one traffic log record in full").add_argument("uuid")
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
    sp = add("chat", cmd_chat, "send one prompt through the gateway", ws=False)
    key = os.environ.get("FAIG_KEY")
    sp.add_argument("--key", default=key, required=not key, help="faig_... secret (FAIG_KEY)")
    sp.add_argument("--model", required=True)
    sp.add_argument("--max-tokens", type=int, default=256)
    sp.add_argument("text")
    add("licenses", cmd_licenses, "appliance licenses", ws=False)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Read the settings file before building the parser: its defaults use FAIG_KEY.
    env_file = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--env-file"), None)
    if env_file:
        try:
            load_env(Path(env_file))
        except FileNotFoundError as e:
            print(f"pyfortiaigate: {e}", file=sys.stderr)
            return 2
    args = parser().parse_args(argv)
    if not os.environ.get("FAIG_URL"):
        print(
            "pyfortiaigate: set FAIG_URL (and FAIG_TOKEN or FAIG_USERNAME/FAIG_PASSWORD)",
            file=sys.stderr,
        )
        return 2
    if args.insecure:
        os.environ["FAIG_VERIFY_TLS"] = "false"
    try:
        with FortiAIGate.from_env() as c:
            result = args.fn(c, args)
    except (FaigError, LookupError, ValueError, TimeoutError) as e:
        print(f"pyfortiaigate: {e}", file=sys.stderr)
        return 1
    if result is None:
        return 0
    if isinstance(result, tuple):
        rows, columns = result
        if args.json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print(table(rows, columns) if rows else "(none)")
    else:
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
