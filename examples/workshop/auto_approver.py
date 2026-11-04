"""Instructor script: auto-approve every student change during a class.

Every student change to a detector, guardrail or policy waits in the org admin's
review queue, and FortiAIGate has no setting to turn that off. This loop clears
the queue so students never wait on you. Leave it running for the whole class.

Run it as the ORG ADMIN (not a student). It reads the same settings as the
``pyfortiaigate`` command line: FAIG_URL, FAIG_USERNAME and FAIG_PASSWORD from the
environment or from ``~/.config/pyfortiaigate/.env`` (written by
``pyfortiaigate config init``; FAIG_ENV_FILE points at another file). FAIG_WS and
FAIG_KEY are not needed. It loops until Ctrl+C; --interval sets the pause.

    python auto_approver.py student            # every workspace named student*
    python auto_approver.py student01 student02 student03
    python auto_approver.py student --once     # clear the queue once and exit

Safety rules this follows:

* Only approves changes owned by the workspaces you name. Anything else in the
  queue (the org's own work, other classes) is left alone.
* Approving by id, never by name: the same name can be pending in several
  workspaces.
* A change someone else approved first (or a student withdrew) is not an error.
* The session expires after ~24 minutes; the client logs in again on its own, so
  the loop can run all day.
* The workspace list is re-read on every pass, so workspaces created after the
  loop started are picked up.

On a class VM the same loop runs as a systemd service started at boot, so a
laptop closing its lid does not stop it. See ``docs/guide/approval.md``.
"""

from __future__ import annotations

import argparse
import sys
import time

from pyfortiaigate import QUEUE_KIND, FaigError, FortiAIGate
from pyfortiaigate.settings import load_settings


def class_workspace_ids(faig: FortiAIGate, names: list[str]) -> set[str]:
    """Ids of the workspaces whose name equals, or starts with, one of ``names``."""
    return {
        w["id"]
        for w in faig.workspaces()
        if any(str(w.get("workspaceName", "")).startswith(n) for n in names)
    }


def approve_pending(faig: FortiAIGate, ws_ids: set[str]) -> int:
    """Approve every queued change owned by ``ws_ids``. Returns how many."""
    done = 0
    for item in faig.review_queue():
        if item.get("ownerWorkspaceId") not in ws_ids:
            continue  # never approve anything outside the class
        kind = QUEUE_KIND.get(item.get("type", ""))
        if not kind:
            continue
        try:
            faig.approve(kind, item["id"])
        except FaigError as e:
            # Lost a race (already approved or withdrawn): fine. Say so, move on.
            print(f"skipped {item['type']} {item['name']!r}: {e}", file=sys.stderr)
            continue
        who = (item.get("submittedBy") or {}).get("email", "?")
        print(
            f"approved {item['type']} {item['name']!r} ({item.get('changeKind')}) from {who}",
            flush=True,
        )
        done += 1
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("workspaces", nargs="+", help="workspace names or name prefixes to approve for")
    ap.add_argument("--once", action="store_true", help="clear the queue once and exit")
    ap.add_argument(
        "--interval", type=float, default=3.0, help="seconds between passes (default 3)"
    )
    args = ap.parse_args()

    total = 0
    with FortiAIGate.from_env(load_settings()) as faig:
        while True:
            try:
                total += approve_pending(faig, class_workspace_ids(faig, args.workspaces))
            except FaigError as e:
                # FAIG still coming up, or a blip: keep going rather than die mid-class.
                print(f"pass failed, retrying: {e}", file=sys.stderr)
            if args.once:
                break
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                break
    print(f"approved {total} change(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
