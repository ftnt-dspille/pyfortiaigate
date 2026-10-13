"""What has your workspace spent, and on which model? The numbers behind the
console's Usage and Cost pages.

FIXME: rank the spend by model.
"""

import sys

from pyfortiaigate import rank_items

from lab import WS, connect

with connect() as faig:
    usage = faig.usage_summary(ws_id=WS)  # default window: the last 30 days
    cost = faig.cost_summary(ws_id=WS)
    window = cost["window"]
    spend = cost["totals"]["chargebackSpend"]
    print(f"{WS}, {window['from']} .. {window['to']}")
    print(f"  requests  {usage['totals']['requests']}")
    print(f"  tokens    {usage['totals']['tokens']}")
    print(f"  spend     ${spend['amount']:.6f}  (${spend.get('perRequest') or 0:.6f} per request)")

    # FIXME: the cost rankings for this workspace, grouped BY MODEL.
    # Find the method on https://ftnt-dspille.github.io/pyfortiaigate/actions/
    # (remember ws_id=WS, or you are asking for the whole organization).
    rankings = None

    if rankings is None:
        sys.exit("\nFIXME: set rankings")
    print("\nSpend by model:")
    for item in rank_items(rankings):
        amount = (item.get("chargebackSpend") or {}).get("amount") or 0
        print(f"  ${amount:.6f}  {item.get('name')}")
