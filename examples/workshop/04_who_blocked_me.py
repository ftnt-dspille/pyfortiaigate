"""Which detectors blocked your key's last 10 requests, and on what? The
traffic log as a report instead of a page of clicks.

FIXME: count the blocks per detector.
"""

import sys
from collections import Counter

from lab import KEY_NAME, WS, connect

with connect() as faig:
    rows = list(
        faig.traffic_logs(
            range="24h", filters={"virtual_key": KEY_NAME, "verdict": "Block"}, ws_id=WS
        )
    )
    print(f"{len(rows)} blocked request(s) for {KEY_NAME} in the last 24h\n")

    per_detector: Counter = Counter()
    for row in rows[:10]:
        # A row is a summary; the full record has the prompt, tokens, cost and
        # "violation": what matched on each side, {"input": [...], "output": [...]}.
        rec = faig.traffic_log(row["uuid"], WS)
        prompt = (rec.get("prompt") or {}).get("original") or ""
        side = rec.get("guardType") or "input"
        for hit in (rec.get("violation") or {}).get(side) or []:
            print(
                f"  {side:<6} {hit['detectorName']:<28} {hit['details'][:40]:<41} {prompt[:30]!r}"
            )

            # FIXME: count this hit against its detector's name
            # (hint: a Counter works like a dict: per_detector[name] += 1)

    if rows and not per_detector:
        sys.exit("\nFIXME: per_detector is still empty")
    print(f"\nBlocks per detector, last {min(len(rows), 10)} blocked requests:")
    for name, n in per_detector.most_common():
        print(f"  {n:>3}  {name}")
