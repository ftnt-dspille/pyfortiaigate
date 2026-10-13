"""Fail when the built docs contain a cross-reference that did not resolve.

mkdocstrings links the types in signatures optionally: an unresolved one is
rendered as plain text (``<span title="pyfortiaigate....">``) and the strict
build stays green. This makes it an error.

    mkdocs build --strict && python scripts/check_site_refs.py site
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

UNRESOLVED = re.compile(r'<span title="(pyfortiaigate\.[\w.]+)"')


def main(site: str) -> int:
    missing: dict[str, set[str]] = {}
    for page in Path(site).rglob("*.html"):
        for ref in UNRESOLVED.findall(page.read_text(encoding="utf-8")):
            missing.setdefault(ref, set()).add(str(page.relative_to(site)))
    for ref, pages in sorted(missing.items()):
        print(f"unresolved {ref} on {', '.join(sorted(pages))}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "site"))
