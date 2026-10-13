"""``python -m pyfortiaigate``: the command-line tool (see ``pyfortiaigate.cli``)."""

import sys  # pragma: no cover

from .cli import main

sys.exit(main())
