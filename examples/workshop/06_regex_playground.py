"""Write a regex detector in code and try it in the detector Playground. Nothing
is saved, so nothing goes to your instructor for approval.

Spilleus keeps ordering Palo Alto gear by part number. Catch the part numbers
(PA- followed by three or four digits) and leave everything else alone.

FIXME: write PATTERN so every line below says ok.
"""

import sys

from pyfortiaigate import regex_detector_body

from lab import WS, connect

# FIXME: a regular expression for PA-440, PA-5450, PA-7080 ...
PATTERN = None

SAMPLES = [  # (text, should it match?)
    ("Order four PA-5450 firewalls through Supply", True),
    ("Ship a PA-440 to the Endor outpost", True),
    ("pa-7080 x2, expedite", True),
    ("Upgrade the FortiGate 3001F to 7.6", False),
    ("Spa-1000 day for the stormtroopers", False),
    ("Our NOVA-2000 coffee machine is broken", False),
]

if PATTERN is None:
    sys.exit("FIXME: set PATTERN (test it at https://regex101.com first if you like)")

body = regex_detector_body("panw-part-numbers", [("panw part", PATTERN, "block")])
with connect() as faig:
    wrong = 0
    for text, expected in SAMPLES:
        result = faig.playground(text, body, ws_id=WS)
        ok = result["matched"] == expected
        wrong += not ok
        print(f"{'ok' if ok else 'WRONG':<6} matched={result['matched']!s:<5} {text}")
    print("\nAll correct!" if not wrong else f"\n{wrong} wrong: adjust PATTERN and run again")
