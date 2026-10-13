# pyfortiaigate

Python client for the **FortiAIGate 8.x** management API and its
OpenAI-compatible gateway. Standard library only: no dependencies, and the
client is one self-contained module you can copy onto a host that cannot
`pip install`.

```bash
pip install pyfortiaigate
```

```python
from pyfortiaigate import FortiAIGate, approve_new, regex_detector_body

with FortiAIGate("https://faig.example.com", "admin", "<password>") as faig:
    ws = faig.workspace_by_name("team-a")
    det = faig.create_detector(
        ws["id"], regex_detector_body("no-ssn", [("ssn", r"\d{3}-\d{2}-\d{4}", "block")])
    )
    approve_new(faig, ws["id"], "detectors", det)  # draft -> pending -> active
```

## What it handles for you

- **Auth:** session login (logs in on first call, again when the session
  expires) or a bearer token; a fresh CSRF token for every mutation.
- **Flaky networks:** transport failures are retried with backoff. A request
  that was never answered is retried for every method; a connection dropped
  after the request went out is retried only for GET, so a mutation is never
  sent twice.
- **One connection:** requests reuse a keep-alive HTTPS connection, which
  matters through tunnels where every new connect costs seconds.
- **Undocumented behaviour:** body builders encode what the API silently
  requires (a regex detector's flat `rules` list, DLP `disposition`, at least
  one detector per guardrail).

## Coverage

Users and invitations, workspaces, detectors (custom and built-in), guardrails
(including scan tests), policies, the approval workflow, virtual keys (create,
update, rotate, revoke), usage and cost reports, guardrail analytics, traffic and
ICAP logs, the detector Playground, Natural Language detectors, AI providers,
models and what a key may call, DLP labels, audit logs, and the gateway
(`check_key`, `available_models`, `chat_completion`).

Full reference: **https://ftnt-dspille.github.io/pyfortiaigate/**

## TLS

Verification is on by default. For an appliance with a self-signed
certificate, pass its CA: `FortiAIGate(url, user, pw, verify="/path/ca.pem")`.
`verify=False` turns checking off and is for isolated labs only.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest                 # offline suite, coverage enforced
.venv/bin/ruff format --check . && .venv/bin/ruff check .
.venv/bin/mypy src               # strict
.venv/bin/mkdocs serve           # docs at http://127.0.0.1:8000
```

Live tests are opt-in and read-only. Fill in `.env` (gitignored; copied from
`.env.example`), set `FAIG_LIVE=1`, then:

```bash
.venv/bin/pytest tests/live -v
```

Unofficial; not affiliated with or supported by Fortinet. MIT licensed.
