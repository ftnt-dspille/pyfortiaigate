# pyfortiaigate

Python client for the **FortiAIGate 8.x** management API and its
OpenAI-compatible gateway.

- **No dependencies.** Standard library only; the client is one self-contained
  module you can copy onto a host that cannot `pip install`.
- **Handles the API's sharp edges:** session login and re-login, a CSRF token
  per mutation, and body builders for what the API silently requires.
- **Safe retries.** A request that was never answered is retried; a mutation
  that may already have landed is never sent twice.
- **Typed** (`py.typed`, mypy `--strict`) and tested against a local HTTP
  server, with coverage enforced.

## Install

```bash
pip install pyfortiaigate
```

Python 3.10+.

## Quick start

```python
from pyfortiaigate import FortiAIGate, blocked, regex_detector_body

with FortiAIGate("https://faig.example.com", "admin", "<password>") as faig:
    # A detector, a guardrail and a policy that use it. ensure_* creates what
    # is missing, updates what differs and approves it; safe to re-run.
    faig.ensure_detector(
        "team-a", regex_detector_body("no-ssn", [("ssn", r"\d{3}-\d{2}-\d{4}", "block")])
    )
    faig.ensure_guardrail("team-a", "pii", ["no-ssn"])
    faig.ensure_policy("team-a", "pii-policy", ["pii"], ["pii"], provider_ids=["openai"])

    # A virtual key bound to the policy, used on the gateway
    key = faig.ensure_virtual_key("team-a", "app", policy_ids=["pii-policy"])
    reply = faig.chat_completion(
        key.secret, "gpt-4o-mini", [{"role": "user", "content": "My SSN is 123-45-6789"}]
    )
    print("blocked" if blocked(reply) else reply["choices"][0]["message"]["content"])
```

Workspaces, detectors, guardrails, policies and keys can be named directly:
see [Names & re-runnable setup](guide/setup.md). For quick looks from the shell
there is a [command line](guide/cli.md). Every method and the call it makes: [Actions](actions.md).

## Configuration from the environment

```python
faig = FortiAIGate.from_env()
```

| Variable | Meaning |
|---|---|
| `FAIG_URL` | Management URL (`https://host`, a bare host, or `https://host/api`) |
| `FAIG_USERNAME` / `FAIG_PASSWORD` | Session login (the account's email, or `admin`) |
| `FAIG_TOKEN` | Bearer token instead of a login |
| `FAIG_CA_BUNDLE` | CA file that signed the appliance's certificate |
| `FAIG_VERIFY_TLS` | `false` turns certificate checking off (isolated labs only) |

!!! note
    Unofficial; not affiliated with or supported by Fortinet. The management
    API has no published specification: behaviour documented here was verified
    against FortiAIGate 8.0.2.
