# Command line

Installing the package adds a `pyfortiaigate` command (also
`python -m pyfortiaigate`) for quick looks without writing a script. Everything
is read-only except `chat`, which sends one prompt through the gateway.

Settings come from the same `FAIG_*` variables as `FortiAIGate.from_env()`. A
`.env` file in the current directory fills in what the shell does not set
(`--env-file` picks another).

```bash
pyfortiaigate whoami
pyfortiaigate workspaces
pyfortiaigate keys --ws team-a --status active
pyfortiaigate guardrails --ws team-a
```

## What did a run cost?

```bash
pyfortiaigate cost --days 1 --by key
pyfortiaigate usage --from 2026-10-01 --to 2026-10-13 --by workspace --limit 5
pyfortiaigate breakdown cost key <key-id> --days 1
```

## Why was a student blocked?

```bash
pyfortiaigate logs --key student04 --verdict Block --range 24h
pyfortiaigate log <uuid>                        # the full record: detector, guardrail, prompt
pyfortiaigate scan --ws team-a --guardrail pii "my SSN is 123-45-6789"
pyfortiaigate models --key faig_...             # which models the key may call
pyfortiaigate chat --key faig_... --model gpt-4o-mini "hello"
```

## Other commands

| Command | Shows |
|---|---|
| `detectors`, `policies` | A workspace's (`--ws`) or the org's objects |
| `models` | Org models; `--ws` a workspace's allowed models; `--key` what a key may call |
| `audit --action Approve --range 7d` | Audit log rows |
| `licenses` | Appliance licenses |

Add `--json` before the command for raw JSON, for example
`pyfortiaigate --json logs --key student04 | jq`. `--insecure` skips TLS
verification. Exit status is 1 on an API error and 2 when no URL is configured.
