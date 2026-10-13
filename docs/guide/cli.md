# Command line

Installing the package adds a `pyfortiaigate` command (also
`python -m pyfortiaigate`) for quick looks without writing a script. Everything
is read-only except `chat`, which sends one prompt through the gateway.

```bash
pip install "pyfortiaigate[cli]"    # with rich: colour, panels and bar charts
pip install pyfortiaigate           # no dependencies: the same output as plain text
```

With the `[cli]` extra, a terminal gets coloured tables, panels and bar charts
drawn with [rich](https://rich.readthedocs.io). A pipe (`| grep`, `| less`, a
log file) always gets plain aligned text, and so does `--plain` or
`FAIG_CLI_STYLE=plain`. `FAIG_CLI_STYLE=rich` forces the rich form.

## Settings

Settings come from the same `FAIG_*` variables as `FortiAIGate.from_env()`.
A settings file's `FAIG_*` lines fill in what the shell does not set (other
lines are ignored). Put yours in `~/.config/pyfortiaigate/.env` and every
command finds it; `chmod 600` it, since it holds your password (the command
warns when other users can read it). `--env-file <path>` or `FAIG_ENV_FILE`
reads a different file instead. A `.env` in the current directory is never
read, so a stray one cannot point your credentials at another server.

Two settings save typing: `FAIG_WS` is the default `--ws` (pass `--ws ''` for
the org-wide view), and `FAIG_KEY` the default `--key`.

## One screen

```bash
pyfortiaigate dashboard --ws team-a            # the last 7 days; --days 30 for a month
```

Requests, tokens and spend; how many requests were blocked; blocks per detector
(read from the most recent blocked records, `--sample 20`); spend by model;
requests per day; and the latest blocked prompts with what stopped them.

## Who am I, and what is configured?

```bash
pyfortiaigate whoami
pyfortiaigate workspaces --mine
pyfortiaigate members --ws team-a
pyfortiaigate guardrails --ws team-a           # each with its detectors, by name
pyfortiaigate builtins                         # built-in detectors and their ids
pyfortiaigate keys --ws team-a --status active
pyfortiaigate check-key --key faig_...         # valid? which models may it call?
```

## What did a run cost?

```bash
pyfortiaigate cost --days 1 --by key
pyfortiaigate usage --from 2026-10-01 --to 2026-10-13 --by workspace --limit 5
pyfortiaigate trend cost --ws team-a --days 14  # a bar per day
pyfortiaigate trend usage --interval hourly --days 1 --measure tokens
pyfortiaigate breakdown cost key <key-id> --days 1
```

## Why was a student blocked?

```bash
pyfortiaigate logs --key student04-key --verdict Block --range 24h
pyfortiaigate logs --ws team-a --follow          # new rows as they arrive; Ctrl+C stops
pyfortiaigate log <uuid>                         # verdict, prompt, answer and what matched
pyfortiaigate scan --ws team-a --guardrail pii "my SSN is 123-45-6789"
pyfortiaigate chat --key faig_... --model gpt-4o-mini "hello"
```

`scan` runs a guardrail (or `--detector` ids) over text without calling a model:
no tokens, nothing in the traffic log.

## Try a regex before you save it

```bash
pyfortiaigate try-regex --ws team-a '(?i)\bPA-\d{3,4}\b' "Order four PA-5450" "Spa-1000 day"
```

Each line says MATCH or `-`, with the matched text highlighted (`[bracketed]`
in plain text). It uses the detector Playground, so nothing is saved and nothing
needs approval.

## Other commands

| Command | Shows |
|---|---|
| `detectors`, `policies` | A workspace's (`--ws`) or the org's objects |
| `models` | Org models; `--ws` a workspace's allowed models; `--key` what a key may call |
| `audit --action Approve --range 7d` | Audit log rows |
| `licenses` | Appliance licenses |

`--json` prints the raw API data instead, before or after the command:
`pyfortiaigate logs --key student04-key --json | jq`. `--insecure` skips TLS
verification. Exit status is 1 on an API error and 2 when no URL is configured.
