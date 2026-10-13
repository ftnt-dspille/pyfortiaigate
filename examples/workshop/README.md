# Workshop scripts

Short scripts for a hands-on FortiAIGate lab. Each one uses only your own
workspace and virtual key, through calls a workspace member can make.

```bash
python3 -m venv ~/faig-py && . ~/faig-py/bin/activate
pip install pyfortiaigate
mkdir -p ~/.config/pyfortiaigate
cp env.example ~/.config/pyfortiaigate/.env    # then fill it in
chmod 600 ~/.config/pyfortiaigate/.env
python 01_hello.py
```

| Script | What it does | To do |
|---|---|---|
| `01_hello.py` | who you are, your workspace's objects, does your key work | none, runs as-is |
| `02_red_team.py` | send a batch of prompts, report which were blocked | FIXME 1, FIXME 2 |
| `03_scan_first.py` | scan text with a guardrail, no model call, no tokens | FIXME |
| `04_who_blocked_me.py` | blocked requests from the traffic log, counted per detector | FIXME |
| `05_spend_report.py` | usage and spend for your workspace, by model | FIXME |
| `06_regex_playground.py` | try a regex detector in the Playground without saving it | FIXME |

The same settings file drives the command line:

```bash
pyfortiaigate whoami
pyfortiaigate logs --ws studentXX --verdict Block
```
