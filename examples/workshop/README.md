# Workshop scripts

Short scripts for a hands-on FortiAIGate lab. Each one uses only your own
workspace and virtual key, through calls a workspace member can make.

```bash
python3 -m venv ~/faig-py && . ~/faig-py/bin/activate
pip install "pyfortiaigate[cli]"
pyfortiaigate config init     # asks for your address, login, workspace and key
python 01_hello.py
```

| Script | What it does | To do |
|---|---|---|
| `01_hello.py` | who you are, your workspace's objects, does your key work | none, runs as-is |
| `02_red_team.py` | send a batch of prompts, report which were blocked | FIXME 1, FIXME 2 |
| `03_scan_first.py` | scan text with your DLP detector, no model call, no tokens | FIXME |
| `04_who_blocked_me.py` | blocked requests from the traffic log, counted per detector | FIXME |
| `05_spend_report.py` | usage and spend for your workspace, by model | FIXME |
| `06_regex_playground.py` | try a regex detector without saving it | FIXME |

`scenarios.json` is the workshop's catalog of test prompts:

```bash
pyfortiaigate scenarios scenarios.json        # PASS or MISMATCH per case
```

The same settings drive the command line (`pyfortiaigate config` shows them):

```bash
pyfortiaigate dashboard
pyfortiaigate logs --verdict Block --follow
```
