# Approval workflow

Detectors, guardrails and policies created inside a workspace start as
**draft** and only take effect once an org admin approves them:

```
draft --submit--> pending --approve--> active
                          --reject---> rejected
```

Editing an **active** guardrail or detector applies immediately, with no
re-approval.

## As the org admin

`approve_new` walks a freshly created object to active in one call:

```python
det = faig.create_detector(ws_id, body)
approve_new(faig, ws_id, "detectors", det)
```

If another approver gets there first (the object is no longer pending), that is
not an error.

## Reviewing what others submitted

```python
from pyfortiaigate import QUEUE_KIND

for item in faig.review_queue():
    faig.approve(QUEUE_KIND[item["type"]], item["id"])
```

## Auto-approving a whole class

Every student change waits for an org admin, and FortiAIGate has no setting to
turn that off. For a class, run a loop that clears the queue for the class's
workspaces only. The full script is `examples/workshop/auto_approver.py`; the
core is:

```python
from pyfortiaigate import QUEUE_KIND, FaigError

def approve_pending(faig, ws_ids: set[str]) -> int:
    done = 0
    for item in faig.review_queue():
        if item.get("ownerWorkspaceId") not in ws_ids:
            continue                      # never approve outside the class
        try:
            faig.approve(QUEUE_KIND[item["type"]], item["id"])   # by id, not name
            done += 1
        except FaigError:
            pass                          # someone approved or withdrew it first
    return done
```

Run it as the org admin and leave it running:

```bash
python examples/workshop/auto_approver.py student      # every workspace named student*
python examples/workshop/auto_approver.py student --once
```

Rules worth keeping: approve by id (the same name can be pending in several
workspaces), re-read the workspace list every pass (workspaces created after the
loop started are picked up), and treat a lost race as normal. The client logs in
again by itself when the ~24 minute session expires, so the loop can run all day.

### Setup: how the script gets its credentials

The script reads the same settings as the `pyfortiaigate` command line
(`load_settings()`), in this order: a `FAIG_*` environment variable, then the
settings file. It needs the **org admin** login, not a student's, and it does not
need `FAIG_WS` or `FAIG_KEY`.

1. Install the library: `pip install pyfortiaigate` (the `[cli]` extra is only
   for the `pyfortiaigate` command).
2. Write the settings file once: `pyfortiaigate config init`. It asks for the
   address, login and password and saves them to
   `~/.config/pyfortiaigate/.env` with mode `0600`. Or write it by hand:

   ```
   FAIG_URL=https://faig.example.com
   FAIG_USERNAME=admin@example.com
   FAIG_PASSWORD=<your-password>
   FAIG_VERIFY_TLS=false      # only for a lab appliance with a self-signed certificate
   ```

3. Check it: `pyfortiaigate config` shows what is set (secrets masked) and
   `pyfortiaigate whoami` proves the login works.

To keep the admin login apart from your own, put it in a separate file and point
at it: `FAIG_ENV_FILE=/path/to/admin.env python auto_approver.py student`.
A `.env` in the current directory is never read.

### Running it in a loop

The script already loops: it checks the queue every 3 seconds (`--interval N`
changes that) until you press Ctrl+C, and `--once` runs a single pass. Start it
before class and leave it in the foreground of a terminal (`tmux` or `screen`
keeps it alive if you disconnect):

```bash
python examples/workshop/auto_approver.py student --interval 5
```

On the lab VM, run it as a service so it starts at boot and restarts on any
error (FortiAIGate still coming up, a network blip). Put the settings in a
root-only file and let `systemd` supply them:

```ini
# /etc/systemd/system/faig-approver.service
[Unit]
Description=FortiAIGate class auto-approver
After=network-online.target

[Service]
EnvironmentFile=/etc/faig-approver.env      # FAIG_URL, FAIG_USERNAME, FAIG_PASSWORD
ExecStart=/usr/bin/python3 /opt/faig-approver/auto_approver.py student
Restart=always
RestartSec=15
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo install -m 600 -o root admin.env /etc/faig-approver.env
sudo systemctl daemon-reload && sudo systemctl enable --now faig-approver
journalctl -u faig-approver -f          # one "approved ..." line per change
```

`EnvironmentFile` takes plain `NAME=value` lines with no `export` and no quotes
around the value. `systemctl stop faig-approver` ends it after class.

## Body builders

The API accepts bodies that store fine and then do nothing. The builders encode
the shapes that work:

- `regex_detector_body(name, [(rule_name, pattern, disposition)])` fills the
  flat `rules` list the engine matches on, not just the editor's `regexRules`
  (which alone matches nothing), and refuses an empty rule list.
- `dlp_detector_body(name, categories)` uses `disposition` (not `action`);
  category names come from `dlp_labels()`.
- `guardrail_body(name, detector_ids)` refuses a guardrail with no detectors.
