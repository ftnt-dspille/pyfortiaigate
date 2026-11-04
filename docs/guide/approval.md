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

A laptop closing its lid stops the loop. For a real class, run the same script
on the lab VM as a `systemd` service with `Restart=always` so it starts at boot
and recovers from FortiAIGate still coming up.

## Body builders

The API accepts bodies that store fine and then do nothing. The builders encode
the shapes that work:

- `regex_detector_body(name, [(rule_name, pattern, disposition)])` fills the
  flat `rules` list the engine matches on, not just the editor's `regexRules`
  (which alone matches nothing), and refuses an empty rule list.
- `dlp_detector_body(name, categories)` uses `disposition` (not `action`);
  category names come from `dlp_labels()`.
- `guardrail_body(name, detector_ids)` refuses a guardrail with no detectors.
