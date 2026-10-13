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

## Body builders

The API accepts bodies that store fine and then do nothing. The builders encode
the shapes that work:

- `regex_detector_body(name, [(rule_name, pattern, disposition)])` fills the
  flat `rules` list the engine matches on, not just the editor's `regexRules`
  (which alone matches nothing), and refuses an empty rule list.
- `dlp_detector_body(name, categories)` uses `disposition` (not `action`);
  category names come from `dlp_labels()`.
- `guardrail_body(name, detector_ids)` refuses a guardrail with no detectors.
