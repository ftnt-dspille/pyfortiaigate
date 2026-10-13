# Names & re-runnable setup

## Refer to things by name

Every argument that names a workspace, detector, guardrail, policy or virtual
key takes its **id**, its **name**, or the **record** you already hold:

```python
faig.create_guardrail("team-a", "pii", ["no-ssn", "prompt-injection"])
faig.create_policy("team-a", "pii-policy", ["pii"], ["pii"], provider_ids=["openai"])
faig.create_virtual_key("team-a", "student04", policy_ids=["pii-policy"])
faig.approve("guardrails", "pii")          # found in the review queue
faig.revoke_virtual_key("student04", ws_id="team-a")
```

A name is looked up in the method's workspace (`ws_id`), or org-wide when the
method has none. FortiAIGate refuses a second detector, guardrail or policy
with the same name in a workspace (409), so those names are unambiguous. A
detector name can also be a built-in detector's name or slug
(`"prompt-injection"`).

**Virtual key names are not unique.** If two keys share a name, the lookup
raises `ValueError` and you pass the id. A key can also be named by its
`faig_...` secret, which embeds its id.

Each lookup costs one list call; ids skip it. `resolve_detector`,
`resolve_guardrail`, `resolve_policy`, `resolve_virtual_key` and
`resolve_workspace` return the id if you want to look up once and reuse it.

## Re-runnable setup with `ensure_*`

Lab and onboarding scripts are re-run: after a partial failure, for a new
student, or to fix one setting. The `ensure_*` methods make an object match
what you ask for, by name, and do nothing when it already does:

```python
from pyfortiaigate import regex_detector_body

det = faig.ensure_detector(
    "team-a", regex_detector_body("no-ssn", [("ssn", r"\d{3}-\d{2}-\d{4}", "block")])
)
gr = faig.ensure_guardrail("team-a", "pii", ["no-ssn"])
pol = faig.ensure_policy("team-a", "pii-policy", ["pii"], ["pii"], provider_ids=["openai"])
key = faig.ensure_virtual_key("team-a", "student04", policy_ids=["pii-policy"], rpm=30)

print(det.action, gr.action, pol.action, key.action)  # created | updated | unchanged
if key.secret:  # only when the key was just created
    save(key.secret)
```

Each returns an `Ensured(record, action, secret)` with `.id` and `.changed`.

- **Compared fields** are the ones you pass. Fields the appliance adds (rule
  ids, counts, timestamps) are ignored, and lists of ids compare as sets.
- **Approval:** with `approve=True` (the default, org admin only) a new or
  still-draft object is submitted and approved, and an active object's pending
  change is approved. `approve=False` leaves it as it is.
- **Keys:** a key's secret is returned only when it is created. For an existing
  key `Ensured.secret` is None; rotate the key if you need a new one. Revoked
  keys are ignored, so `ensure_virtual_key` after a revoke creates a fresh key.
