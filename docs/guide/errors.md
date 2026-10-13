# Errors & rate limits

## Exception types

Every HTTP error is a `FaigError`, raised as the subclass for its status, so
existing `except FaigError` code keeps working:

| Exception | Status | Typical cause |
|---|---|---|
| `AuthError` | 401, 403 | Bad credentials, a rejected virtual key, a call the role may not make |
| `NotFound` | 404 | No such object or path |
| `ModelNotAvailable` | 404 (gateway) | The key is not granted that model; `available_models(key)` lists what it may call |
| `Conflict` | 409 | A name already used in the workspace (`e.field == "name"`) |
| `ValidationError` | 400, 422 | The body was refused; the message usually lists the allowed values |
| `RateLimited` | 429 | A key's rpm/tpm limit |
| `ServerError` | 5xx | The appliance or an upstream provider failed |

Each carries `status`, `method`, `path`, the raw `body`, the decoded `data`,
the gateway's OpenAI-style `code` (`model_not_found`,
`rate_limit_exceeded`, ...) and the `field` a 409 or 422 names.

```python
from pyfortiaigate import Conflict, ModelNotAvailable

try:
    faig.chat_completion(secret, "gpt-4o", messages)
except ModelNotAvailable:
    print("this key may call:", faig.available_models(secret))

try:
    faig.create_detector("team-a", body)
except Conflict:
    pass  # already there; or use ensure_detector
```

Name lookups raise `LookupError` (no such name) or `ValueError` (two keys share
the name); see [Names & re-runnable setup](setup.md).

## Waiting out rate limits

A virtual key's `rpm`/`tpm` limit answers HTTP 429. By default the client
raises `RateLimited` at once. To wait and retry instead, give the client a
budget in seconds:

```python
faig = FortiAIGate.from_env(rate_limit_wait=90)
```

Within the budget a 429 is retried, for any method (a 429 means nothing was
processed): after `Retry-After` when the server sends one, otherwise after
1, 2, 4, ... seconds. FortiAIGate 8.0.2 sends no `Retry-After`, and an rpm
window is a minute long, so a budget under about 60 s rarely helps.
