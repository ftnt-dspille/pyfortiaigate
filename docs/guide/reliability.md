# Reliability

## Retries

Transport failures are retried with exponential backoff: 1, 2, 4, 8, 16 s
(`retries=5` by default). What gets retried depends on whether the request may
already have been applied:

| Failure | GET | POST / PUT / PATCH / DELETE |
|---|---|---|
| Connect refused, reset during TLS, failed send (never answered) | retried | retried |
| Connection dropped after the request was sent | retried | **raised**: it may have landed |
| HTTP error status (4xx, 5xx) | raised | raised |

The one exception for HTTP statuses: a single re-login on `401` and a single
fresh CSRF token on a CSRF `403`. Each retry is logged as a warning on the
`pyfortiaigate` logger:

```python
import logging

logging.basicConfig(level=logging.WARNING)
```

When a mutation is raised after a drop, check the object's state before
retrying it yourself: a create may have succeeded.

## Connection reuse

Requests share one keep-alive HTTPS connection. Through a tunnel (IAP, SSH
port forwards) a new connection can cost seconds, and every mutation is two
requests (CSRF token, then the call). The connection is reopened after 30 s
idle, when the server closes it, or after any transport error.

The client is not thread-safe: give each thread its own `FortiAIGate`.

## Timeouts

`timeout=60` seconds per request by default. `chat_completion` uses at least
120 s, since a completion waits on the upstream model.
