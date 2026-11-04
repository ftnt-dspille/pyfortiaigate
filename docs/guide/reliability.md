# Reliability

## Retries

Transport failures are retried with exponential backoff: 1, 2, 4, 8, 16 s
(`retries=5` by default). What gets retried depends on whether the request may
already have been applied:

| Failure | GET | POST / PUT / PATCH / DELETE |
|---|---|---|
| Connect refused, reset during TLS, failed send (never answered) | retried | retried |
| Connection dropped after the request was sent | retried | **raised**: it may have landed |
| HTTP `500` / `502` / `503` / `504` on a **gateway call** (chat, models) | retried | retried |
| HTTP `500` / `502` / `503` / `504` on a management call | retried | **raised**: it may have landed |
| Any other HTTP error status | raised | raised |

A gateway call is safe to repeat (a chat completion or a model list changes nothing),
so a transient `500` from the gateway or its model provider is retried up to
`server_retries=3` times with backoff of 1, 2, 4 s, then raised as `ServerError`.
Set `server_retries=0` to turn it off. The 7 seconds of backoff covers a brief blip, not an
outage: when the gateway marks an upstream down (`503` "every upstream credential for this
model is currently unavailable") it can stay that way for a minute or more, and the call
still raises `ServerError`.

The other exceptions for HTTP statuses: a single re-login on `401`, a single fresh
CSRF token on a CSRF `403`, and waiting out `429` when the client has a
`rate_limit_wait` budget (see [Errors & rate limits](errors.md)). Each retry is logged as a warning on the
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
