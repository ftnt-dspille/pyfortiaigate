# Authentication & TLS

## Session login

```python
faig = FortiAIGate("https://faig.example.com", "a@example.com", "<password>")
```

The login name is the account's **email** (the built-in administrator is
`admin`). The client logs in on its first call, not in the constructor, so
creating a client never touches the network. Call `login()` to fail fast.

Sessions expire (about 24 minutes on 8.0.2). A `401` means nothing was applied,
so the client logs in again and resends the request once. A second `401` raises
`FaigError`.

Every mutation (POST, PUT, PATCH, DELETE) carries a fresh `X-CSRF-Token`
fetched just before it. A `403` that names the CSRF token is retried once with
a new token.

## Bearer token

```python
faig = FortiAIGate("https://faig.example.com", token="<token>")
```

No login and no CSRF exchange; a `401` is raised as-is.

## Virtual keys are not API credentials

A virtual key (`faig_...`) authenticates on the **gateway** only. Pass it to
`check_key` or `chat_completion`; it is never accepted on `/api/v1/*`.

## TLS

| `verify=` | Behaviour |
|---|---|
| `True` (default) | System trust store. |
| `"/path/ca.pem"` | Trust the CA that signed the appliance's certificate. Use this for a self-signed appliance. |
| `False` | No verification. Only for an isolated lab you control. |

## Errors

Every HTTP status >= 400 raises `FaigError` with `.status`, `.method`, `.path`
and the raw response `.body`. The message uses the response's `error`,
`message` or `detail` field when there is one.
