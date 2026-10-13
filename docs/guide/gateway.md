# Virtual keys & the gateway

## Creating a key

```python
key = faig.create_virtual_key(ws_id, "app", policy_ids=[policy_id], provider_ids=["openai"])
secret = secret_from_response(key)  # returned ONCE; store it now
```

The secret is never readable again. It embeds the key's id, so code that only
holds the secret can still manage the key:

```python
faig.revoke_virtual_key(key_id_from_secret(secret))
```

`rotate_virtual_key` returns a new secret, once, the same way.
`update_virtual_key` reads the current record and resends it with your changes,
because the API replaces the whole record; `policy_ids` replaces the attached
policy list.

## Using a key

```python
faig.check_key(secret)
# {"valid": True, "model_count": 4, "http_status": 200}

reply = faig.chat_completion(secret, "gpt-4o-mini", [{"role": "user", "content": "hi"}])
```

The gateway applies the key's policies. **A guardrail block is not an error:**
the gateway answers HTTP 200 with `finish_reason: "content_filter"`. Test for it
with `blocked(reply)`.

If the gateway is served from a different host than the management console,
pass `gateway_url=` to the client.
