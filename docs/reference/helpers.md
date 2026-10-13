# Helpers & body builders

## Errors

::: pyfortiaigate.FaigError

::: pyfortiaigate.AuthError

::: pyfortiaigate.NotFound

::: pyfortiaigate.ModelNotAvailable

::: pyfortiaigate.Conflict

::: pyfortiaigate.ValidationError

::: pyfortiaigate.RateLimited

::: pyfortiaigate.ServerError

::: pyfortiaigate.error_for

## Results

::: pyfortiaigate.Ensured

## Body builders

::: pyfortiaigate.regex_detector_body

::: pyfortiaigate.dlp_detector_body

::: pyfortiaigate.ai_detector_body

::: pyfortiaigate.guardrail_body

## Workflow

::: pyfortiaigate.approve_new

## Responses

::: pyfortiaigate.items

::: pyfortiaigate.rank_items

::: pyfortiaigate.breakdown_items

::: pyfortiaigate.blocked

::: pyfortiaigate.collect_stream

::: pyfortiaigate.secret_from_response

::: pyfortiaigate.key_id_from_secret

::: pyfortiaigate.key_update_body

::: pyfortiaigate.origin

## Constants

| Name | Value | Use |
|---|---|---|
| `ROLE_MEMBER` | `"org_member"` | default role for `invite` (8.0.2 rejects plain `member`) |
| `ROLE_ADMIN` | `"org_admin"` | org administrator |
| `QUEUE_KIND` | `{"guardrail": "guardrails", ...}` | review-queue `type` -> the `approve` / `reject` kind |
