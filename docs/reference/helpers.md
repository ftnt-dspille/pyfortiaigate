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

::: pyfortiaigate.Renewed

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
| [](){#pyfortiaigate.client.ROLE_MEMBER}[](){#pyfortiaigate.ROLE_MEMBER}`ROLE_MEMBER` | `"org_member"` | default role for `invite` (8.0.2 rejects plain `member`) |
| [](){#pyfortiaigate.client.ROLE_ADMIN}[](){#pyfortiaigate.ROLE_ADMIN}`ROLE_ADMIN` | `"org_admin"` | org administrator |
| [](){#pyfortiaigate.client.QUEUE_KIND}[](){#pyfortiaigate.QUEUE_KIND}`QUEUE_KIND` | `{"guardrail": "guardrails", ...}` | review-queue `type` -> the `approve` / `reject` kind |
| [](){#pyfortiaigate.client.LOG_PAGE}[](){#pyfortiaigate.LOG_PAGE}`LOG_PAGE` | `50` | default page size for the log iterators (the console's) |
