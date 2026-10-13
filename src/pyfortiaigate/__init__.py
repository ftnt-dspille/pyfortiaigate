"""Python client for the FortiAIGate 8.x management and gateway API."""

from .client import (
    QUEUE_KIND,
    ROLE_ADMIN,
    ROLE_MEMBER,
    FaigError,
    FortiAIGate,
    approve_new,
    blocked,
    dlp_detector_body,
    guardrail_body,
    items,
    key_id_from_secret,
    key_update_body,
    origin,
    regex_detector_body,
    secret_from_response,
)

__all__ = [
    "QUEUE_KIND",
    "ROLE_ADMIN",
    "ROLE_MEMBER",
    "FaigError",
    "FortiAIGate",
    "approve_new",
    "blocked",
    "dlp_detector_body",
    "guardrail_body",
    "items",
    "key_id_from_secret",
    "key_update_body",
    "origin",
    "regex_detector_body",
    "secret_from_response",
]
