"""Builds without the guardrail tester or the unsaved-detector Playground.

Later 8.0.2 builds dropped ``POST .../guardrails/test`` and ``POST .../detectors/test``
(both answer 405); only a SAVED custom detector can be tested
(``POST .../detectors/{uuid}/test``), and built-in detectors not at all.
"""

from __future__ import annotations

import uuid

import pytest

from pyfortiaigate import FaigError, FortiAIGate, dlp_detector_body, regex_detector_body

from .conftest import FakeFaig

WS = "/api/v1/workspaces/w1"


def _id() -> str:
    return str(uuid.uuid4())


def test_guardrail_scan_falls_back_to_one_detector_at_a_time(
    faig: FortiAIGate, fake: FakeFaig
) -> None:
    dlp, rx = _id(), _id()
    fake.answer(
        "GET", f"{WS}/guardrails/g1", (200, {"id": "g1", "detectorIds": [dlp, rx, "mitre-atlas"]})
    )
    fake.answer("POST", f"{WS}/guardrails/test", (405, "Method Not Allowed"))
    fake.answer(
        "POST",
        f"{WS}/detectors/{dlp}/test",
        (200, {"matched": True, "finalDisposition": "block", "details": "CVV x1 (block)"}),
    )
    fake.answer(
        "POST", f"{WS}/detectors/{rx}/test", (200, {"matched": True, "finalDisposition": "alert"})
    )
    out = faig.test_guardrail("card 4532 cvv 391", guardrail_id="g1", ws_id="w1")
    assert out["finalDisposition"] == "block"
    rows = {r["detectorId"]: r for r in out["results"]}
    assert rows[dlp]["status"] == "tested"
    assert rows[dlp]["matched"]
    assert rows["mitre-atlas"]["status"] == "untested"
    assert not rows["mitre-atlas"]["matched"]
    assert fake.calls("POST", f"{WS}/detectors/{dlp}/test")[0].body == {
        "input": "card 4532 cvv 391"
    }


def test_a_missing_guardrail_tester_is_remembered(faig: FortiAIGate, fake: FakeFaig) -> None:
    d = _id()
    fake.answer("POST", f"{WS}/guardrails/test", (405, "Method Not Allowed"))
    fake.answer("POST", f"{WS}/detectors/{d}/test", (200, {"matched": False}))
    faig.test_guardrail("one", [d], ws_id="w1")
    faig.test_guardrail("two", [d], ws_id="w1")
    assert len(fake.calls("POST", f"{WS}/guardrails/test")) == 1


def test_only_built_ins_leave_no_disposition(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", "/api/v1/admin/guardrails/test", (404, "404 page not found"))
    out = faig.test_guardrail("hi", [{"id": "mitre-atlas"}])
    assert out["finalDisposition"] is None
    assert [r["status"] for r in out["results"]] == ["untested"]


def test_other_errors_are_not_swallowed(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", f"{WS}/guardrails/test", (403, "forbidden"))
    with pytest.raises(FaigError):
        faig.test_guardrail("hi", [_id()], ws_id="w1")


def test_playground_matches_a_regex_body_locally(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", f"{WS}/detectors/test", (405, "Method Not Allowed"))
    body = regex_detector_body("parts", [("pa", r"(?i)\bPA-\d{3,4}\b", "block")])
    hit = faig.playground("Order four PA-5450 and a pa-440", body, "w1")
    miss = faig.playground("Spa-1000 day for the stormtroopers", body, "w1")
    assert hit["matched"]
    assert hit["finalDisposition"] == "block"
    assert hit["checkedLocally"]
    assert hit["spans"] == [{"start": 11, "end": 18}, {"start": 25, "end": 31}]
    assert not miss["matched"]
    assert miss["spans"] == []
    assert len(fake.calls("POST", f"{WS}/detectors/test")) == 1  # remembered


def test_playground_cannot_fake_a_dlp_body(faig: FortiAIGate, fake: FakeFaig) -> None:
    fake.answer("POST", f"{WS}/detectors/test", (405, "Method Not Allowed"))
    body = dlp_detector_body("cards", ["Credit/debit card"])
    with pytest.raises(FaigError, match="unsaved detector"):
        faig.playground("4532 1188 0343 6467", body, "w1")
