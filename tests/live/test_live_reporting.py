"""Read-only: usage/cost/analytics reports, traffic and ICAP logs, and the
model/permission lookups. Opt-in like the other live tests (FAIG_LIVE=1)."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from pyfortiaigate import FaigError, FortiAIGate, breakdown_items, rank_items

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not os.environ.get("FAIG_LIVE"), reason="set FAIG_LIVE=1 to run"),
]


@pytest.fixture(scope="module")
def live() -> Iterator[FortiAIGate]:
    with FortiAIGate.from_env() as c:
        yield c


@pytest.fixture(scope="module")
def ws(live: FortiAIGate) -> str:
    name = os.environ.get("FAIG_WRITE_WORKSPACE")
    w = live.workspace_by_name(name) if name else (live.workspaces() or [None])[0]
    if not w:
        pytest.skip("no workspace to read")
    return str(w["id"])


@pytest.mark.parametrize("scope", ["org", "workspace"])
def test_usage_and_cost_reports(live: FortiAIGate, ws: str, scope: str) -> None:
    w = ws if scope == "workspace" else None
    assert {"window", "totals"} <= live.usage_summary(workspace_id=w).keys()
    assert "chargebackSpend" in live.cost_summary(workspace_id=w)["totals"]
    assert live.usage_trend(interval="daily", workspace_id=w)["interval"] == "daily"
    assert isinstance(live.cost_trend(interval="weekly", workspace_id=w)["points"], list)
    for by in ("key", "user", "model") + (("workspace",) if w is None else ()):
        ranks = live.usage_rankings(by=by, limit=3, order_by="tokens", workspace_id=w)
        assert "meta" in ranks  # no items at all when nothing was used in the window
        assert len(rank_items(ranks)) <= 3
        costs = live.cost_rankings(by=by, limit=3, workspace_id=w)
        assert len(rank_items(costs)) <= 3
    both = live.usage_rankings(by="key", limit=2, end="both", workspace_id=w)
    assert isinstance(rank_items(both, "bottom"), list)
    assert {"summary", "detectors", "violations"} <= live.analytics(limit=3, workspace_id=w).keys()


@pytest.mark.parametrize("by", ["key", "user", "model"])
@pytest.mark.parametrize("scope", ["org", "workspace"])
def test_breakdown_of_the_top_item(live: FortiAIGate, ws: str, scope: str, by: str) -> None:
    w = ws if scope == "workspace" else None
    # Rankings keep deleted keys (deleted: true); their breakdown is a 404.
    top = [
        r
        for r in rank_items(live.usage_rankings(by=by, limit=10, workspace_id=w))
        if not r.get("deleted")
    ]
    if not top:
        pytest.skip(f"no live {by} with usage in the {scope} window")
    # A key, user or workspace splits by model; a model by who used it.
    usage = live.usage_breakdown(by, top[0]["id"], workspace_id=w)
    assert {"tokens", "requests"} <= usage["total"].keys()
    rows = breakdown_items(usage)
    assert rows
    assert {"name", "tokens", "requests"} <= rows[0].keys()
    cost = live.cost_breakdown(by, top[0]["id"], workspace_id=w)
    assert "amount" in cost["total"]["chargebackSpend"]
    spend = breakdown_items(cost)
    assert spend
    assert {"name", "chargebackSpend"} <= spend[0].keys()


def test_traffic_logs_page_and_detail(live: FortiAIGate) -> None:
    rows = list(live.traffic_logs(range="all", max_items=3))
    if not rows:
        pytest.skip("no traffic logged")
    detail = live.traffic_log(rows[0]["uuid"])
    assert {"model", "verdict", "cost", "requestPath"} <= detail.keys()


def test_traffic_logs_cursor_reaches_a_second_page(live: FortiAIGate) -> None:
    first = live.traffic_logs_page(range="all", limit=2)
    if not first.get("hasNext"):
        pytest.skip("fewer than three log rows")
    uuids = [r["uuid"] for r in live.traffic_logs(range="all", page_size=2, max_items=4)]
    assert len(uuids) == len(set(uuids)) == 4, "cursor paging repeated or lost rows"


def test_traffic_log_filters_really_filter(live: FortiAIGate) -> None:
    """The API ignores a misspelled filter; this proves ours are honoured."""
    opts = live.traffic_log_filter_options(range="all")
    models = opts.get("model") or []
    if len(models) < 2:
        pytest.skip("need two models in the logs")
    everything = live.traffic_logs_page(range="all", limit=1)["total"]
    only = live.traffic_logs_page(range="all", limit=50, filters={"model": models[-1]})
    assert 0 < only["total"] < everything
    assert all(r["model"] == models[-1] for r in only["items"])
    excluded = live.traffic_logs_page(
        range="all", limit=50, filters={"model": {"operator": "is not", "value": models[-1]}}
    )
    assert excluded["total"] == everything - only["total"]


def test_workspace_traffic_logs(live: FortiAIGate, ws: str) -> None:
    rows = list(live.traffic_logs(range="all", max_items=2, workspace_id=ws))
    for r in rows:
        assert live.traffic_log(r["uuid"], ws)["uuid"] == r["uuid"]


def test_icap_logs_or_feature_off(live: FortiAIGate) -> None:
    try:
        rows = list(live.icap_logs(range="all", max_items=2))
    except FaigError as e:
        if e.status == 404:
            pytest.skip("ICAP logging is not enabled on this appliance")
        raise
    assert isinstance(rows, list)
    assert isinstance(live.icap_log_filter_options(range="all"), dict)


def test_model_and_permission_lookups(live: FortiAIGate, ws: str) -> None:
    models = live.models()
    assert models
    assert "label" in models[0]
    assert isinstance(live.workspace_models(ws), list)
    assert isinstance(live.grantable_providers(ws), list)
    assert isinstance(live.grantable_providers(), list)
    assert isinstance(live.attachable_policies(ws), list)
    assert isinstance(live.model_groups(ws), list)
    assert "allowedModels" in live.workspace(ws)


def test_custom_time_window(live: FortiAIGate) -> None:
    import datetime as dt

    rows = list(live.traffic_logs(range="all", max_items=1))
    if not rows:
        pytest.skip("no traffic logged")
    t = int(rows[0]["timeStamp"])
    around = live.traffic_logs_page(start=t - 1000, end=t + 1000, limit=50)
    assert rows[0]["uuid"] in {r["uuid"] for r in around["items"]}
    assert all(t - 1000 <= int(r["timeStamp"]) <= t + 1000 for r in around["items"])
    as_datetime = live.traffic_logs_page(
        start=dt.datetime.fromtimestamp((t - 1000) / 1000, dt.timezone.utc),
        end=dt.datetime.fromtimestamp((t + 1000) / 1000, dt.timezone.utc),
    )
    assert as_datetime["total"] == around["total"]
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)
    empty = live.traffic_logs_page(start=future, end=future + dt.timedelta(hours=1))
    assert empty["total"] == 0


def test_contains_and_does_not_contain(live: FortiAIGate) -> None:
    models = live.traffic_log_filter_options(range="all").get("model") or []
    everything = live.traffic_logs_page(range="all", limit=1)["total"]
    # A substring some logged models have and some do not.
    sub = next(
        (m[-6:] for m in models if 0 < sum(m[-6:] in x for x in models) < len(models)),
        None,
    )
    if not sub:
        pytest.skip("need models that differ in their last six characters")
    has = live.traffic_logs_page(
        range="all", limit=50, filters={"model": {"operator": "contains", "value": sub}}
    )
    lacks = live.traffic_logs_page(
        range="all", limit=50, filters={"model": {"operator": "does not contain", "value": sub}}
    )
    assert 0 < has["total"] < everything
    assert has["total"] + lacks["total"] == everything
    assert all(sub in r["model"] for r in has["items"])
    # Rows with no model (refused before routing) count as "does not contain".
    assert all(sub not in (r["model"] or "") for r in lacks["items"])


def test_workspace_traffic_filter_options(live: FortiAIGate, ws: str) -> None:
    opts = live.traffic_log_filter_options(range="all", workspace_id=ws)
    assert {"model", "verdict", "virtualKey"} <= opts.keys()
