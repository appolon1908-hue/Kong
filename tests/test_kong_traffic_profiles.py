"""Named edge traffic profiles: every Middleware contract route takes its rate,
burst and body limit from one selector over the foundation catalogue, the shared
Redis limiter fails closed, and effectful transport never retries."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import kong_traffic_policy as traffic  # noqa: E402

FOUNDATION = json.loads((ROOT / "config/kong-gateway-foundation.v1.json").read_text(encoding="utf-8"))
CONTRACT = json.loads((ROOT / "config/middleware-public-api-route-contract.v1.json").read_text(encoding="utf-8"))
SHARED = [row for row in CONTRACT["routes"] if row["classification"] == "shared_edge"]
PRIVILEGED, WEBHOOKS = traffic.selection_inputs()
MISSION_NAMES = {
    "rate": {"public-read", "authenticated-read", "authenticated-write", "webhook", "login-sensitive", "operator", "high-cost"},
    "body": {"small-api", "normal-api", "webhook", "large-metadata", "approved-upload"},
    "transport": {"read-fast", "read-standard", "command-accept", "webhook", "control-plane"},
}


def test_catalogue_declares_every_named_profile():
    edge = traffic.catalogue()["edge"]
    for kind, names in MISSION_NAMES.items():
        assert set(edge[kind]) == names, kind


@pytest.mark.parametrize("manifest", ["config/kong-middleware-routes.production.yml",
                                      "config/staging/kong-middleware-routes.staging.yml"])
def test_every_generated_route_carries_its_selected_profile(manifest):
    rows = {row["operation_id"]: row for row in SHARED}
    service = yaml.safe_load((ROOT / manifest).read_text(encoding="utf-8"))["services"][0]
    for route in service["routes"]:
        operation = next(p for p in route["plugins"] if p["name"] == "codestra-authz")["config"]["operation_id"]
        expected = traffic.select(rows[operation], PRIVILEGED, WEBHOOKS)
        plugins = {p["name"]: p["config"] for p in route["plugins"]}
        rate = plugins["rate-limiting"]
        assert (rate["minute"], rate["second"]) == (expected["perMinute"], expected["perSecond"]), route["name"]
        assert rate["policy"] == "redis" and rate["fault_tolerant"] is False, route["name"]
        assert plugins["request-size-limiting"]["allowed_payload_size"] == expected["bodyMegabytes"], route["name"]
    transport = traffic.catalogue()["edge"]["transport"]["command-accept"]
    timeout = FOUNDATION["profiles"]["timeout"][transport["timeout"]]
    assert (service["connect_timeout"], service["read_timeout"], service["write_timeout"], service["retries"]) == (
        timeout["connectMs"], timeout["readMs"], timeout["writeMs"], 0)


def test_selection_rules():
    reads = [row for row in SHARED if row["method"] == "GET" and row["scope"] not in PRIVILEGED
             and (row["method"], row["path"]) not in WEBHOOKS]
    writes = [row for row in SHARED if row["method"] != "GET" and row["scope"] not in PRIVILEGED
              and (row["method"], row["path"]) not in WEBHOOKS]
    assert {traffic.select(r, PRIVILEGED, WEBHOOKS)["rate"] for r in reads} == {"authenticated-read"}
    assert {traffic.select(r, PRIVILEGED, WEBHOOKS)["rate"] for r in writes} == {"authenticated-write"}
    for row in SHARED:
        selected = traffic.select(row, PRIVILEGED, WEBHOOKS)
        if (row["method"], row["path"]) in WEBHOOKS:
            assert (selected["rate"], selected["body"]) == ("webhook", "webhook")
        elif row["scope"] in PRIVILEGED:
            assert selected["rate"] == "operator"
    assert {traffic.select(r, PRIVILEGED, WEBHOOKS)["rate"] for r in SHARED} == {
        "authenticated-read", "authenticated-write", "operator", "webhook"}


def _broken(mutate):
    foundation = copy.deepcopy(FOUNDATION)
    mutate(foundation["profiles"])
    return foundation


@pytest.mark.parametrize("mutate,match", [
    (lambda p: p["edgeTraffic"]["limiter"].update(faultTolerant=True), "fail closed"),
    (lambda p: p["edgeTraffic"]["limiter"].update(policy="local"), "fail closed"),
    (lambda p: p["edgeTraffic"]["transport"]["command-accept"].update(retry="TRANSPORT_CONNECT_ONLY_1"), "must not retry"),
    (lambda p: p["edgeTraffic"]["transport"]["webhook"].update(retry="KONG_DEFAULT_IMPLICIT"), "not transport safe"),
    (lambda p: p["edgeTraffic"]["rate"]["operator"].update(profile="NO_SUCH_PROFILE"), "positive foundation limit"),
    (lambda p: p["edgeTraffic"]["rate"]["operator"].update(perSecond=0), "positive foundation limit"),
    (lambda p: p["edgeTraffic"]["body"].update({"normal-api": "UNBOUNDED"}), "bounded foundation size"),
])
def test_catalogue_downgrades_fail_closed(mutate, match):
    with pytest.raises(traffic.TrafficProfileError, match=match):
        traffic.catalogue(_broken(mutate))
