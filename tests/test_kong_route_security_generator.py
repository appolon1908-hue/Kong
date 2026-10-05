from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kong_route_security", ROOT / "scripts/generate_kong_route_security.py")
assert SPEC and SPEC.loader
generator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)

CONTRACT = generator.load_json(generator.CONTRACT_PATH)
PROFILES = generator.load_json(generator.PROFILES_PATH)
POLICY = generator.load_json(generator.POLICY_PATH)
PIN = generator.load_json(generator.PIN_PATH)


def test_committed_route_security_is_current():
    assert generator.main(["--check"]) == 0


def test_every_contract_route_has_exactly_one_projected_row():
    rows = POLICY["v3MiddlewareSecurityAuthority"]["routeSecurity"]
    assert [r["operationId"] for r in rows] == [r["operation_id"] for r in CONTRACT["routes"]]
    assert len(rows) == PIN["routeCount"]
    source = POLICY["v3MiddlewareSecurityAuthority"]["source"]
    assert source["routeContractSha256"] == PIN["contractSha256"]
    assert source["classificationCounts"] == PIN["classificationCounts"]


def test_render_is_deterministic():
    first = generator.render(POLICY, CONTRACT, PROFILES, PIN)
    second = generator.render(copy.deepcopy(POLICY), copy.deepcopy(CONTRACT), copy.deepcopy(PROFILES), PIN)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_replay_scope_routes_are_user_only_with_role_mfa_and_boundary():
    privileged = set(PROFILES["v3CallerAuthority"]["tokenPolicy"]["privilegedScopes"])
    rows = generator.build_rows(CONTRACT, PROFILES)
    replay = [r for r in rows if r["requiredScope"] == generator.REPLAY_SCOPE]
    assert replay
    for row in replay:
        assert row["actorKindsAllowed"] == ["user"] and row["grantTypesAllowed"] == ["authorization_code"]
        assert row["requiredRealmRole"] == "platform-operator" and row["humanMfaRequired"] is True
        assert {"role", "mfa", "replay"} <= set(row["failClosedDimensions"])
        assert row["replayBoundary"]["serviceReplayAllowed"] is False
    for row in rows:
        if row["classification"] == "shared_edge" and row["requiredScope"] in privileged and "user" in row["actorKindsAllowed"]:
            assert row["humanMfaRequired"] is True, row["operationId"]


def test_denied_and_private_routes_never_reach_the_public_edge():
    for row in generator.build_rows(CONTRACT, PROFILES):
        if row["classification"] == "denied":
            assert row["requiredScope"] is None and row["kongPublicEdgeEnforcement"] is False
        if row["classification"] == "private_only":
            assert row["kongPublicEdgeEnforcement"] is False
            assert row["identityPropagationProfile"] == "private-only-not-through-public-kong"


def test_unknown_caller_fails_closed():
    contract = copy.deepcopy(CONTRACT)
    contract["routes"][-1]["calling_client"] = "not-a-reviewed-client"
    with pytest.raises(generator.RouteSecurityError, match="unknown caller"):
        generator.build_rows(contract, PROFILES)


def test_unclassified_route_fails_closed():
    contract = copy.deepcopy(CONTRACT)
    shared = next(r for r in contract["routes"] if r["classification"] == "shared_edge")
    shared["classification"] = "public_fallback"
    with pytest.raises(generator.RouteSecurityError, match="unclassified"):
        generator.build_rows(contract, PROFILES)


def test_contract_that_does_not_match_the_pin_is_refused():
    contract = copy.deepcopy(CONTRACT)
    contract["routes"] = contract["routes"][:-1]
    with pytest.raises(generator.RouteSecurityError, match="does not match pin"):
        generator.render(POLICY, contract, PROFILES, PIN)


def test_registry_entry_that_disagrees_with_the_contract_is_rejected():
    entries = copy.deepcopy(POLICY["routes"])
    shared = next(r for r in CONTRACT["routes"] if r["classification"] == "shared_edge")
    name = generator.route_name(shared)
    entry = next(e for e in entries if e["routeId"] == name)
    entry["requiredScopes"] = ["platform.admin"]
    with pytest.raises(generator.RouteSecurityError, match="disagrees with contract"):
        generator.upsert_entries(entries, CONTRACT, generator.access_entry)


def test_missing_registry_entries_are_generated_for_both_environments():
    entries = [e for e in copy.deepcopy(POLICY["routes"]) if not e["routeId"].startswith("middleware-")]
    added = generator.upsert_entries(entries, CONTRACT, generator.access_entry)
    shared = [r for r in CONTRACT["routes"] if r["classification"] == "shared_edge"]
    assert len(added) == 2 * len(shared)
    assert sum(a.endswith("@staging") for a in added) == len(shared)
