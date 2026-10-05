"""The canonical upstream registry: every Kong upstream is one entry naming its
repository, TLS requirement and route families; Middleware binds :8095 and no
Middleware-governed upstream may still target :8080."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("kong_upstream_registry_validator", ROOT / "scripts/validate_kong_foundation.py")
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

PROVIDER_SPEC = importlib.util.spec_from_file_location("provider_control_validator", ROOT / "scripts/validate_provider_control_routes.py")
assert PROVIDER_SPEC and PROVIDER_SPEC.loader
provider_control = importlib.util.module_from_spec(PROVIDER_SPEC)
PROVIDER_SPEC.loader.exec_module(provider_control)

PIN = json.loads((ROOT / "config/middleware-public-api-route-contract.pin.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def result() -> dict:
    return validator.validate_foundation(root=ROOT)


def check(result: dict, mutate) -> dict:
    foundation = copy.deepcopy(result["foundation"])
    mutate(foundation)
    services = {entry["serviceId"]: entry for entry in foundation["services"]}
    return validator.validate_upstream_registry(foundation, services, result["materialized"])


def service(foundation: dict, service_id: str) -> dict:
    return next(entry for entry in foundation["services"] if entry["serviceId"] == service_id)


def test_registry_invariants_hold(result):
    status = result["upstreamRegistry"]
    assert status["middlewareUpstreamPort"] == 8095
    assert status["legacy8080Upstreams"] == 0
    assert status["unregisteredUpstreams"] == 0
    assert set(status["residual8080"].values()) <= {"DELETE", "TEST_ONLY"}
    for service_id in status["residual8080"]:
        entry = result["services"][service_id]
        assert entry["upstreamClass"] not in result["foundation"]["debtRules"]["middlewareUpstreamClasses"]
        assert entry["lifecycle"] != "CANONICAL"


def test_every_middleware_upstream_belongs_to_the_pinned_repository_on_8095(result):
    classes = set(result["foundation"]["debtRules"]["middlewareUpstreamClasses"])
    governed = [e for e in result["services"].values() if e["upstreamClass"] in classes]
    assert governed
    for entry in governed:
        assert entry["repository"] == PIN["repository"], entry["serviceId"]
        assert entry["upstream"]["port"] != 8080, entry["serviceId"]
    assert result["services"]["middleware-integration-api"]["upstream"] == {
        "protocol": "http", "host": "middleware-integration-api", "port": 8095}


def test_provider_control_contract_is_pinned_to_the_canonical_listener(result):
    contract = json.loads((ROOT / "config/kong-provider-control-routes.v1.json").read_text(encoding="utf-8"))
    assert contract["service"] == {"host": "middleware-integration-api", "port": 8095, "protocol": "http"}
    provider_control.validate(contract)
    entry = result["services"]["provider-control-middleware"]
    assert "RETIRED_UPSTREAM_ALIAS" not in entry["acceptedFindings"]
    legacy = copy.deepcopy(contract)
    legacy["service"] = {"host": "appolon-middleware-integration-api", "port": 8080, "protocol": "http"}
    with pytest.raises(ValueError, match="middleware upstream service drift"):
        provider_control.validate(legacy)


@pytest.mark.parametrize("path,family", [
    ("/v1/sms", "/v1/sms"),
    ("/api/v1/control/messages", "/api/v1/control"),
    ("~/platform/v1/contacts/[^/]+$", "/platform/v1/contacts"),
    ("~/api/v1/integrations/n8n/results/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "/api/v1/integrations"),
    ("~/v1/foo[0-9]+$", "/v1"),
    ("~/platform/v1/me$", "/platform/v1/me"),
    ("/", "/"),
])
def test_route_family_uses_complete_literal_segments(path, family):
    assert validator.route_family(path) == family


@pytest.mark.parametrize("mutate,match", [
    (lambda f: service(f, "codestra-control-plane").pop("repository"), "lacks repository"),
    (lambda f: service(f, "codestra-control-plane").update(repository="someone/else"), "unknown repository"),
    (lambda f: service(f, "middleware-integration-api").update(repository="appolon1908/Kong"), "must belong to"),
    (lambda f: service(f, "middleware-integration-api").update(tlsRequired=True), "tlsRequired disagrees"),
    (lambda f: service(f, "codestra-community-n8n-middleware").update(tlsRequired=False), "tlsRequired disagrees"),
    (lambda f: service(f, "codestra-control-plane")["upstream"].update(host="control.example.com"), "private network service name"),
    (lambda f: service(f, "codestra-control-plane").update(routeFamilies=["/api/v1/control"]), "routeFamilies"),
    (lambda f: service(f, "codestra-crm-api").pop("port8080Disposition"), "must be classified"),
    (lambda f: service(f, "codestra-crm-api").update(port8080Disposition="KEEP"), "must be classified"),
    (lambda f: service(f, "codestra-token-validator").update(lifecycle="CANONICAL"), "must not target :8080"),
    (lambda f: service(f, "codestra-control-plane").update(port8080Disposition="DELETE"), "carries port8080Disposition"),
])
def test_registry_entry_drift_fails_closed(result, mutate, match):
    with pytest.raises(validator.FoundationError, match=match):
        check(result, mutate)


def test_middleware_upstream_back_on_8080_fails_closed(result):
    def mutate(foundation):
        service(foundation, "codestra-website-api")["upstream"]["port"] = 8080
        service(foundation, "codestra-website-api")["port8080Disposition"] = "HISTORICAL"
    with pytest.raises(validator.FoundationError, match="must target :8095"):
        check(result, mutate)


def test_retired_alias_counts_as_a_legacy_8080_upstream(result):
    def mutate(foundation):
        entry = service(foundation, "codestra-community-n8n-middleware")
        entry["upstream"].update(protocol="http", host="appolon-middleware-integration-api", port=8080)
        entry.update(tlsRequired=False, port8080Disposition="DELETE")
    with pytest.raises(validator.FoundationError, match="still target :8080 or a retired alias"):
        check(result, mutate)


def test_route_bound_to_an_unregistered_upstream_fails_closed(result):
    def mutate(foundation):
        foundation["routes"][0]["serviceId"] = "not-in-the-registry"
    with pytest.raises(validator.FoundationError, match="outside the registry"):
        check(result, mutate)
