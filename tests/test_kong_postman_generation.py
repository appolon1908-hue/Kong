from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_kong_postman.py"
SPEC = importlib.util.spec_from_file_location("kong_postman_generator", MODULE_PATH)
assert SPEC and SPEC.loader
postman = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = postman
SPEC.loader.exec_module(postman)

CASES = postman.load_json(postman.CASES_PATH)
COLLECTION = postman.load_json(postman.COLLECTION_PATH)
ENVIRONMENT = postman.load_json(postman.ENVIRONMENT_PATH)


def test_checked_in_collection_and_environment_are_deterministic() -> None:
    assert COLLECTION == postman.render_collection(CASES)
    assert ENVIRONMENT == postman.render_environment()


def test_collection_is_bound_to_final_middleware_digest() -> None:
    assert CASES["source_contract_sha256"] == postman.FINAL_DIGEST
    assert COLLECTION["variable"] == [
        {"key": "source_contract_sha256", "value": postman.FINAL_DIGEST}
    ]


def test_collection_covers_required_crm_automation_and_webhook_families() -> None:
    assert CASES["route_family_counts"] == {
        "Automation V2": 13,
        "CRM Contacts": 9,
        "CRM Opportunities": 4,
        "CRM Tasks": 2,
        "CRM Tickets": 4,
        "Webhook & Event Ingress": 3,
    }
    assert len(CASES["routes"]) == 35
    paths = {(row["method"], row["path"]) for row in CASES["routes"]}
    assert ("POST", "/platform/v1/integrations/github/events") in paths
    assert ("POST", "/api/v1/odoo/events") in paths
    assert ("POST", "/api/v1/integrations/n8n/results") in paths
    assert sum(1 for row in CASES["routes"] if row["path"].startswith("/v2/automation/")) == 13


def test_negative_matrix_contains_auth_edge_idempotency_size_and_pending_denials() -> None:
    negative = next(folder for folder in COLLECTION["item"] if folder["name"] == "Negative Security & Edge")
    names = {item["name"] for item in negative["item"]}
    assert names == {
        "missing-token",
        "wrong-issuer",
        "wrong-audience",
        "wrong-azp",
        "missing-scope",
        "missing-idempotency",
        "wrong-method",
        "oversize-body",
        "private-metrics",
        "private-internal",
        "pending-telnexa",
        "pending-vicidial",
        "pending-n8n-ack",
        "pending-observability",
        "pending-sms-inbound",
    }


def test_environment_is_safe_by_default_and_contains_no_credentials() -> None:
    values = {row["key"]: row["value"] for row in ENVIRONMENT["values"]}
    assert values["base_url"] == "http://127.0.0.1:8000"
    assert values["RUN_KONG_V3_PARITY"] == "false"
    for key in (
        "bearer_token",
        "wrong_issuer_token",
        "wrong_audience_token",
        "wrong_azp_token",
        "missing_scope_token",
    ):
        assert values[key] == ""


def test_collection_has_explicit_live_run_guard() -> None:
    prerequest = next(event for event in COLLECTION["event"] if event["listen"] == "prerequest")
    rendered = "\n".join(prerequest["script"]["exec"])
    assert "RUN_KONG_V3_PARITY" in rendered
    assert "disabled" in rendered


def _request_items(items):
    for item in items:
        if "item" in item:
            yield from _request_items(item["item"])
        if "request" in item:
            yield item


def test_every_generated_request_has_response_assertions() -> None:
    items = list(_request_items(COLLECTION["item"]))
    assert items
    assert all(any(event["listen"] == "test" for event in item.get("event", [])) for item in items)
    negative = next(folder for folder in COLLECTION["item"] if folder["name"] == "Negative Security & Edge")
    for item in negative["item"]:
        script = "\n".join(
            line
            for event in item["event"]
            if event["listen"] == "test"
            for line in event["script"]["exec"]
        )
        assert "fail-closed" in script


def test_live_run_guard_skips_instead_of_throwing() -> None:
    prerequest = next(event for event in COLLECTION["event"] if event["listen"] == "prerequest")
    rendered = "\n".join(prerequest["script"]["exec"])
    assert "RUN_KONG_V3_PARITY" in rendered
    assert "pm.execution.skipRequest()" in rendered
    assert "throw new Error" not in rendered
