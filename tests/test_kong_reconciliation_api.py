import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = str(ROOT / "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_reconciliation_api import ReconciliationAPI


class Store:
    def load(self, ident):
        if ident == "missing":
            raise FileNotFoundError
        return {"id": ident, "status": "SUCCEEDED"}


class Executor:
    desired_hash = "a" * 64
    store = Store()

    def plan(self):
        return {"summary": {"KEEP": 1}}

    def dry_run(self, **kwargs):
        if not kwargs["idempotency_key"]:
            raise ValueError("valid Idempotency-Key required")
        return {"id": "dry", "status": "DRY_RUN"}

    def apply(self, **kwargs):
        if kwargs["expected_hash"] != self.desired_hash:
            raise RuntimeError("desired-state hash mismatch")
        return {"id": "apply", "status": "SUCCEEDED"}

    def rollback(self, ident):
        return {"id": ident, "status": "ROLLED_BACK"}

    def evidence(self, ident):
        return {"id": ident, "status": "SUCCEEDED", "pre_apply_sha256": "b" * 64}


def call(method, path, headers=None, body=None):
    return ReconciliationAPI(Executor()).handle(
        method, path, headers or {"x-correlation-id": "corr"},
        b"" if body is None else json.dumps(body).encode(),
    )


def test_plan_endpoint():
    status, payload = call("GET", "/platform/v1/kong/reconciliation/plan")
    assert status == 200
    assert payload["result"]["summary"] == {"KEEP": 1}


def test_dry_run_requires_idempotency_key():
    status, payload = call("POST", "/platform/v1/kong/reconciliation/dry-run")
    assert status == 400
    assert payload["error"]["code"] == "INVALID_REQUEST"


def test_apply_endpoint_validates_hash():
    status, payload = call(
        "POST",
        "/platform/v1/kong/reconciliation/apply",
        {"x-correlation-id": "c", "idempotency-key": "k"},
        {"desired_state_sha256": "bad"},
    )
    assert status == 409
    assert payload["error"]["code"] == "RECONCILIATION_REJECTED"


def test_apply_success():
    status, payload = call(
        "POST",
        "/platform/v1/kong/reconciliation/apply",
        {"x-correlation-id": "c", "idempotency-key": "k"},
        {"desired_state_sha256": "a" * 64},
    )
    assert status == 200
    assert payload["result"]["status"] == "SUCCEEDED"


def test_rollback_and_evidence_endpoints():
    status, payload = call(
        "POST",
        "/platform/v1/kong/reconciliation/rollback",
        body={"execution_id": "exec-1"},
    )
    assert status == 200
    assert payload["result"]["status"] == "ROLLED_BACK"
    status, payload = call("GET", "/platform/v1/kong/reconciliation/executions/exec-1/evidence")
    assert status == 200
    assert payload["result"]["pre_apply_sha256"] == "b" * 64


def test_unknown_route_is_deterministic_404():
    status, payload = call("GET", "/platform/v1/kong/reconciliation/nope")
    assert status == 404
    assert payload["error"]["code"] == "NOT_FOUND"


def test_bad_execution_id_is_404():
    status, payload = call("GET", "/platform/v1/kong/reconciliation/executions/a/b")
    assert status == 404
