#!/usr/bin/env python3
"""PAS-152 desired-state execution, readback, rollback and journal core.

The planner remains read-only. This layer consumes its deterministic plan and
only mutates Kong when CODESTRA_KONG_RECONCILIATION_APPLY_ENABLED=true.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kong_admin_channel import (
    PRIVATE_ADMIN_URL,
    AdminError,
    admin_request,
    collect_admin_rows,
    http_admin_request,
    normalize_admin_reference,
)
from plan_kong_route_reconciliation import build_plan, validate_manifest

CANONICAL_JSON = dict(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
MUTATIONS = {"CREATE", "UPDATE", "DELETE"}
TERMINAL = {"SUCCEEDED", "ROLLED_BACK", "ROLLBACK_FAILED", "FAILED"}
ALLOWED_UPSTREAM_PORTS = {8095}
FORBIDDEN_UPSTREAM_PORTS = {8080, 8096}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, **CANONICAL_JSON).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


VOLATILE_RUNTIME_FIELDS = {"id", "created_at", "updated_at", "ws_id", "cache_key"}


def semantic_snapshot(value: Any) -> Any:
    """Normalize Kong readback so rollback compares configuration, not runtime IDs/order."""
    if isinstance(value, dict):
        return {
            key: semantic_snapshot(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_RUNTIME_FIELDS
        }
    if isinstance(value, list):
        normalized = [semantic_snapshot(item) for item in value]
        return sorted(normalized, key=lambda item: canonical_json(item))
    return value


def sanitize(value: Any) -> Any:
    """Remove fields whose names can contain credentials before persistence/API."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            lower = str(key).lower()
            if any(token in lower for token in ("password", "secret", "token", "authorization", "apikey", "api_key")):
                out[key] = "[REDACTED]"
            else:
                out[key] = sanitize(item)
        return out
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


@dataclass(frozen=True)
class AdapterConfig:
    base_url: str = PRIVATE_ADMIN_URL
    auth_ref: str = "local-docker-admin-channel"
    timeout_seconds: float = 10.0
    read_retries: int = 2


class KongAdminAdapter:
    """Single bounded Admin API adapter. Mutations are never transport-retried."""

    def __init__(self, config: AdapterConfig | None = None):
        self.config = config or AdapterConfig()
        if not self.config.base_url:
            raise ValueError("Kong Admin base URL is required")
        if not self.config.auth_ref:
            raise ValueError("Kong Admin authentication reference is required")
        if self.config.timeout_seconds <= 0 or self.config.read_retries < 0:
            raise ValueError("invalid Admin API timeout/retry configuration")

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict | None:
        attempts = self.config.read_retries + 1 if method == "GET" else 1
        last: Exception | None = None
        for index in range(attempts):
            try:
                if self.config.base_url == PRIVATE_ADMIN_URL:
                    return admin_request(
                        method,
                        normalize_admin_reference(path),
                        payload,
                        payload_encoding="json",
                    )
                return http_admin_request(
                    self.config.base_url,
                    method,
                    path,
                    payload,
                    payload_encoding="json",
                    timeout=self.config.timeout_seconds,
                )
            except AdminError as exc:
                last = exc
                if method != "GET" or index + 1 >= attempts:
                    break
                time.sleep(min(0.25 * (index + 1), 0.75))
        raise RuntimeError(f"Kong Admin {method} failed") from last

    def get(self, path: str) -> dict:
        return self._request("GET", path) or {}

    def create(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, payload) or {}

    def update(self, path: str, payload: dict) -> dict:
        return self._request("PATCH", path, payload) or {}

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    def rows(self, path: str) -> list[dict]:
        return collect_admin_rows(
            lambda ref: self.get(ref),
            path,
            normalize_admin_reference,
        )

    def snapshot(self) -> dict:
        return {
            "services": self.rows("/services?size=1000"),
            "routes": self.rows("/routes?size=1000"),
            "plugins": self.rows("/plugins?size=1000"),
            "upstreams": self.rows("/upstreams?size=1000"),
            "consumers": self.rows("/consumers?size=1000"),
        }


class ExecutionStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass

    def _path(self, execution_id: str) -> Path:
        if not SAFE_ID.fullmatch(execution_id):
            raise ValueError("invalid execution id")
        return self.root / f"{execution_id}.json"

    def save(self, record: dict) -> None:
        record = sanitize(record)
        target = self._path(record["id"])
        fd, name = tempfile.mkstemp(prefix=".execution-", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(name, 0o600)
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def load(self, execution_id: str) -> dict:
        return json.loads(self._path(execution_id).read_text(encoding="utf-8"))

    def find_idempotency(self, key: str, mode: str) -> dict | None:
        digest = hashlib.sha256(f"{mode}\0{key}".encode()).hexdigest()
        for path in self.root.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if value.get("idempotency_digest") == digest:
                return value
        return None


class DesiredStateExecutor:
    def __init__(
        self,
        adapter: KongAdminAdapter,
        store: ExecutionStore,
        manifest: dict,
        inventory: dict,
        *,
        apply_enabled: bool | None = None,
    ):
        validate_manifest(manifest)
        self.adapter = adapter
        self.store = store
        self.manifest = manifest
        self.inventory = inventory
        self.apply_enabled = (
            os.getenv("CODESTRA_KONG_RECONCILIATION_APPLY_ENABLED", "").lower() == "true"
            if apply_enabled is None else apply_enabled
        )
        self.desired_hash = sha256_json(manifest)
        self.authority_routes = {
            row["name"]: row for row in inventory.get("routes", [])
            if isinstance(row.get("name"), str)
        }
        self.blocked_routes = {
            row["route"] for row in inventory.get("activationBlockedRoutes", [])
            if isinstance(row.get("route"), str) and row.get("activationAuthorized") is False
        }

    def _plan_from_snapshot(self, snapshot: dict) -> dict:
        return build_plan(
            self.manifest,
            snapshot["routes"],
            snapshot["services"],
            snapshot["plugins"],
            self.authority_routes,
            self.blocked_routes,
        )

    def plan(self) -> dict:
        snapshot = self.adapter.snapshot()
        result = self._plan_from_snapshot(snapshot)
        result["desired_state_sha256"] = self.desired_hash
        return result

    def dry_run(self, *, idempotency_key: str, correlation_id: str) -> dict:
        return self._start(
            mode="DRY_RUN",
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            execute=False,
        )

    def apply(self, *, idempotency_key: str, correlation_id: str, expected_hash: str) -> dict:
        if not self.apply_enabled:
            raise PermissionError("runtime apply disabled")
        if expected_hash != self.desired_hash:
            raise RuntimeError("desired-state hash mismatch")
        return self._start(
            mode="APPLY",
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            execute=True,
        )

    def _start(self, *, mode: str, idempotency_key: str, correlation_id: str, execute: bool) -> dict:
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValueError("valid Idempotency-Key required")
        if not correlation_id or len(correlation_id) > 200:
            raise ValueError("valid correlation id required")
        prior = self.store.find_idempotency(idempotency_key, mode)
        if prior is not None:
            return prior

        snapshot = self.adapter.snapshot()
        plan = self._plan_from_snapshot(snapshot)
        execution_id = str(uuid.uuid4())
        record = {
            "id": execution_id,
            "schema": "codestra.kong.reconciliation-execution.v1",
            "mode": mode,
            "status": "DRY_RUN" if not execute else "RUNNING",
            "correlation_id": correlation_id,
            "idempotency_digest": hashlib.sha256(f"{mode}\0{idempotency_key}".encode()).hexdigest(),
            "desired_state_sha256": self.desired_hash,
            "created_at_unix": int(time.time()),
            "plan": plan,
            "pre_apply_snapshot": sanitize(snapshot),
            "operations": [],
            "rollback": None,
        }
        self.store.save(record)
        if not execute:
            return record
        errors = [item for item in plan["plan"] if item["action"] == "ERROR"]
        if errors:
            record["status"] = "FAILED"
            record["failure"] = {"code": "PLAN_NOT_EXECUTABLE", "count": len(errors)}
            self.store.save(record)
            return record

        try:
            for item in plan["plan"]:
                if item["action"] in MUTATIONS:
                    operation = self._execute_item(item, snapshot, execution_id)
                    record["operations"].append(operation)
                    self.store.save(record)
            readback = self.adapter.snapshot()
            verification = self._verify_readback(plan, readback)
            record["post_apply_readback"] = sanitize(readback)
            record["post_apply_verification"] = verification
            if not verification["matches"]:
                raise RuntimeError("post-apply readback mismatch")
            record["status"] = "SUCCEEDED"
            self.store.save(record)
            return record
        except Exception as exc:
            record["status"] = "FAILED"
            record["failure"] = {"code": "APPLY_FAILED", "message": str(exc)[:240]}
            self.store.save(record)
            self.rollback(execution_id, automatic=True)
            return self.store.load(execution_id)

    def _verify_readback(self, original_plan: dict, snapshot: dict) -> dict:
        routes = {r.get("name"): r for r in snapshot["routes"] if r.get("name")}
        services = {s.get("id"): s for s in snapshot["services"] if s.get("id")}
        mismatches = []
        for item in original_plan["plan"]:
            action = item["action"]
            route = routes.get(item["route"])
            if action == "DELETE":
                if route is not None:
                    mismatches.append({"route": item["route"], "reason": "delete_not_applied"})
                continue
            if action in {"KEEP", "UPDATE"}:
                if route is None:
                    mismatches.append({"route": item["route"], "reason": "route_missing"})
                    continue
                current = services.get((route.get("service") or {}).get("id"), {})
                expected = item.get("target") or item.get("expected")
                if expected and (current.get("host"), current.get("port")) != (
                    expected.get("host"), expected.get("port")
                ):
                    mismatches.append({"route": item["route"], "reason": "upstream_mismatch"})
            elif action == "CREATE":
                if route is None:
                    mismatches.append({"route": item["route"], "reason": "create_missing"})
            elif action == "ERROR":
                mismatches.append({"route": item["route"], "reason": "plan_error"})
        return {"matches": not mismatches, "mismatches": mismatches}

    def _execute_item(self, item: dict, snapshot: dict, execution_id: str) -> dict:
        action = item["action"]
        route = next((r for r in snapshot["routes"] if r.get("name") == item["route"]), None)
        if action == "UPDATE":
            if route is None:
                raise RuntimeError("update route missing")
            service_id = (route.get("service") or {}).get("id")
            service = next((s for s in snapshot["services"] if s.get("id") == service_id), None)
            if service is None:
                raise RuntimeError("update service missing")
            target = item["target"]
            self._validate_upstream(target["host"], target["port"])
            shared = [
                r for r in snapshot["routes"]
                if (r.get("service") or {}).get("id") == service_id
            ]
            if len(shared) > 1:
                raise RuntimeError("shared service update requires isolated service")
            before = {"route": sanitize(route), "service": sanitize(service)}
            changed = self.adapter.update(
                f"/services/{service_id}",
                {"host": target["host"], "port": target["port"]},
            )
            return {
                "action": "UPDATE",
                "route": item["route"],
                "before": before,
                "after": sanitize(changed),
            }
        if action == "DELETE":
            if route is None:
                raise RuntimeError("delete route missing")
            plugins = [
                p for p in snapshot["plugins"]
                if (p.get("route") or {}).get("id") == route.get("id")
            ]
            if sanitize(plugins) != plugins:
                raise RuntimeError("delete rollback would require persisted secret material")
            self.adapter.delete(f"/routes/{route['id']}")
            return {
                "action": "DELETE",
                "route": item["route"],
                "before": {"route": sanitize(route), "plugins": sanitize(plugins)},
            }
        if action == "CREATE":
            desired = item.get("desired")
            if not isinstance(desired, dict):
                raise RuntimeError("create missing governed desired payload")
            service_payload = desired.get("service")
            route_payload = desired.get("route")
            plugins = desired.get("plugins", [])
            if not isinstance(service_payload, dict) or not isinstance(route_payload, dict):
                raise RuntimeError("create desired payload incomplete")
            self._validate_upstream(service_payload.get("host"), service_payload.get("port"))
            service = self.adapter.create("/services", service_payload)
            route_payload = dict(route_payload)
            route_payload["service"] = {"id": service["id"]}
            route_created = self.adapter.create("/routes", route_payload)
            created_plugins = []
            for plugin in plugins:
                payload = dict(plugin)
                payload["route"] = {"id": route_created["id"]}
                created_plugins.append(self.adapter.create("/plugins", payload))
            return {
                "action": "CREATE",
                "route": item["route"],
                "after": {
                    "service": sanitize(service),
                    "route": sanitize(route_created),
                    "plugins": sanitize(created_plugins),
                },
            }
        raise RuntimeError(f"unsupported mutation action: {action}")

    @staticmethod
    def _validate_upstream(host: Any, port: Any) -> None:
        if not isinstance(host, str) or not host:
            raise RuntimeError("invalid upstream host")
        if port in FORBIDDEN_UPSTREAM_PORTS:
            raise RuntimeError("forbidden direct/legacy upstream port")
        if port not in ALLOWED_UPSTREAM_PORTS:
            raise RuntimeError("upstream port is not allowlisted")

    def rollback(self, execution_id: str, *, automatic: bool = False) -> dict:
        record = self.store.load(execution_id)
        if record.get("status") == "ROLLED_BACK":
            return record
        outcomes = []
        try:
            for operation in reversed(record.get("operations", [])):
                action = operation["action"]
                if action == "UPDATE":
                    service = operation["before"]["service"]
                    self.adapter.update(
                        f"/services/{service['id']}",
                        {
                            "host": service["host"],
                            "port": service["port"],
                            "protocol": service.get("protocol"),
                        },
                    )
                elif action == "DELETE":
                    route = operation["before"]["route"]
                    route_fields = {
                        "name", "protocols", "methods", "hosts", "paths", "headers",
                        "https_redirect_status_code", "regex_priority", "strip_path",
                        "path_handling", "preserve_host", "request_buffering",
                        "response_buffering", "snis", "sources", "destinations",
                        "tags", "service",
                    }
                    route_payload = {
                        key: value for key, value in route.items()
                        if key in route_fields
                    }
                    created = self.adapter.create("/routes", route_payload)
                    plugin_fields = {
                        "name", "config", "enabled", "protocols", "tags",
                        "ordering", "instance_name", "service", "consumer",
                    }
                    for plugin in operation["before"].get("plugins", []):
                        value = {
                            key: item for key, item in plugin.items()
                            if key in plugin_fields
                        }
                        value["route"] = {"id": created["id"]}
                        self.adapter.create("/plugins", value)
                elif action == "CREATE":
                    after = operation["after"]
                    route = after.get("route") or {}
                    service = after.get("service") or {}
                    if route.get("id"):
                        self.adapter.delete(f"/routes/{route['id']}")
                    if service.get("id"):
                        self.adapter.delete(f"/services/{service['id']}")
                outcomes.append({"route": operation["route"], "action": action, "status": "ROLLED_BACK"})
            readback = self.adapter.snapshot()
            expected_hash = sha256_json(semantic_snapshot(record["pre_apply_snapshot"]))
            actual_hash = sha256_json(semantic_snapshot(sanitize(readback)))
            if actual_hash != expected_hash:
                raise RuntimeError("rollback readback mismatch")
            record["status"] = "ROLLED_BACK"
            record["rollback"] = {
                "automatic": automatic,
                "status": "SUCCEEDED",
                "operations": outcomes,
                "readback_sha256": actual_hash,
            }
        except Exception as exc:
            record["status"] = "ROLLBACK_FAILED"
            record["rollback"] = {
                "automatic": automatic,
                "status": "FAILED",
                "operations": outcomes,
                "error": str(exc)[:240],
            }
        self.store.save(record)
        return record

    def evidence(self, execution_id: str) -> dict:
        record = self.store.load(execution_id)
        return {
            "id": record["id"],
            "status": record["status"],
            "correlation_id": record["correlation_id"],
            "desired_state_sha256": record["desired_state_sha256"],
            "plan_summary": record["plan"].get("summary", {}),
            "operations": record.get("operations", []),
            "rollback": record.get("rollback"),
            "pre_apply_sha256": sha256_json(record["pre_apply_snapshot"]),
            "post_apply_sha256": (
                sha256_json(record["post_apply_readback"])
                if record.get("post_apply_readback") is not None else None
            ),
        }


def load_default_executor(
    root: Path,
    *,
    adapter: KongAdminAdapter | None = None,
    store_root: Path | None = None,
    apply_enabled: bool | None = None,
) -> DesiredStateExecutor:
    manifest = json.loads((root / "config/kong-route-reconciliation.pas236.json").read_text())
    inventory = json.loads((root / "config/kong-production-route-inventory.v2.json").read_text())
    return DesiredStateExecutor(
        adapter or KongAdminAdapter(),
        ExecutionStore(store_root or root / ".runtime/kong-reconciliation"),
        manifest,
        inventory,
        apply_enabled=apply_enabled,
    )
