"""Traffic authority shared by the existing compilers; never an apply grant.

Concurrency is explicitly per worker; IP rate/burst and optional verified-tenant
quotas use shared Redis across gateway nodes.
"""
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "config/kong-gateway-foundation.v1.json"
PROFILES = ROOT / "config/kong-authentication-profiles.v1.json"
WEBHOOKS = ROOT / "config/kong-webhook-registry.v1.json"
READ_METHODS = {"GET", "HEAD"}


def traffic_policy(route, upstream):
    selected = route.get("trafficPolicy", {})
    return {
        "ratePerMinute": route["ratePerMinute"],
        "burstPerSecond": selected.get("burstPerSecond", min(10, route["ratePerMinute"])),
        "maxConcurrentPerWorker": selected.get("maxConcurrentPerWorker", 32),
        "tenantQuotaPerMinute": selected.get("tenantQuotaPerMinute", 0),
        "concurrencyScope": "worker", "tenantQuotaScope": "shared-redis",
        "maxBodyBytes": route["maxBodyBytes"], "timeouts": dict(upstream["timeouts"]),
        "retries": upstream["retries"],
        "unsafeRetriesExplicitlyAuthorized": route.get("retrySafe", False),
    }


def resource_guard(route_key, policy, redis=None):
    if len(route_key) > 128:
        route_key = "route-" + hashlib.sha256(route_key.encode()).hexdigest()
    result = {"route_key": route_key,
        "concurrency_limit_per_worker": policy["maxConcurrentPerWorker"],
        "tenant_quota_per_minute": policy["tenantQuotaPerMinute"]}
    if result["tenant_quota_per_minute"]:
        result["redis"] = dict(redis)
    return {"name": "codestra-resource-guard", "config": result}


def passive_health():
    return {"type": "http", "healthy": {"successes": 2}, "unhealthy": {
        "http_statuses": [500, 502, 503, 504], "http_failures": 3,
        "tcp_failures": 2, "timeouts": 2}}


def middleware_policy():
    return traffic_policy({"ratePerMinute": 120, "maxBodyBytes": 2 * 1024 * 1024}, {
        "timeouts": {"connectMs": 5000, "readMs": 30000, "writeMs": 30000}, "retries": 0})

class TrafficProfileError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def catalogue(foundation: dict[str, Any] | None = None) -> dict[str, Any]:
    foundation = foundation or _load(FOUNDATION)
    profiles = foundation["profiles"]
    edge = profiles["edgeTraffic"]
    for name, rate in edge["rate"].items():
        if rate["profile"] not in profiles["rateLimit"] or not isinstance(rate["perSecond"], int) or rate["perSecond"] < 1:
            raise TrafficProfileError(f"rate profile {name} is not backed by a positive foundation limit")
    for name, body in edge["body"].items():
        if profiles["requestSize"].get(body, {}).get("maxBodyBytes") is None:
            raise TrafficProfileError(f"body profile {name} is not backed by a bounded foundation size")
    for name, transport in edge["transport"].items():
        if transport["timeout"] not in profiles["timeout"] or transport["retry"] not in profiles["retry"]:
            raise TrafficProfileError(f"transport profile {name} references an unknown timeout or retry profile")
        if not profiles["retry"][transport["retry"]]["transportSafe"]:
            raise TrafficProfileError(f"transport profile {name} uses a retry profile that is not transport safe")
    for name in ("command-accept", "webhook", "control-plane"):
        if profiles["retry"][edge["transport"][name]["retry"]]["retries"] != 0:
            raise TrafficProfileError(f"effectful transport profile {name} must not retry")
    limiter = edge["limiter"]
    if limiter["policy"] != "redis" or limiter["faultTolerant"] is not False:
        raise TrafficProfileError("protected rate limits must use the shared Redis limiter and fail closed")
    return {"profiles": profiles, "edge": edge}


def selection_inputs() -> tuple[set[str], set[tuple[str, str]]]:
    privileged = set(_load(PROFILES)["v3CallerAuthority"]["tokenPolicy"]["privilegedScopes"])
    webhooks = {(e["method"], e["path"]) for e in _load(WEBHOOKS)["canonical_entries"]}
    return privileged, webhooks


def select(row: dict[str, Any], privileged: set[str], webhooks: set[tuple[str, str]],
           foundation: dict[str, Any] | None = None) -> dict[str, Any]:
    """The rate and body profile of one shared_edge contract operation."""
    data = catalogue(foundation)
    if (row["method"], row["path"]) in webhooks:
        rate, body = "webhook", "webhook"
    elif row["scope"] in privileged:
        rate, body = "operator", "small-api" if row["method"] in READ_METHODS else "normal-api"
    elif row["method"] in READ_METHODS:
        rate, body = "authenticated-read", "small-api"
    else:
        rate, body = "authenticated-write", "normal-api"
    rate_entry = data["edge"]["rate"][rate]
    body_profile = data["edge"]["body"][body]
    body_bytes = data["profiles"]["requestSize"][body_profile]["maxBodyBytes"]
    if body_bytes % (1024 * 1024):
        raise TrafficProfileError(f"body profile {body} must be a whole number of megabytes")
    return {
        "rate": rate, "rateLimitProfile": rate_entry["profile"],
        "perMinute": data["profiles"]["rateLimit"][rate_entry["profile"]]["perMinute"],
        "perSecond": rate_entry["perSecond"],
        "body": body, "requestSizeProfile": body_profile, "bodyMegabytes": body_bytes // (1024 * 1024),
    }
