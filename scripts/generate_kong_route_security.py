#!/usr/bin/env python3
"""Derive Kong's per-route security projection from the Middleware contract.

`v3MiddlewareSecurityAuthority.routeSecurity` in config/kong-access-policy.v1.json
has one row per Middleware operation. Every field follows from the contract row
and the caller policy in config/kong-authentication-profiles.v1.json, so the
rows are generated rather than edited by hand:

    python3 scripts/generate_kong_route_security.py --write
    python3 scripts/generate_kong_route_security.py --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/middleware-public-api-route-contract.v1.json"
PROFILES_PATH = ROOT / "config/kong-authentication-profiles.v1.json"
POLICY_PATH = ROOT / "config/kong-access-policy.v1.json"
PIN_PATH = ROOT / "config/middleware-public-api-route-contract.pin.json"
FOUNDATION_PATH = ROOT / "config/kong-gateway-foundation.v1.json"
CANONICAL_PATH = "config/kong-canonical-middleware-routes.json"
PRODUCTION_PATH = "config/kong-middleware-routes.production.yml"
STAGING_PATH = "config/staging/kong-middleware-routes.staging.yml"
AUTHORITY_PATH = "config/kong-middleware-authority.v2.json"
SERVICE_ID = "middleware-integration-api"
AUDIENCE_PROFILE = {"middleware-api": "MIDDLEWARE_API", "codestra-callback-api": "CALLBACK_API"}
ISSUER_PROFILE = {"production": "KEYCLOAK_CODESTRA_PRODUCTION", "staging": "KEYCLOAK_CODESTRA_STAGING"}
# Existing registry entries are curated; these fields may differ from the rule
# (event/webhook ingest traffic classes and reviewer notes).
CURATED_FIELDS = {"notes", "trafficClass"}
# Owned by the named traffic-profile selector: rewritten, never curated by hand.
DERIVED_FIELDS = {"rateLimitProfile", "requestSizeProfile"}

TENANT_AUTHORITY = "token-claim; X-Tenant-ID is selector-only"
BASE_DIMENSIONS = ["issuer", "audience", "azp", "scope", "tenant", "expiry"]
REPLAY_SCOPE = "platform.command.replay"
REPLAY_ROLE = "platform-operator"
AZP_MODE = {
    "CLIENT_FAMILY": "reviewed-family-member",
    "CONCRETE_SERVICE_CLIENT": "literal",
    "CONCRETE_HUMAN_CLIENT": "literal",
    "SYMBOLIC_RUNTIME_SELECTOR": "runtime-selector",
}


class RouteSecurityError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def caller_selector(row: dict[str, Any]) -> str:
    selected = row["calling_client"]
    if isinstance(selected, list):
        if len(selected) != 1:
            raise RouteSecurityError(f"{row['operation_id']}: routeSecurity needs exactly one caller selector")
        selected = selected[0]
    return selected


def route_security_row(row: dict[str, Any], callers: dict[str, Any], privileged: set[str]) -> dict[str, Any]:
    selector = caller_selector(row)
    caller = callers.get(selector)
    if caller is None:
        raise RouteSecurityError(f"{row['operation_id']}: unknown caller {selector!r}")
    classification = row["classification"]
    out: dict[str, Any] = {
        "operationId": row["operation_id"],
        "method": row["method"],
        "path": row["path"],
        "classification": classification,
        "auth": row["auth"],
        "audience": row["audience"],
        "callerSelector": selector,
        "callerClass": caller["class"],
        "azpMode": AZP_MODE[caller["class"]],
    }
    if classification == "denied":
        out.update(actorKindsAllowed=[], grantTypesAllowed=[], requiredScope=None, requiredRealmRole=None,
                   humanPkceRequired=False, humanMfaRequired=False, maximumAccessTokenLifetimeSeconds=None,
                   tenantAuthority="not-applicable", identityPropagationProfile="NONE_TERMINATED",
                   kongPublicEdgeEnforcement=False, failClosedDimensions=[])
        return out

    scope = row["scope"]
    replay = scope == REPLAY_SCOPE
    actors = ["user"] if replay else list(caller["actorKinds"])
    grants = ["authorization_code"] if replay else list(caller["grantTypes"])
    has_user = "user" in actors
    policy = caller.get("humanMfaPolicy")
    mfa = has_user and (replay or policy == "required" or (policy == "required-for-privileged" and scope in privileged))
    out.update(
        actorKindsAllowed=actors,
        grantTypesAllowed=grants,
        requiredScope=scope,
        requiredRealmRole=REPLAY_ROLE if replay else None,
        humanPkceRequired=bool(has_user and caller.get("humanPkceRequired", False)),
        humanMfaRequired=bool(mfa),
        maximumAccessTokenLifetimeSeconds=caller["maxAccessTokenLifetimeSeconds"],
        tenantAuthority=TENANT_AUTHORITY,
    )
    if classification == "private_only":
        out.update(identityPropagationProfile="private-only-not-through-public-kong",
                   kongPublicEdgeEnforcement=False, failClosedDimensions=[])
        return out
    if classification != "shared_edge":
        raise RouteSecurityError(f"{row['operation_id']}: unclassified route {classification!r}")
    dimensions = list(BASE_DIMENSIONS)
    if replay:
        dimensions += ["role", "mfa", "replay"]
    elif mfa:
        dimensions.append("mfa")
    out.update(identityPropagationProfile="V3_MIDDLEWARE_STRIP_AND_PROPAGATE",
               kongPublicEdgeEnforcement=True, failClosedDimensions=dimensions)
    if replay:
        out["replayBoundary"] = {
            "serviceReplayAllowed": False,
            "requiredActorKind": "user",
            "requiredGrantType": "authorization_code",
            "pkceRequired": True,
            "requiredScope": REPLAY_SCOPE,
            "requiredRealmRole": REPLAY_ROLE,
            "mfaRequired": True,
        }
    return out


def route_name(row: dict[str, Any]) -> str:
    import sys
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from scripts.generate_middleware_routes import safe_name
    return safe_name(row["operation_id"])


def route_traffic(row: dict[str, Any]) -> dict[str, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from scripts.kong_traffic_policy import select, selection_inputs
    return select(row, *selection_inputs())


def foundation_entry(row: dict[str, Any], environment: str) -> dict[str, Any]:
    """Registry entry for one shared-edge Middleware operation in one environment."""
    name = route_name(row)
    human_or_service = row["auth"] == "service-or-user-jwt"
    if environment == "production":
        route_id, service_id = name, SERVICE_ID
        bindings = [{"source": path, "route": name, "role": "DESIRED"}
                    for path in (CANONICAL_PATH, PRODUCTION_PATH, AUTHORITY_PATH)]
    else:
        route_id, service_id = f"{name}@staging", f"{SERVICE_ID}@staging"
        bindings = [{"source": STAGING_PATH, "route": name, "role": "DESIRED"}]
    return {
        "routeId": route_id,
        "serviceId": service_id,
        "environment": environment,
        "bindings": bindings,
        "trafficClass": "READ_API" if row["method"] == "GET" else "COMMAND_API",
        "authentication": "AUTHENTICATED" if human_or_service else "SERVICE_AUTHENTICATED",
        "mechanism": "OIDC_BEARER",
        "rateLimitProfile": route_traffic(row)["rateLimitProfile"],
        "requestSizeProfile": route_traffic(row)["requestSizeProfile"],
        "lifecycle": "CANONICAL",
        "activation": "SOURCE_CANDIDATE",
        "disposition": "KEEP",
        "acceptedFindings": [],
        "audience": row["audience"],
        "requiredScopes": [row["scope"]],
        "scopeAuthority": AUTHORITY_PATH,
        "contractOperation": row["operation_id"],
        "contractAuthentication": row["auth"],
        "contractExpectedAzp": row["calling_client"],
    }


def access_entry(row: dict[str, Any], environment: str) -> dict[str, Any]:
    """Access-policy entry for one shared-edge Middleware operation in one environment."""
    name = route_name(row)
    human_or_service = row["auth"] == "service-or-user-jwt"
    return {
        "routeId": name if environment == "production" else f"{name}@staging",
        "environment": environment,
        "accessClass": "AUTHENTICATED" if human_or_service else "SERVICE_AUTHENTICATED",
        "authenticationProfile": "HUMAN_OR_SERVICE_OIDC_V1" if human_or_service else "SERVICE_OIDC_V1",
        "issuerProfile": ISSUER_PROFILE[environment],
        "audienceProfile": AUDIENCE_PROFILE[row["audience"]],
        "requiredScopes": [row["scope"]],
        "authorizedParties": "consumer-mapped",
        "principalClasses": ["HUMAN", "SERVICE"] if human_or_service else ["SERVICE"],
        "identityPropagation": "OIDC_STRIP_AND_CONTRACT_METADATA",
        "tenantPolicy": "CLAIM_ONLY_MIDDLEWARE_VALIDATES",
        "failurePolicy": "FAIL_CLOSED_V1",
        "tokenCache": "OIDC_CACHE_V1",
        "acceptedFindings": ["EXPECTED_AZP_ENFORCED_UPSTREAM"],
        "scopeAuthority": AUTHORITY_PATH,
        "contractOperation": row["operation_id"],
        "contractAuthentication": row["auth"],
        "contractExpectedAzp": row["calling_client"],
    }


def upsert_entries(entries: list[dict[str, Any]], contract: dict[str, Any], build) -> list[str]:
    """Generate entries for shared-edge operations that have none. Existing entries
    are kept but must agree with the rule outside CURATED_FIELDS; DERIVED_FIELDS
    are rewritten from the traffic-profile selector."""
    by_id = {entry["routeId"]: entry for entry in entries}
    added: list[str] = []
    insert_at = 1 + max((i for i, e in enumerate(entries)
                         if "contractOperation" in e and e["routeId"].startswith("middleware-")),
                        default=len(entries) - 1)
    for row in contract["routes"]:
        if row["classification"] != "shared_edge":
            continue
        for environment in ("production", "staging"):
            expected = build(row, environment)
            current = by_id.get(expected["routeId"])
            if current is None:
                entries.insert(insert_at, expected)
                insert_at += 1
                added.append(expected["routeId"])
                continue
            for key in DERIVED_FIELDS & set(expected):
                current[key] = expected[key]
            drift = sorted(key for key in set(expected) | set(current)
                           if key not in CURATED_FIELDS and expected.get(key) != current.get(key))
            if drift:
                raise RouteSecurityError(f"{expected['routeId']}: registry entry disagrees with contract on {drift}")
    return added


def build_rows(contract: dict[str, Any], profiles: dict[str, Any]) -> list[dict[str, Any]]:
    authority = profiles["v3CallerAuthority"]
    privileged = set(authority["tokenPolicy"]["privilegedScopes"])
    rows = [route_security_row(row, authority["callers"], privileged) for row in contract["routes"]]
    keys = [(r["method"], r["path"]) for r in rows]
    if len(set(keys)) != len(keys) or len({r["operationId"] for r in rows}) != len(rows):
        raise RouteSecurityError("duplicate method+path or operationId in Middleware contract")
    return rows


def render(policy: dict[str, Any], contract: dict[str, Any], profiles: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any]:
    rows = build_rows(contract, profiles)
    counts: dict[str, int] = {}
    for row in contract["routes"]:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    out = json.loads(json.dumps(policy))
    authority = out["v3MiddlewareSecurityAuthority"]
    authority["routeSecurity"] = rows
    source = authority["source"]
    digest = canonical_digest(contract)
    if digest != pin["contractSha256"]:
        raise RouteSecurityError(f"Middleware contract digest {digest} does not match pin {pin['contractSha256']}")
    source["middlewareRepository"] = pin["repository"]
    source["middlewareCommit"] = pin["commit"]
    source["routeContractSha256"] = digest
    source["routeCount"] = len(rows)
    source["classificationCounts"] = {name: counts.get(name, 0) for name in ("shared_edge", "denied", "private_only")}
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    policy = load_json(POLICY_PATH)
    rendered = render(policy, load_json(CONTRACT_PATH), load_json(PROFILES_PATH), load_json(PIN_PATH))
    contract = load_json(CONTRACT_PATH)
    foundation = load_json(FOUNDATION_PATH)
    profiles = load_json(PROFILES_PATH)
    pin = load_json(PIN_PATH)
    profiles["v3CallerAuthority"]["middleware"].update(
        repository=pin["repository"], commit=pin["commit"], routeContractPath=pin["path"],
        routeContractSha256=pin["contractSha256"], routeCount=pin["routeCount"])
    added_access = upsert_entries(rendered["routes"], contract, access_entry)
    added_foundation = upsert_entries(foundation["routes"], contract, foundation_entry)
    outputs = (
        (POLICY_PATH, json.dumps(rendered, indent=2, ensure_ascii=False) + "\n"),
        (FOUNDATION_PATH, json.dumps(foundation, indent=2, ensure_ascii=False) + "\n"),
        (PROFILES_PATH, json.dumps(profiles, indent=2, ensure_ascii=False) + "\n"),
    )
    if args.check:
        stale = [path.name for path, body in outputs if path.read_text(encoding="utf-8") != body]
        if stale:
            print("KONG_ROUTE_SECURITY=STALE " + ",".join(stale))
            return 1
    else:
        for path, body in outputs:
            path.write_text(body, encoding="utf-8", newline="\n")
        print(f"ADDED_ACCESS={len(added_access)} ADDED_FOUNDATION={len(added_foundation)}")
    rows = rendered["v3MiddlewareSecurityAuthority"]["routeSecurity"]
    print(f"KONG_ROUTE_SECURITY=PASS ROWS={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
