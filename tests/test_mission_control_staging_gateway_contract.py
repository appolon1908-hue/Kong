"""Staging gateway route is read-only, Keycloak-guarded, and not live."""
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "deploy/staging/mission-control-dashboard.kong.yml"


def test_staging_route_has_scoped_identity_and_no_effects():
    doc = yaml.safe_load(PATH.read_text())
    assert doc["_format_version"] == "3.0"
    service = doc["services"][0]
    assert service["host"] == "mission-control-readonly"
    assert service["port"] == 8792
    assert service["retries"] == 0
    assert "codestra.runtime-apply-authorized.false" in service["tags"]
    assert "codestra.provider-effects-enabled.false" in service["tags"]
    route = service["routes"][0]
    assert route["methods"] == ["GET"]
    assert route["strip_path"] is False
    assert route["hosts"] == ["dashboard.staging.internal.codestra.agency"]
    assert route["paths"][0].startswith("~^/platform/v1/dashboard/")
    plugin = {p["name"]: p["config"] for p in route["plugins"]}
    assert plugin["openid-connect"]["auth_methods"] == ["bearer"]
    assert plugin["openid-connect"]["audience"] == ["mission-control-backend"]
    assert plugin["openid-connect"]["scopes_required"] == ["dashboard.read"]
    assert plugin["openid-connect"]["issuer"].startswith(
        "https://auth-staging.codestra.co/realms/codestra/"
    )
    assert {"X-User-ID", "X-Authenticated-Tenant", "X-Internal-Service"}.issubset(
        set(plugin["request-transformer"]["remove"]["headers"])
    )
    assert plugin["rate-limiting"]["fault_tolerant"] is False
    assert plugin["request-size-limiting"]["allowed_payload_size"] == 1
