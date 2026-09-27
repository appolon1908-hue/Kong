#!/usr/bin/env python3
"""Validate frozen K1 authority and runtime profiles without applying configuration."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_authority(document):
    expected = {
        "version": "1.0", "production_mode": "hybrid", "fallback_mode": "traditional",
        "fallback_requires_explicit_approval": True, "standalone_dbless_production": False,
        "declarative_config_role": "validation-and-source-generation-only",
        "admin_api": {"public": False, "proxy_data_plane": "disabled", "control_plane": "loopback-only"},
        "hybrid_cluster": {"mtls": True, "pki": "private", "ports": [8005, 8006]},
        "runtime_apply_authorized": False,
    }
    # JSON comparison retains boolean versus integer distinctions.
    require(json.dumps(document, sort_keys=True) == json.dumps(expected, sort_keys=True),
            "frozen K1 authority mismatch")


def trusted_sources(value):
    require(isinstance(value, str) and bool(value), "missing exact trusted proxy CIDRs")
    if re.fullmatch(r"\$\{KONG_TRUSTED_IPS:\?[^}]+\}", value):
        return  # Required source template; rendered values are checked by this same validator.
    for item in value.split(","):
        network = ipaddress.ip_network(item.strip(), strict=True)
        require(network.prefixlen > 0, "universal proxy trust is forbidden")


def secret_reference(service, value):
    require(isinstance(value, str) and value.startswith("/run/secrets/"), "private mounted PKI required")
    name = value.removeprefix("/run/secrets/")
    names = {s if isinstance(s, str) else s.get("target", s.get("source"))
             for s in service.get("secrets", [])}
    require(name in names and "/" not in name, "PKI secret not mounted")


def validate_profile(document, mode, approval=None, legacy=False):
    require(mode in {"hybrid", "traditional"}, "standalone DB-less production is forbidden")
    if mode == "traditional":
        require(isinstance(approval, str) and re.fullmatch(r"KONG:[A-Za-z0-9:_-]+", approval),
                "traditional fallback requires explicit KONG approval reference")
    expected_roles = ({"kong-gateway": "data_plane"} if legacy else
                      {"kong-cp": "control_plane", "kong-dp-1": "data_plane", "kong-dp-2": "data_plane"}
                      if mode == "hybrid" else
                      {"kong-proxy-1": "traditional", "kong-proxy-2": "traditional", "kong-management": "traditional"})
    require(isinstance(document, dict), "compose must be a mapping")
    services = document.get("services", {})
    require(isinstance(services, dict), "services must be a mapping")
    declared_networks = document.get("networks", {})
    require(isinstance(declared_networks, dict), "networks must be a mapping")
    if legacy:
        expected_names = {"kong_cluster": "codestra_kong_cluster", "kong_frontend": "codestra_edge",
                          "codestra_backend": "codestra_backend", "codestra_observability": "codestra-observability"}
    else:
        boundary = yaml.safe_load((ROOT / "deploy/gateway-platform/network-boundaries.yaml").read_text())
        expected_names = {key: value["docker_name"] for key, value in boundary["networks"].items()
                          if value.get("internal_required") is True}
    require(set(declared_networks) == set(expected_names), "unknown network authority")
    for key, actual in declared_networks.items():
        require(actual == {"external": True, "name": expected_names[key]}, "private network mapping mismatch")
    declared_secrets = document.get("secrets", {})
    require(isinstance(declared_secrets, dict), "secrets must be a mapping")
    if mode == "hybrid":
        names = ("cluster_ca", "dp_cert", "dp_key") if legacy else (
            "cluster_ca", "cp_cert", "cp_key", "dp1_cert", "dp1_key", "dp2_cert", "dp2_key")
        for key in names:
            suffix = {"cluster_ca": "cluster-ca.crt", "dp_cert": "dp.crt", "dp_key": "dp.key"}.get(key)
            expected = ("/etc/codestra/secrets/kong/" + suffix if legacy else
                        "${GATEWAY_SECRET_DIRECTORY:?approved local secret directory required}/" + key)
            require(declared_secrets.get(key) == {"file": expected},
                    "private-PKI secret source authority mismatch")
    if mode == "hybrid":
        require(declared_networks.get("kong_cluster") == {
            "external": True, "name": "codestra_kong_cluster"}, "private cluster network authority mismatch")
    require(set(services) == set(expected_roles), "unexpected or missing runtime services")
    for name, service in services.items():
        require(isinstance(service, dict), "service must be a mapping")
        env = service.get("environment", {})
        require(isinstance(env, dict), "environment must be an explicit mapping")
        role = expected_roles[name]
        require(env.get("KONG_ROLE") == role, "role does not match selected profile")
        require(not service.get("network_mode") and not service.get("privileged"), "unsafe container network/privilege")
        require(service.get("read_only") is True, "runtime filesystem must be read-only")
        require(service.get("profiles") == [mode + "-source"], "explicit source profile required")
        ports = service.get("ports", [])
        require(ports == (["127.0.0.1:8000:8000"] if legacy else []),
                "Admin, status and cluster ports must never be published")
        require(env.get("CODESTRA_RUNTIME_APPLY_AUTHORIZED") == "false", "runtime apply is unauthorized")
        require(not any(k.startswith("KONG_DECLARATIVE_CONFIG") for k in env),
                "declarative configuration cannot become runtime apply authority")
        require(env.get("KONG_ADMIN_GUI_LISTEN") == "off", "Admin GUI must be off")
        proxy = env.get("KONG_PROXY_LISTEN")
        management = role == "control_plane" or name == "kong-management"
        require(env.get("KONG_ADMIN_LISTEN") == ("127.0.0.1:8001" if management else "off"),
                "Admin API must be loopback on management and disabled on proxies")
        require(proxy == "off" if management else proxy in {"0.0.0.0:8443 ssl", "0.0.0.0:8000"},
                "invalid management/proxy listener separation")
        if not management:
            trusted_sources(env.get("KONG_TRUSTED_IPS"))
            require(env.get("KONG_REAL_IP_HEADER") == "X-Forwarded-For"
                    and env.get("KONG_REAL_IP_RECURSIVE") == "on", "forwarded header authority mismatch")
        require(env.get("KONG_STATUS_LISTEN") == "0.0.0.0:8100", "private status listener required")
        healthcheck = service.get("healthcheck", {})
        require(isinstance(healthcheck, dict) and healthcheck.get("disable", False) is False,
                "readiness must remain enabled")
        require(healthcheck.get("test") == [
            "CMD", "curl", "--fail", "--silent", "--show-error", "--max-time", "3",
            "http://127.0.0.1:8100/status/ready"], "readiness must check config and dependency readiness")
        mounts = service.get("volumes", [])
        guard = [v for v in mounts if isinstance(v, dict) and v.get("target") == "/etc/codestra/runtime-guard.sh"]
        expected_guard_source = "../gateway-platform/runtime-guard.sh" if legacy else "./runtime-guard.sh"
        require(guard == [{"type": "bind", "source": expected_guard_source,
                          "target": "/etc/codestra/runtime-guard.sh", "read_only": True}],
                "immutable runtime guard mount required")
        if not legacy:
            wrapper = [v for v in mounts if isinstance(v, dict)
                       and v.get("target") == "/usr/local/bin/codestra-kong-entrypoint"]
            require(wrapper == [{"type": "bind", "source": "./codestra-kong-entrypoint.sh",
                                 "target": "/usr/local/bin/codestra-kong-entrypoint", "read_only": True}],
                    "reviewed entrypoint source required")
        expected_entrypoint = (["sh", "/etc/codestra/runtime-guard.sh"] if legacy
                               else ["/usr/local/bin/codestra-kong-entrypoint"])
        require(service.get("entrypoint") == expected_entrypoint, "guarded entrypoint required")
        require(service.get("command") == ["kong", "docker-start"], "only guarded Kong startup allowed")
        networks = set(service.get("networks", []))
        expected_networks = ({"kong_frontend", "codestra_backend", "codestra_observability", "kong_cluster"}
                             if legacy else
                             {"kong_admin", "kong_database", "kong_cluster", "observability"} if role == "control_plane" else
                             {"kong_admin", "kong_database", "observability"} if name == "kong-management" else
                             {"kong_proxy", "kong_cluster", "kong_rate_limit", "observability", "middleware_upstream"}
                             if role == "data_plane" else
                             {"kong_proxy", "kong_database", "kong_rate_limit", "observability", "middleware_upstream"})
        require(networks == expected_networks, "runtime network separation violated")
        if role == "data_plane":
            require(env.get("KONG_DATABASE") == "off", "data plane must not have database authority")
            require(not any(k.startswith("KONG_PG_") for k in env), "data plane database settings forbidden")
            secret_names = {v if isinstance(v, str) else v.get("source") for v in service.get("secrets", [])}
            require(not secret_names & {"kong_runtime_password", "kong_database_runtime_password", "cp_key", "cp_cert"},
                    "data plane cannot mount database or control-plane credentials")
            require("kong_database" not in networks and "kong_admin" not in networks, "data plane isolation violated")
        else:
            require(env.get("KONG_DATABASE") == "postgres", "standalone DB-less production is forbidden")
            require(env.get("KONG_PG_SSL") == "on" and env.get("KONG_PG_SSL_VERIFY") == "on",
                    "database TLS verification required")
            require(bool(env.get("KONG_PG_HOST")), "database dependency must be explicit")
        if mode == "hybrid":
            require("kong_cluster" in networks, "private cluster network required")
            require(env.get("KONG_CLUSTER_MTLS") == "pki", "private-PKI mTLS required")
            node = "dp" if legacy else {"kong-cp": "cp", "kong-dp-1": "dp1", "kong-dp-2": "dp2"}[name]
            require(env.get("KONG_CLUSTER_CA_CERT") == "/run/secrets/cluster_ca"
                    and env.get("KONG_CLUSTER_CERT") == f"/run/secrets/{node}_cert"
                    and env.get("KONG_CLUSTER_CERT_KEY") == f"/run/secrets/{node}_key",
                    "per-node cluster identity required")
            for key in ("KONG_CLUSTER_CA_CERT", "KONG_CLUSTER_CERT", "KONG_CLUSTER_CERT_KEY"):
                secret_reference(service, env.get(key))
            if role == "control_plane":
                require(env.get("KONG_CLUSTER_LISTEN") == "0.0.0.0:8005"
                        and env.get("KONG_CLUSTER_TELEMETRY_LISTEN") == "0.0.0.0:8006",
                        "cluster ports must be 8005/8006 on private network only")
                require("kong_proxy" not in networks and "middleware_upstream" not in networks,
                        "control plane must not proxy traffic")
            else:
                for key, expected in {
                    "KONG_CLUSTER_CONTROL_PLANE": "kong-cp.internal.codestra:8005",
                    "KONG_CLUSTER_TELEMETRY_ENDPOINT": "kong-cp.internal.codestra:8006",
                    "KONG_CLUSTER_SERVER_NAME": "kong-cp.internal.codestra",
                    "KONG_CLUSTER_TELEMETRY_SERVER_NAME": "kong-cp.internal.codestra",
                }.items():
                    require(env.get(key) == expected, "control-plane endpoint/SNI mismatch")
        else:
            require(env.get("CODESTRA_TRADITIONAL_APPROVAL") ==
                    "${CODESTRA_TRADITIONAL_APPROVAL:?explicit KONG fallback approval required}" or
                    env.get("CODESTRA_TRADITIONAL_APPROVAL") == approval,
                    "fallback approval must be carried by runtime configuration")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("authority", nargs="?", default=str(ROOT / "config/kong-runtime-config-mode.v1.json"))
    parser.add_argument("--compose", type=Path)
    parser.add_argument("--mode", choices=["hybrid", "traditional"], default="hybrid")
    parser.add_argument("--traditional-approval")
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_authority(json.loads(Path(args.authority).read_text()))
        if args.compose:
            validate_profile(yaml.safe_load(args.compose.read_text()), args.mode, args.traditional_approval, args.legacy)
        else:
            validate_profile(yaml.safe_load((ROOT / "deploy/gateway-platform/compose.hybrid.yaml").read_text()), "hybrid")
            validate_profile(yaml.safe_load((ROOT / "deploy/kong/compose.kong.yaml").read_text()), "hybrid", legacy=True)
    except (ValueError, TypeError, KeyError, OSError, yaml.YAMLError) as error:
        print(f"kong-runtime-mode: FAIL {error}", file=sys.stderr)
        return 1
    print("kong-runtime-mode: PASS; runtime apply unauthorized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
