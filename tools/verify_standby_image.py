#!/usr/bin/env python3
"""Verify a locally built standby auth image before it may be published.

BUILD and PUBLISH are separate release steps: nothing reaches the registry
until this verifier accepts the image that ``docker buildx build --load``
produced. The checks are static (``docker inspect``) plus one contained smoke
run that imports the application with synthetic secret files; no network, no
database, no Kong. The pure functions are unit-tested with inspect fixtures.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED_USER = "65532:65532"
EXPECTED_CMD_PREFIX = ["uvicorn", "standby_auth:app"]
SOURCE_LABEL_PREFIX = "https://github.com/"
SECRET_ENV = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_KEY|HMAC)", re.IGNORECASE)
ALLOWED_ENV_PREFIXES = ("PATH=", "LANG=", "GPG_KEY=", "PYTHON_VERSION=", "PYTHON_SHA256=", "PYTHONUNBUFFERED=")
SHA = re.compile(r"[0-9a-f]{40}\Z")
SMOKE_PYTHON = """
import os
from pathlib import Path
import standby_auth
import body_limit
assert os.getuid() == 65532
assert Path("/data").is_dir()
assert Path("/app/standby_auth.py").is_file()
assert Path("/app/body_limit.py").is_file()
print("STANDBY_IMPORT=OK")
"""


class ImageError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ImageError(reason)


def check_config(inspected: dict, expected_revision: str) -> dict:
    """Validate one ``docker inspect`` entry of the built image."""
    require(SHA.fullmatch(expected_revision or "") is not None, "expected_revision_format")
    config = inspected.get("Config") or {}
    require(config.get("User") == EXPECTED_USER, f"image_runs_as:{config.get('User')!r}")
    cmd = config.get("Cmd") or []
    require(list(cmd[:2]) == EXPECTED_CMD_PREFIX, f"unexpected_cmd:{cmd}")
    require(not config.get("Entrypoint"), "unexpected_entrypoint")
    labels = config.get("Labels") or {}
    require(labels.get("org.opencontainers.image.revision") == expected_revision, "revision_label_mismatch")
    require(labels.get("org.opencontainers.image.version") == expected_revision, "version_label_mismatch")
    require(str(labels.get("org.opencontainers.image.source", "")).startswith(SOURCE_LABEL_PREFIX), "source_label_missing")
    for entry in config.get("Env") or []:
        name = entry.split("=", 1)[0]
        require(not SECRET_ENV.search(name), f"secret_like_env:{name}")
        require(entry.startswith(ALLOWED_ENV_PREFIXES), f"unexpected_env:{name}")
    require(not config.get("ExposedPorts") or set(config["ExposedPorts"]) <= {"8080/tcp"}, "unexpected_exposed_ports")
    require(inspected.get("Architecture") == "amd64" and inspected.get("Os") == "linux", "unexpected_platform")
    layers = (inspected.get("RootFS") or {}).get("Layers") or []
    require(0 < len(layers) <= 12, f"unexpected_layer_count:{len(layers)}")
    return {"user": config["User"], "layers": len(layers), "revision": expected_revision}


def docker(*args: str) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=300, check=False)
    if result.returncode != 0:
        # The full (bounded) diagnostics go to stderr so a failed smoke run is explainable from the CI log.
        sys.stderr.write((result.stdout + result.stderr)[-4000:])
        raise ImageError(f"docker_{args[0]}_failed:{result.stderr.strip().splitlines()[-1][:200] if result.stderr.strip() else 'no stderr'}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True, help="local tag produced by docker buildx build --load")
    parser.add_argument("--expected-revision", required=True)
    args = parser.parse_args()
    try:
        entries = json.loads(docker("inspect", args.image))
        require(isinstance(entries, list) and len(entries) == 1, "inspect_ambiguous")
        summary = check_config(entries[0], args.expected_revision)
        # Mirrors deploy/kong-production-standby/compose.standby.yaml: read-only root,
        # tmpfs /tmp, a writable /data state volume (the application opens its
        # SQLite state at import), all capabilities dropped, no new privileges,
        # no network. The tmpfs stands in for the standby_state volume.
        with tempfile.TemporaryDirectory(prefix=".kong-standby-smoke-", dir=Path.cwd()) as secret_dir:
            secret_root = Path(secret_dir)
            database_secret = secret_root / "database-url"
            webhook_secret = secret_root / "webhook-hmac"
            database_secret.write_text("postgresql://synthetic.invalid/standby", encoding="utf-8")
            webhook_secret.write_text("synthetic-webhook-hmac", encoding="utf-8")
            os.chmod(database_secret, 0o444)
            os.chmod(webhook_secret, 0o444)
            smoke = docker(
                "run", "--rm", "--network", "none", "--read-only",
                "--tmpfs", "/tmp:rw,size=4m",
                "--tmpfs", "/data:rw,size=8m,uid=65532,gid=65532,mode=0700",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--mount", f"type=bind,src={database_secret},dst=/run/secrets/database-url,readonly",
                "--mount", f"type=bind,src={webhook_secret},dst=/run/secrets/webhook-hmac,readonly",
                "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--env", "STATE_DB=/data/state.sqlite3",
                "--env", "DATABASE_URL_FILE=/run/secrets/database-url",
                "--env", "WEBHOOK_HMAC_FILE=/run/secrets/webhook-hmac",
                "--workdir", "/app",
                "--entrypoint", "python",
                args.image, "-c", SMOKE_PYTHON,
            )
        require("STANDBY_IMPORT=OK" in smoke, "smoke_import_failed")
    except (ImageError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"STANDBY_IMAGE=FAIL {error}")
        return 2
    print("STANDBY_IMAGE=PASS")
    print(f"IMAGE_USER={summary['user']} IMAGE_LAYERS={summary['layers']} IMAGE_REVISION={summary['revision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
