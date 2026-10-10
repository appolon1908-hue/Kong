"""CI host privilege boundaries for the exact-SHA Kong admission pipeline."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _jobs(workflow: str) -> dict:
    source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    return yaml.safe_load(source)["jobs"]


def test_os_package_installation_is_not_run_on_unprivileged_self_hosted_runner():
    for workflow in ("validate.yml", "kong-v3-certification.yml"):
        for name, job in _jobs(workflow).items():
            needs_os_packages = any("sudo apt-get" in step.get("run", "") for step in job.get("steps", []))
            if needs_os_packages:
                assert job["runs-on"] == "ubuntu-24.04", (workflow, name)


def test_protected_source_and_merge_checks_remain_mandatory():
    jobs = _jobs("validate.yml")
    assert jobs["source-head"]["runs-on"] == "ubuntu-24.04"
    assert jobs["merge-result"]["runs-on"] == "ubuntu-24.04"
    assert jobs["validate"]["needs"] == ["source-head", "merge-result"]
    required = jobs["validate"]["steps"][0]["run"]
    assert 'test "${HEAD_RESULT}" = success' in required
    assert 'test "${MERGE_RESULT}" = success' in required
    for name in ("source-head", "merge-result"):
        text = repr(jobs[name]["steps"])
        assert "EXPECTED_SHA" in text
        assert "persist-credentials" in text


def test_static_certification_keeps_exact_sha_gitleaks_and_effect_denial():
    jobs = _jobs("kong-v3-certification.yml")
    cert = jobs["static-certification"]
    assert cert["runs-on"] == "ubuntu-24.04"
    steps = cert["steps"]
    combined = "\n".join(step.get("run", "") for step in steps)
    assert "git rev-parse HEAD" in combined
    assert "gitleaks dir --redact --no-banner --exit-code 1" in combined
    assert "PROVIDER_EFFECTS=0" in combined
    assert "RUNTIME_APPLY_AUTHORIZED=NO" in combined
    assert "git diff --check" in combined
