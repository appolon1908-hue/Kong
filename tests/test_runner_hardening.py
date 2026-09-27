from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_buildx_builder_id_is_recorded_before_create_and_inspect():
    for path, prefix in (
        (".github/workflows/release-preflight.yml", 'builder="kong-preflight-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"'),
        (".github/workflows/release.yml", 'builder="kong-release-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"'),
    ):
        text = read(path)
        start = text.index(prefix)
        output = text.index('echo "builder=${builder}" >> "${GITHUB_OUTPUT}"', start)
        create = text.index('docker buildx create --name "${builder}"', start)
        inspect = text.index("docker buildx inspect --bootstrap", start)
        assert start < output < create < inspect


def test_gitleaks_uses_runner_scoped_temp_and_strict_checksum():
    text = read(".github/workflows/security.yml")
    block = text[text.index("- name: Scan Git history for secrets"):text.index("- name: Set up Python 3.12")]
    assert "set -Eeuo pipefail" in block
    assert '${RUNNER_TEMP}/gitleaks.tar.gz' in block
    assert "sha256sum --check --strict" in block
    assert 'tar -xzf "${RUNNER_TEMP}/gitleaks.tar.gz" -C "${RUNNER_TEMP}" gitleaks' in block
    assert '"${RUNNER_TEMP}/gitleaks" git --redact --no-banner .' in block
    assert "/tmp/gitleaks" not in block
