"""Independent static check of the read-only dashboard staging route."""
from __future__ import annotations
import re
import unittest
from pathlib import Path

import yaml

ROOT=Path(__file__).resolve().parents[1]
DATA=yaml.safe_load((ROOT/"config/staging/kong-mission-control-dashboard.staging.yml").read_text())


class DashboardStagingRouteTest(unittest.TestCase):
    def test_staging_only_no_runtime_effects(self):
        service,=DATA["services"]
        self.assertEqual(service["protocol"],"http")
        self.assertEqual(service["host"],"mission-control-readonly")
        self.assertIn("codestra.runtime-apply-authorized.false",service["tags"])
        self.assertIn("codestra.external-effects.false",service["tags"])

    def test_exact_get_only_authority(self):
        route,=DATA["services"][0]["routes"]
        self.assertEqual(route["methods"],["GET"])
        self.assertFalse(route["strip_path"])
        self.assertTrue(route["preserve_host"])
        self.assertEqual(route["hosts"],["api.codestra.co"])
        pattern=route["paths"][0]
        self.assertTrue(pattern.startswith("~^"))
        compiled=re.compile(pattern[1:])
        for item in ["contract","repositories","repository","agents","sources","tasks","task","local-work","notifications"]:
            self.assertTrue(compiled.fullmatch("/platform/v1/dashboard/"+item),item)
        for path in ["/platform/v1/commands","/platform/v1/dashboard/metrics",
                     "/platform/v1/dashboard/../internal","/internal","/platform/v1/dashboard/extra"]:
            self.assertIsNone(compiled.fullmatch(path),path)

    def test_auth_scopes_strip_trust_and_rate_limit(self):
        route,=DATA["services"][0]["routes"]
        plugins={x["name"]:x["config"] for x in route["plugins"]}
        self.assertEqual(plugins["openid-connect"]["audience"],["mission-control-backend"])
        self.assertEqual(plugins["openid-connect"]["scopes_required"],["mission.dashboard.read"])
        self.assertIn("auth-staging.codestra.co",plugins["openid-connect"]["issuer"])
        self.assertIn("X-Authenticated-Tenant",plugins["request-transformer"]["remove"]["headers"])
        self.assertEqual(plugins["rate-limiting"]["fault_tolerant"],False)

if __name__=="__main__":
    unittest.main()
