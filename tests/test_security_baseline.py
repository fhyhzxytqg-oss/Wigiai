import os
import unittest
from datetime import datetime, timezone

from src import mcp_server, oauth_example
from src.iteration_governance import PromotionPolicy, SimulationResult, evaluate_promotion


class TestMcpServer(unittest.TestCase):
    def setUp(self):
        mcp_server.REQUIRE_AUTH = False
        mcp_server.SHARED_SECRET = ""

    def test_invalid_jsonrpc(self):
        response = mcp_server.handle_request({"jsonrpc": "1.0", "id": 1, "method": "tools/list"})
        self.assertIn("error", response)

    def test_echo_rejects_long_text(self):
        response = mcp_server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "echo",
                    "arguments": {"text": "x" * (mcp_server.MAX_ECHO_TEXT_CHARS + 1)},
                },
            }
        )
        self.assertIn("error", response)

    def test_auth_required_without_secret_rejected(self):
        mcp_server.REQUIRE_AUTH = True
        mcp_server.SHARED_SECRET = ""
        response = mcp_server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hello"}},
            }
        )
        self.assertIn("error", response)
        self.assertIn("Unauthorized", response["error"]["message"])


class TestOAuthHelpers(unittest.TestCase):
    def test_pkce_pair(self):
        verifier, challenge = oauth_example.generate_pkce_pair()
        self.assertTrue(len(verifier) >= 43)
        self.assertTrue(len(challenge) >= 43)

    def test_state_round_trip(self):
        os.environ["OAUTH_STATE_SIGNING_SECRET"] = "unit-test-secret"
        oauth_example.STATE_SIGNING_SECRET = "unit-test-secret"

        token = oauth_example.generate_state({"tenant": "wigiai"})
        payload = oauth_example.validate_state(token)
        self.assertEqual(payload["tenant"], "wigiai")

    def test_reject_non_allowlisted_host(self):
        oauth_example.ALLOWED_HOSTS = ["wigiai.com"]
        with self.assertRaises(ValueError):
            oauth_example._ensure_https("https://provider.example.com/oauth2/authorize")


class TestIterationGovernance(unittest.TestCase):
    def test_promotion_blocked_when_security_findings_present(self):
        result = SimulationResult(
            scenario_id="batch-1",
            prediction_accuracy=0.80,
            contradiction_precision=0.80,
            contradiction_recall=0.72,
            p95_latency_ms=900,
            security_findings_high=1,
            security_findings_critical=0,
            legal_policy_violations=0,
        )
        decision = evaluate_promotion(
            [result],
            now=datetime(2026, 4, 26, 12, 0, tzinfo=timezone.utc),
        )
        self.assertFalse(decision["approved"])
        self.assertIn("high security findings must be zero", decision["reasons"])

    def test_promotion_approved_on_sunday_with_clean_results(self):
        result = SimulationResult(
            scenario_id="batch-2",
            prediction_accuracy=0.82,
            contradiction_precision=0.80,
            contradiction_recall=0.78,
            p95_latency_ms=850,
            security_findings_high=0,
            security_findings_critical=0,
            legal_policy_violations=0,
        )
        decision = evaluate_promotion(
            [result],
            policy=PromotionPolicy(min_prediction_accuracy=0.75),
            now=datetime(2026, 4, 26, 12, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(decision["approved"])


if __name__ == "__main__":
    unittest.main()
