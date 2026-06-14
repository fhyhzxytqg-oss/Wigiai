# Wigiai Secure MCP + OAuth Baseline

You were right to challenge the first draft: it was a **starter**, not a secure production baseline.
This revision raises the floor with security controls better aligned to legal-litigation workloads.

## What's included

- `src/mcp_server.py`
  - strict JSON-RPC validation
  - bounded input size
  - required-by-default HMAC authentication (`WIGIAI_MCP_SHARED_SECRET`)
  - replay protection (`nonce` + timestamp window)
  - tamper-evident audit chain events to stderr
- `src/oauth_example.py`
  - PKCE (`S256`) helper generation
  - signed, expiring state tokens (CSRF mitigation)
  - strict HTTPS URL enforcement
  - explicit OAuth host allow-listing (`OAUTH_ALLOWED_HOSTS`)
  - token redaction helper for safe logging
- `src/iteration_governance.py`
  - weekly self-iteration promotion gate for your orchestrator heartbeat
  - enforces security-first release policy (Sunday UTC + zero critical/high findings)
  - enforces product quality thresholds (prediction accuracy + contradiction F1 + latency budget)

## Environment variables

### MCP

- `WIGIAI_MCP_SHARED_SECRET` (recommended in production)
- `WIGIAI_MCP_REQUIRE_AUTH` (default: `1`)
- `WIGIAI_MCP_MAX_LINE_BYTES` (default: `65536`)
- `WIGIAI_MCP_MAX_ECHO_CHARS` (default: `2000`)
- `WIGIAI_MCP_AUTH_WINDOW_SECONDS` (default: `300`)
- `WIGIAI_MCP_AUDIT_LOG_STDERR` (default: `1`)

### OAuth

- `OAUTH_AUTHORIZATION_ENDPOINT`
- `OAUTH_TOKEN_ENDPOINT`
- `OAUTH_REDIRECT_URI`
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET` (only for confidential clients)
- `OAUTH_STATE_SIGNING_SECRET` (**required** for state generation/validation)
- `OAUTH_ALLOWED_HOSTS` (comma-separated host allow-list)

## Security caveats (important)

- These files are still a **baseline**, not a complete security architecture.
- For production handling legal data, add:
  - mTLS or private-network transport for MCP,
  - centralized secrets management (KMS/HSM),
  - audit logging with tamper evidence,
  - mandatory at-rest encryption and key rotation,
  - dependency and SAST/DAST scanning in CI,
  - regular penetration testing.

## Quick checks

```bash
python3 -m py_compile src/mcp_server.py src/oauth_example.py src/iteration_governance.py
python3 -m unittest -v tests/test_security_baseline.py
python3 -m compileall -q src tests
```

## Suggested integration pattern for your orchestrator (Alpha/Omega)

1. Run your weekly simulation swarm on Sunday UTC with fixed evaluation datasets.
2. Convert each scenario output into a `SimulationResult`.
3. Call `evaluate_promotion(...)` and only promote when `approved=True`.
4. Record `metrics` + `reasons` in an immutable audit log and require human sign-off for legal-risk releases.
