"""Security-hardened MCP-style server over stdin/stdout (JSON-RPC 2.0).

Design goals for legal-tech workloads:
- strict input validation
- replay protection on tool execution
- optional HMAC request authentication for tools/call
- bounded payload sizes to reduce abuse risk
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from typing import Any, Dict, Tuple

JSONRPC_VERSION = "2.0"
MAX_LINE_BYTES = int(os.getenv("WIGIAI_MCP_MAX_LINE_BYTES", "65536"))
MAX_ECHO_TEXT_CHARS = int(os.getenv("WIGIAI_MCP_MAX_ECHO_CHARS", "2000"))
AUTH_WINDOW_SECONDS = int(os.getenv("WIGIAI_MCP_AUTH_WINDOW_SECONDS", "300"))
NONCE_CACHE_LIMIT = int(os.getenv("WIGIAI_MCP_NONCE_CACHE_LIMIT", "5000"))
SHARED_SECRET = os.getenv("WIGIAI_MCP_SHARED_SECRET", "")
REQUIRE_AUTH = os.getenv("WIGIAI_MCP_REQUIRE_AUTH", "1") == "1"
AUDIT_LOG_STDERR = os.getenv("WIGIAI_MCP_AUDIT_LOG_STDERR", "1") == "1"

_USED_NONCES: Dict[str, int] = {}
_AUDIT_CHAIN_PREV = "0" * 64


def _write(message: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _validate_base_request(request: Dict[str, Any]) -> Tuple[bool, str]:
    if request.get("jsonrpc") != JSONRPC_VERSION:
        return False, "jsonrpc must be '2.0'"
    if "method" not in request or not isinstance(request["method"], str):
        return False, "method must be a string"
    if "id" in request and not isinstance(request["id"], (str, int, type(None))):
        return False, "id must be string, integer, or null"
    if "params" in request and not isinstance(request["params"], dict):
        return False, "params must be an object"
    return True, ""


def _append_audit_event(event_type: str, request_id: Any, detail: str) -> None:
    """Write tamper-evident audit events to stderr."""
    global _AUDIT_CHAIN_PREV
    event = {
        "ts": int(time.time()),
        "event": event_type,
        "request_id": request_id,
        "detail": detail,
    }
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    prev_hash = _AUDIT_CHAIN_PREV
    chain_input = f"{prev_hash}:{canonical}".encode("utf-8")
    event_hash = hashlib.sha256(chain_input).hexdigest()
    _AUDIT_CHAIN_PREV = event_hash
    if AUDIT_LOG_STDERR:
        sys.stderr.write(
            json.dumps(
                {"audit": event, "chain_prev": prev_hash, "chain_hash": event_hash},
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stderr.flush()


def _prune_nonce_cache(now_ts: int) -> None:
    expired = [nonce for nonce, ts in _USED_NONCES.items() if now_ts - ts > AUTH_WINDOW_SECONDS]
    for nonce in expired:
        _USED_NONCES.pop(nonce, None)

    if len(_USED_NONCES) > NONCE_CACHE_LIMIT:
        for nonce, _ in sorted(_USED_NONCES.items(), key=lambda item: item[1])[: len(_USED_NONCES) - NONCE_CACHE_LIMIT]:
            _USED_NONCES.pop(nonce, None)


def _verify_auth(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify HMAC auth envelope.

    Expected params.auth fields:
    {
      "ts": <unix timestamp int>,
      "nonce": "...",
      "signature": "hex hmac sha256"
    }

    Signature base string:
      "{ts}:{nonce}:{tool_name}:{canonical_arguments_json}"
    """
    if not SHARED_SECRET:
        if REQUIRE_AUTH:
            return False, "server auth required but shared secret not configured"
        return True, ""

    auth = params.get("auth")
    if not isinstance(auth, dict):
        return False, "auth object required"

    ts = auth.get("ts")
    nonce = auth.get("nonce")
    signature = auth.get("signature")
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if not isinstance(ts, int) or not isinstance(nonce, str) or not isinstance(signature, str):
        return False, "invalid auth fields"
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        return False, "invalid tool call fields"
    if len(nonce) < 16 or len(nonce) > 128:
        return False, "invalid nonce length"

    now_ts = int(time.time())
    if abs(now_ts - ts) > AUTH_WINDOW_SECONDS:
        return False, "stale timestamp"

    _prune_nonce_cache(now_ts)
    if nonce in _USED_NONCES:
        return False, "replay detected"

    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    base = f"{ts}:{nonce}:{tool_name}:{canonical_args}".encode("utf-8")
    expected = hmac.new(SHARED_SECRET.encode("utf-8"), base, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, signature):
        return False, "invalid signature"

    _USED_NONCES[nonce] = now_ts
    return True, ""


def _tool_list() -> Dict[str, Any]:
    requires_auth = bool(SHARED_SECRET) or REQUIRE_AUTH
    return {
        "tools": [
            {
                "name": "echo",
                "description": "Returns caller text. Use for connectivity smoke tests only.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "maxLength": MAX_ECHO_TEXT_CHARS},
                    },
                    "required": ["text"],
                    "additionalProperties": False,
                },
                "security": {
                    "requires_auth": requires_auth,
                    "auth_mode": "hmac-sha256" if SHARED_SECRET else "misconfigured-required-auth",
                },
            }
        ]
    }


def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    valid, err = _validate_base_request(request)
    request_id = request.get("id")
    if not valid:
        return _error(request_id, -32600, f"Invalid Request: {err}")

    method = request.get("method")
    params = request.get("params", {})

    if method == "initialize":
        if REQUIRE_AUTH and not SHARED_SECRET:
            _append_audit_event("startup_misconfiguration", request_id, "auth required but secret missing")
        session_id = secrets.token_urlsafe(18)
        return _result(
            request_id,
            {
                "serverInfo": {"name": "wigiai-mcp", "version": "0.2.0"},
                "capabilities": {"tools": {}},
                "security": {
                    "auth_required_for_tools_call": bool(SHARED_SECRET) or REQUIRE_AUTH,
                    "max_line_bytes": MAX_LINE_BYTES,
                    "max_echo_chars": MAX_ECHO_TEXT_CHARS,
                    "audit_log_chain": AUDIT_LOG_STDERR,
                },
                "session": {"id": session_id},
            },
        )

    if method == "tools/list":
        return _result(request_id, _tool_list())

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, -32602, "Invalid params: name must be str and arguments must be object")

        auth_ok, auth_err = _verify_auth(params)
        if not auth_ok:
            _append_audit_event("auth_failure", request_id, auth_err)
            return _error(request_id, -32001, f"Unauthorized: {auth_err}")

        if name == "echo":
            text = arguments.get("text")
            if not isinstance(text, str):
                _append_audit_event("validation_failure", request_id, "echo.text not string")
                return _error(request_id, -32602, "Invalid params: text must be string")
            if len(text) > MAX_ECHO_TEXT_CHARS:
                _append_audit_event("validation_failure", request_id, "echo.text too long")
                return _error(request_id, -32602, f"Invalid params: text too long (>{MAX_ECHO_TEXT_CHARS})")
            _append_audit_event("tool_call_success", request_id, "echo")
            return _result(request_id, {"content": [{"type": "text", "text": text}]})

        _append_audit_event("validation_failure", request_id, f"unknown tool {name}")
        return _error(request_id, -32602, f"Unknown tool: {name}")

    return _error(request_id, -32601, f"Method not found: {method}")


def main() -> int:
    while True:
        line = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
        if not line:
            return 0

        if len(line) > MAX_LINE_BYTES:
            _write(_error(None, -32600, f"Input exceeds {MAX_LINE_BYTES} bytes"))
            continue

        raw = line.decode("utf-8", errors="replace").strip()
        if not raw:
            continue

        try:
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise ValueError("Top-level JSON must be an object")
            response = handle_request(request)
        except json.JSONDecodeError:
            response = _error(None, -32700, "Parse error")
        except ValueError as exc:
            response = _error(None, -32600, f"Invalid Request: {exc}")
        except Exception:
            response = _error(None, -32000, "Server error")

        _write(response)


if __name__ == "__main__":
    raise SystemExit(main())
