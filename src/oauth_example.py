"""Security-focused OAuth 2.1-style helper utilities.

This module favors patterns appropriate for legal-tech workloads:
- PKCE for authorization code flow
- signed + expiring state tokens (CSRF mitigation)
- strict HTTPS endpoint validation
- explicit timeout handling
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from typing import Dict, Tuple

AUTHORIZATION_ENDPOINT = os.getenv("OAUTH_AUTHORIZATION_ENDPOINT", "https://provider.example.com/oauth2/authorize")
TOKEN_ENDPOINT = os.getenv("OAUTH_TOKEN_ENDPOINT", "https://provider.example.com/oauth2/token")
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "https://wigiai.com/oauth/callback")
SCOPES = os.getenv("OAUTH_SCOPES", "openid profile email").split()
STATE_SIGNING_SECRET = os.getenv("OAUTH_STATE_SIGNING_SECRET", "")
STATE_TTL_SECONDS = int(os.getenv("OAUTH_STATE_TTL_SECONDS", "600"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("OAUTH_REQUEST_TIMEOUT_SECONDS", "20"))
ALLOWED_HOSTS = [h.strip() for h in os.getenv("OAUTH_ALLOWED_HOSTS", "provider.example.com,wigiai.com").split(",") if h.strip()]


def _ensure_https(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("OAuth endpoint and redirect URLs must use https")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("OAuth URL host is not in OAUTH_ALLOWED_HOSTS")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> Tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def generate_state(payload: Dict[str, str] | None = None) -> str:
    if not STATE_SIGNING_SECRET:
        raise ValueError("OAUTH_STATE_SIGNING_SECRET must be set")

    now_ts = int(time.time())
    data = {
        "iat": now_ts,
        "exp": now_ts + STATE_TTL_SECONDS,
        "nonce": secrets.token_urlsafe(16),
        "payload": payload or {},
    }
    body = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(STATE_SIGNING_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    envelope = {"d": _b64url(body), "s": sig}
    return _b64url(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))


def validate_state(state_token: str) -> Dict[str, str]:
    if not STATE_SIGNING_SECRET:
        raise ValueError("OAUTH_STATE_SIGNING_SECRET must be set")

    padded = state_token + "=" * (-len(state_token) % 4)
    envelope = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

    body_b64 = envelope.get("d", "")
    sig = envelope.get("s", "")

    body_padded = body_b64 + "=" * (-len(body_b64) % 4)
    body = base64.urlsafe_b64decode(body_padded)

    expected = hmac.new(STATE_SIGNING_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("Invalid state signature")

    data = json.loads(body.decode("utf-8"))
    now_ts = int(time.time())
    if now_ts > int(data.get("exp", 0)):
        raise ValueError("State token expired")
    if now_ts < int(data.get("iat", 0)) - 30:
        raise ValueError("State token issued in the future")

    return data.get("payload", {})


def build_authorization_url(client_id: str, state: str, code_challenge: str) -> str:
    _ensure_https(AUTHORIZATION_ENDPOINT)
    _ensure_https(REDIRECT_URI)

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTHORIZATION_ENDPOINT}?{urllib.parse.urlencode(params)}"


def exchange_code_for_token(client_id: str, code: str, code_verifier: str, client_secret: str | None = None) -> Dict:
    _ensure_https(TOKEN_ENDPOINT)
    _ensure_https(REDIRECT_URI)

    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        payload["client_secret"] = client_secret

    encoded_payload = urllib.parse.urlencode(payload).encode("utf-8")
    request = urllib.request.Request(
        TOKEN_ENDPOINT,
        data=encoded_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        body = response.read().decode("utf-8")
    return json.loads(body)


def redact_token_response(token_response: Dict) -> Dict:
    redacted = dict(token_response)
    for key in ("access_token", "refresh_token", "id_token"):
        if key in redacted:
            redacted[key] = "***REDACTED***"
    return redacted


if __name__ == "__main__":
    client_id = os.environ.get("OAUTH_CLIENT_ID", "")
    client_secret = os.environ.get("OAUTH_CLIENT_SECRET")

    verifier, challenge = generate_pkce_pair()
    state = generate_state({"tenant": "wigiai"})
    auth_url = build_authorization_url(client_id=client_id, state=state, code_challenge=challenge)

    print("Authorization URL:")
    print(auth_url)
    print("\nStore code_verifier securely server-side until callback:")
    print(f"code_verifier={verifier[:8]}...<redacted>")

    _ = validate_state(state)
    print("State token generated and validated successfully.")

    if os.environ.get("OAUTH_DEMO_CODE"):
        token_payload = exchange_code_for_token(
            client_id=client_id,
            client_secret=client_secret,
            code=os.environ["OAUTH_DEMO_CODE"],
            code_verifier=verifier,
        )
        print("Token response (redacted):")
        print(redact_token_response(token_payload))
