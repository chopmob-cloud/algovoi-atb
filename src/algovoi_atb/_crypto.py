"""Falcon-1024 certificate verification.

Full crypto verification requires:  pip install algovoi-atb[verify]
(installs pqcrypto>=0.4.0 and rfc8785>=0.1.2)

Without the extras, verify_certificate() still checks envelope structure,
algorithm, expiry, and issuer — it returns failure_reason="falcon_unavailable"
only when signature verification is reached and pqcrypto is absent.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

from algovoi_atb.models import CertVerifyResult

try:
    import rfc8785 as _rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def verify_certificate(
    envelope_b64: str,
    pk_b64: str | None = None,
    *,
    hub_url: str = "https://agent-trust-bench.algovoi.co.uk",
    expected_issuer: str | None = None,
) -> CertVerifyResult:
    """Verify a base64url ATB Pass Certificate envelope.

    Args:
        envelope_b64: The ``certificate`` string returned by
            ``/sessions/me/certificate``.
        pk_b64: The Falcon-1024 PQClean public key in base64 (standard, not
            URL-safe). Fetch it from ``/.well-known/atb-keys.json`` under
            ``keys[0].public_key_pqclean_b64``.  If omitted *and*
            ``pqcrypto`` is installed, you must supply this — signature
            verification cannot proceed without the public key.
        hub_url: Only used for documentation purposes in the error message.
        expected_issuer: Optional DID to enforce. Defaults to the AlgoVoi
            reference bench issuer.

    Returns:
        :class:`CertVerifyResult` — check ``.valid`` and ``.grants_discount``.

    Full verification requires ``pip install algovoi-atb[verify]``.
    Without the extras, structure and expiry are still checked.
    """
    # 1. Decode envelope
    try:
        envelope_json = _b64url_decode(envelope_b64).decode("utf-8")
        envelope: dict[str, Any] = json.loads(envelope_json)
    except Exception as exc:
        return CertVerifyResult(valid=False, failure_reason=f"envelope_decode: {exc}")

    # 2. Shape check
    payload = envelope.get("payload")
    sig_b64: str | None = envelope.get("sig")
    alg: str | None = envelope.get("alg")
    kid: str | None = envelope.get("kid")

    if not isinstance(payload, dict) or not isinstance(sig_b64, str) or alg != "Falcon-1024":
        return CertVerifyResult(valid=False, failure_reason="envelope_shape")

    # 3. Parse payload fields
    issuer: str | None = payload.get("bench_issuer")
    payload_kid: str | None = payload.get("bench_kid")
    score: float | None = payload.get("score")
    passed: bool | None = payload.get("passed")
    methodology: str | None = payload.get("methodology_version")
    expires_at_str: str | None = payload.get("expires_at")
    issued_at_str: str | None = payload.get("issued_at")

    # 4. Issuer check
    if expected_issuer is not None and issuer != expected_issuer:
        return CertVerifyResult(
            valid=False,
            kid=kid,
            issuer=issuer,
            failure_reason="wrong_issuer",
        )

    # 5. kid consistency
    if kid is not None and payload_kid is not None and kid != payload_kid:
        return CertVerifyResult(valid=False, failure_reason="kid_mismatch", kid=kid)

    # 6. Parse timestamps
    expires_at: datetime | None = None
    issued_at: datetime | None = None
    try:
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        if issued_at_str:
            issued_at = datetime.fromisoformat(issued_at_str.replace("Z", "+00:00"))
    except ValueError:
        return CertVerifyResult(valid=False, failure_reason="timestamp_parse")

    # 7. Expiry
    if expires_at is not None and datetime.now(timezone.utc) > expires_at:
        return CertVerifyResult(
            valid=False,
            passed=passed,
            score=score,
            expires_at=expires_at,
            issued_at=issued_at,
            kid=kid,
            issuer=issuer,
            methodology_version=methodology,
            failure_reason="expired",
        )

    # 8. Signature verification (requires extras)
    if not _HAS_CRYPTO:
        return CertVerifyResult(
            valid=False,
            passed=passed,
            score=score,
            expires_at=expires_at,
            issued_at=issued_at,
            kid=kid,
            issuer=issuer,
            methodology_version=methodology,
            failure_reason="falcon_unavailable — install algovoi-atb[verify]",
        )

    if pk_b64 is None:
        return CertVerifyResult(
            valid=False,
            passed=passed,
            score=score,
            expires_at=expires_at,
            issued_at=issued_at,
            kid=kid,
            issuer=issuer,
            methodology_version=methodology,
            failure_reason=(
                "no_public_key — pass pk_b64 from "
                f"{hub_url}/agent-trust-bench/.well-known/atb-keys.json"
            ),
        )

    try:
        pk_bytes = base64.b64decode(pk_b64)
        sig_bytes = _b64url_decode(sig_b64)
        canonical = _rfc8785.dumps(payload)
        verify_ok = bool(_falcon_verify(pk_bytes, canonical, sig_bytes))
    except Exception as exc:
        return CertVerifyResult(
            valid=False,
            passed=passed,
            score=score,
            expires_at=expires_at,
            issued_at=issued_at,
            kid=kid,
            issuer=issuer,
            methodology_version=methodology,
            failure_reason=f"sig_verify_error: {exc}",
        )

    if not verify_ok:
        return CertVerifyResult(
            valid=False,
            passed=passed,
            score=score,
            expires_at=expires_at,
            issued_at=issued_at,
            kid=kid,
            issuer=issuer,
            methodology_version=methodology,
            failure_reason="sig_invalid",
        )

    return CertVerifyResult(
        valid=True,
        passed=passed,
        score=score,
        expires_at=expires_at,
        issued_at=issued_at,
        kid=kid,
        issuer=issuer,
        methodology_version=methodology,
    )
