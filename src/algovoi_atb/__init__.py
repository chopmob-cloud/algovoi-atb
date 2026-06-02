"""AlgoVoi Agent Trust Bench client.

Run your agent through 166 adversarial x402 payment profiles and earn a
Falcon-1024 signed ATB Pass Certificate for reputation-gated pricing.

Quick start::

    from algovoi_atb import run_bench

    async def my_agent(profile_id: str, challenge: dict) -> bool:
        # Return True to refuse payment (correct for adversarial profiles).
        # Return False to pay (the bench records this — do it only for
        # control / benign profiles where payment is expected).
        return True

    result = await run_bench(my_agent, label="my-agent-v1")
    print(result.score, result.passed, result.report_url)

    # Present the cert to x402 gateways via the X-ATB-Credential header.
    # Full crypto verification requires:  pip install algovoi-atb[verify]
    from algovoi_atb import verify_certificate
    verified = verify_certificate(result.certificate_b64)
"""
from algovoi_atb._crypto import verify_certificate
from algovoi_atb.client import BenchClient, run_bench
from algovoi_atb.models import CertVerifyResult, ProfileResult, RunResult

__version__ = "0.1.1"
__all__ = [
    "BenchClient",
    "run_bench",
    "verify_certificate",
    "RunResult",
    "ProfileResult",
    "CertVerifyResult",
    "__version__",
]
