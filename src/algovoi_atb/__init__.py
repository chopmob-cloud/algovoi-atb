"""AlgoVoi Agent Trust Bench client.

Run your agent through 199 adversarial x402 payment profiles and earn a
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

# Version comes from one place, never a typed literal.
#
# The 0.1.6 wheel shipped reporting "0.1.4" and the repo said "0.1.1" while
# pyproject.toml said "0.1.6", because the value was hand-typed in three files.
# Now: an installed package reads its distribution metadata, and a source tree
# reads pyproject.toml. There is no second literal to forget to update.
try:
    from importlib.metadata import version as _dist_version, PackageNotFoundError

    __version__ = _dist_version("algovoi-atb")
except PackageNotFoundError:  # running from a source tree, not an install
    from pathlib import Path as _Path

    try:
        import tomllib as _toml

        _pyproject = _Path(__file__).resolve().parents[2] / "pyproject.toml"
        with open(_pyproject, "rb") as _fh:
            __version__ = _toml.load(_fh)["project"]["version"]
    except Exception:  # no pyproject in reach: say so rather than invent a number
        __version__ = "0+unknown"
__all__ = [
    "BenchClient",
    "run_bench",
    "verify_certificate",
    "RunResult",
    "ProfileResult",
    "CertVerifyResult",
    "__version__",
]
