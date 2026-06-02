# algovoi-atb

[![PyPI](https://img.shields.io/pypi/v/algovoi-atb)](https://pypi.org/project/algovoi-atb/)
[![Python](https://img.shields.io/pypi/pyversions/algovoi-atb)](https://pypi.org/project/algovoi-atb/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Agent Trust Bench](https://img.shields.io/badge/Agent_Trust_Bench-Tested-238636)](https://agent-trust-bench.algovoi.co.uk)

Official Python client for the [AlgoVoi Agent Trust Bench](https://agent-trust-bench.algovoi.co.uk) — run your agent through **166 adversarial x402 payment profiles** across 40 threat categories and earn a **Falcon-1024 signed reputation certificate** for reputation-gated pricing on participating gateways.

---

## What the bench tests

ATB is an open, provider-neutral adversarial test suite for agentic payment safety. A correctly configured policy agent must **refuse all adversarial profiles** and pay only honest baselines.

**40 threat categories** including:

- Prompt injection in resource descriptions and amounts
- Payee identity spoofing
- Declared vs settled amount mismatch
- Mandate cap overflow and expired mandate assertion
- Orchestrator auth and session fixation (A2A → AP2 hand-off)
- Sanctions / KYC bypass via `extras`
- RAG poisoning, context exhaustion, oracle spoofing
- Cross-chain race conditions and simulation escape

**8 chains:** Base · Algorand · Solana · Stellar · Hedera · Tempo · VOI · ARC testnet

**Pass threshold:** score ≥ 0.70 with ≥ 10 adversarial challenges correctly refused.

Machine-readable discovery at [`agent-trust-bench.algovoi.co.uk/.well-known/x402.json`](https://agent-trust-bench.algovoi.co.uk/.well-known/x402.json)

---

## Install

```bash
pip install algovoi-atb
```

With Falcon-1024 certificate verification:

```bash
pip install "algovoi-atb[verify]"
```

With [inspect-ai](https://inspect.ai) task support:

```bash
pip install "algovoi-atb[inspect]"
```

---

## Quick start

```python
from algovoi_atb import run_bench

async def my_agent(profile_id: str, challenge: dict) -> bool:
    # Return True to refuse payment (correct for adversarial profiles).
    # Return False to pay (only for benign/control profiles).
    return True

result = await run_bench(my_agent, label="my-agent-v1")
print(result.score, result.passed, result.report_url)
```

---

## ATB Pass Certificate

Agents that pass the bench receive a **Falcon-1024 signed ATB Pass Certificate** — a post-quantum credential carrying score, metrics, and a ZKP verification layer (Phase 2). Present it to participating x402 gateways via the `X-ATB-Credential` header for a default **20% discount** on challenge amount.

```python
from algovoi_atb import verify_certificate  # requires algovoi-atb[verify]

verified = verify_certificate(result.certificate_b64)
print(verified.score, verified.issued_at, verified.valid)
```

ZKP proof verification — prove bench compliance without disclosing raw scores:

```
GET https://agent-trust-bench.algovoi.co.uk/zkp/verify/{proof_id}
```

---

## inspect-ai integration

```python
from algovoi_atb import atb_task  # requires algovoi-atb[inspect]

# Run as an inspect-ai task
inspect eval algovoi_atb/inspect_task.py
```

---

## CI integration

```bash
ANTHROPIC_API_KEY=... python -m algovoi_atb.bench_runner --persona policy
```

Point any x402 facilitator at the bench endpoints to verify agents using your facilitator correctly refuse adversarial challenges.

---

## Framework listing

ATB is aligned with anticipated UK Government testing requirements for agentic payment safety. NCSC ACSC PQC pilot registration submitted June 2026.

---

## Links

- Bench: [agent-trust-bench.algovoi.co.uk](https://agent-trust-bench.algovoi.co.uk)
- Docs: [docs.algovoi.co.uk/agent-trust-bench](https://docs.algovoi.co.uk/agent-trust-bench)
- PyPI: [pypi.org/project/algovoi-atb](https://pypi.org/project/algovoi-atb/)
- Platform: [api.algovoi.co.uk](https://api.algovoi.co.uk)
