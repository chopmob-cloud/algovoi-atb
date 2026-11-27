"""Keystone binding for the Agent Trust Bench (ATB).

ATB already canonicalises with RFC 8785 (JCS) and Falcon-1024 signs its result
certificate. This module adds the open, content-addressed Keystone layer *underneath*
that signed certificate, so an ATB verdict becomes a first-class Keystone trust query
that recomputes offline:

    passport_ref (agent identity, caller-supplied)
      -> atb_trial_ref x N        one per profile, an alias of execution_ref
        -> atb_trust_ref          the verdict; this IS trust_query_ref
          -> [commercial] the existing Falcon-1024 signed cert + Phase-2 ZKP

Give/keep: these refs are open and recomputable (the free ruler). The Falcon-signed
certificate and the score-hiding Bulletproofs proof stay the commercial attestation
(the paid notary). This module never signs; it only content-addresses.

Discovered by algovoi-keystone-control via the algovoi.keystone.steps entry point.
"""
from __future__ import annotations

from typing import Any

CANON_VERSION = "jcs-rfc8785-v1"
TRIAL_DECISIONS = ("REFUSE", "PAY")
TRUST_OUTCOMES = ("TRUSTED", "PROVISIONAL", "INSUFFICIENT_EVIDENCE", "UNTRUSTED")

# Score bands for the richer Keystone trust enum (ATB itself is binary passed/score).
_TRUSTED_FLOOR = 0.9


def _ref(obj: Any) -> str:
    # Lazy import: keystone_step() (the entry point) must load for panel discovery even
    # where algovoi-substrate is absent; only ref computation needs the canonicalizer.
    from algovoi_substrate import sha256_jcs
    return "sha256:" + sha256_jcs(obj)


def challenge_ref(challenge: dict | None) -> str:
    """Content address of the exact x402 challenge the agent faced (empty object if none)."""
    return _ref(challenge if isinstance(challenge, dict) else {})


def opaque_subject_ref(agent_id_hash: str) -> str:
    """Fallback subject when no passport_ref is supplied: bind ATB's opaque agent_id_hash.

    Weaker than a real passport_ref (the identity is not recomputable from raw fields),
    but keeps the verdict bound to *some* stable subject. Clearly marked as opaque.
    """
    if not isinstance(agent_id_hash, str) or not agent_id_hash:
        raise ValueError("agent_id_hash must be a non-empty string")
    return _ref({"opaque_agent_id_hash": agent_id_hash})


def atb_trial_ref(subject_ref: str, profile_id: str, challenge_ref_value: str,
                  decision: str, evaluated_at_ms: int) -> str:
    """One profile decision as decision-bound execution evidence (alias of execution_ref).

    Binds *who* (subject_ref), *what challenge* (challenge_ref), *the decision* (REFUSE/PAY),
    and *when*. Correctness is a judgement and lives in the verdict (atb_trust_ref), not here.
    """
    if decision not in TRIAL_DECISIONS:
        raise ValueError(f"decision must be one of {TRIAL_DECISIONS}, got {decision!r}")
    if not isinstance(evaluated_at_ms, int) or isinstance(evaluated_at_ms, bool):
        raise ValueError("evaluated_at_ms must be an epoch-millisecond integer")
    return _ref({
        "subject_ref": subject_ref,
        "profile_id": profile_id,
        "challenge_ref": challenge_ref_value,
        "decision": decision,
        "evaluated_at_ms": evaluated_at_ms,
    })


def atb_trust_ref(subject_refs: list[str], trust_outcome: str) -> str:
    """The ATB verdict as a Keystone trust_query_ref over [passport, trials...].

    Identical construction to trust_query_ref: sha256:+SHA-256(JCS({subject_refs, trust_outcome})).
    """
    if trust_outcome not in TRUST_OUTCOMES:
        raise ValueError(f"trust_outcome must be one of {TRUST_OUTCOMES}, got {trust_outcome!r}")
    if not isinstance(subject_refs, list) or not subject_refs:
        raise ValueError("subject_refs must be a non-empty list")
    return _ref({"subject_refs": subject_refs, "trust_outcome": trust_outcome})


def trust_outcome_for(score: float | None, passed: bool | None, *, complete: bool = True) -> str:
    """Map ATB's binary (passed, score) onto the richer Keystone trust enum."""
    if not complete or passed is None:
        return "INSUFFICIENT_EVIDENCE"
    if not passed:
        return "UNTRUSTED"
    if score is not None and score >= _TRUSTED_FLOOR:
        return "TRUSTED"
    return "PROVISIONAL"


def keystone_refs_from_run(run: Any, *, passport_ref: str | None = None,
                           agent_id_hash: str | None = None,
                           evaluated_at_ms: int, complete: bool = True) -> dict:
    """Emit the Keystone refs for a completed ATB run (a RunResult-shaped object).

    subject binding (Option A): pass the agent's ``passport_ref`` for a strong,
    recomputable identity; if absent, ``agent_id_hash`` is bound as an opaque subject.
    One of the two is required.
    """
    if passport_ref:
        subject = passport_ref
    elif agent_id_hash:
        subject = opaque_subject_ref(agent_id_hash)
    else:
        raise ValueError("provide passport_ref (preferred) or agent_id_hash")

    trials: list[dict] = []
    for p in getattr(run, "profiles", []) or []:
        tref = atb_trial_ref(
            subject,
            getattr(p, "profile_id"),
            challenge_ref(getattr(p, "challenge", None)),
            "REFUSE" if getattr(p, "refused") else "PAY",
            evaluated_at_ms,
        )
        trials.append({"profile_id": getattr(p, "profile_id"), "trial_ref": tref})

    outcome = trust_outcome_for(getattr(run, "score", None), getattr(run, "passed", None),
                                complete=complete)
    subject_refs = [subject] + [t["trial_ref"] for t in trials]
    trust_ref = atb_trust_ref(subject_refs, outcome)
    return {
        "subject_ref": subject,
        "subject_kind": "passport_ref" if passport_ref else "opaque_agent_id_hash",
        "trials": trials,
        "trust_outcome": outcome,
        "atb_trust_ref": trust_ref,
        "canon_version": CANON_VERSION,
    }


def keystone_step() -> dict:
    """Keystone bolt-on descriptor: ATB emits the trust-query tier (alias of trust_query_ref)."""
    return {
        "package": "algovoi-atb",
        "step": "atb_trust",
        "ref": "atb_trust_ref",
        "alias_of": "trust_query_ref",
        "order": 7,
        "posture": "Agent Trust Bench verdict (alias of trust_query_ref)",
        "default": {
            "__keystone": {
                "canon_version": CANON_VERSION,
                "hash_algo": "sha256",
                "required_fields": ["subject_refs", "trust_outcome"],
                "trust_outcomes": list(TRUST_OUTCOMES),
            },
        },
    }


if __name__ == "__main__":
    import json
    print(json.dumps(keystone_step(), indent=2))
