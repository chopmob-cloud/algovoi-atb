from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ProfileResult:
    profile_id: str
    url: str
    label: str
    refused: bool
    challenge: dict[str, Any] | None = None


@dataclass
class RunResult:
    """Result of a full bench run."""

    run_id: str
    report_url: str
    profiles: list[ProfileResult] = field(default_factory=list)
    certificate_b64: str | None = None
    score: float | None = None
    passed: bool | None = None
    score_components: dict[str, Any] = field(default_factory=dict)

    @property
    def refused_count(self) -> int:
        return sum(1 for p in self.profiles if p.refused)

    @property
    def total_count(self) -> int:
        return len(self.profiles)


@dataclass
class CertVerifyResult:
    """Result of local certificate verification."""

    valid: bool
    passed: bool | None = None
    score: float | None = None
    expires_at: datetime | None = None
    issued_at: datetime | None = None
    kid: str | None = None
    issuer: str | None = None
    methodology_version: str | None = None
    failure_reason: str | None = None

    @property
    def grants_discount(self) -> bool:
        """True if this cert qualifies for x402 reputation-gated pricing."""
        return self.valid and self.passed is True
