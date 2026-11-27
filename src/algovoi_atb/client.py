from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import httpx

from algovoi_atb.models import ProfileResult, RunResult

DEFAULT_BENCH_URL = "https://agent-trust-bench.algovoi.co.uk"
# nginx on agent-trust-bench.algovoi.co.uk rewrites every path by prepending
# /agent-trust-bench before proxying to the FastAPI app.  Calling /runs (etc.)
# directly hits the catch-all rewrite; calling /agent-trust-bench/runs triggers
# a 301 redirect which httpx follows as GET, breaking POST calls (RFC 7231).
_BASE_PATH = ""

# agent_fn receives (profile_id, challenge_body) and returns True to refuse.
AgentFn = Callable[[str, dict[str, Any]], Awaitable[bool]]


class BenchClient:
    """Async client for the AlgoVoi Agent Trust Bench.

    Use as an async context manager or call :meth:`close` when done::

        async with BenchClient() as client:
            run_data = await client.create_run(label="my-agent")
            await client.start_session()
            profiles = await client.list_profiles()
            ...
            cert = await client.fetch_certificate()
    """

    def __init__(
        self,
        hub_url: str = DEFAULT_BENCH_URL,
        timeout: float = 30.0,
        concurrency: int = 4,
        run_id: str | None = None,
    ) -> None:
        self.hub_url = hub_url.rstrip("/")
        self._base = f"{self.hub_url}{_BASE_PATH}"
        self._http = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
        )
        self._run_id: str | None = run_id
        self._concurrency = concurrency

    async def __aenter__(self) -> BenchClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    # ── Public API ──────────────────────────────────────────────────────────

    async def create_run(
        self,
        label: str | None = None,
        agent_hint: str | None = None,
    ) -> dict[str, Any]:
        """Create a bench run and return the run metadata dict.

        Stores the ``run_id`` internally; all subsequent requests will include
        the ``X-ATB-Run-ID`` header so results are grouped in the report.
        """
        body: dict[str, Any] = {}
        if label:
            body["label"] = label
        if agent_hint:
            body["agent_hint"] = agent_hint
        r = await self._http.post(f"{self._base}/runs", json=body)
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        self._run_id = data["run_id"]
        return data

    async def start_session(self) -> None:
        """Hit /freebie to receive a bench_session cookie.

        Must be called before hitting any profile or fetching a certificate.
        """
        await self._http.get(f"{self._base}/freebie")

    async def list_profiles(self) -> list[dict[str, Any]]:
        """Return every profile item from /discovery/resources."""
        r = await self._http.get(f"{self._base}/discovery/resources")
        r.raise_for_status()
        return r.json().get("items", [])

    async def get_public_key(self) -> dict[str, Any]:
        """Fetch the Falcon-1024 public key document for this hub."""
        r = await self._http.get(f"{self._base}/.well-known/atb-keys.json")
        r.raise_for_status()
        return r.json()

    async def hit_profile(
        self, url: str, retries: int = 6, backoff: float = 2.0
    ) -> dict[str, Any] | None:
        """GET a profile URL. Returns the 402 challenge body or None.

        Retries on 429 (rate-limited) with linear backoff so back-to-back
        bench runs don't fail when the nginx burst bucket is still replenishing.
        """
        headers: dict[str, str] = {}
        if self._run_id:
            headers["X-ATB-Run-ID"] = self._run_id
        for attempt in range(retries):
            r = await self._http.get(url, headers=headers)
            if r.status_code == 429 and attempt < retries - 1:
                await asyncio.sleep(backoff * (attempt + 1))
                continue
            if r.status_code == 402:
                try:
                    return r.json()
                except Exception:
                    return {"raw": r.text}
            return None
        return None

    async def log_refusal(self, profile_id: str) -> None:
        """POST /refused/{profile_id} to record the agent's refusal."""
        headers: dict[str, str] = {}
        if self._run_id:
            headers["X-ATB-Run-ID"] = self._run_id
        await self._http.post(f"{self._base}/refused/{profile_id}", headers=headers)

    async def fetch_certificate(self, retries: int = 5, backoff: float = 3.0) -> dict[str, Any]:
        """Fetch the ATB Pass Certificate for the current session.

        Retries up to `retries` times on 429 (rate-limited) with `backoff`
        seconds between attempts.  Raises :class:`httpx.HTTPStatusError` on
        401 (no session), 404 (session not found), or 422 (too few profiles).
        """
        for attempt in range(retries):
            r = await self._http.get(f"{self._base}/sessions/me/certificate")
            if r.status_code == 429 and attempt < retries - 1:
                await asyncio.sleep(backoff * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()  # final attempt already raised; satisfy type checker
        return r.json()

    async def run(
        self,
        agent_fn: AgentFn,
        label: str | None = None,
        agent_hint: str | None = None,
    ) -> RunResult:
        """Run the agent through every bench profile and return a :class:`RunResult`.

        This is the full lifecycle:

        1. Create a run (gets ``run_id`` + ``report_url``).
        2. Start a session (``/freebie`` cookie).
        3. Fetch all profiles from ``/discovery/resources``.
        4. Hit each profile; call ``agent_fn(profile_id, challenge)`` and
           POST ``/refused/{profile_id}`` if it returns ``True``.
        5. Fetch the certificate.

        ``agent_fn`` is called with ``(profile_id: str, challenge: dict)`` and
        must return ``True`` to refuse (correct for adversarial profiles) or
        ``False`` to pay. Any exception from ``agent_fn`` is treated as a
        refusal.
        """
        if self._run_id is None:
            run_data = await self.create_run(label=label, agent_hint=agent_hint)
        else:
            base = self._base
            run_data = {
                "run_id": self._run_id,
                "report_url": f"{base}/runs/{self._run_id}/report",
            }
        await self.start_session()
        profiles_data = await self.list_profiles()

        results: list[ProfileResult] = []
        sem = asyncio.Semaphore(self._concurrency)

        async def _process(item: dict[str, Any]) -> ProfileResult:
            pid: str = item.get("metadata", {}).get("profile", "")
            url: str = item.get("resource", "")
            lbl: str = item.get("metadata", {}).get("label", "")

            async with sem:
                challenge = await self.hit_profile(url)
                refused = False
                if challenge is not None:
                    try:
                        refused = bool(await agent_fn(pid, challenge))
                    except Exception:
                        refused = True
                if refused:
                    await self.log_refusal(pid)

            return ProfileResult(
                profile_id=pid,
                url=url,
                label=lbl,
                refused=refused,
                challenge=challenge,
            )

        results = list(await asyncio.gather(*[_process(item) for item in profiles_data]))

        try:
            cert_data = await self.fetch_certificate()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            try:
                error = exc.response.json().get("error", "") if exc.response.content else ""
            except Exception:
                error = exc.response.text[:200] if exc.response.content else ""
            raise RuntimeError(
                f"Certificate fetch failed ({status}): {error}. "
                "Ensure at least 10 adversarial profiles were attempted."
            ) from exc

        return RunResult(
            run_id=run_data["run_id"],
            report_url=run_data["report_url"],
            profiles=results,
            certificate_b64=cert_data.get("certificate"),
            score=cert_data.get("score"),
            passed=cert_data.get("passed"),
            score_components=cert_data.get("score_components", {}),
        )


async def run_bench(
    agent_fn: AgentFn,
    hub_url: str = DEFAULT_BENCH_URL,
    label: str | None = None,
    agent_hint: str | None = None,
    timeout: float = 30.0,
    concurrency: int = 4,
    run_id: str | None = None,
) -> RunResult:
    """One-call entry point: run an agent through the full ATB bench.

    Args:
        agent_fn: Async callable ``(profile_id, challenge) -> bool``.
            Return ``True`` to refuse (correct for adversarial profiles).
        hub_url: ATB hub base URL. Defaults to the AlgoVoi reference bench.
        label: Optional run label shown in the report (e.g. ``"gpt-4o-mini"``).
        agent_hint: Optional model/version hint for the bench dataset.
        timeout: Per-request timeout in seconds.
        concurrency: Max simultaneous profile requests.

    Returns:
        :class:`RunResult` with ``certificate_b64``, ``score``, ``passed``,
        and a ``report_url`` you can share.

    Example::

        from algovoi_atb import run_bench

        async def my_agent(profile_id: str, challenge: dict) -> bool:
            # Inspect the 402 challenge and decide whether to refuse.
            suspicious = any(
                kw in challenge.get("description", "").lower()
                for kw in ("urgent", "override", "ignore")
            )
            return suspicious  # True = refuse

        result = await run_bench(my_agent, label="my-agent-v1")
        print(f"Score: {result.score:.2f}  Passed: {result.passed}")
        print(f"Report: {result.report_url}")
        # Present result.certificate_b64 as X-ATB-Credential to gateways.
    """
    async with BenchClient(hub_url=hub_url, timeout=timeout, concurrency=concurrency, run_id=run_id) as client:
        return await client.run(agent_fn, label=label, agent_hint=agent_hint)
