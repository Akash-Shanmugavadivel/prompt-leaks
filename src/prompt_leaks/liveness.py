"""Opt-in, read-only credential liveness checks against fixed provider APIs."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx

from .models import LivenessResult, LivenessStatus


_GITHUB_RULES = {
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
}
_OPENAI_RULES = {"openai-api-key", "prompt-openai-project-key"}
_GITLAB_RULES = {"gitlab-pat", "gitlab-pat-routable"}
_SLACK_RULES = {
    "slack-bot-token",
    "slack-legacy-bot-token",
    "slack-legacy-token",
    "slack-legacy-workspace-token",
    "slack-user-token",
}
_STRIPE_RULES = {"stripe-access-token"}


def provider_for_rule(rule_id: str) -> str | None:
    """Return the verifier provider for a detection rule, if supported."""
    if rule_id in _GITHUB_RULES:
        return "github"
    if rule_id in _OPENAI_RULES:
        return "openai"
    if rule_id in _GITLAB_RULES:
        return "gitlab"
    if rule_id in _SLACK_RULES:
        return "slack"
    if rule_id in _STRIPE_RULES:
        return "stripe"
    return None


class ProviderLivenessVerifier:
    """Verify supported credentials without logging or retaining their values."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        max_checks: int = 5,
        max_concurrency: int = 3,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_checks <= 0:
            raise ValueError("max_checks must be positive")
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._timeout_seconds = timeout_seconds
        self._max_checks = max_checks
        self._checks_started = 0
        self._counter_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> ProviderLivenessVerifier:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(
                max_connections=3,
                max_keepalive_connections=3,
            ),
            headers={"User-Agent": "prompt-leaks/0.1"},
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def verify(self, *, rule_id: str, secret: str) -> LivenessResult:
        provider = provider_for_rule(rule_id)
        if provider is None:
            return LivenessResult(
                status="unsupported",
                reason="no_safe_verifier",
            )

        async with self._counter_lock:
            if self._checks_started >= self._max_checks:
                return LivenessResult(
                    status="indeterminate",
                    provider=provider,
                    reason="verification_limit",
                )
            self._checks_started += 1

        if self._client is None:
            raise RuntimeError("ProviderLivenessVerifier must be used as a context manager")

        try:
            async with self._semaphore:
                response = await self._request(provider, secret)
        except httpx.TimeoutException:
            return self._result(provider, "indeterminate", "timeout")
        except httpx.RequestError:
            return self._result(provider, "indeterminate", "network_error")

        if provider == "slack":
            return self._classify_slack(response)
        return self._classify_http(provider, response.status_code)

    async def _request(self, provider: str, secret: str) -> httpx.Response:
        assert self._client is not None
        if provider == "github":
            return await self._client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {secret}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        if provider == "openai":
            return await self._client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {secret}"},
            )
        if provider == "gitlab":
            return await self._client.get(
                "https://gitlab.com/api/v4/user",
                headers={"PRIVATE-TOKEN": secret},
            )
        if provider == "slack":
            return await self._client.post(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {secret}"},
            )
        if provider == "stripe":
            return await self._client.get(
                "https://api.stripe.com/v1/balance",
                auth=httpx.BasicAuth(secret, ""),
            )
        raise AssertionError(f"unsupported provider mapping: {provider}")

    def _classify_slack(self, response: httpx.Response) -> LivenessResult:
        if response.status_code == 429:
            return self._result("slack", "restricted", "rate_limited")
        if response.status_code != 200:
            return self._classify_http("slack", response.status_code)
        try:
            payload = response.json()
        except ValueError:
            return self._result("slack", "indeterminate", "invalid_response")
        if payload.get("ok") is True:
            return self._result("slack", "active", "authenticated")
        error = payload.get("error")
        if error in {"invalid_auth", "not_authed", "token_revoked", "account_inactive"}:
            return self._result("slack", "invalid", "authentication_rejected")
        if error == "ratelimited":
            return self._result("slack", "restricted", "rate_limited")
        return self._result("slack", "indeterminate", "provider_rejected_request")

    def _classify_http(self, provider: str, status_code: int) -> LivenessResult:
        if 200 <= status_code < 300:
            return self._result(provider, "active", "authenticated")
        if status_code == 401:
            return self._result(provider, "invalid", "authentication_rejected")
        if status_code in {403, 429}:
            reason = "rate_limited" if status_code == 429 else "access_restricted"
            return self._result(provider, "restricted", reason)
        return self._result(provider, "indeterminate", "unexpected_provider_response")

    @staticmethod
    def _result(
        provider: str,
        status: LivenessStatus,
        reason: str,
    ) -> LivenessResult:
        return LivenessResult(
            status=status,
            provider=provider,
            reason=reason,
            checked_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
