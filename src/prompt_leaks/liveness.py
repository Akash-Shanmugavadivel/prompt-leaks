"""Configurable, read-only credential checks against fixed provider APIs."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence

import httpx

from .models import LivenessResult, LivenessStatus


VerificationTarget = tuple[str, str, int, int]
SUPPORTED_PROVIDERS = frozenset(
    {
        "anthropic",
        "aws",
        "azure",
        "gcp",
        "github",
        "gitlab",
        "huggingface",
        "npm",
        "openai",
        "slack",
        "stripe",
    }
)

_RULE_PROVIDERS = {
    "anthropic-api-key": "anthropic",
    "aws-access-token": "aws",
    "prompt-aws-secret-access-key": "aws",
    "prompt-aws-session-token": "aws",
    "azure-ad-client-secret": "azure",
    "gcp-api-key": "gcp",
    "github-app-token": "github",
    "github-fine-grained-pat": "github",
    "github-oauth": "github",
    "github-pat": "github",
    "gitlab-pat": "gitlab",
    "gitlab-pat-routable": "gitlab",
    "huggingface-access-token": "huggingface",
    "huggingface-organization-api-token": "huggingface",
    "npm-access-token": "npm",
    "openai-api-key": "openai",
    "prompt-openai-project-key": "openai",
    "slack-bot-token": "slack",
    "slack-legacy-bot-token": "slack",
    "slack-legacy-token": "slack",
    "slack-legacy-workspace-token": "slack",
    "slack-user-token": "slack",
    "stripe-access-token": "stripe",
}

_AZURE_TENANT_RE = re.compile(
    r"(?i)\b(?:AZURE[_-]?)?TENANT[_ -]?ID\s*[:=]\s*"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b"
)
_AZURE_CLIENT_RE = re.compile(
    r"(?i)\b(?:AZURE[_-]?)?CLIENT[_ -]?ID\s*[:=]\s*"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b"
)


@dataclass(frozen=True, slots=True)
class LivenessSettings:
    """Trusted server-side controls for active credential verification."""

    enabled_providers: frozenset[str] = SUPPORTED_PROVIDERS
    timeout_seconds: float = 5.0
    max_checks: int = 5
    max_concurrency: int = 3
    anthropic_version: str = "2023-06-01"

    @classmethod
    def from_environment(cls) -> LivenessSettings:
        raw_providers = os.getenv("PROMPT_LEAKS_LIVENESS_PROVIDERS")
        if raw_providers:
            providers = frozenset(
                item.strip().casefold()
                for item in raw_providers.split(",")
                if item.strip()
            )
        else:
            providers = SUPPORTED_PROVIDERS
        unknown = providers - SUPPORTED_PROVIDERS
        if unknown:
            raise ValueError(f"unsupported liveness providers: {sorted(unknown)!r}")
        return cls(
            enabled_providers=providers,
            timeout_seconds=float(
                os.getenv("PROMPT_LEAKS_LIVENESS_TIMEOUT_SECONDS", "5")
            ),
            max_checks=int(os.getenv("PROMPT_LEAKS_LIVENESS_MAX_CHECKS", "5")),
            max_concurrency=int(
                os.getenv("PROMPT_LEAKS_LIVENESS_MAX_CONCURRENCY", "3")
            ),
            anthropic_version=os.getenv(
                "PROMPT_LEAKS_ANTHROPIC_VERSION", "2023-06-01"
            ),
        )


def provider_for_rule(rule_id: str) -> str | None:
    return _RULE_PROVIDERS.get(rule_id)


class ProviderLivenessVerifier:
    """Verify supported credentials without logging or retaining their values."""

    def __init__(
        self,
        *,
        settings: LivenessSettings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings or LivenessSettings.from_environment()
        if self._settings.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self._settings.max_checks <= 0:
            raise ValueError("max_checks must be positive")
        if self._settings.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._transport = transport
        self._checks_started = 0
        self._counter_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(self._settings.max_concurrency)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> ProviderLivenessVerifier:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._settings.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            limits=httpx.Limits(
                max_connections=self._settings.max_concurrency,
                max_keepalive_connections=self._settings.max_concurrency,
            ),
            headers={"User-Agent": "prompt-leaks/0.1"},
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def verify(self, *, rule_id: str, secret: str) -> LivenessResult:
        """Verify one standalone credential; paired credentials use verify_many."""
        return (
            await self.verify_many(((rule_id, secret, 0, len(secret)),), context=secret)
        )[0]

    async def verify_many(
        self,
        targets: Sequence[VerificationTarget],
        *,
        context: str,
    ) -> tuple[LivenessResult, ...]:
        results: list[LivenessResult | None] = [None] * len(targets)
        await self._verify_aws_groups(targets, results)

        async def verify_index(index: int, target: VerificationTarget) -> None:
            if results[index] is None:
                rule_id, secret, _start, _end = target
                results[index] = await self._verify_one(rule_id, secret, context)

        await asyncio.gather(
            *(verify_index(index, target) for index, target in enumerate(targets))
        )
        return tuple(
            result
            if result is not None
            else LivenessResult(status="indeterminate", reason="internal_error")
            for result in results
        )

    async def _verify_aws_groups(
        self,
        targets: Sequence[VerificationTarget],
        results: list[LivenessResult | None],
    ) -> None:
        access_indices = [
            index for index, target in enumerate(targets) if target[0] == "aws-access-token"
        ]
        secret_indices = [
            index
            for index, target in enumerate(targets)
            if target[0] == "prompt-aws-secret-access-key"
        ]
        session_indices = [
            index
            for index, target in enumerate(targets)
            if target[0] == "prompt-aws-session-token"
        ]
        used: set[int] = set()

        for access_index in access_indices:
            access = targets[access_index]
            available_secrets = [index for index in secret_indices if index not in used]
            if not available_secrets:
                results[access_index] = self._unverified(
                    "aws", "missing_credential_pair"
                )
                continue
            secret_index = min(
                available_secrets,
                key=lambda index: abs(targets[index][2] - access[2]),
            )
            used.add(secret_index)
            secret = targets[secret_index]
            session_index = (
                min(
                    session_indices,
                    key=lambda index: abs(targets[index][2] - access[2]),
                )
                if session_indices
                else None
            )
            if access[1].startswith("ASIA") and session_index is None:
                result = self._unverified("aws", "missing_session_token")
            else:
                result = await self._verify_aws(
                    access[1],
                    secret[1],
                    targets[session_index][1] if session_index is not None else None,
                )
            results[access_index] = result
            results[secret_index] = result
            if session_index is not None:
                results[session_index] = result

        for index in secret_indices + session_indices:
            if results[index] is None:
                results[index] = self._unverified("aws", "missing_credential_pair")

    async def _verify_one(
        self,
        rule_id: str,
        secret: str,
        context: str,
    ) -> LivenessResult:
        provider = provider_for_rule(rule_id)
        if provider is None:
            return LivenessResult(status="unsupported", reason="no_safe_verifier")
        if provider not in self._settings.enabled_providers:
            return LivenessResult(
                status="unsupported",
                provider=provider,
                reason="provider_disabled",
            )
        if provider == "azure":
            return await self._verify_azure(secret, context)
        if not await self._reserve_check():
            return self._unverified(provider, "verification_limit")
        try:
            async with self._semaphore:
                response = await self._request(provider, secret)
        except httpx.TimeoutException:
            return self._result(provider, "indeterminate", "timeout")
        except httpx.RequestError:
            return self._result(provider, "indeterminate", "network_error")

        if provider == "slack":
            return self._classify_slack(response)
        if provider == "gcp":
            return self._classify_gcp(response)
        return self._classify_http(provider, response.status_code)

    async def _verify_azure(self, secret: str, context: str) -> LivenessResult:
        tenant_match = _AZURE_TENANT_RE.search(context)
        client_match = _AZURE_CLIENT_RE.search(context)
        if tenant_match is None or client_match is None:
            return self._unverified("azure", "missing_credential_context")
        if not await self._reserve_check():
            return self._unverified("azure", "verification_limit")
        assert self._client is not None
        try:
            async with self._semaphore:
                response = await self._client.post(
                    "https://login.microsoftonline.com/"
                    f"{tenant_match.group(1)}/oauth2/v2.0/token",
                    data={
                        "client_id": client_match.group(1),
                        "client_secret": secret,
                        "grant_type": "client_credentials",
                        "scope": "https://management.azure.com/.default",
                    },
                )
        except httpx.TimeoutException:
            return self._result("azure", "indeterminate", "timeout")
        except httpx.RequestError:
            return self._result("azure", "indeterminate", "network_error")
        if 200 <= response.status_code < 300:
            return self._result("azure", "active", "authenticated")
        try:
            error = str(response.json().get("error", ""))
        except (ValueError, AttributeError):
            error = ""
        if error in {"invalid_client", "invalid_grant"}:
            return self._result("azure", "invalid", "authentication_rejected")
        if error == "unauthorized_client":
            return self._result(
                "azure", "valid_but_restricted", "access_restricted"
            )
        return self._classify_http("azure", response.status_code)

    async def _verify_aws(
        self,
        access_key: str,
        secret_key: str,
        session_token: str | None,
    ) -> LivenessResult:
        if "aws" not in self._settings.enabled_providers:
            return LivenessResult(
                status="unsupported", provider="aws", reason="provider_disabled"
            )
        if not await self._reserve_check():
            return self._unverified("aws", "verification_limit")
        assert self._client is not None
        request = self._aws_request(access_key, secret_key, session_token)
        try:
            async with self._semaphore:
                response = await self._client.send(request)
        except httpx.TimeoutException:
            return self._result("aws", "indeterminate", "timeout")
        except httpx.RequestError:
            return self._result("aws", "indeterminate", "network_error")
        if 200 <= response.status_code < 300:
            return self._result("aws", "active", "authenticated")
        body = response.text
        if any(
            code in body
            for code in (
                "ExpiredToken",
                "InvalidClientTokenId",
                "InvalidSignatureException",
                "SignatureDoesNotMatch",
                "UnrecognizedClientException",
            )
        ):
            return self._result("aws", "invalid", "authentication_rejected")
        if response.status_code in {403, 429}:
            return self._result(
                "aws", "valid_but_restricted", "access_restricted"
            )
        return self._result("aws", "indeterminate", "unexpected_provider_response")

    def _aws_request(
        self,
        access_key: str,
        secret_key: str,
        session_token: str | None,
    ) -> httpx.Request:
        assert self._client is not None
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        body = b"Action=GetCallerIdentity&Version=2011-06-15"
        headers = {
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "host": "sts.amazonaws.com",
            "x-amz-date": amz_date,
        }
        if session_token:
            headers["x-amz-security-token"] = session_token
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(
            f"{name}:{headers[name].strip()}\n" for name in sorted(headers)
        )
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_request = (
            f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )
        scope = f"{date_stamp}/us-east-1/sts/aws4_request"
        string_to_sign = (
            "AWS4-HMAC-SHA256\n"
            f"{amz_date}\n{scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )
        signing_key = self._aws_signing_key(secret_key, date_stamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode(), hashlib.sha256
        ).hexdigest()
        headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return self._client.build_request(
            "POST", "https://sts.amazonaws.com/", headers=headers, content=body
        )

    @staticmethod
    def _aws_signing_key(secret_key: str, date_stamp: str) -> bytes:
        date_key = hmac.new(
            f"AWS4{secret_key}".encode(), date_stamp.encode(), hashlib.sha256
        ).digest()
        region_key = hmac.new(date_key, b"us-east-1", hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"sts", hashlib.sha256).digest()
        return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()

    async def _request(self, provider: str, secret: str) -> httpx.Response:
        assert self._client is not None
        if provider == "anthropic":
            return await self._client.get(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": secret,
                    "anthropic-version": self._settings.anthropic_version,
                },
            )
        if provider == "gcp":
            return await self._client.get(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": secret},
            )
        if provider == "github":
            return await self._client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {secret}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        if provider == "gitlab":
            return await self._client.get(
                "https://gitlab.com/api/v4/user",
                headers={"PRIVATE-TOKEN": secret},
            )
        if provider == "huggingface":
            return await self._client.get(
                "https://huggingface.co/api/whoami-v2",
                headers={"Authorization": f"Bearer {secret}"},
            )
        if provider == "npm":
            return await self._client.get(
                "https://registry.npmjs.org/-/whoami",
                headers={"Authorization": f"Bearer {secret}"},
            )
        if provider == "openai":
            return await self._client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {secret}"},
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

    async def _reserve_check(self) -> bool:
        if self._client is None:
            raise RuntimeError("ProviderLivenessVerifier must be used as a context manager")
        async with self._counter_lock:
            if self._checks_started >= self._settings.max_checks:
                return False
            self._checks_started += 1
            return True

    def _classify_slack(self, response: httpx.Response) -> LivenessResult:
        if response.status_code == 429:
            return self._result("slack", "valid_but_restricted", "rate_limited")
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
            return self._result("slack", "valid_but_restricted", "rate_limited")
        return self._result("slack", "indeterminate", "provider_rejected_request")

    def _classify_gcp(self, response: httpx.Response) -> LivenessResult:
        if 200 <= response.status_code < 300:
            return self._result("gcp", "active", "authenticated")
        try:
            payload_text = str(response.json())
        except ValueError:
            payload_text = ""
        if "API_KEY_INVALID" in payload_text or "API key not valid" in payload_text:
            return self._result("gcp", "invalid", "authentication_rejected")
        return self._classify_http("gcp", response.status_code)

    def _classify_http(self, provider: str, status_code: int) -> LivenessResult:
        if 200 <= status_code < 300:
            return self._result(provider, "active", "authenticated")
        if status_code == 401:
            return self._result(provider, "invalid", "authentication_rejected")
        if status_code in {403, 429}:
            reason = "rate_limited" if status_code == 429 else "access_restricted"
            return self._result(provider, "valid_but_restricted", reason)
        return self._result(provider, "indeterminate", "unexpected_provider_response")

    @staticmethod
    def _unverified(provider: str, reason: str) -> LivenessResult:
        return LivenessResult(
            status="indeterminate",
            provider=provider,
            reason=reason,
        )

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
