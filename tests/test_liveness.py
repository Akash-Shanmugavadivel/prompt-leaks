from __future__ import annotations

import unittest

import httpx

from prompt_leaks.liveness import LivenessSettings, ProviderLivenessVerifier
from prompt_leaks.service import get_detector


class LivenessVerifierTests(unittest.IsolatedAsyncioTestCase):
    async def test_detector_pairs_aws_credentials_from_prompt(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.host, "sts.amazonaws.com")
            return httpx.Response(200, text="<GetCallerIdentityResponse />")

        access_key = "AKIA" + "A2B3C4D5E6F7G2H3"
        secret_key = ("aB3/Cd4+Ef5=Gh6/Ij7+Kl8=Mn9/Op2+Qr3=St4/")[:40]
        prompt = (
            f"AWS_ACCESS_KEY_ID={access_key}\n"
            f"AWS_SECRET_ACCESS_KEY={secret_key}"
        )
        async with ProviderLivenessVerifier(
            transport=httpx.MockTransport(handler)
        ) as verifier:
            result = await get_detector().scan_with_liveness(prompt, verifier)

        findings = {finding.rule_id: finding for finding in result.findings}
        self.assertEqual(findings["aws-access-token"].liveness.status, "active")
        self.assertEqual(
            findings["prompt-aws-secret-access-key"].liveness.status,
            "active",
        )

    async def test_new_standalone_providers_authenticate(self) -> None:
        visited: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            visited.append(request.url.host)
            return httpx.Response(200, json={"ok": True})

        settings = LivenessSettings(max_checks=10)
        cases = (
            ("anthropic-api-key", "anthropic", "api.anthropic.com"),
            ("gcp-api-key", "gcp", "generativelanguage.googleapis.com"),
            ("huggingface-access-token", "huggingface", "huggingface.co"),
            ("npm-access-token", "npm", "registry.npmjs.org"),
        )
        async with ProviderLivenessVerifier(
            settings=settings,
            transport=httpx.MockTransport(handler),
        ) as verifier:
            for rule_id, provider, host in cases:
                with self.subTest(provider=provider):
                    result = await verifier.verify(rule_id=rule_id, secret="mock-secret")
                    self.assertEqual(result.status, "active")
                    self.assertEqual(result.provider, provider)
                    self.assertEqual(visited[-1], host)

    async def test_aws_pair_uses_one_signed_sts_request(self) -> None:
        request_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            self.assertEqual(request.url.host, "sts.amazonaws.com")
            self.assertTrue(request.headers["authorization"].startswith("AWS4-HMAC-SHA256"))
            self.assertIn(b"GetCallerIdentity", request.content)
            return httpx.Response(200, text="<GetCallerIdentityResponse />")

        access_key = "AKIA" + "A2" * 8
        secret_key = "aB3/" * 10
        targets = (
            ("aws-access-token", access_key, 0, len(access_key)),
            ("prompt-aws-secret-access-key", secret_key, 30, 30 + len(secret_key)),
        )
        async with ProviderLivenessVerifier(
            transport=httpx.MockTransport(handler)
        ) as verifier:
            results = await verifier.verify_many(targets, context="")

        self.assertEqual(request_count, 1)
        self.assertEqual([result.status for result in results], ["active", "active"])
        self.assertTrue(all(result.provider == "aws" for result in results))

    async def test_aws_requires_the_credential_pair(self) -> None:
        request_count = 0

        async def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(500)

        access_key = "AKIA" + "A2" * 8
        async with ProviderLivenessVerifier(
            transport=httpx.MockTransport(handler)
        ) as verifier:
            results = await verifier.verify_many(
                (("aws-access-token", access_key, 0, len(access_key)),),
                context="",
            )

        self.assertEqual(request_count, 0)
        self.assertEqual(results[0].status, "indeterminate")
        self.assertEqual(results[0].reason, "missing_credential_pair")

    async def test_azure_client_credentials_use_fixed_login_host(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.host, "login.microsoftonline.com")
            self.assertIn(b"grant_type=client_credentials", request.content)
            self.assertIn(b"client_secret=mock-secret", request.content)
            return httpx.Response(200, json={"access_token": "discarded"})

        context = (
            "AZURE_TENANT_ID=11111111-1111-4111-8111-111111111111 "
            "AZURE_CLIENT_ID=22222222-2222-4222-8222-222222222222 "
            "AZURE_CLIENT_SECRET=mock-secret"
        )
        async with ProviderLivenessVerifier(
            transport=httpx.MockTransport(handler)
        ) as verifier:
            result = await verifier.verify_many(
                (("azure-ad-client-secret", "mock-secret", 100, 111),),
                context=context,
            )

        self.assertEqual(result[0].status, "active")
        self.assertNotIn("discarded", str(result[0].to_dict()))

    async def test_restricted_and_ambiguous_responses_are_distinct(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.headers.get("authorization") == "Bearer restricted":
                return httpx.Response(403)
            return httpx.Response(503)

        settings = LivenessSettings(max_checks=10)
        async with ProviderLivenessVerifier(
            settings=settings,
            transport=httpx.MockTransport(handler),
        ) as verifier:
            restricted = await verifier.verify(
                rule_id="github-pat", secret="restricted"
            )
            ambiguous = await verifier.verify(rule_id="github-pat", secret="ambiguous")

        self.assertEqual(restricted.status, "valid_but_restricted")
        self.assertEqual(ambiguous.status, "indeterminate")

    async def test_gcp_explicit_invalid_key_response(self) -> None:
        async def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                400,
                json={"error": {"details": [{"reason": "API_KEY_INVALID"}]}},
            )

        async with ProviderLivenessVerifier(
            transport=httpx.MockTransport(handler)
        ) as verifier:
            result = await verifier.verify(rule_id="gcp-api-key", secret="mock-key")

        self.assertEqual(result.status, "invalid")

    async def test_provider_can_be_disabled_without_network_access(self) -> None:
        request_count = 0

        async def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(200)

        settings = LivenessSettings(enabled_providers=frozenset({"github"}))
        async with ProviderLivenessVerifier(
            settings=settings,
            transport=httpx.MockTransport(handler),
        ) as verifier:
            result = await verifier.verify(
                rule_id="anthropic-api-key", secret="mock-secret"
            )

        self.assertEqual(request_count, 0)
        self.assertEqual(result.status, "unsupported")
        self.assertEqual(result.reason, "provider_disabled")


if __name__ == "__main__":
    unittest.main()
