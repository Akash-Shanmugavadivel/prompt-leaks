"""Built-in prompt-focused detection rules."""

from __future__ import annotations

import re

from .config import DetectorConfig
from .models import Allowlist, Rule


def _rule(
    rule_id: str,
    description: str,
    regex: str,
    *,
    keywords: tuple[str, ...],
    secret_group: int | str | None = None,
    entropy: float = 0.0,
    tags: tuple[str, ...] = (),
    generic: bool = False,
    priority: int = 50,
    flags: int = 0,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        description=description,
        regex=re.compile(regex, flags),
        keywords=keywords,
        secret_group=secret_group,
        min_entropy=entropy,
        tags=tags,
        generic=generic,
        priority=priority,
    )


def default_config() -> DetectorConfig:
    """Return conservative built-in rules suitable for user prompts."""
    placeholders = Allowlist(
        target="secret",
        regexes=(
            re.compile(
                r"(?i)^(?:example|sample|placeholder|changeme|dummy|redacted|"
                r"your[_ -]?(?:api[_ -]?key|token|secret|password)|"
                r"insert[_ -].*|replace[_ -].*|<[^>]+>|\$\{[^}]+\})$"
            ),
            re.compile(r"(?i)^(?:x+|0+|a+|\*+|\.+|-+)$"),
        ),
    )

    rules = (
        _rule(
            "private-key",
            "Private key material was included in the prompt.",
            r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?"
            r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            keywords=("-----begin",),
            tags=("private-key", "high-confidence"),
            priority=120,
        ),
        _rule(
            "aws-access-key-id",
            "Possible AWS access key ID.",
            r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b",
            keywords=("akia", "asia", "aida", "aroa", "aipa", "anpa", "anva", "asca"),
            entropy=3.0,
            tags=("aws", "cloud", "high-confidence"),
            priority=110,
        ),
        _rule(
            "openai-api-key",
            "Possible OpenAI API key.",
            r"\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}\b",
            keywords=("sk-",),
            entropy=3.0,
            tags=("openai", "api-key", "high-confidence"),
            priority=110,
        ),
        _rule(
            "github-token",
            "Possible GitHub access token.",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b",
            keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
            entropy=3.0,
            tags=("github", "token", "high-confidence"),
            priority=110,
        ),
        _rule(
            "gitlab-token",
            "Possible GitLab personal access token.",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
            keywords=("glpat-",),
            entropy=3.0,
            tags=("gitlab", "token", "high-confidence"),
            priority=110,
        ),
        _rule(
            "google-api-key",
            "Possible Google API key.",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            keywords=("aiza",),
            entropy=3.0,
            tags=("google", "api-key", "high-confidence"),
            priority=110,
        ),
        _rule(
            "slack-token",
            "Possible Slack token.",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,250}\b",
            keywords=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"),
            entropy=2.5,
            tags=("slack", "token", "high-confidence"),
            priority=110,
        ),
        _rule(
            "stripe-secret-key",
            "Possible Stripe live secret key.",
            r"\b[rs]k_live_[A-Za-z0-9]{16,}\b",
            keywords=("sk_live_", "rk_live_"),
            entropy=3.0,
            tags=("stripe", "api-key", "high-confidence"),
            priority=110,
        ),
        _rule(
            "database-url-password",
            "Password embedded in a database connection URL.",
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:\s/@]+:([^@\s/]{4,})@",
            keywords=("postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://"),
            secret_group=1,
            entropy=1.5,
            tags=("database", "password", "high-confidence"),
            priority=105,
            flags=re.IGNORECASE,
        ),
        _rule(
            "bearer-token",
            "Possible bearer token.",
            r"\bbearer\s+([A-Za-z0-9._~+/-]{16,}={0,2})",
            keywords=("bearer",),
            secret_group=1,
            entropy=3.0,
            tags=("authorization", "token"),
            generic=True,
            priority=60,
            flags=re.IGNORECASE,
        ),
        _rule(
            "jwt",
            "Possible JSON Web Token.",
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\b",
            keywords=("eyj",),
            entropy=3.5,
            tags=("jwt", "token"),
            generic=True,
            priority=55,
        ),
        _rule(
            "generic-assigned-secret",
            "Possible credential assigned to a secret-like field.",
            r"\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|client[_ -]?secret|"
            r"secret[_ -]?key|password|passwd|pwd)\b\s*(?:=|:|is)\s*[\"']?"
            r"([A-Za-z0-9_./+=:@-]{8,})",
            keywords=(
                "api_key", "api-key", "api key", "access_token", "access token",
                "auth_token", "client_secret", "client secret", "secret_key",
                "password", "passwd", "pwd",
            ),
            secret_group=1,
            entropy=2.0,
            tags=("generic", "credential"),
            generic=True,
            priority=40,
            flags=re.IGNORECASE,
        ),
    )
    return DetectorConfig(rules=rules, global_allowlists=(placeholders,))

