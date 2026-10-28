# prompt-leaks

`prompt-leaks` is a Python 3.12 library and FastAPI service that scans user
prompts for secrets before an AI call. It is an independent implementation of
the main detection ideas used by Gitleaks:

- keyword prefiltering;
- provider and context specific regular expressions;
- secret capture groups and Shannon entropy checks;
- Luhn and IBAN checksum validation;
- rule and global allowlists;
- bounded Base64, hexadecimal, and percent decoding;
- deduplication between provider specific and generic findings.

The public result includes rule and location metadata. It never includes the
matched secret.

## Install

From PowerShell:

```powershell
cd "C:\Users\Akash vel\Documents\Codex\2026-10-27\ps-n-codex-the-term-node\outputs\prompt-leaks"
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

To enable Microsoft Presidio PII analysis, install the optional dependency and
an English spaCy model:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[presidio]"
.\.venv\Scripts\python.exe -m spacy download en_core_web_lg
```

## Use as a Python function

```python
from prompt_leaks import scan_prompt

result = scan_prompt(user_prompt, mode="block")

if result.detected:
    # Do not send user_prompt to the model.
    print(result.to_dict())
else:
    response = ai_client.responses.create(
        model="your-model",
        input=user_prompt,
    )
```

To replace detected values and continue with a sanitized prompt:

```python
result = scan_prompt(user_prompt, mode="redact")
prompt_for_model = result.sanitized_prompt
```

Enable Presidio when names, email addresses, phone numbers, locations, national
identifiers, and other contextual PII should also be detected:

```python
from prompt_leaks import PresidioScanConfig, scan_prompt

result = scan_prompt(
    user_prompt,
    mode="redact",
    presidio=PresidioScanConfig(
        language="en",
        entities=("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"),
        score_threshold=0.6,
    ),
)
prompt_for_model = result.sanitized_prompt
```

Liveness checking is asynchronous because it contacts credential issuers:

```python
from prompt_leaks import scan_prompt_with_liveness

result = await scan_prompt_with_liveness(user_prompt, mode="block")
for finding in result.findings:
    if finding.liveness is not None:
        print(finding.rule_id, finding.liveness.status)
```

Conversation scanning detects credentials split at message boundaries:

```python
from prompt_leaks import scan_messages

result = scan_messages(
    ["Use token github_", "pat_REMAINDER_OF_TOKEN"],
    mode="block",
)
```

The detector loads and compiles the packaged 233-rule catalog once per Python
process. Calls after the first reuse the same detector.

## Run the FastAPI service

```powershell
.\.venv\Scripts\prompt-leaks-api.exe
```

Liveness is available by default because the launcher binds to `127.0.0.1`.
Disable it when active checks are not authorized:

```powershell
$env:PROMPT_LEAKS_ENABLE_LIVENESS = "false"
.\.venv\Scripts\prompt-leaks-api.exe
```

The service listens on `http://127.0.0.1:8000`. Interactive OpenAPI docs are
available at `http://127.0.0.1:8000/docs`.

You can also start it through Uvicorn:

```powershell
.\.venv\Scripts\python.exe -m uvicorn prompt_leaks.api:app --host 127.0.0.1 --port 8000
```

## Send a prompt in the request body

```powershell
$body = @{
    prompt = "password = CorrectHorseBatteryStaple42"
    mode = "block"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/v1/scan" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

Request body:

```json
{
  "prompt": "Authorization: Bearer AbC123xYz987LmN456PqR789",
  "mode": "block",
  "verify_liveness": false
}
```

Safe response:

```json
{
  "detected": true,
  "action": "block",
  "finding_count": 1,
  "findings": [
    {
      "rule_id": "prompt-bearer-token",
      "description": "Possible bearer token in an authorization header.",
      "start_offset": 22,
      "end_offset": 46,
      "start_line": 1,
      "end_line": 1,
      "start_column": 23,
      "end_column": 47,
      "entropy": 4.3349,
      "severity": "critical",
      "confidence": 0.9,
      "tags": ["prompt-extension", "authorization", "token"],
      "encodings": []
    }
  ]
}
```

Supported modes:

- `block`: return findings and omit the original prompt from the response.
- `redact`: return findings plus `sanitized_prompt` with secrets replaced.

To scan a conversation, send `messages` instead of `prompt`:

```json
{
  "messages": [
    {"role": "user", "content": "Use token github_"},
    {"role": "user", "content": "pat_REMAINDER_OF_TOKEN"}
  ],
  "mode": "redact",
  "verify_liveness": false
}
```

Cross-message findings include `start_message_index` and
`end_message_index`. Redact mode returns `sanitized_messages`.

## Microsoft Presidio PII analysis

Presidio is optional and runs locally in the API process. Add a `presidio`
object to enable it for a request:

```json
{
  "prompt": "My name is Sanjay Kumar and my email is sanjay@example.com",
  "mode": "redact",
  "verify_liveness": false,
  "presidio": {
    "language": "en",
    "entities": ["PERSON", "EMAIL_ADDRESS"],
    "score_threshold": 0.6
  }
}
```

Abridged example output:

```json
{
  "detected": true,
  "action": "redact",
  "finding_count": 2,
  "findings": [
    {
      "rule_id": "presidio-person",
      "severity": "medium",
      "confidence": 0.85,
      "tags": ["pii", "presidio", "person"]
    },
    {
      "rule_id": "presidio-email-address",
      "severity": "medium",
      "confidence": 1.0,
      "tags": ["pii", "presidio", "email_address"]
    }
  ],
  "sanitized_prompt": "My name is [REDACTED:presidio-person] and my email is [REDACTED:presidio-email-address]"
}
```

Presidio supplies entity type, location, and confidence. `prompt-leaks` maps
those spans into its existing findings, overlap deduplication, multi-message,
allowlist, block, and redaction pipeline. Raw PII is not returned in findings.
If a deterministic rule and Presidio identify the same span, the deterministic
rule wins.

Omit `entities` to use all entities supported by the installed Presidio
recognizers. Disable this feature server-wide with:

```powershell
$env:PROMPT_LEAKS_ENABLE_PRESIDIO = "false"
```

Presidio requires an NLP model and adds more CPU, memory, and startup time than
the deterministic secret rules. The analyzer is created lazily on the first
Presidio request and then reused.

## Credential liveness

Set `verify_liveness` to `true` to request active verification:

```json
{
  "prompt": "GITHUB_TOKEN=ghp_example",
  "mode": "block",
  "verify_liveness": true
}
```

Supported providers are Anthropic, AWS, Azure, Google Cloud, GitHub, GitLab.com,
Hugging Face, npm, OpenAI, Slack, and Stripe. Each provider is contacted through
a fixed HTTPS endpoint with a read only identity, model-list, or account
metadata request. Other secrets and PII receive `unsupported` without a network
request.

Each finding may include:

```json
{
  "liveness": {
    "status": "invalid",
    "provider": "github",
    "reason": "authentication_rejected",
    "checked_at": "2026-10-27T12:00:00Z"
  }
}
```

Statuses are `active`, `invalid`, `valid_but_restricted`, `indeterminate`, and
`unsupported`. `valid_but_restricted` means authentication was accepted but a
scope, policy, quota, or rate limit blocked the read operation. Ambiguous and
server-side failures return `indeterminate`. Provider response bodies and
matched credentials are never returned.

AWS verification requires an access key ID and secret access key in the same
prompt. Temporary `ASIA` credentials also require a session token:

```text
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=...
```

AWS credentials are signed locally and checked with STS `GetCallerIdentity`.
Azure client-secret verification requires contextual tenant and client IDs:

```text
AZURE_TENANT_ID=00000000-0000-4000-8000-000000000000
AZURE_CLIENT_ID=00000000-0000-4000-8000-000000000000
AZURE_CLIENT_SECRET=...
```

Configure active checks with trusted server environment variables:

```powershell
$env:PROMPT_LEAKS_LIVENESS_PROVIDERS = "github,aws,azure,anthropic,gcp,huggingface,npm"
$env:PROMPT_LEAKS_LIVENESS_TIMEOUT_SECONDS = "5"
$env:PROMPT_LEAKS_LIVENESS_MAX_CHECKS = "5"
$env:PROMPT_LEAKS_LIVENESS_MAX_CONCURRENCY = "3"
$env:PROMPT_LEAKS_ANTHROPIC_VERSION = "2023-06-01"
```

Provider URLs remain fixed in code to prevent prompt-controlled network
destinations. Checks use no redirects or environment proxy.

Prompts are limited to 100,000 characters. FastAPI returns HTTP `422` when
the body is missing, malformed, too large, or contains an unsupported mode.

## Endpoint placement

Call `/v1/scan` after parsing the incoming body and before logging, tracing,
queuing, storing, indexing, or sending the prompt to the model provider. Avoid
request-body capture in the API server, proxy, and error tracker.

Safe audit records may contain a request ID, rule IDs, finding count, action,
and timestamp. Do not record the prompt, regex match, secret, or line excerpt.

## Organization rules and allowlists

Place trusted organization rules and global allowlists in a separate TOML file,
then set its path before starting the service:

```powershell
$env:PROMPT_LEAKS_ORG_CONFIG = "examples\organization-rules.toml"
.\.venv\Scripts\prompt-leaks-api.exe
```

Organization rules with an existing ID replace the packaged rule. New IDs are
added, and organization global allowlists are appended. Keep this file under
administrator control; never accept rule or allowlist configuration from a
prompt author. See `examples/organization-rules.toml` for the schema.

## Rule catalog

The packaged catalog contains 221 content detection rules imported from the
Gitleaks catalog plus twelve prompt specific rules. These cover standalone
bearer headers, MongoDB URI passwords, private key blocks, SSNs, medical
diagnosis codes, passport numbers, dates of birth, checksum-valid payment
cards and IBANs, AWS secret and session credentials, and OpenAI project keys.
The filename only `pkcs12-file` rule is omitted because prompt scanning has no
file path.

Run the included credential, PII, and clean-prompt evaluation set with:

```powershell
.\.venv\Scripts\python.exe examples\evaluate_prompts.py
```

Run provider verification tests with mocked HTTP transports:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`examples/custom-rules.toml` is the readable catalog copy. To regenerate it
from a Gitleaks checkout:

```powershell
.\.venv\Scripts\python.exe scripts\import_gitleaks_rules.py `
    C:\path\to\gitleaks\config\gitleaks.toml `
    examples\custom-rules.toml
```

The same generated file must be copied to
`src\prompt_leaks\catalog\gitleaks.toml` before building a release. Source
attribution is in `THIRD_PARTY_NOTICES.md`.

Deterministic rules cannot prove that a prompt is secret free. Unknown, newly
issued, or deliberately obfuscated credential formats can evade them.
