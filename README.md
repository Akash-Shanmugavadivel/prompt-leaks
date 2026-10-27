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

The detector loads and compiles the packaged 231-rule catalog once per Python
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

## Credential liveness

Set `verify_liveness` to `true` to request active verification:

```json
{
  "prompt": "GITHUB_TOKEN=ghp_example",
  "mode": "block",
  "verify_liveness": true
}
```

Supported providers are GitHub, OpenAI, GitLab.com, Slack, and Stripe. Each
provider is contacted through a fixed HTTPS endpoint with a read only identity
or account metadata request. Other secrets and PII receive `unsupported`
without a network request.

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

Statuses are `active`, `invalid`, `restricted`, `indeterminate`, and
`unsupported`. Provider response bodies and matched credentials are never
returned. Checks use a five second timeout, no redirects, no environment proxy,
at most three concurrent connections, and at most five provider calls per
prompt.

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
Gitleaks catalog plus ten prompt specific rules. These cover standalone
bearer headers, MongoDB URI passwords, private key blocks, SSNs, medical
diagnosis codes, passport numbers, dates of birth, checksum-valid payment
cards and IBANs, and OpenAI project keys. The filename only `pkcs12-file` rule
is omitted because prompt scanning has no file path.

Run the included credential, PII, and clean-prompt evaluation set with:

```powershell
.\.venv\Scripts\python.exe examples\evaluate_prompts.py
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
