"""Small prompt-leaks evaluation set covering credentials, PII, and clean text."""

from prompt_leaks import scan_prompt


GITHUB_TEST_TOKEN = "ghp_" + ("98aB7c6D5e4F3g2H1i0JkLmNoPqRsTuVwXyZ")
SLACK_TEST_TOKEN = "xoxb-" + "123456789012-345678901234-abcdefghijklmnopqrstuvwx"
STRIPE_TEST_TOKEN = "rk_live_" + "89AbCdEfGhIjKlMnOpQrStUv"
OPENAI_TEST_TOKEN = "sk-proj-" + "aB9cD8eF7gH6jI5kL4mN3oP2qR1sT"


TEST_CASES = [
    (1, "Developer", "Refactor this TypeScript interface to support optional pagination metadata.", False),
    (2, "Developer", f"Fix CI pipeline failure using GITHUB_TOKEN={GITHUB_TEST_TOKEN} pushing to repo corp/core-api.", True),
    (3, "Developer", "Write a Dockerfile for a Go microservice using a multi-stage Alpine build.", False),
    (4, "Developer", "Resolve connection timeout for mongodb+srv://admin:P@ssw0rd99!@cluster0.abcde.mongodb.net/prod_db from AWS Lambda.", True),
    (5, "Developer", "Generate unit tests in pytest for validating ISO-8601 timestamp parsing.", False),
    (6, "Developer", f"Configure alert webhook with Slack bot token {SLACK_TEST_TOKEN} to post in #incident-alerts.", True),
    (7, "Developer", "Decrypt payload using RSA private key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4X...-----END RSA PRIVATE KEY-----.", True),
    (8, "HR", "Write five behavioral interview questions to assess cross-functional conflict resolution.", False),
    (9, "HR", "Update direct deposit for Sarah Connor (SSN: 987-65-4321, DOB: 05/14/1982) to routing 121000358, account 4589201948.", True),
    (10, "HR", "Draft an internal announcement detailing company-observed holidays for the upcoming year.", False),
    (11, "HR", "Draft PIP review notes for Employee #44029 citing medical leave diagnosis code F32.9 and attendance logs.", True),
    (12, "HR", "Compose an onboarding welcome email template for incoming software engineering interns.", False),
    (13, "HR", "Prepare employment contract for Mark Vance: Passport A12948201, home address 742 Evergreen Terr, base salary $310,000.", True),
    (14, "HR", "Summarize current market benchmarks for corporate 401(k) matching percentages.", False),
    (15, "Finance", "Calculate the net present value (NPV) of a 3-year equipment lease at an 8% discount rate.", False),
    (16, "Finance", f"Process payment using Stripe key {STRIPE_TEST_TOKEN} to vendor IBAN DE89370400440532013000.", True),
    (17, "Finance", "Provide an Excel formula to compute compound annual growth rate (CAGR) across columns B through F.", False),
    (18, "Finance", "Authorize SaaS renewal charge on Corporate Visa 4111-2222-3333-4444, Exp 11/28, CVV 392, amount $14,200.", True),
    (19, "Finance", f"Reconcile unreleased Q3 financial forecast: Project Titan pre-IPO valuation deck access key {OPENAI_TEST_TOKEN}.", True),
    (20, "Finance", "Draft standard operating procedure bullet points for quarterly capital expenditure depreciation audits.", False),
]


def main() -> int:
    failures = 0
    print(f"{'ID':<4} | {'Role':<10} | {'Expected':<8} | {'Actual':<8} | Status")
    print("-" * 58)

    for case_id, role, prompt, expected in TEST_CASES:
        result = scan_prompt(prompt, mode="block")
        actual = result.detected
        passed = actual == expected
        failures += not passed
        print(
            f"{case_id:<4} | {role:<10} | "
            f"{('LEAK' if expected else 'CLEAN'):<8} | "
            f"{('LEAK' if actual else 'CLEAN'):<8} | "
            f"{'PASS' if passed else 'FAIL'}"
        )
        if not passed:
            print(f"     Safe scan details: {result.to_dict()}")

    print("-" * 58)
    print(f"Total: {len(TEST_CASES)} | Passed: {len(TEST_CASES) - failures} | Failed: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
