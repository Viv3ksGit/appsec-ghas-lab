# AppSec GHAS Lab: securing the SDLC end to end

A hands-on lab that wires **GitHub Advanced Security** and third-party CI/CD security
tooling around a deliberately vulnerable Flask API, with **LLM-assisted alert triage**
layered on top. Every control here is defined as code.

> ⚠️ `app/`, `Dockerfile` and `infra/` are **intentionally vulnerable**. Never deploy them.

## What's in the pipeline

| SDLC stage | Control | Where |
|---|---|---|
| Developer workstation | gitleaks pre-commit hook | `.pre-commit-config.yaml` |
| `git push` | **Secret scanning push protection** (+ custom pattern, validity checks) | `scripts/setup-ghas.sh` |
| Pull request: SAST | **CodeQL** advanced setup, `security-extended` suite + a **custom query**, plus a CodeQL scan of the workflows themselves | `.github/workflows/codeql.yml`, `.github/codeql/` |
| Pull request: SAST (3rd party) | Semgrep → SARIF → code scanning | `third-party-scanners.yml` |
| Pull request: SCA | **Dependency review** blocks newly introduced high-severity CVEs and denied licences | `dependency-review.yml` |
| Pull request: IaC / container | Trivy (vuln, misconfig, secret) + Checkov → SARIF | `third-party-scanners.yml` |
| Pull request: pipeline itself | zizmor Actions audit; OpenSSF Scorecard | `pipeline-security.yml` |
| Merge gate | **Ruleset**: PR required, required checks, **code scanning merge protection** (blocks on high+ CodeQL alerts) | `scripts/setup-ghas.sh` |
| Triage | 🤖 **AI triage**: Claude reviews each open alert, gives a TP/FP verdict, adjusted severity, exploit scenario and fix, posted as a sticky PR comment | `ai-triage.yml`, `.github/scripts/ai_triage.py` |
| Remediation | Copilot Autofix on CodeQL alerts; Dependabot security updates (grouped) | `dependabot.yml` |
| Release | SBOM (SPDX) + **signed build provenance** via artifact attestations (Sigstore/OIDC) | `supply-chain.yml` |

## How the workflows themselves are hardened

- `permissions: {}` at the top of every workflow; each job asks for exactly the scopes it needs.
- Every third-party action is **pinned to a full commit SHA** (with the version in a comment, kept fresh by Dependabot). That's the defence against tag-repointing attacks like the 2025 `tj-actions/changed-files` compromise.
- `persist-credentials: false` on checkout, so the token doesn't stay on disk for later steps.
- The AI triage runs on `workflow_run` but **never checks out PR code**: it reads PR source through the API as data. That avoids the "pwn request" pattern.
- Untrusted event fields go through `env:`, never `${{ }}` inside `run:` (template injection).
- CodeQL's `actions` language and zizmor continuously check the workflows for regressions.

## Vulnerability map (app/app.py)

| Endpoint | Vulnerability | CWE |
|---|---|---|
| `/users` | SQL injection | CWE-89 |
| `/ping` | OS command injection | CWE-78 |
| `/download` | Path traversal | CWE-22 |
| `/fetch` | SSRF (cloud metadata) | CWE-918 |
| `/greet` | Server-side template injection | CWE-1336 |
| `/session`, `/config` | Insecure deserialization (pickle, YAML) | CWE-502 |
| `/me` | JWT signature not verified | CWE-347 |
| `/register` | Weak password hashing (MD5) | CWE-328 |
| app config | Hard-coded secret, debug mode | CWE-798, CWE-489 |

Plus outdated pinned dependencies (`requirements.txt`), an EOL root-user container, and
misconfigured Terraform (public S3, `0.0.0.0/0` SSH, `*:*` IAM, unencrypted public RDS).

## Setup

```bash
gh repo create appsec-ghas-lab --public --source . --push
scripts/setup-ghas.sh <owner>/appsec-ghas-lab
gh secret set ANTHROPIC_API_KEY        # enables the AI triage workflow
```

New to this? Start with [docs/SETUP.md](docs/SETUP.md) (full from-zero guide), then [docs/DEMO.md](docs/DEMO.md).

## The AI triage design

- **Advisory, human-in-the-loop.** It never dismisses alerts. Engineers and AppSec decide.
- **Prompt injection aware.** Source code is fenced as untrusted data, and the model is told to ignore instructions inside it. The model has no tools, and the token can't write to alerts.
- **Structured output.** The JSON schema guarantees `verdict / confidence / adjusted_severity / exploit_scenario / remediation`, so results can feed metrics (FP rate per rule, precision per tool).
- **Fails open and capped.** A per-run alert cap bounds cost, and an LLM outage never blocks a merge.
- **Next steps:** measure agreement against human triage decisions, auto-suggest a dismissal reason for high-confidence FPs, and feed confirmed FPs back into query tuning.
