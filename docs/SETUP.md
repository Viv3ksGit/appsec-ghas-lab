# Setting up this lab from zero

## 0. What you actually need (no server, no special OS)

Nothing in this lab runs on your computer. **All scanning runs on GitHub's cloud**:
every workflow says `runs-on: ubuntu-latest`, which means GitHub spins up a fresh,
temporary Ubuntu Linux machine (a "runner") for each job, runs the scan, and throws it away.

Your laptop (Windows, Mac or Linux, any of them) only does two things: edit files and
`git push` them. So you need:

| Need | Why | Get it |
|---|---|---|
| GitHub account (free) | Hosts the repo, runs Actions, provides GHAS | github.com |
| **Public** repository | GHAS features (CodeQL, secret scanning, push protection) are **free only on public repos**; private repos need paid licences | chosen at repo creation |
| Git | Version control, to push code | git-scm.com (Windows: "Git for Windows", includes Git Bash) |
| GitHub CLI (`gh`) | Create the repo and change settings from the terminal | cli.github.com |
| A code editor | Edit files | VS Code |
| *(optional)* Anthropic API key | Only for the AI triage workflow | console.anthropic.com |

You do **not** install CodeQL, Semgrep, Trivy, Checkov or zizmor locally. Each workflow
downloads its tool onto the runner automatically.

## 1. Install and log in (one time)

```bash
git --version          # check git is installed
gh --version           # check GitHub CLI is installed
gh auth login          # choose GitHub.com > HTTPS > login with browser
gh auth status         # confirm you're logged in
git config --global user.name "Your Name"
git config --global user.email "<id>+<username>@users.noreply.github.com"   # keeps your real email private
```

## 2. Create the project files

The repo layout and what each part does:

```
appsec-ghas-lab/
├── app/                      THE TARGET: a deliberately vulnerable Flask API
│   ├── app.py                  11 intentional vulns (SQLi, cmd injection, SSRF...)
│   └── requirements.txt        old library versions with known CVEs
├── Dockerfile                container config with bad practices (EOL image, root user)
├── infra/main.tf             Terraform with cloud misconfigs (public S3, open SSH)
│
├── .github/                  EVERYTHING GITHUB READS
│   ├── workflows/              CI/CD pipelines (GitHub Actions); each .yml runs on push/PR
│   │   ├── codeql.yml            GitHub's own SAST engine
│   │   ├── dependency-review.yml blocks PRs that add vulnerable dependencies
│   │   ├── third-party-scanners.yml  Semgrep + Trivy + Checkov → results into GitHub
│   │   ├── pipeline-security.yml    zizmor + OpenSSF Scorecard (secures the pipeline itself)
│   │   ├── supply-chain.yml         SBOM + signed build provenance
│   │   └── ai-triage.yml            Claude reviews the alerts and comments on the PR
│   ├── codeql/                 CodeQL config + a custom query you wrote
│   ├── scripts/ai_triage.py    the AI triage program
│   ├── dependabot.yml          tells Dependabot what to keep updated
│   └── CODEOWNERS              who must review sensitive paths
│
├── scripts/setup-ghas.sh     turns on the GitHub security settings via API
├── .pre-commit-config.yaml   gitleaks: catches secrets on your laptop before commit
└── SECURITY.md               how to report vulnerabilities
```

Key idea: **GitHub automatically recognises files in `.github/`**. Put a YAML file in
`.github/workflows/` and it becomes a pipeline; put `dependabot.yml` in `.github/` and
Dependabot starts. There's no other "install" step.

## 3. Create the repo on GitHub and push

```bash
cd appsec-ghas-lab
git init -b main
git add -A
git commit -m "Initial lab"
gh repo create appsec-ghas-lab --public --source . --push
```

The moment this push lands, GitHub reads `.github/workflows/` and starts the scans.
Watch them under the repo's **Actions** tab.

## 4. Turn on the GitHub security settings

These are repository **settings**, not files, so they're switched on separately.
Either run the script:

```bash
bash scripts/setup-ghas.sh <your-username>/appsec-ghas-lab
```

…or click through the UI. Here is what the script does, and where each setting is in the UI:

| Setting | UI location | What it does |
|---|---|---|
| Dependabot alerts | Settings → Advanced Security | Alerts on vulnerable dependencies |
| Dependabot security updates | same | Auto-opens PRs that upgrade them |
| Secret scanning | same | Finds secrets already committed |
| Push protection | same | **Blocks** a push that contains a secret |
| Private vulnerability reporting | same | Lets outsiders report bugs privately |
| Default token = read-only | Settings → Actions → General → Workflow permissions | Workflows get minimal rights unless they ask |
| **Ruleset** on `main` | Settings → Rules → Rulesets | Requires a PR, requires checks to pass, and blocks merge if CodeQL finds high/critical issues |

(Code scanning needs no switch: uploading results from the CodeQL workflow turns it on.
We use **"advanced setup"** (our own workflow file) rather than "default setup" (one click
in Settings), because advanced setup allows the custom query and config.)

## 5. (Optional) Turn on AI triage

```bash
gh secret set ANTHROPIC_API_KEY -R <your-username>/appsec-ghas-lab   # paste key when prompted
```

Secrets are encrypted by GitHub and only exposed to workflows as `${{ secrets.NAME }}`;
they never appear in code or logs. Without the key, the triage workflow just skips.

## 6. Verify it works

| Check | Where |
|---|---|
| All workflows green | **Actions** tab |
| Findings from every tool | **Security → Code scanning** (filter by tool) |
| Vulnerable dependencies | **Security → Dependabot** |
| Upgrade PRs | **Pull requests** (opened by Dependabot) |
| Merge gate | Open any PR: merging is blocked until checks pass |

Then follow [DEMO.md](DEMO.md) to try it hands-on.

## 7. (Optional) Local pre-commit hook

```bash
pip install pre-commit
pre-commit install      # now gitleaks scans every commit on your machine
```

## How it all flows

```
 you: git push / open PR
          │
          ▼
 GitHub ── push protection checks for secrets ──► blocked if found
          │
          ▼
 Actions runners (temporary Ubuntu VMs) run in parallel:
   CodeQL · Semgrep · Trivy · Checkov · zizmor · Scorecard · Dependency Review
          │  each uploads results in SARIF format
          ▼
 Security tab: one list of alerts from all tools
          │
          ├──► AI triage workflow: Claude reviews alerts → PR comment
          │
          ▼
 Ruleset on main: checks must pass + no high/critical CodeQL alerts → merge allowed
          │
          ▼
 Supply-chain workflow on main: SBOM + signed provenance for the build
```
