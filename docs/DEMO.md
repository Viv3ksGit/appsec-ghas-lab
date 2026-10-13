# 10-minute demo walkthrough

## 1. Security overview (1 min)
**Security** tab: code scanning alerts grouped by tool (CodeQL, Semgrep, Trivy,
Checkov, zizmor, Scorecard), Dependabot alerts, secret scanning. Filter by
`tool:CodeQL severity:critical`. Open the SQL injection alert to show the **data-flow
path** from `request.args` to `execute()`, plus **Copilot Autofix**.

## 2. A PR that introduces a vulnerability (4 min)
```bash
git switch -c feature/report-export
```
Add to `app/app.py`:
```python
@app.route("/report")
def report():
    fmt = request.args.get("fmt", "csv")
    return subprocess.check_output(f"generate_report --format {fmt}", shell=True)
```
And add a vulnerable dependency to `app/requirements.txt`: `Pillow==8.0.0`
```bash
git commit -am "Add report export" && git push -u origin HEAD
gh pr create --fill
```
Show:
- CodeQL annotates the diff inline (`py/command-line-injection` + the custom `subprocess-shell-true` query).
- **Dependency review** fails, with a comment listing the Pillow CVEs.
- The **ruleset** blocks the merge ("Code scanning results: high or higher").
- The **🤖 AI security triage** comment: verdict, exploit scenario, suggested fix.

Then fix it (`subprocess.run(["generate_report", "--format", fmt])` + an allow-list),
push, and show the alert auto-closing and the gate going green.

## 3. Push protection (1 min)
Create a throwaway GitHub fine-grained PAT with **no permissions**, put it in a file,
commit and push. Push protection blocks the push and shows the bypass reasons
(false positive / used in tests / will fix later). **Revoke the PAT afterwards.**

## 4. Supply chain (2 min)
Download the `release` artifact from the latest `Supply chain` run, then:
```bash
gh attestation verify app.tar.gz -R <owner>/appsec-ghas-lab
```
This shows Sigstore-signed provenance tying the artifact to this repo, workflow and commit.

## 5. Pipeline hardening (2 min)
Open any workflow: `permissions: {}`, SHA pins, `persist-credentials: false`. Then the
**zizmor** and **CodeQL (actions)** alerts, and the Scorecard results.
