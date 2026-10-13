#!/usr/bin/env bash
# Enables GHAS features + a merge-gating ruleset on the lab repo, as code.
# Usage: scripts/setup-ghas.sh <owner>/<repo>
# Note: on PUBLIC repos code scanning, secret scanning and push protection are free.
# Private repos need GitHub Secret Protection / GitHub Code Security licences.
set -euo pipefail
REPO="${1:?usage: setup-ghas.sh owner/repo}"

try() { local label="$1"; shift; "$@" >/dev/null 2>&1 && echo "  ok: $label" || echo "  skipped (plan/licence?): $label"; }

echo "== Secret scanning + push protection"
for feature in secret_scanning secret_scanning_push_protection \
               secret_scanning_non_provider_patterns secret_scanning_validity_checks; do
  echo "{\"security_and_analysis\":{\"$feature\":{\"status\":\"enabled\"}}}" \
    | try "$feature" gh api -X PATCH "repos/$REPO" --input - --silent
done

echo "== Dependabot alerts + security updates, private vulnerability reporting"
try dependabot-alerts gh api -X PUT "repos/$REPO/vulnerability-alerts" --silent
try dependabot-security-updates gh api -X PUT "repos/$REPO/automated-security-fixes" --silent
try private-vuln-reporting gh api -X PUT "repos/$REPO/private-vulnerability-reporting" --silent

echo "== Ruleset: PR required, status checks, and CodeQL merge protection on main"
gh api -X POST "repos/$REPO/rulesets" --input - --silent <<'JSON'
{
  "name": "main: secure SDLC gates",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "Dependency Review" },
          { "context": "Analyze (python)" } ] } },
    { "type": "code_scanning", "parameters": {
        "code_scanning_tools": [
          { "tool": "CodeQL", "security_alerts_threshold": "high_or_higher", "alerts_threshold": "errors" } ] } }
  ]
}
JSON
echo "  ok: ruleset created"

echo
echo "Manual steps (UI only):"
echo "  1. Settings > Secrets and variables > Actions: add ANTHROPIC_API_KEY (for AI triage)"
echo "  2. Settings > Code security: add a custom secret scanning pattern, e.g. lab-[a-z]+-secret-[a-z-]+"
echo "  3. Settings > Actions > General: 'Read repository contents' default token permission"
