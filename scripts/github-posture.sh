#!/usr/bin/env bash
#
# Applies Kura's GitHub repository security posture (the parts that live in
# GitHub's settings rather than in the tree). Run it against any clone/fork
# of this template to reproduce the same baseline. It is idempotent: the
# toggles use PUT, and the branch ruleset is skipped if it already exists.
#
#   scripts/github-posture.sh            # apply to the repo `gh` is pointed at
#   REPO=owner/name scripts/github-posture.sh
#
# What it configures:
#   1. Dependabot vulnerability alerts                (enable)
#   2. Dependabot automated security-fix PRs          (enable)
#   3. Private vulnerability reporting                (enable)
#   4. Merge settings: squash/rebase only, auto-delete merged branches
#   5. A ruleset on the default branch:
#        - require a pull request (0 approvals -> sole maintainer can
#          self-merge), with squash/rebase merges only
#        - require the `build-test` status check to pass, branch up to date
#        - require linear history
#        - block force-pushes and branch deletion
#        - no bypass actors (the rules apply to admins too)
#   6. A tag ruleset protecting `v*` release tags:
#        - block tag deletion and tag-moving (non-fast-forward)
#        - new tags can still be created, but never repointed or deleted,
#          so a published release's tag is immutable
#
# The companion in-tree pieces (LICENSE, SECURITY.md, dependabot.yml, the
# hardened CI/CodeQL/dependency-review workflows, scripts/release.sh, and
# .github/workflows/release.yml) are committed in the repo.
#
# PREREQUISITES
#   - gh (GitHub CLI), authenticated with admin on the target repo.
#
# NOTE on full release immutability: the `v*` tag ruleset below makes the
# release tag immutable. To also make the *release assets* immutable, enable
# "Immutable releases" under repo Settings -> General (no stable REST API at
# time of writing) — this script prints a reminder at the end.

set -euo pipefail

REPO="${REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
echo "Applying GitHub security posture to: ${REPO}"

api() { gh api -H "Accept: application/vnd.github+json" "$@"; }

echo "1/6  Enabling Dependabot vulnerability alerts..."
api -X PUT "repos/${REPO}/vulnerability-alerts" --silent

echo "2/6  Enabling Dependabot automated security fixes..."
api -X PUT "repos/${REPO}/automated-security-fixes" --silent

echo "3/6  Enabling private vulnerability reporting..."
api -X PUT "repos/${REPO}/private-vulnerability-reporting" --silent

echo "4/6  Setting merge methods (squash/rebase) + auto-delete branches..."
api -X PATCH "repos/${REPO}" \
  -F allow_merge_commit=false \
  -F allow_squash_merge=true \
  -F allow_rebase_merge=true \
  -F delete_branch_on_merge=true \
  --silent

echo "5/6  Creating the default-branch ruleset 'main'..."
if api "repos/${REPO}/rulesets" --jq '.[].name' | grep -qx "main"; then
  echo "      A ruleset named 'main' already exists; leaving it unchanged."
else
  api -X POST "repos/${REPO}/rulesets" --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["squash", "rebase"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "do_not_enforce_on_create": false,
        "required_status_checks": [ { "context": "build-test" } ]
      }
    }
  ],
  "bypass_actors": []
}
JSON
  echo "      Ruleset created."
fi

echo "6/6  Creating the 'release-tags' ruleset (v* immutability)..."
if api "repos/${REPO}/rulesets" --jq '.[].name' | grep -qx "release-tags"; then
  echo "      A ruleset named 'release-tags' already exists; leaving it unchanged."
else
  api -X POST "repos/${REPO}/rulesets" --input - <<'JSON'
{
  "name": "release-tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["refs/tags/v*"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" }
  ],
  "bypass_actors": []
}
JSON
  echo "      Ruleset created."
fi

echo
echo "Done. Verify under: https://github.com/${REPO}/settings"
echo
echo "One manual step (no stable REST API): enable 'Immutable releases' at"
echo "  https://github.com/${REPO}/settings  (General -> Releases)"
echo "to make published release assets immutable as well as the tags."
