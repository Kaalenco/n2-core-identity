# Workflow run object — useful properties:
#   .id              numeric run ID (used for delete/re-run API calls)
#   .name            display name of the run (e.g. "CI Build")
#   .path            workflow file path (e.g. ".github/workflows/dotnet.yml")
#   .event           trigger event: push | pull_request | schedule | workflow_dispatch | ...
#   .status          current state:  queued | in_progress | completed
#   .conclusion      final result:   success | failure | cancelled | skipped | timed_out | null (if not completed)
#   .created_at      ISO 8601 UTC timestamp when the run was queued
#   .updated_at      ISO 8601 UTC timestamp of the last status change
#   .run_number      sequential counter per workflow (resets per workflow file)
#   .head_branch     branch that triggered the run
#   .head_sha        commit SHA that triggered the run
#   .html_url        URL to view the run in the GitHub UI

REPO="Kaalenco/n2-core-identity"
RETENTION_DAYS=10
CUTOFF=$(date -d "$RETENTION_DAYS days ago" --utc +%Y-%m-%dT%H:%M:%SZ)

# Optional: count runs first
gh api --paginate "/repos/$REPO/actions/runs?per_page=100" --jq '.workflow_runs[].id' | wc -l

# Delete failed runs older than 10 days, and ALL codeql.yml runs older than 10 days
gh api --paginate "/repos/$REPO/actions/runs?per_page=100" \
  --jq '.workflow_runs[] | select(.created_at < "'"$CUTOFF"'") | select(.conclusion == "failure" or .path == ".github/workflows/codeql.yml") | .id' \
| while read -r RUN_ID; do
    echo "Deleting run $RUN_ID"
    gh api -X DELETE "/repos/$REPO/actions/runs/$RUN_ID" >/dev/null
  done
