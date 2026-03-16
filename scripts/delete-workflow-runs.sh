# delete-workflow-runs.sh
#
# Deletes workflow runs according to these rules:
#   - All runs older than LOG_RETENTION_DAYS are removed (logs have expired, no audit value)
#   - Runs older than RETENTION_DAYS are removed, except successful dotnet.yml runs
#     (kept as a release audit trail until logs expire)
#
# Environment variables:
#   REPO                GitHub repository in "owner/repo" format (required)
#   RETENTION_DAYS      Days to retain non-publish runs (optional, default: 10)
#   LOG_RETENTION_DAYS  Days after which all runs are removed regardless of conclusion (optional, default: 90)
#   GH_TOKEN            Fine-grained PAT with Actions: Read and Write permission (required).
#                       Must NOT be the auto-provided GITHUB_TOKEN: that token is scoped to the
#                       current workflow run and GitHub will return 403 when it tries to delete
#                       runs created by other workflows or tokens. A PAT acts as a user-level
#                       credential and can delete any run in the repository.
#                       The gh CLI resolves credentials in order: GH_TOKEN → GITHUB_TOKEN →
#                       stored login, so setting GH_TOKEN here ensures the PAT is used.
#
# Usage:
#   REPO="owner/repo" bash scripts/delete-workflow-runs.sh
#
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

REPO="${REPO:?Environment variable REPO is required (format: owner/repo)}"
RETENTION_DAYS="${RETENTION_DAYS:-10}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
CUTOFF=$(date -d "$RETENTION_DAYS days ago" --utc +%Y-%m-%dT%H:%M:%SZ)
LOG_CUTOFF=$(date -d "$LOG_RETENTION_DAYS days ago" --utc +%Y-%m-%dT%H:%M:%SZ)

echo "Cleaning up runs in $REPO"
echo "  Regular cutoff : older than $RETENTION_DAYS days ($CUTOFF)"
echo "  Log expiry cutoff: older than $LOG_RETENTION_DAYS days ($LOG_CUTOFF)"

# Count runs first
TOTAL=$(gh api --paginate "/repos/$REPO/actions/runs?per_page=100" --jq '.workflow_runs[].id' | wc -l)
echo "Total runs found: $TOTAL"

# Delete runs matching either condition:
#   1. Older than LOG_RETENTION_DAYS (logs expired — always remove)
#   2. Older than RETENTION_DAYS and not a successful dotnet.yml run
gh api --paginate "/repos/$REPO/actions/runs?per_page=100" \
  --jq '.workflow_runs[] |
    select(
      .created_at < "'"$LOG_CUTOFF"'" or
      (.created_at < "'"$CUTOFF"'" and ((.path == ".github/workflows/dotnet.yml" and .conclusion == "success") | not))
    ) | .id' \
| while read -r RUN_ID; do
    echo "Deleting run $RUN_ID"
    gh api -X DELETE "/repos/$REPO/actions/runs/$RUN_ID" >/dev/null
  done
