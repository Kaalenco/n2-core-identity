#!/usr/bin/env bash
# verify-workflow-params.sh
#
# Verifies that required workflow parameters are set and reports defaults for
# optional ones. Exits with code 1 if any required parameter is missing,
# causing the workflow job to fail and gating all subsequent steps.
#
# Usage:
#   bash scripts/verify-workflow-params.sh REQUIRED_VAR [OPTIONAL_VAR=default] ...
#
# Arguments:
#   REQUIRED_VAR        Environment variable that must be non-empty.
#   OPTIONAL_VAR=value  Environment variable with a fallback default (informational only).
#
# Example (in a workflow step):
#   - name: Verify workflow parameters
#     env:
#       CSPROJ_PATH: ${{ vars.CSPROJ_PATH }}
#       PACKAGE_N2:  ${{ secrets.PACKAGE_N2 }}
#     run: bash scripts/verify-workflow-params.sh CSPROJ_PATH PACKAGE_N2 RETENTION_DAYS=10

set -uo pipefail

ERRORS=0

echo "Verifying workflow parameters..."
echo ""

for PARAM in "$@"; do
  if [[ "$PARAM" == *"="* ]]; then
    # Optional parameter with a default value
    NAME="${PARAM%%=*}"
    DEFAULT="${PARAM#*=}"
    VALUE="${!NAME:-}"
    if [[ -z "$VALUE" ]]; then
      echo "  [default]  $NAME is not set — will use default: $DEFAULT"
    else
      echo "  [ok]       $NAME is set"
    fi
  else
    # Required parameter
    VALUE="${!PARAM:-}"
    if [[ -z "$VALUE" ]]; then
      echo "  [missing]  $PARAM is required but not set"
      ERRORS=$((ERRORS + 1))
    else
      echo "  [ok]       $PARAM is set"
    fi
  fi
done

echo ""

if [[ $ERRORS -gt 0 ]]; then
  echo "Verification failed: $ERRORS required parameter(s) are missing."
  echo "Set the missing values under: Settings → Secrets and variables → Actions."
  exit 1
fi

echo "All parameters verified successfully."
