#!/bin/bash
# SOCRadar TAXII Test Script
# Enables Logic App, waits for run, verifies indicators, DISABLES
# Usage: ./taxii-test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load config
if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config" 2>/dev/null
fi

# Validate
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ]; then
    echo "ERROR: Missing config."
    exit 1
fi

POLLING="${POLLING_INTERVAL_MINUTES:-15}"
LOGIC_APP_NAME="${PLAYBOOK_NAME:-SOCRadar-TAXII-Import}"
SENTINEL_URL="https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights"
PASSED=0
FAILED=0
TOTAL=0

pass() {
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  PASS: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
    echo "  FAIL: $1"
}

# CRITICAL: Always disable Logic App on exit
cleanup() {
    echo ""
    echo "=== DISABLING Logic App ==="
    az logic workflow update --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --state Disabled -o none 2>/dev/null || true
    STATE=$(az logic workflow show --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --query "state" -o tsv 2>/dev/null || echo "UNKNOWN")
    echo "  Logic App state: $STATE"
}
trap cleanup EXIT

echo "=== TAXII TEST ==="
echo "  Workspace: $WORKSPACE_NAME"
echo "  Logic App: $LOGIC_APP_NAME"
echo "  Polling: ${POLLING}m"
echo ""

# 1. Check Logic App exists
echo "[1/7] Checking Logic App..."
APP_STATE=$(az logic workflow show --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --query "state" -o tsv 2>/dev/null || echo "MISSING")
if [ "$APP_STATE" != "MISSING" ]; then pass "Logic App exists ($APP_STATE)"; else fail "Logic App MISSING"; fi

# 2. Check Function App exists
echo ""
echo "[2/7] Checking Function App..."
FUNC_COUNT=$(az functionapp list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'func-socradar-taxii')] | length(@)" -o tsv 2>/dev/null || echo "0")
if [ "$FUNC_COUNT" -ge 1 ]; then pass "Function App exists"; else fail "Function App MISSING"; fi

# 3. Check role assignments
echo ""
echo "[3/7] Checking Role Assignments..."
ROLE_COUNT=$(az role assignment list --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" --query "[?principalType=='ServicePrincipal'] | length(@)" -o tsv 2>/dev/null || echo "0")
if [ "$ROLE_COUNT" -ge 1 ]; then pass "Role assignments: $ROLE_COUNT (>=1)"; else fail "Role assignments: $ROLE_COUNT (<1)"; fi

# 4. Count pre-existing indicators
echo ""
echo "[4/7] Counting existing SOCRadar TAXII indicators..."
PRE_COUNT=$(az rest --method POST \
    --url "$SENTINEL_URL/threatIntelligence/main/queryIndicators?api-version=2024-03-01" \
    --body '{"keywords":"SOCRadar TAXII","pageSize":100}' \
    --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
echo "  Pre-test indicator count: $PRE_COUNT"

# 5. Enable and wait for first run
echo ""
echo "[5/7] Enabling Logic App and waiting for first run..."
az logic workflow update --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --state Enabled -o none

WAIT_SECONDS=$(( (POLLING * 60) + 120 ))
echo "  Waiting ${WAIT_SECONDS}s for first run (polling=${POLLING}m + 2min buffer)..."
sleep "$WAIT_SECONDS"

# 6. Check results
echo ""
echo "[6/7] Checking results..."

# Check run history
LAST_STATUS=$(az logic workflow run list --workflow-name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --query "[0].status" -o tsv 2>/dev/null || echo "UNKNOWN")
echo "  Last run status: $LAST_STATUS"

if [ "$LAST_STATUS" = "Succeeded" ]; then
    pass "Logic App run succeeded"
elif [ "$LAST_STATUS" = "Running" ]; then
    echo "  Still running, waiting 60 more seconds..."
    sleep 60
    LAST_STATUS=$(az logic workflow run list --workflow-name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --query "[0].status" -o tsv 2>/dev/null || echo "UNKNOWN")
    if [ "$LAST_STATUS" = "Succeeded" ]; then pass "Logic App run succeeded (delayed)"; else fail "Logic App run: $LAST_STATUS"; fi
else
    fail "Logic App run: $LAST_STATUS"
fi

# Count post-test indicators
POST_COUNT=$(az rest --method POST \
    --url "$SENTINEL_URL/threatIntelligence/main/queryIndicators?api-version=2024-03-01" \
    --body '{"keywords":"SOCRadar TAXII","pageSize":100}' \
    --query "value | length(@)" -o tsv 2>/dev/null || echo "0")
echo "  Post-test indicator count: $POST_COUNT (was: $PRE_COUNT)"

NEW_INDICATORS=$((POST_COUNT - PRE_COUNT))
if [ "$NEW_INDICATORS" -gt 0 ]; then
    pass "New indicators created: $NEW_INDICATORS"
elif [ "$POST_COUNT" -gt 0 ]; then
    pass "Indicators exist: $POST_COUNT (may be upserts)"
else
    fail "No indicators found after test"
fi

# 7. Logic App will be disabled by trap handler
echo ""
echo "[7/7] Disabling Logic App (trap handler)..."

# Summary
echo ""
echo "======================================="
echo "  TAXII TEST RESULTS"
echo "  Passed: $PASSED / $TOTAL"
echo "  Failed: $FAILED / $TOTAL"
echo "======================================="
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "  SOME TESTS FAILED!"
    exit 1
else
    echo "  ALL TESTS PASSED!"
fi
