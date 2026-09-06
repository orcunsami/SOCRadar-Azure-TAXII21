#!/bin/bash
# SOCRadar TAXII 2.1 Function App - Azure Test Script
# Triggers the import twice and checks TI indicators, the checkpoint and the audit table.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ENV_SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}"
ENV_RESOURCE_GROUP="${RESOURCE_GROUP:-}"
ENV_WORKSPACE_NAME="${WORKSPACE_NAME:-}"
ENV_WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-}"
ENV_ENABLE_AUDIT_LOGGING="${ENABLE_AUDIT_LOGGING:-}"

if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config"
fi

SUBSCRIPTION_ID="${ENV_SUBSCRIPTION_ID:-${SUBSCRIPTION_ID:-}}"
RESOURCE_GROUP="${ENV_RESOURCE_GROUP:-${RESOURCE_GROUP:-}}"
WORKSPACE_NAME="${ENV_WORKSPACE_NAME:-${WORKSPACE_NAME:-}}"
WORKSPACE_RESOURCE_GROUP="${ENV_WORKSPACE_RESOURCE_GROUP:-${WORKSPACE_RESOURCE_GROUP:-}}"
ENABLE_AUDIT_LOGGING="${ENV_ENABLE_AUDIT_LOGGING:-${ENABLE_AUDIT_LOGGING:-true}}"
WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-$RESOURCE_GROUP}"
AUDIT_WAIT_SECONDS="${AUDIT_WAIT_SECONDS:-900}"
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ]; then
    echo "ERROR: set SUBSCRIPTION_ID, RESOURCE_GROUP and WORKSPACE_NAME (scripts/test.config or environment)"
    exit 1
fi

FUNC_APP_NAME=$(az functionapp list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'socradar-taxii-')].name" -o tsv 2>/dev/null | head -1)
if [ -z "$FUNC_APP_NAME" ]; then
    echo "ERROR: No Function App found. Run portal_setup.sh first."
    exit 1
fi

# Stop the Function App on exit (cost control).
cleanup() {
    echo ""
    echo "=== CLEANUP: Stopping Function App ==="
    az functionapp stop --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" 2>/dev/null || true
    FA_STATE=$(az functionapp show --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" --query "state" -o tsv 2>/dev/null || echo "UNKNOWN")
    echo "  $FUNC_APP_NAME state: $FA_STATE"
}
trap cleanup EXIT

WS_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$WORKSPACE_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME"
TI_QUERY_URL="https://management.azure.com${WS_ID}/providers/Microsoft.SecurityInsights/threatIntelligence/main/queryIndicators?api-version=2025-09-01"

master_key() {
    az functionapp keys list --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" --query "masterKey" -o tsv 2>/dev/null
}

trigger_function() {
    local key
    key=$(master_key)
    [ -z "$key" ] && { echo "ERROR: Could not get master key"; return 1; }
    curl -s -o /dev/null -w "%{http_code}" \
        -X POST "https://${FUNC_APP_NAME}.azurewebsites.net/admin/functions/socradar_taxii_import" \
        -H "x-functions-key: $key" -H "Content-Type: application/json" -d '{}'
}

wait_for_completion() {
    local MAX_WAIT=${1:-300} INTERVAL=10 ELAPSED=0 key
    key=$(master_key)
    echo "  Waiting for function to complete (max ${MAX_WAIT}s)..."
    sleep 15
    ELAPSED=15
    while [ $ELAPSED -lt $MAX_WAIT ]; do
        printf "\r  [%3ds] Running...   " $ELAPSED
        local STATUS
        STATUS=$(curl -s -H "x-functions-key: $key" \
            "https://${FUNC_APP_NAME}.azurewebsites.net/admin/functions/socradar_taxii_import/status" 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('is_running', 'unknown'))" 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "False" ] || [ "$STATUS" = "false" ]; then
            echo ""; echo "  Completed (${ELAPSED}s)"; return 0
        fi
        sleep $INTERVAL
        ELAPSED=$((ELAPSED + INTERVAL))
    done
    echo ""; echo "  Timeout after ${MAX_WAIT}s (function may still be running)"
}

# Every SOCRadar TAXII indicator in the workspace, one externalId per line,
# with the revoked flag as a second column. The query pages with a skipToken.
ti_rows() {
    local body='{"sources":["SOCRadar TAXII"],"pageSize":1000,"includeDisabled":true}' page token
    while :; do
        page=$(az rest --method POST --url "$TI_QUERY_URL" --body "$body" -o json 2>/dev/null) || break
        printf '%s' "$page" | python3 -c 'import sys, json
for v in json.load(sys.stdin).get("value", []):
    p = v.get("properties", {})
    print("%s\t%s" % (p.get("externalId", ""), "revoked" if p.get("revoked") else "active"))'
        token=$(printf '%s' "$page" | python3 -c 'import sys, json, urllib.parse
n = json.load(sys.stdin).get("nextLink", "")
q = urllib.parse.parse_qs(urllib.parse.urlsplit(n).query) if n else {}
print((q.get("$skipToken") or q.get("skipToken") or [""])[0])')
        [ -z "$token" ] && break
        body=$(printf '%s' "$token" | python3 -c 'import sys, json; print(json.dumps({"sources":["SOCRadar TAXII"],"pageSize":1000,"includeDisabled":True,"skipToken":sys.stdin.read().strip()}))')
    done
}
ti_count() { ti_rows | wc -l | tr -d ' '; }
ti_revoked_count() { ti_rows | awk -F'\t' '$2=="revoked"' | wc -l | tr -d ' '; }

echo "=== SOCRadar TAXII 2.1 Function App - Test ==="
echo ""
echo "Config:"
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Workspace:      $WORKSPACE_NAME ($WORKSPACE_RESOURCE_GROUP)"
echo "  Function App:   $FUNC_APP_NAME"
echo ""

ACCOUNT=$(az account show --query "user.name" -o tsv 2>/dev/null)
if [ -z "$ACCOUNT" ]; then
    echo "Not logged in. Run: az login --use-device-code"
    exit 1
fi
echo "Logged in as: $ACCOUNT"
echo ""

echo "=== Pre-Test: Checking Resources ==="
FA_STATE=$(az functionapp show --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" --query "state" -o tsv 2>/dev/null || echo "NOT_FOUND")
if [ "$FA_STATE" != "Running" ]; then
    echo "  Starting Function App..."
    az functionapp start --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" 2>/dev/null
    sleep 10
fi
echo "  Function App: $FUNC_APP_NAME ($FA_STATE)"
FA_PRINCIPAL=$(az identity show --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" -n "SOCRadar-TAXII-MI" --query principalId -o tsv 2>/dev/null || echo "")
if [ -n "$FA_PRINCIPAL" ]; then
    SENTINEL_ROLE=$(az role assignment list --assignee "$FA_PRINCIPAL" --scope "$WS_ID" \
        --query "[?roleDefinitionName=='Microsoft Sentinel Contributor'].roleDefinitionName" -o tsv 2>/dev/null)
    [ -n "$SENTINEL_ROLE" ] && echo "  Sentinel Contributor: OK" || echo "  Sentinel Contributor: MISSING (may fail)"
fi
COUNT_BEFORE=$(ti_count)
echo "  TI Indicators before: $COUNT_BEFORE"
echo ""

echo "=== Test 1: Trigger Import ==="
HTTP_CODE=$(trigger_function)
echo "  Triggered (HTTP $HTTP_CODE)"
wait_for_completion 300
echo ""

echo "=== Test 2: Checking TI Indicators ==="
sleep 5
COUNT_AFTER=$(ti_count)
NEW_INDICATORS=$((COUNT_AFTER - COUNT_BEFORE))
echo "  TI Indicators before: $COUNT_BEFORE"
echo "  TI Indicators after:  $COUNT_AFTER"
echo "  New indicators:       $NEW_INDICATORS"
echo "  Flagged revoked:      $(ti_revoked_count)"
echo ""

echo "=== Test 3: Checking Storage Checkpoint ==="
STORAGE_ACCOUNT=$(az storage account list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].name" -o tsv 2>/dev/null | head -1)
CHECKPOINTS=0
if [ -n "$STORAGE_ACCOUNT" ]; then
    echo "  Storage Account: $STORAGE_ACCOUNT"
    CHECKPOINTS=$(az storage entity query --table-name "TAXIIState" --account-name "$STORAGE_ACCOUNT" --auth-mode login --query "items | length(@)" -o tsv 2>/dev/null || echo "0")
    echo "  Checkpoint entries: $CHECKPOINTS"
    az storage entity query --table-name "TAXIIState" --account-name "$STORAGE_ACCOUNT" --auth-mode login \
        --query "items[].{Collection:PartitionKey, AddedAfter:AddedAfter, Cursor:Cursor, Pages:PagesFetched, LastRun:LastRun}" -o table 2>/dev/null || true
else
    echo "  Storage Account: NOT FOUND"
fi
echo ""

echo "=== Test 4: Second Run (Checkpoint Test) ==="
HTTP_CODE=$(trigger_function)
echo "  Triggered (HTTP $HTTP_CODE)"
wait_for_completion 300
COUNT_FINAL=$(ti_count)
echo "  Indicators after 2nd run: $COUNT_FINAL (delta: $((COUNT_FINAL - COUNT_AFTER)))"
# Dedup is proven by no STIX id appearing twice after two runs.
DUP_IDS=$(ti_rows | cut -f1 | sort | uniq -d | wc -l | tr -d ' ')
echo "  STIX ids present more than once: $DUP_IDS"
[ "$DUP_IDS" = "0" ] && CHECKPOINT_OK="PASS" || CHECKPOINT_OK="FAIL"
echo ""

AUDIT_OK="SKIPPED"
if [ "$ENABLE_AUDIT_LOGGING" = "true" ]; then
    echo "=== Test 5: Audit Table (up to ${AUDIT_WAIT_SECONDS}s, a new table ingests slowly) ==="
    CUSTOMER_ID=$(az monitor log-analytics workspace show --subscription "$SUBSCRIPTION_ID" -g "$WORKSPACE_RESOURCE_GROUP" -n "$WORKSPACE_NAME" --query customerId -o tsv 2>/dev/null)
    ELAPSED=0; ROWS=""
    while [ $ELAPSED -lt "$AUDIT_WAIT_SECONDS" ]; do
        ROWS=$(az monitor log-analytics query -w "$CUSTOMER_ID" \
            --analytics-query "SOCRadar_TAXII_Audit_CL | where TimeGenerated > ago(2h) | order by TimeGenerated desc | take 5 | project TimeGenerated, ApiRoot, Status, IndicatorsCreated, IndicatorsRevoked, IndicatorsSkipped, IndicatorsFailed, PagesFetched" \
            -o tsv 2>/dev/null || true)
        [ -n "$ROWS" ] && break
        printf "\r  [%3ds] waiting for audit rows..." $ELAPSED
        sleep 30; ELAPSED=$((ELAPSED + 30))
    done
    echo ""
    if [ -n "$ROWS" ]; then
        echo "$ROWS" | sed 's/^/  /'
        echo "$ROWS" | grep -q "Success" && AUDIT_OK="PASS" || AUDIT_OK="WARN (no Success row)"
    else
        AUDIT_OK="WARN (no rows yet)"
    fi
    echo ""
fi

echo "==========================================="
echo "            TEST SUMMARY"
echo "==========================================="
echo ""
echo "| Test                  | Result          |"
echo "|-----------------------|-----------------|"
[ "$NEW_INDICATORS" -gt 0 ] 2>/dev/null && echo "| Import Run            | PASS ($NEW_INDICATORS new) |" || echo "| Import Run            | WARN (0 new)    |"
[ "$CHECKPOINTS" -gt 0 ] 2>/dev/null && echo "| Storage Checkpoint    | PASS            |" || echo "| Storage Checkpoint    | FAIL            |"
echo "| Checkpoint Dedup      | $CHECKPOINT_OK            |"
echo "| Audit Table           | $AUDIT_OK |"
echo ""
echo "Indicators: $COUNT_BEFORE -> $COUNT_AFTER -> $COUNT_FINAL"
[ "$CHECKPOINT_OK" = "FAIL" ] && exit 1
echo "Function App will be STOPPED by cleanup trap."
