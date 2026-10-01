#!/bin/bash
# SOCRadar TAXII 2.1 Function App - Azure Test Script
# Triggers the import and checks the indicators in Log Analytics, the checkpoint and the audit table.
# Indicators are counted with a Log Analytics query, not the Sentinel queryIndicators API: that API
# is capped per page and shows the current state, so a product that re-uploads everything still passes.

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

# The admin status endpoint returns {} on this host, so completion is read from
# Application Insights instead: the invocation recorded after the trigger time, whether it
# succeeded, and its "Step 3: Import complete" line (the run reached its end with no failed
# indicator and no failed or partial collection). A run that failed, or whose end was never
# seen, is not a run: the dedup check would compare two reads of a product that did nothing.
# Ingestion lags one to three minutes; the wait covers that.
AI_APP=$(az resource list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --resource-type Microsoft.Insights/components --query "[?starts_with(name, 'socradar-taxii-ai-')].name" -o tsv 2>/dev/null | head -1)
ai_row() {   # first row of an Application Insights query, tab separated; empty when none
    az monitor app-insights query --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --app "$AI_APP" \
        --analytics-query "$1" -o json 2>/dev/null | python3 -c 'import sys, json
rows = json.load(sys.stdin)["tables"][0]["rows"]
print("\t".join(str(c) for c in rows[0]) if rows else "")' 2>/dev/null || true
}
step3_clean() {   # the Step 3 line: no failed indicator, every collection succeeded, none partial
    printf '%s' "$1" | python3 -c 'import re, sys
m = re.search(r"(\d+) failed, \d+ revoked, \d+ pages, (\d+)/(\d+) collections succeeded, (\d+) partial", sys.stdin.read())
sys.exit(0 if m and m.group(1) == "0" and m.group(2) == m.group(3) != "0" and m.group(4) == "0" else 1)'
}
wait_for_completion() {
    local MAX_WAIT=${1:-420} INTERVAL=20 ELAPSED=0 T0="$2" row ok step3
    echo "  Waiting for an invocation after $T0 (max ${MAX_WAIT}s)..."
    while [ $ELAPSED -lt $MAX_WAIT ]; do
        sleep $INTERVAL
        ELAPSED=$((ELAPSED + INTERVAL))
        row=$(ai_row "requests | where name == 'socradar_taxii_import' and timestamp > datetime($T0) | order by timestamp asc | take 1 | project timestamp, success, duration=round(duration)")
        if [ -n "$row" ]; then
            ok=$(printf '%s' "$row" | cut -f2)
            if [ "$ok" != "True" ]; then
                echo ""; echo "  Invocation: $row (timestamp, success, ms): it did not succeed"
                return 1
            fi
            step3=$(ai_row "traces | where timestamp > datetime($T0) and message has 'Step 3: Import complete' | order by timestamp asc | take 1 | project message")
            if [ -n "$step3" ]; then
                echo ""; echo "  Invocation: $row (timestamp, success, ms)"
                echo "  ${step3:0:200}"
                step3_clean "$step3" && return 0
                echo "  The run reported failed indicators or a failed/partial collection"
                return 1
            fi
        fi
        printf "\r  [%3ds] waiting...   " $ELAPSED
    done
    echo ""; echo "  No successful invocation with a Step 3 line seen within ${MAX_WAIT}s"
    return 1
}

CUSTOMER_ID=$(az monitor log-analytics workspace show --subscription "$SUBSCRIPTION_ID" -g "$WORKSPACE_RESOURCE_GROUP" -n "$WORKSPACE_NAME" --query customerId -o tsv 2>/dev/null)
STORAGE_ACCOUNT=$(az storage account list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].name" -o tsv 2>/dev/null | head -1)

# "<rows> <distinct ids>" of every SOCRadar TAXII indicator in Log Analytics, or UNREADABLE.
# The table is an append log: a re-uploaded indicator adds a row but not an id, so the rows
# are what shows a re-upload. A missing table is zero rows; any other failure is UNREADABLE,
# never zero (zero would make a broken read look like a clean run).
ti_stats() {
    local out err rc=0
    err=$(mktemp)
    out=$(az monitor log-analytics query -w "$CUSTOMER_ID" --analytics-query \
        "ThreatIntelIndicators | where SourceSystem == 'SOCRadar TAXII' | summarize Rows=count() by Id | summarize Rows=sum(Rows), Ids=count() | project s=strcat(tostring(coalesce(Rows, 0)), ' ', tostring(Ids))" \
        --query "[0].s" -o tsv 2>"$err") || rc=$?
    if [ $rc -ne 0 ] && grep -qi "failed to resolve table" "$err"; then
        out="0 0"; rc=0
    fi
    rm -f "$err"
    if [ $rc -eq 0 ] && printf '%s' "$out" | grep -Eq '^[0-9]+ [0-9]+$'; then
        printf '%s' "$out"
    else
        printf 'UNREADABLE'
    fi
}
# Log Analytics ingests with a lag: read until two reads a minute apart agree. A lag longer than
# that minute can still settle early and read a late row as a change; that fails the check
# (the safe direction), as does a live feed that gains an indicator between two runs.
ti_settled() {
    local prev="" cur n=0
    while [ $n -lt "${LAW_SETTLE_READS:-20}" ]; do
        cur=$(ti_stats)
        if [ "$cur" != "UNREADABLE" ] && [ "$cur" = "$prev" ]; then
            printf '%s' "$cur"; return 0
        fi
        prev="$cur"; sleep 60; n=$((n + 1))
    done
    printf '%s' "${cur:-UNREADABLE}"
    [ "$cur" = "UNREADABLE" ] || printf ' UNSETTLED'
}
# Checkpoint rows that still hold a cursor: a collection the last run paused on.
open_cursors() {
    [ -n "$STORAGE_ACCOUNT" ] || return 0   # prints nothing: the caller reads that as unreadable
    az storage entity query --table-name "TAXIIState" --account-name "$STORAGE_ACCOUNT" --auth-mode key \
        --query "items[?Cursor!=''] | length(@)" -o tsv 2>/dev/null || true
}
# trigger + wait; non-zero when the run was not seen (an unseen run proves nothing).
run_import() {
    local t0 code
    t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    code=$(trigger_function) || code="no-key"
    echo "  Triggered (HTTP $code)"
    case "$code" in 200|202) ;; *) return 1 ;; esac
    wait_for_completion 420 "$t0"
}

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
echo "  Reading the indicators already in Log Analytics (settles over two reads a minute apart)..."
LAW_BEFORE=$(ti_settled)
case "$LAW_BEFORE" in UNREADABLE*|*UNSETTLED) echo "ERROR: no stable baseline from Log Analytics ($LAW_BEFORE)"; exit 1 ;; esac
echo "  Log Analytics before (rows ids): $LAW_BEFORE"
echo ""

echo "=== Test 1: Trigger Import ==="
RUN1_SEEN="yes"; run_import || RUN1_SEEN="no"
echo ""

echo "=== Test 2: Checking TI Indicators (Log Analytics, distinct STIX ids) ==="
LAW_AFTER=$(ti_settled)
case "$LAW_AFTER" in UNREADABLE*|*UNSETTLED) NEW_INDICATORS="unreadable" ;; *) NEW_INDICATORS=$(( ${LAW_AFTER#* } - ${LAW_BEFORE#* } )) ;; esac
echo "  Log Analytics before (rows ids): $LAW_BEFORE"
echo "  Log Analytics after  (rows ids): $LAW_AFTER"
echo "  New distinct indicators:         $NEW_INDICATORS"
echo ""

echo "=== Test 3: Checking Storage Checkpoint ==="
CHECKPOINTS=0
if [ -n "$STORAGE_ACCOUNT" ]; then
    echo "  Storage Account: $STORAGE_ACCOUNT"
    CHECKPOINTS=$(az storage entity query --table-name "TAXIIState" --account-name "$STORAGE_ACCOUNT" --auth-mode key --query "items | length(@)" -o tsv 2>/dev/null || echo "0")
    echo "  Checkpoint entries: $CHECKPOINTS"
    az storage entity query --table-name "TAXIIState" --account-name "$STORAGE_ACCOUNT" --auth-mode key \
        --query "items[].{Collection:PartitionKey, AddedAfter:AddedAfter, Cursor:Cursor, Pages:PagesFetched, LastRun:LastRun}" -o table 2>/dev/null || true
else
    echo "  Storage Account: NOT FOUND"
fi
echo ""

echo "=== Test 4: Checkpoint Dedup (two more runs must load nothing) ==="
# A run that paused on its time budget (the default 48 hour lookback can) leaves a cursor and
# legitimately loads more on the next run. Drain those first; the dedup assert only means
# something once the collection is caught up.
DRAIN=0; OPEN=$(open_cursors)
while printf '%s' "$OPEN" | grep -Eq '^[1-9][0-9]*$' && [ $DRAIN -lt "${DRAIN_MAX:-6}" ]; do
    DRAIN=$((DRAIN + 1)); echo "  Collection not caught up, catch-up run $DRAIN"
    run_import || break
    OPEN=$(open_cursors)
done
CHECKPOINT_OK="FAIL (could not run the dedup check)"
if ! printf '%s' "$OPEN" | grep -Eq '^[0-9]+$'; then
    CHECKPOINT_OK="FAIL (checkpoint table unreadable)"
    echo "  $CHECKPOINT_OK"
elif [ "$OPEN" != "0" ]; then
    CHECKPOINT_OK="SKIPPED (collection not caught up after $DRAIN catch-up runs)"
    echo "  $CHECKPOINT_OK"
elif [ "$RUN1_SEEN" != "yes" ] && [ $DRAIN -eq 0 ]; then
    echo "  The first run was not seen, nothing to compare against"
else
    BASE=$(ti_settled)
    echo "  Log Analytics baseline (rows ids): $BASE"
    case "$BASE" in
        UNREADABLE*|*UNSETTLED) CHECKPOINT_OK="FAIL (Log Analytics unreadable)" ;;
        0\ *) CHECKPOINT_OK="FAIL (no indicator rows in Log Analytics, nothing to dedup against)" ;;
        *)
            CHECKPOINT_OK="PASS"
            for n in 2 3; do
                if ! run_import; then CHECKPOINT_OK="FAIL (run $n was not seen)"; break; fi
                NOW=$(ti_settled)
                echo "  After run $n (rows ids): $NOW"
                if [ "$NOW" != "$BASE" ]; then CHECKPOINT_OK="FAIL (run $n changed $BASE to $NOW)"; break; fi
            done ;;
    esac
fi
echo "  Checkpoint dedup: $CHECKPOINT_OK"
echo ""

AUDIT_OK="SKIPPED"
if [ "$ENABLE_AUDIT_LOGGING" = "true" ]; then
    echo "=== Test 5: Audit Table (up to ${AUDIT_WAIT_SECONDS}s, a new table ingests slowly) ==="
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
[ "$RUN1_SEEN" = "yes" ] && [ "$NEW_INDICATORS" -gt 0 ] 2>/dev/null && echo "| Import Run            | PASS ($NEW_INDICATORS new) |" || echo "| Import Run            | WARN (run not seen or 0 new) |"
[ "$CHECKPOINTS" -gt 0 ] 2>/dev/null && echo "| Storage Checkpoint    | PASS            |" || echo "| Storage Checkpoint    | FAIL            |"
echo "| Checkpoint Dedup      | $CHECKPOINT_OK |"
echo "| Audit Table           | $AUDIT_OK |"
echo ""
echo "Log Analytics (rows ids): $LAW_BEFORE -> $LAW_AFTER"
case "$CHECKPOINT_OK" in FAIL*) exit 1 ;; esac
echo "Function App will be STOPPED by cleanup trap."
