#!/bin/bash
# SOCRadar TAXII 2.1 Function App - Azure FAST RESET
# Deletes everything without confirmation - for dev/test only!
# Usage: ./portal_reset.sh [workspace_name]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ENV_SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}"
ENV_RESOURCE_GROUP="${RESOURCE_GROUP:-}"
ENV_WORKSPACE_NAME="${WORKSPACE_NAME:-}"
ENV_WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-}"

if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config"
fi
if [ -n "$1" ]; then
    WORKSPACE_NAME="$1"
fi

SUBSCRIPTION_ID="${ENV_SUBSCRIPTION_ID:-${SUBSCRIPTION_ID:-}}"
RESOURCE_GROUP="${ENV_RESOURCE_GROUP:-${RESOURCE_GROUP:-}}"
WORKSPACE_NAME="${ENV_WORKSPACE_NAME:-${WORKSPACE_NAME:-}}"
WORKSPACE_RESOURCE_GROUP="${ENV_WORKSPACE_RESOURCE_GROUP:-${WORKSPACE_RESOURCE_GROUP:-}}"
WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-$RESOURCE_GROUP}"
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ]; then
    echo "ERROR: set SUBSCRIPTION_ID, RESOURCE_GROUP and WORKSPACE_NAME (scripts/test.config or environment)"
    exit 1
fi
case "$RESOURCE_GROUP$WORKSPACE_RESOURCE_GROUP" in *prod*|*Prod*|*PROD*) echo "ERROR: refusing to reset a resource group named like production"; exit 1;; esac
AZ="az --subscription $SUBSCRIPTION_ID"

echo "=== TAXII FUNCTION APP - FAST RESET ==="
echo "  Workspace:       $WORKSPACE_NAME ($WORKSPACE_RESOURCE_GROUP)"
echo "  Resource Group:  $RESOURCE_GROUP"
echo ""

echo "[1/8] Deleting Function App..."
for fa in $($AZ functionapp list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'socradar-taxii-')].name" -o tsv 2>/dev/null); do
    $AZ functionapp stop --name "$fa" -g "$RESOURCE_GROUP" 2>/dev/null || true
    $AZ functionapp delete --name "$fa" -g "$RESOURCE_GROUP" --keep-empty-plan 2>/dev/null || true
    echo "  Deleted: $fa"
done
$AZ appservice plan delete --name "SOCRadar-TAXII-Plan" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
for ds in $($AZ resource list -g "$RESOURCE_GROUP" --resource-type "Microsoft.Resources/deploymentScripts" --query "[?starts_with(name, 'triggerFirstRun-')].id" -o tsv 2>/dev/null); do
    $AZ resource delete --ids "$ds" 2>/dev/null || true
done
echo "  Done"

echo "[2/8] Deleting Role Assignments + Identity..."
MI_PRINCIPAL=$($AZ identity show -g "$RESOURCE_GROUP" -n "SOCRadar-TAXII-MI" --query principalId -o tsv 2>/dev/null || echo "")
if [ -n "$MI_PRINCIPAL" ]; then
    for id in $(az role assignment list --all --assignee "$MI_PRINCIPAL" --query "[].id" -o tsv 2>/dev/null); do
        az role assignment delete --ids "$id" 2>/dev/null || true
    done
    $AZ identity delete -g "$RESOURCE_GROUP" -n "SOCRadar-TAXII-MI" 2>/dev/null || true
fi
echo "  Done"

echo "[3/8] Deleting Storage Account..."
for sa in $($AZ storage account list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].name" -o tsv 2>/dev/null); do
    $AZ storage account delete --name "$sa" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
    echo "  Deleted: $sa"
done
echo "  Done"

echo "[4/8] Deleting Audit Infrastructure (DCR, DCE, table)..."
$AZ monitor data-collection rule delete --name "SOCRadar-TAXII-Audit-DCR" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
$AZ monitor data-collection endpoint delete --name "SOCRadar-TAXII-DCE" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
$AZ monitor log-analytics workspace table delete --workspace-name "$WORKSPACE_NAME" -g "$WORKSPACE_RESOURCE_GROUP" --name "SOCRadar_TAXII_Audit_CL" --yes 2>/dev/null || true
echo "  Done"

echo "[5/8] Deleting Application Insights + Workbook..."
for ai in $($AZ resource list -g "$RESOURCE_GROUP" --resource-type "Microsoft.Insights/components" --query "[?starts_with(name, 'socradar-taxii-ai-')].id" -o tsv 2>/dev/null); do
    $AZ resource delete --ids "$ai" 2>/dev/null || true
done
for wb in $($AZ resource list -g "$RESOURCE_GROUP" --resource-type "Microsoft.Insights/workbooks" --query "[].id" -o tsv 2>/dev/null); do
    $AZ resource delete --ids "$wb" 2>/dev/null || true
done
echo "  Done"

# TI indicators are not deleted one by one: the indicators API DELETE returns
# 200 for an indicator that came in through the upload API and leaves it in
# place (measured 6 Sep 2026). They go with the workspace.
echo "[6/8] TI indicators: removed with the workspace"

if [ "$WORKSPACE_RESOURCE_GROUP" = "$RESOURCE_GROUP" ]; then
    echo "[7/8] Deleting Sentinel + Workspace..."
    az rest --method DELETE \
        --url "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" 2>/dev/null || true
    $AZ resource delete --ids "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($WORKSPACE_NAME)" 2>/dev/null || true
    $AZ monitor log-analytics workspace delete --workspace-name "$WORKSPACE_NAME" -g "$RESOURCE_GROUP" --force --yes 2>/dev/null || true
    echo "  Done"
else
    echo "[7/8] Workspace lives in $WORKSPACE_RESOURCE_GROUP: left in place"
fi

echo "[8/8] Remaining resources in $RESOURCE_GROUP:"
$AZ resource list -g "$RESOURCE_GROUP" --query "[].{name:name, type:type}" -o table 2>/dev/null || true
echo ""
echo "=== RESET COMPLETE ==="
echo "NOTE: Use a NEW workspace name next time (soft-delete keeps the old one for 14 days)"
