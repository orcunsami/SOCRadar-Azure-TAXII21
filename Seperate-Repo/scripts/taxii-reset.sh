#!/bin/bash
# SOCRadar TAXII Azure FAST RESET
# Deletes EVERYTHING without confirmation - for dev/test only!
# Usage: ./taxii-reset.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load config
if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config" 2>/dev/null
fi

# Validate
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ]; then
    echo "ERROR: Missing config. Copy test.config.example to test.config and fill values."
    exit 1
fi

LOGIC_APP_NAME="${PLAYBOOK_NAME:-SOCRadar-TAXII-Import}"
WORKSPACE_NAME="${WORKSPACE_NAME:-}"

echo "=== TAXII FAST RESET ==="
echo "  Resource Group: $RESOURCE_GROUP"
echo "  Logic App: $LOGIC_APP_NAME"
echo ""

# 1. Disable Logic App (stop burning money)
echo "[1/8] Disabling Logic App..."
az logic workflow update --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --state Disabled -o none 2>/dev/null || true
echo "  Done"

# 2. Delete Role Assignments
echo "[2/8] Deleting Role Assignments..."
for id in $(az role assignment list --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" --query "[?principalType=='ServicePrincipal'].id" -o tsv 2>/dev/null); do
    az role assignment delete --ids "$id" 2>/dev/null || true
done
# Storage-scoped role assignments
for sa in $(az storage account list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].id" -o tsv 2>/dev/null); do
    for id in $(az role assignment list --scope "$sa" --query "[?principalType=='ServicePrincipal'].id" -o tsv 2>/dev/null); do
        az role assignment delete --ids "$id" 2>/dev/null || true
    done
done
echo "  Done"

# 3. Delete Logic App
echo "[3/8] Deleting Logic App..."
az logic workflow delete --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
echo "  Done"

# 4. Delete Function App + App Service Plan + App Insights
echo "[4/8] Deleting Function App..."
for func in $(az functionapp list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'func-socradar-taxii')].name" -o tsv 2>/dev/null); do
    az functionapp delete --name "$func" -g "$RESOURCE_GROUP" 2>/dev/null || true
done
for asp in $(az appservice plan list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'asp-')].name" -o tsv 2>/dev/null); do
    az appservice plan delete --name "$asp" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
done
for ai in $(az monitor app-insights component show -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'ai-')].name" -o tsv 2>/dev/null); do
    az monitor app-insights component delete --app "$ai" -g "$RESOURCE_GROUP" 2>/dev/null || true
done
echo "  Done"

# 5. Delete Storage Account
echo "[5/8] Deleting Storage Accounts..."
for sa in $(az storage account list -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].name" -o tsv 2>/dev/null); do
    az storage account delete --name "$sa" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
done
echo "  Done"

# 6. Delete DCRs and DCE (audit infrastructure)
echo "[6/8] Deleting Audit Infrastructure..."
az monitor data-collection rule delete --name "SOCRadar-TAXII-Import-DCR" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
az monitor data-collection endpoint delete --name "SOCRadar-TAXII-DCE" -g "$RESOURCE_GROUP" --yes 2>/dev/null || true
echo "  Done"

# 7. Delete Custom Tables
echo "[7/8] Deleting Custom Tables..."
if [ -n "$WORKSPACE_NAME" ]; then
    az monitor log-analytics workspace table delete --workspace-name "$WORKSPACE_NAME" -g "$RESOURCE_GROUP" --name "SOCRadar_TAXII_Import_CL" --yes 2>/dev/null || true
fi
echo "  Done"

# 8. Delete TI Indicators with SOCRadar TAXII source
echo "[8/8] Deleting TI Indicators..."
if [ -n "$WORKSPACE_NAME" ]; then
    SENTINEL_URL="https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/providers/Microsoft.SecurityInsights"
    TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv 2>/dev/null || echo "")
    if [ -n "$TOKEN" ]; then
        # Query indicators with SOCRadar TAXII source
        INDICATORS=$(az rest --method POST \
            --url "$SENTINEL_URL/threatIntelligence/main/queryIndicators?api-version=2024-03-01" \
            --body '{"keywords":"SOCRadar TAXII","pageSize":100}' \
            --query "value[].name" -o tsv 2>/dev/null || echo "")

        count=0
        for name in $INDICATORS; do
            [ -z "$name" ] && continue
            az rest --method DELETE \
                --url "$SENTINEL_URL/threatIntelligence/main/indicators/$name?api-version=2024-03-01" \
                2>/dev/null || true
            count=$((count + 1))
        done
        echo "  Deleted $count TI indicators"
    else
        echo "  Skipped (no access token)"
    fi
else
    echo "  Skipped (no WORKSPACE_NAME)"
fi

echo ""
echo "=== TAXII RESET COMPLETE ==="
echo ""
ALL_RESOURCES=$(az resource list -g "$RESOURCE_GROUP" --query "length(@)" -o tsv 2>/dev/null || echo "0")
echo "  Resources in RG: $ALL_RESOURCES"

if [ "$ALL_RESOURCES" = "0" ]; then
    echo ""
    echo "  RG is CLEAN - ready for fresh deploy!"
else
    echo ""
    echo "  Remaining resources:"
    az resource list -g "$RESOURCE_GROUP" --query "[].{name:name, type:type}" -o table 2>/dev/null
fi
