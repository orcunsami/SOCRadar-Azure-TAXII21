#!/bin/bash
# SOCRadar TAXII 2.1 Function App - Azure Setup Script
# Deploys azuredeploy.json and verifies the Function App, roles and checkpoint table.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/.."

ENV_SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-}"
ENV_RESOURCE_GROUP="${RESOURCE_GROUP:-}"
ENV_WORKSPACE_NAME="${WORKSPACE_NAME:-}"
ENV_WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-}"
ENV_LOCATION="${LOCATION:-}"
ENV_DEPLOY_NEW_WORKSPACE="${DEPLOY_NEW_WORKSPACE:-}"
ENV_API_ROOTS="${API_ROOTS:-}"
ENV_COLLECTION_IDS="${COLLECTION_IDS:-}"
ENV_POLLING_INTERVAL_MINUTES="${POLLING_INTERVAL_MINUTES:-}"
ENV_INITIAL_LOOKBACK_HOURS="${INITIAL_LOOKBACK_HOURS:-}"
ENV_ENABLE_AUDIT_LOGGING="${ENABLE_AUDIT_LOGGING:-}"
ENV_PACKAGE_URI="${PACKAGE_URI:-}"
ENV_TAXII_USERNAME="${TAXII_USERNAME:-}"
ENV_TAXII_PASSWORD="${TAXII_PASSWORD:-}"
ENV_TAXII_PASSWORD_FILE="${TAXII_PASSWORD_FILE:-}"

# Load .env (TAXII credentials)
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env" 2>/dev/null
fi

# Load test.config (Azure resources)
if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config"
fi

SUBSCRIPTION_ID="${ENV_SUBSCRIPTION_ID:-${SUBSCRIPTION_ID:-}}"
RESOURCE_GROUP="${ENV_RESOURCE_GROUP:-${RESOURCE_GROUP:-}}"
WORKSPACE_NAME="${ENV_WORKSPACE_NAME:-${WORKSPACE_NAME:-}}"
WORKSPACE_RESOURCE_GROUP="${ENV_WORKSPACE_RESOURCE_GROUP:-${WORKSPACE_RESOURCE_GROUP:-}}"
LOCATION="${ENV_LOCATION:-${LOCATION:-westeurope}}"
DEPLOY_NEW_WORKSPACE="${ENV_DEPLOY_NEW_WORKSPACE:-${DEPLOY_NEW_WORKSPACE:-true}}"
API_ROOTS="${ENV_API_ROOTS:-${API_ROOTS:-}}"
COLLECTION_IDS="${ENV_COLLECTION_IDS:-${COLLECTION_IDS:-}}"
POLLING_INTERVAL_MINUTES="${ENV_POLLING_INTERVAL_MINUTES:-${POLLING_INTERVAL_MINUTES:-60}}"
INITIAL_LOOKBACK_HOURS="${ENV_INITIAL_LOOKBACK_HOURS:-${INITIAL_LOOKBACK_HOURS:-48}}"
ENABLE_AUDIT_LOGGING="${ENV_ENABLE_AUDIT_LOGGING:-${ENABLE_AUDIT_LOGGING:-true}}"
PACKAGE_URI="${ENV_PACKAGE_URI:-${PACKAGE_URI:-}}"
TAXII_USERNAME="${ENV_TAXII_USERNAME:-${TAXII_USERNAME:-}}"
TAXII_PASSWORD="${ENV_TAXII_PASSWORD:-${TAXII_PASSWORD:-}}"
TAXII_PASSWORD_FILE="${ENV_TAXII_PASSWORD_FILE:-${TAXII_PASSWORD_FILE:-}}"
WORKSPACE_RESOURCE_GROUP="${WORKSPACE_RESOURCE_GROUP:-$RESOURCE_GROUP}"

# The password can come from a file so it never sits on a command line.
if [ -z "$TAXII_PASSWORD" ] && [ -n "$TAXII_PASSWORD_FILE" ] && [ -f "$TAXII_PASSWORD_FILE" ]; then
    TAXII_PASSWORD="$(head -c 4096 "$TAXII_PASSWORD_FILE" | tr -d '\r\n')"
fi

if [ -z "$TAXII_USERNAME" ] || [ -z "$TAXII_PASSWORD" ]; then
    echo "ERROR: Missing TAXII_USERNAME / TAXII_PASSWORD (scripts/.env, or TAXII_PASSWORD_FILE)"
    exit 1
fi
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ]; then
    echo "ERROR: Missing SUBSCRIPTION_ID, RESOURCE_GROUP or WORKSPACE_NAME (scripts/test.config or environment)"
    exit 1
fi
if [ -z "$API_ROOTS" ] || [ -z "$COLLECTION_IDS" ]; then
    echo "ERROR: Missing API_ROOTS or COLLECTION_IDS"
    exit 1
fi
if [ "$WORKSPACE_RESOURCE_GROUP" != "$RESOURCE_GROUP" ] && [ "$DEPLOY_NEW_WORKSPACE" = "true" ]; then
    echo "NOTE: cross-RG deploy, DeployNewWorkspace is ignored; $WORKSPACE_NAME must exist in $WORKSPACE_RESOURCE_GROUP with Microsoft Sentinel enabled"
    DEPLOY_NEW_WORKSPACE="false"
fi

TEMPLATE="$REPO_ROOT/azuredeploy.json"
if [ ! -f "$TEMPLATE" ]; then
    echo "ERROR: Template not found: $TEMPLATE"
    exit 1
fi

echo "=== SOCRadar TAXII 2.1 Function App - Setup ==="
echo ""
echo "Configuration:"
echo "  Resource Group:     $RESOURCE_GROUP"
echo "  Workspace:          $WORKSPACE_NAME (in $WORKSPACE_RESOURCE_GROUP)"
echo "  Location:           $LOCATION"
echo "  API roots:          $API_ROOTS"
echo "  Collections:        $COLLECTION_IDS"
echo "  Polling:            $POLLING_INTERVAL_MINUTES min"
echo "  Lookback:           $INITIAL_LOOKBACK_HOURS h"
echo "  Audit Logging:      $ENABLE_AUDIT_LOGGING"
[ -n "$PACKAGE_URI" ] && echo "  Package:            custom (PackageUri override)"
echo ""

# Check login
ACCOUNT=$(az account show --query "user.name" -o tsv 2>/dev/null)
if [ -z "$ACCOUNT" ]; then
    echo "Not logged in. Run: az login --use-device-code"
    exit 1
fi
echo "Logged in as: $ACCOUNT"
echo ""

# Parameters go through a private file so the secret is not on the command line.
umask 077
PARAMS_FILE="$(mktemp)"
trap 'rm -f "$PARAMS_FILE"' EXIT
python3 - "$PARAMS_FILE" <<'PY'
import json, os, sys
def b(v): return str(v).lower() == "true"
p = {
    "WorkspaceName": os.environ["WORKSPACE_NAME"],
    "DeployNewWorkspace": b(os.environ["DEPLOY_NEW_WORKSPACE"]),
    "WorkspaceResourceGroup": os.environ["WORKSPACE_RESOURCE_GROUP"],
    "WorkspaceLocation": os.environ["LOCATION"],
    "ApiRoots": os.environ["API_ROOTS"],
    "CollectionIds": os.environ["COLLECTION_IDS"],
    "TAXIIUsername": os.environ["TAXII_USERNAME"],
    "TAXIIPassword": os.environ["TAXII_PASSWORD"],
    "PollingIntervalMinutes": int(os.environ["POLLING_INTERVAL_MINUTES"]),
    "InitialLookbackHours": int(os.environ["INITIAL_LOOKBACK_HOURS"]),
    "EnableAuditLogging": b(os.environ["ENABLE_AUDIT_LOGGING"]),
}
if os.environ.get("PACKAGE_URI"):
    p["PackageUri"] = os.environ["PACKAGE_URI"]
json.dump({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
           "contentVersion": "1.0.0.0",
           "parameters": {k: {"value": v} for k, v in p.items()}}, open(sys.argv[1], "w"))
PY
export WORKSPACE_NAME DEPLOY_NEW_WORKSPACE WORKSPACE_RESOURCE_GROUP LOCATION API_ROOTS COLLECTION_IDS \
       TAXII_USERNAME TAXII_PASSWORD POLLING_INTERVAL_MINUTES INITIAL_LOOKBACK_HOURS ENABLE_AUDIT_LOGGING PACKAGE_URI

# Step 1: Deploy ARM template
echo "=== Step 1: Deploying ARM Template ==="
az deployment group create \
    --subscription "$SUBSCRIPTION_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --name "azuredeploy" \
    --template-file "$TEMPLATE" \
    --parameters "@$PARAMS_FILE" \
    --query "{state:properties.provisioningState, duration:properties.duration}" -o table
rm -f "$PARAMS_FILE"

FUNC_APP_NAME=$(az deployment group show --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" -n "azuredeploy" \
    --query "properties.outputs.functionAppName.value" -o tsv 2>/dev/null)
if [ -z "$FUNC_APP_NAME" ]; then
    FUNC_APP_NAME=$(az functionapp list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'socradar-taxii-')].name" -o tsv 2>/dev/null | head -1)
fi
if [ -z "$FUNC_APP_NAME" ]; then
    echo "ERROR: Could not find Function App name"
    exit 1
fi
echo ""
echo "  Function App: $FUNC_APP_NAME"
echo ""

# Step 2: Verify Function App and that the package was indexed
echo "=== Step 2: Verifying Function App ==="
FA_STATE=$(az functionapp show --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP" --query "state" -o tsv 2>/dev/null || echo "NOT_FOUND")
echo "  State:        $FA_STATE"
FUNC_COUNT=""
for i in 1 2 3 4 5 6; do
    FUNC_COUNT=$(az functionapp function list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" -n "$FUNC_APP_NAME" --query "length(@)" -o tsv 2>/dev/null || echo "")
    [ "${FUNC_COUNT:-0}" -ge 1 ] 2>/dev/null && break
    sleep 20
done
if [ "${FUNC_COUNT:-0}" -ge 1 ] 2>/dev/null; then
    echo "  Functions:    $FUNC_COUNT indexed"
else
    echo "  Functions:    NONE indexed (package not readable? see scripts/build_package.py)"
    exit 1
fi
echo ""

# Step 3: Verify role assignments
echo "=== Step 3: Verifying Role Assignments ==="
FA_PRINCIPAL=$(az identity show --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" -n "SOCRadar-TAXII-MI" --query principalId -o tsv 2>/dev/null || echo "")
if [ -z "$FA_PRINCIPAL" ]; then
    echo "  ERROR: managed identity SOCRadar-TAXII-MI not found"; exit 1
fi
WS_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$WORKSPACE_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME"
SENTINEL_ROLE=$(az role assignment list --assignee "$FA_PRINCIPAL" --scope "$WS_ID" \
    --query "[?roleDefinitionName=='Microsoft Sentinel Contributor'].roleDefinitionName" -o tsv 2>/dev/null)
[ -n "$SENTINEL_ROLE" ] && echo "  Sentinel Contributor (workspace): OK" || { echo "  Sentinel Contributor (workspace): MISSING"; exit 1; }
# Without --all the list covers the subscription scope only and misses the
# storage-account-scoped assignment the template creates.
STORAGE_ROLE=$(az role assignment list --assignee "$FA_PRINCIPAL" --all \
    --query "[?roleDefinitionName=='Storage Table Data Contributor'].roleDefinitionName" -o tsv 2>/dev/null)
[ -n "$STORAGE_ROLE" ] && echo "  Storage Table Data Contributor: OK" || { echo "  Storage Table Data Contributor: MISSING"; exit 1; }
if [ "$ENABLE_AUDIT_LOGGING" = "true" ]; then
    DCR_ROLE=$(az role assignment list --assignee "$FA_PRINCIPAL" --all \
        --query "[?roleDefinitionName=='Monitoring Metrics Publisher'].roleDefinitionName" -o tsv 2>/dev/null)
    [ -n "$DCR_ROLE" ] && echo "  Monitoring Metrics Publisher (DCR): OK" || { echo "  Monitoring Metrics Publisher (DCR): MISSING"; exit 1; }
    TABLE_RG=$(az monitor log-analytics workspace table show --subscription "$SUBSCRIPTION_ID" -g "$WORKSPACE_RESOURCE_GROUP" --workspace-name "$WORKSPACE_NAME" -n "SOCRadar_TAXII_Audit_CL" --query "provisioningState" -o tsv 2>/dev/null || echo "")
    [ -n "$TABLE_RG" ] && echo "  Audit table in $WORKSPACE_RESOURCE_GROUP: $TABLE_RG" || { echo "  Audit table: MISSING in $WORKSPACE_RESOURCE_GROUP"; exit 1; }
fi
echo ""

# Step 4: Verify Storage
echo "=== Step 4: Verifying Storage ==="
STORAGE_ACCOUNT=$(az storage account list --subscription "$SUBSCRIPTION_ID" -g "$RESOURCE_GROUP" --query "[?starts_with(name, 'srtaxii')].name" -o tsv 2>/dev/null | head -1)
if [ -n "$STORAGE_ACCOUNT" ]; then
    echo "  Storage Account: $STORAGE_ACCOUNT"
    TABLE_EXISTS=$(az storage table list --account-name "$STORAGE_ACCOUNT" --auth-mode login --query "[?name=='TAXIIState'].name" -o tsv 2>/dev/null || echo "")
    [ -n "$TABLE_EXISTS" ] && echo "  TAXIIState Table: OK" || { echo "  TAXIIState Table: MISSING (the template creates it; the deployment did not finish)"; exit 1; }
else
    echo "  ERROR: No storage account found"; exit 1
fi
echo ""

echo "=== Setup Complete ==="
echo ""
echo "  Function App:    $FUNC_APP_NAME ($FA_STATE)"
echo "  Storage Account: $STORAGE_ACCOUNT"
echo "  Workspace:       $WORKSPACE_NAME ($WORKSPACE_RESOURCE_GROUP)"
echo ""
echo "The deployment script already triggered the first run. Next: ./portal_test.sh"
