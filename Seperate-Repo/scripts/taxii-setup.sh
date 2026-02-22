#!/bin/bash
# SOCRadar TAXII Azure Setup
# Deploys Logic App + Function App (disabled) + verifies roles
# Usage: ./taxii-setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE_PATH="$SCRIPT_DIR/../playbooks/SOCRadar-TAXII-Import/azuredeploy.json"
INFRA_TEMPLATE_PATH="$SCRIPT_DIR/../playbooks/SOCRadar-TAXII-Infrastructure/azuredeploy.json"

# Load config
if [ -f "$SCRIPT_DIR/test.config" ]; then
    source "$SCRIPT_DIR/test.config" 2>/dev/null
fi

# Load secrets
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env" 2>/dev/null
fi

# Validate
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ] || [ -z "$TAXII_SERVER_URL" ] || [ -z "$COLLECTION_ID" ]; then
    echo "ERROR: Missing config. Copy test.config.example to test.config and fill values."
    echo "  Required: SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME, TAXII_SERVER_URL, COLLECTION_ID"
    exit 1
fi

if [ -z "$TAXII_PASSWORD" ]; then
    echo "ERROR: TAXII_PASSWORD not set. Create .env with TAXII_PASSWORD=your-api-key"
    exit 1
fi

if [ ! -f "$TEMPLATE_PATH" ]; then
    echo "ERROR: Template not found: $TEMPLATE_PATH"
    exit 1
fi

LOCATION="${LOCATION:-northeurope}"
POLLING="${POLLING_INTERVAL_MINUTES:-15}"
CONFIDENCE="${MIN_CONFIDENCE:-0}"
MAX_PAGES="${MAX_PAGES_PER_RUN:-100}"
AUDIT="${ENABLE_AUDIT_LOGGING:-false}"
LOGIC_APP_NAME="${PLAYBOOK_NAME:-SOCRadar-TAXII-Import}"

echo "=== TAXII DEPLOY ==="
echo "  Template: $TEMPLATE_PATH"
echo "  Workspace: $WORKSPACE_NAME"
echo "  Location: $LOCATION"
echo "  TAXII URL: $TAXII_SERVER_URL"
echo "  Collection: $COLLECTION_ID"
echo "  Polling: ${POLLING}m"
echo "  Min Confidence: $CONFIDENCE"
echo ""

# 1. Deploy Infrastructure (if audit enabled)
if [ "$AUDIT" = "true" ] && [ -f "$INFRA_TEMPLATE_PATH" ]; then
    echo "[1/4] Deploying Infrastructure template..."
    az deployment group create \
        --resource-group "$RESOURCE_GROUP" \
        --template-file "$INFRA_TEMPLATE_PATH" \
        --parameters \
            WorkspaceName="$WORKSPACE_NAME" \
        -o table
    echo ""
else
    echo "[1/4] Skipping Infrastructure (audit logging disabled)"
    echo ""
fi

# 2. Deploy Import Logic App
echo "[2/4] Deploying TAXII Import template..."
az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "$TEMPLATE_PATH" \
    --parameters \
        TAXIIServerUrl="$TAXII_SERVER_URL" \
        CollectionId="$COLLECTION_ID" \
        TAXIIUsername="${TAXII_USERNAME:-$COLLECTION_ID}" \
        TAXIIPassword="$TAXII_PASSWORD" \
        WorkspaceName="$WORKSPACE_NAME" \
        PollingIntervalMinutes="$POLLING" \
        MinConfidence="$CONFIDENCE" \
        MaxPagesPerRun="$MAX_PAGES" \
        EnableAuditLogging="$AUDIT" \
    -o table

echo ""
echo "[3/4] Verifying role assignments..."
PRINCIPAL=$(az logic workflow show --name "$LOGIC_APP_NAME" -g "$RESOURCE_GROUP" --query "identity.principalId" -o tsv 2>/dev/null || echo "")
echo "  Logic App principal: $PRINCIPAL"

ROLE_COUNT=$(az role assignment list --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" --query "[?principalType=='ServicePrincipal'] | length(@)" -o tsv 2>/dev/null || echo "0")
echo "  Role assignments: $ROLE_COUNT"

echo ""
echo "[4/4] Waiting 90s for role propagation..."
sleep 90

echo ""
echo "=== DEPLOY COMPLETE ==="
echo ""
echo "Logic App is DISABLED. Use taxii-test.sh to enable, test, and disable."
echo ""
echo "Resources deployed:"
az resource list -g "$RESOURCE_GROUP" --query "[].{name:name, type:type}" -o table 2>/dev/null
