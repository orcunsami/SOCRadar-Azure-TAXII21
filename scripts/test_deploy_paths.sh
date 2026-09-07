#!/usr/bin/env bash
# Regression test for EXP-AZURE-0198, ported to TAXII 2.1.
#
# A wrong WorkspaceName with the parameters left at their defaults used to
# half-install: ARM treats a condition:false resource as a satisfied dependency,
# so depending on the workspace resource stopped nothing. The storage account,
# the identity and the App Service Plan were created and only then did the
# deployment fail with ResourceNotFound.
#
# It shipped that way because every greenfield E2E ran DeployNewWorkspace=true.
# The path a customer actually clicks -- the defaults -- was never run.
#
# Five paths, each asserting a different thing:
#   A  missing workspace, defaults        -> fails, resource group stays EMPTY
#   B  same RG, DeployNewWorkspace=true   -> succeeds, guard SKIPPED
#   C  existing onboarded workspace, cross-RG -> both guards SUCCEED and resolve
#   D  redeploy against the workspace B made   -> the guard does not block it
#   E  cross-RG onto a workspace with no Microsoft Sentinel -> rejected, nothing created
#
# C matters most: the guard is skipped on the greenfield path, so a wrong
# api-version or field name inside it leaves every test green and fails only at
# a customer. That is exactly how reference(...).name shipped in Incidents.
#
# B and D also assert the package, and not with the provisioning state: the
# function count, the shape of the package pointer, and -- for B -- that the app
# still answers after a restart. With the pointer left at "1" the package is
# staged where the host cannot reload it, so ARM keeps reporting a function
# while the host answers 503 from the next restart onwards. Asserting Succeeded,
# or even the count alone, would pass that.
#
# TAXII credentials are NOT needed -- the deployment only writes them to app
# settings. Pass placeholders so no real secret enters a test run.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$REPO_ROOT/azuredeploy.json"

LOCATION="${TEST_LOCATION:-northeurope}"
KEEP="${KEEP_RESOURCES:-false}"
# An already-onboarded workspace for path C. Created here when not supplied.
EXT_RG="${TEST_ONBOARDED_RG:-}"
EXT_WS="${TEST_ONBOARDED_WS:-}"

SFX=$(python3 -c "import uuid;print(uuid.uuid4().hex[:4])")
RG_APP="rg-taxii-paths-$SFX"
RG_C="rg-taxii-paths-c-$SFX"
RG_BARE="rg-taxii-paths-bare-$SFX"
RG_E="rg-taxii-paths-e-$SFX"
WS="ws-taxii-paths-$SFX"
MISSING="ws-does-not-exist-$SFX"
OWNED_EXT=false

fails=0
row() {  # row <name> <PASS|FAIL> <detail>
    printf '%-38s %-5s %s\n' "$1" "$2" "$3"
    [ "$2" = PASS ] || fails=$((fails + 1))
}

cleanup() {
    if [ "$KEEP" = true ]; then
        echo "KEEP_RESOURCES=true, leaving the resource groups in place"
        return
    fi
    for rg in "$RG_APP" "$RG_C" "$RG_BARE" "$RG_E"; do
        az group delete -n "$rg" --yes --no-wait -o none 2>/dev/null
    done
    if [ "$OWNED_EXT" = true ]; then
        az group delete -n "$EXT_RG" --yes --no-wait -o none 2>/dev/null
        echo "cleanup: delete queued for $RG_APP, $RG_C, $RG_BARE, $RG_E and $EXT_RG"
    else
        echo "cleanup: delete queued for $RG_APP, $RG_C, $RG_BARE and $RG_E"
        echo "         $EXT_RG was supplied, not deleting it"
    fi
}
trap cleanup EXIT

deploy() {  # deploy <rg> <name> <extra params...>
    local rg="$1" name="$2"; shift 2
    az deployment group create -g "$rg" -n "$name" --template-file "$TEMPLATE" \
        --parameters ApiRoots="feedstaxii" CollectionIds="placeholder" \
                     TAXIIUsername="placeholder" TAXIIPassword="placeholder" \
                     WorkspaceLocation="$LOCATION" "$@" \
        -o none 2>/dev/null
}

# The only signal that separates a loaded package from a Running empty app.
# Read through ARM rather than `az functionapp function list`: that command
# returned an empty string right after a deployment while the ARM call already
# reported 1, and an empty read is indistinguishable from a real zero.
function_count() {  # function_count <rg>
    local rg="$1" app sub
    app=$(az functionapp list -g "$rg" --query "[0].name" -o tsv 2>/dev/null)
    [ -n "$app" ] || { echo "no-app"; return; }
    sub=$(az account show --query id -o tsv 2>/dev/null)
    for _ in $(seq 1 6); do
        n=$(az rest --method get --url \
            "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$app/functions?api-version=2023-12-01" \
            --query "length(value)" -o tsv 2>/dev/null)
        case "$n" in ''|*[!0-9]*) ;; *) [ "$n" -ge 1 ] && { echo "$n"; return; };; esac
        python3 -c "import time;time.sleep(15)"
    done
    echo "${n:-0}"
}

# The count is ARM metadata and it lies on its own: on a rig app whose pointer
# was left at "1", ARM kept reporting 1 function while the host answered 503 for
# three and a half minutes. The pointer's SHAPE is the second reading -- the
# package has to sit in the function-releases container the app reloads from.
# The value itself is never printed: it carries a SAS token.
pointer_shape() {  # pointer_shape <rg>
    local rg="$1" app v
    app=$(az functionapp list -g "$rg" --query "[0].name" -o tsv 2>/dev/null)
    [ -n "$app" ] || { echo "no-app"; return; }
    v=$(az functionapp config appsettings list -g "$rg" -n "$app" \
        --query "[?name=='WEBSITE_RUN_FROM_PACKAGE'].value" -o tsv 2>/dev/null)
    case "$v" in
        *function-releases*) echo blob ;;
        1) echo one ;;
        "") echo missing ;;
        *) echo other ;;
    esac
}

# Orcun's failure was "you said it works and it broke". A package the host
# cannot reload survives until the first restart, so restart it here.
survives_restart() {  # survives_restart <rg>
    local rg="$1" app code
    app=$(az functionapp list -g "$rg" --query "[0].name" -o tsv 2>/dev/null)
    [ -n "$app" ] || { echo "no-app"; return; }
    az functionapp restart -g "$rg" -n "$app" -o none 2>/dev/null
    for _ in $(seq 1 12); do
        python3 -c "import time;time.sleep(15)"
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$app.azurewebsites.net/")
        [ "$code" = 200 ] && { echo 200; return; }
    done
    echo "${code:-no-answer}"
}

# Which step failed, read from the deployment rather than inferred from its state.
# On the first run of this script a Function App failure was reported as
# "the guard blocks a workspace that exists", which sent the diagnosis the wrong way.
failed_step() {  # failed_step <rg> <deployment>
    az deployment operation group list -g "$1" -n "$2" \
        --query "[?properties.provisioningState=='Failed'].properties.targetResource.resourceName" \
        -o tsv 2>/dev/null | sort -u | tr '\n' ' '
}

echo "[1/6] Creating resource groups ..."
for rg in "$RG_APP" "$RG_C" "$RG_BARE" "$RG_E"; do
    az group create -n "$rg" -l "$LOCATION" -o none
done
if [ -z "$EXT_RG" ] || [ -z "$EXT_WS" ]; then
    EXT_RG="rg-taxii-paths-ws-$SFX"
    EXT_WS="ws-taxii-onboarded-$SFX"
    OWNED_EXT=true
    az group create -n "$EXT_RG" -l "$LOCATION" -o none
    az monitor log-analytics workspace create -g "$EXT_RG" -n "$EXT_WS" -l "$LOCATION" --retention-time 30 -o none
    # Microsoft Sentinel on top of it, which is what the second guard asserts.
    WSID=$(az monitor log-analytics workspace show -g "$EXT_RG" -n "$EXT_WS" --query id -o tsv)
    az rest --method PUT -o none \
        --uri "https://management.azure.com${WSID}/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2023-02-01" \
        --body '{"properties":{}}' 2>/dev/null
fi
echo "      path C workspace: $EXT_RG / $EXT_WS"

# --- A: the customer's typo, defaults left alone --------------------------------------
echo "[2/6] Path A: missing workspace with the parameters at their defaults ..."
deploy "$RG_APP" path-a WorkspaceName="$MISSING"
state=$(az deployment group show -g "$RG_APP" -n path-a --query properties.provisioningState -o tsv 2>/dev/null)
left=$(az resource list -g "$RG_APP" --query "length(@)" -o tsv 2>/dev/null)
blamed=$(failed_step "$RG_APP" path-a | grep -c 'precheck-workspace-exists')

[ "$state" = Failed ] \
    && row "A deployment fails" PASS "$state" \
    || row "A deployment fails" FAIL "expected Failed, got '${state:-<unreadable>}'"
# The assertion that used to read 3, including a billable App Service Plan.
[ "${left:-x}" = 0 ] \
    && row "A leaves nothing behind" PASS "0 resources" \
    || row "A leaves nothing behind" FAIL "expected 0, found '${left:-<unreadable>}' - the guard did not hold"
[ "${blamed:-0}" -ge 1 ] \
    && row "A blames the precheck" PASS "precheck-workspace-exists" \
    || row "A blames the precheck" FAIL "the precheck was not the failing step"

# --- B: greenfield, the mode every earlier E2E used ------------------------------------
echo "[3/6] Path B: DeployNewWorkspace=true in the same resource group ..."
deploy "$RG_APP" path-b WorkspaceName="$WS" DeployNewWorkspace=true
state=$(az deployment group show -g "$RG_APP" -n path-b --query properties.provisioningState -o tsv 2>/dev/null)
steps=$(failed_step "$RG_APP" path-b)
[ "$state" = Succeeded ] \
    && row "B greenfield succeeds" PASS "$state" \
    || row "B greenfield succeeds" FAIL "expected Succeeded, got '${state:-<unreadable>}', failed step(s): ${steps:-<none>}"
guard_ran=$(az deployment operation group list -g "$RG_APP" -n path-b \
    --query "[?properties.targetResource.resourceName=='precheck-workspace-exists'] | length(@)" -o tsv 2>/dev/null)
[ "${guard_ran:-x}" = 0 ] \
    && row "B skips the precheck" PASS "condition false" \
    || row "B skips the precheck" FAIL "the precheck ran against a workspace being created"
n=$(function_count "$RG_APP")
[ "${n:-0}" -ge 1 ] 2>/dev/null \
    && row "B indexes the function" PASS "$n function(s)" \
    || row "B indexes the function" FAIL "function count was '${n:-<unreadable>}' with the pointer '$(pointer_shape "$RG_APP")' - a blob pointer here means the package arrived and only the indexing was slower than the script's window"
s=$(pointer_shape "$RG_APP")
[ "$s" = blob ] \
    && row "B stores the package where the app reloads it" PASS "pointer is a function-releases blob" \
    || row "B stores the package where the app reloads it" FAIL "pointer shape is '$s' - with 'one' the host answers 503 after a restart while ARM still reports a function"
s=$(survives_restart "$RG_APP")
[ "$s" = 200 ] \
    && row "B still serves after a restart" PASS "host answered 200" \
    || row "B still serves after a restart" FAIL "host answered '$s' - the install works until the first restart"

# --- C: both guards' success branch, which B never exercises ---------------------------
echo "[4/6] Path C: existing onboarded workspace in another resource group ..."
deploy "$RG_C" path-c WorkspaceName="$EXT_WS" WorkspaceResourceGroup="$EXT_RG"
state=$(az deployment group show -g "$RG_C" -n path-c --query properties.provisioningState -o tsv 2>/dev/null)
steps=$(failed_step "$RG_C" path-c)
[ "$state" = Succeeded ] \
    && row "C cross-RG deploy succeeds" PASS "$state" \
    || row "C cross-RG deploy succeeds" FAIL "expected Succeeded, got '${state:-<unreadable>}', failed step(s): ${steps:-<none>}"
for g in precheck-workspace-exists precheck-external-workspace; do
    gs=$(az deployment operation group list -g "$RG_C" -n path-c \
        --query "[?properties.targetResource.resourceName=='$g'].properties.provisioningState" -o tsv 2>/dev/null)
    [ "$gs" = Succeeded ] \
        && row "C $g succeeds" PASS "$gs" \
        || row "C $g succeeds" FAIL "expected Succeeded, got '${gs:-<unreadable>}' - reference() may name a field or api-version that does not exist"
done
# Reading the outputs proves reference() resolved real values rather than empty strings.
ws_id=$(az deployment group show -g "$RG_C" -n precheck-workspace-exists \
    --query "properties.outputs.workspaceId.value" -o tsv 2>/dev/null)
printf '%s' "${ws_id:-}" | grep -Eq '^[0-9a-f]{8}-' \
    && row "C precheck resolves customerId" PASS "looks like a guid" \
    || row "C precheck resolves customerId" FAIL "output was '${ws_id:-<empty>}'"
onb=$(az deployment group show -g "$RG_C" -n precheck-external-workspace \
    --query "properties.outputs.sentinelOnboarded.value" -o tsv 2>/dev/null)
printf '%s' "${onb:-}" | grep -q 'onboardingStates/default' \
    && row "C precheck resolves onboardingState" PASS "resource id" \
    || row "C precheck resolves onboardingState" FAIL "output was '${onb:-<empty>}'"

# --- D: the guard must not block a second, correct deployment --------------------------
echo "[5/6] Path D: redeploying against the workspace B created ..."
deploy "$RG_APP" path-d WorkspaceName="$WS" DeployNewWorkspace=false
state=$(az deployment group show -g "$RG_APP" -n path-d --query properties.provisioningState -o tsv 2>/dev/null)
steps=$(failed_step "$RG_APP" path-d)
[ "$state" = Succeeded ] \
    && row "D redeploy succeeds" PASS "$state" \
    || row "D redeploy succeeds" FAIL "expected Succeeded, got '${state:-<unreadable>}', failed step(s): ${steps:-<none>}"
n=$(function_count "$RG_APP")
[ "${n:-0}" -ge 1 ] 2>/dev/null \
    && row "D still has the package after redeploy" PASS "$n function(s)" \
    || row "D still has the package after redeploy" FAIL "function count was '${n:-<unreadable>}' - the site PUT reset WEBSITE_RUN_FROM_PACKAGE and the push did not re-run"
s=$(pointer_shape "$RG_APP")
[ "$s" = blob ] \
    && row "D still stores the package where the app reloads it" PASS "pointer is a function-releases blob" \
    || row "D still stores the package where the app reloads it" FAIL "pointer shape is '$s' after the redeploy"

# --- E: cross-RG onto a workspace with no Microsoft Sentinel ---------------------------
echo "[6/6] Path E: cross-RG onto a workspace with no Microsoft Sentinel ..."
az monitor log-analytics workspace create -g "$RG_BARE" -n "ws-bare-$SFX" -l "$LOCATION" --retention-time 30 -o none 2>/dev/null
deploy "$RG_E" path-e WorkspaceName="ws-bare-$SFX" WorkspaceResourceGroup="$RG_BARE"
state=$(az deployment group show -g "$RG_E" -n path-e --query properties.provisioningState -o tsv 2>/dev/null)
left=$(az resource list -g "$RG_E" --query "length(@)" -o tsv 2>/dev/null)
blamed=$(failed_step "$RG_E" path-e | grep -c 'precheck-external-workspace')
[ "$state" = Failed ] \
    && row "E rejects un-onboarded workspace" PASS "$state" \
    || row "E rejects un-onboarded workspace" FAIL "expected Failed, got '${state:-<unreadable>}' - a green deploy here means a dead integration"
[ "${left:-x}" = 0 ] \
    && row "E leaves nothing behind" PASS "0 resources" \
    || row "E leaves nothing behind" FAIL "expected 0, found '${left:-<unreadable>}'"
[ "${blamed:-0}" -ge 1 ] \
    && row "E blames the external precheck" PASS "precheck-external-workspace" \
    || row "E blames the external precheck" FAIL "a different step failed - the rejection may be for the wrong reason"

echo
if [ "$fails" -eq 0 ]; then
    echo "All five deployment paths behaved as asserted."
else
    echo "$fails assertion(s) failed."
fi
exit $((fails == 0 ? 0 : 1))
