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
#   A  missing workspace, defaults (DeployNewWorkspace=false) -> fails, resource group stays EMPTY
#   B  same RG, DeployNewWorkspace=true (opt-in create) -> succeeds, guard SKIPPED
#   C  existing onboarded workspace, cross-RG -> both guards SUCCEED and resolve
#   D  redeploy at the defaults against the workspace B made -> the guard does not block it, nothing is sent to it
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
# The deployment checks the TAXII username and password against the server (a 401
# fails it), so B, C, D and E need credentials the server accepts. Required:
#   TEST_TAXII_USERNAME  TEST_TAXII_PASSWORD  TEST_API_ROOT  TEST_COLLECTION_ID
# They travel in 0600 parameter files, never on the az command line.
#   K  existing workspace, a password the server rejects -> Failed in the script, the banner text says so
#   F  what B's first window left in the workspace -> audit rows all Success, indicators landed,
#      a host restart after the first import does not resend it
# F waits up to 25 minutes (ingestion lags); TEST_FIRST_RUN_WAIT and TEST_POLL (seconds) shorten it.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEMPLATE="$REPO_ROOT/azuredeploy.json"

LOCATION="${TEST_LOCATION:-northeurope}"
KEEP="${KEEP_RESOURCES:-false}"
TAXII_USER="${TEST_TAXII_USERNAME:-}"
TAXII_PASS="${TEST_TAXII_PASSWORD:-}"
API_ROOT="${TEST_API_ROOT:-}"
COLLECTION_ID="${TEST_COLLECTION_ID:-}"
if [ -z "$TAXII_USER" ] || [ -z "$TAXII_PASS" ] || [ -z "$API_ROOT" ] || [ -z "$COLLECTION_ID" ]; then
    echo "ERROR: set TEST_TAXII_USERNAME, TEST_TAXII_PASSWORD, TEST_API_ROOT and TEST_COLLECTION_ID: the deployment rejects credentials the server does not accept, so placeholders no longer deploy"
    exit 1
fi
# An already-onboarded workspace for path C. Created here when not supplied.
EXT_RG="${TEST_ONBOARDED_RG:-}"
EXT_WS="${TEST_ONBOARDED_WS:-}"

SFX=$(python3 -c "import uuid;print(uuid.uuid4().hex[:4])")
RG_APP="rg-taxii-paths-$SFX"
RG_C="rg-taxii-paths-c-$SFX"
RG_BARE="rg-taxii-paths-bare-$SFX"
RG_E="rg-taxii-paths-e-$SFX"
RG_K="rg-taxii-paths-k-$SFX"
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
    rm -f "$CRED_FILE" "$DEAD_FILE"
    for rg in "$RG_APP" "$RG_C" "$RG_BARE" "$RG_E" "$RG_K"; do
        az group delete -n "$rg" --yes --no-wait -o none 2>/dev/null
    done
    if [ "$OWNED_EXT" = true ]; then
        az group delete -n "$EXT_RG" --yes --no-wait -o none 2>/dev/null
        echo "cleanup: delete queued for $RG_APP, $RG_C, $RG_BARE, $RG_E, $RG_K and $EXT_RG"
    else
        echo "cleanup: delete queued for $RG_APP, $RG_C, $RG_BARE, $RG_E and $RG_K"
        echo "         $EXT_RG was supplied, not deleting it"
    fi
}
CRED_FILE=""; DEAD_FILE=""
trap cleanup EXIT

# The credentials go in 0600 files, not on the az command line (ps shows argv).
umask 077
CRED_FILE=$(mktemp)
DEAD_FILE=$(mktemp)
mkparams() {  # mkparams <username> <password> <file>
    TU="$1" TP="$2" python3 -c '
import json, os
print(json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                  "contentVersion": "1.0.0.0",
                  "parameters": {"TAXIIUsername": {"value": os.environ["TU"]},
                                 "TAXIIPassword": {"value": os.environ["TP"]}}}))' > "$3"
}
mkparams "$TAXII_USER" "$TAXII_PASS" "$CRED_FILE"
mkparams "$TAXII_USER" "not-the-password-$SFX" "$DEAD_FILE"

deploy() {  # deploy <rg> <name> <extra params...>
    local rg="$1" name="$2"; shift 2
    az deployment group create -g "$rg" -n "$name" --template-file "$TEMPLATE" \
        --parameters @"${PARAM_FILE:-$CRED_FILE}" ApiRoots="$API_ROOT" CollectionIds="$COLLECTION_ID" \
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

echo "[1/8] Creating resource groups ..."
for rg in "$RG_APP" "$RG_C" "$RG_BARE" "$RG_E" "$RG_K"; do
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
echo "[2/8] Path A: missing workspace with DeployNewWorkspace=false ..."
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
echo "[3/8] Path B: new workspace name, parameters at their defaults ..."
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
echo "[4/8] Path C: existing onboarded workspace in another resource group ..."
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
echo "[5/8] Path D: redeploying against the workspace B created ..."
# Give the workspace a non-default retention first: the redeploy must leave it, and its
# lastSkuUpdate, exactly as they were (the customer's case: an existing workspace, defaults).
az monitor log-analytics workspace update -g "$RG_APP" -n "$WS" --retention-time 90 -o none 2>/dev/null
before=$(az monitor log-analytics workspace show -g "$RG_APP" -n "$WS" --query "[retentionInDays, sku.name, sku.lastSkuUpdate]" -o tsv 2>/dev/null | tr '\n' ' ')
deploy "$RG_APP" path-d WorkspaceName="$WS"
after=$(az monitor log-analytics workspace show -g "$RG_APP" -n "$WS" --query "[retentionInDays, sku.name, sku.lastSkuUpdate]" -o tsv 2>/dev/null | tr '\n' ' ')
[ -n "$before" ] && [ "$before" = "$after" ] \
    && row "D leaves the existing workspace untouched" PASS "retention/sku/lastSkuUpdate unchanged" \
    || row "D leaves the existing workspace untouched" FAIL "before='$before' after='$after'"
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
echo "[6/8] Path E: cross-RG onto a workspace with no Microsoft Sentinel ..."
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

# --- K: credentials the server rejects stop the deployment, and say why ----------------
echo "[7/8] Path K: existing workspace, a password the server rejects ..."
az monitor log-analytics workspace create -g "$RG_K" -n "ws-k-$SFX" -l "$LOCATION" --retention-time 30 -o none 2>/dev/null
PARAM_FILE="$DEAD_FILE" deploy "$RG_K" path-k WorkspaceName="ws-k-$SFX"
state=$(az deployment group show -g "$RG_K" -n path-k --query properties.provisioningState -o tsv 2>/dev/null)
blamed=$(failed_step "$RG_K" path-k | grep -c 'triggerFirstRun')
msg=$(az deployment operation group list -g "$RG_K" -n path-k \
    --query "[?starts_with(properties.targetResource.resourceName,'triggerFirstRun')].properties.statusMessage" -o json 2>/dev/null)
[ "$state" = Failed ] \
    && row "K deployment fails" PASS "$state" \
    || row "K deployment fails" FAIL "expected Failed, got '${state:-<unreadable>}': rejected credentials must not give a green deploy"
[ "${blamed:-0}" -ge 1 ] \
    && row "K fails in the credential check" PASS "triggerFirstRun" \
    || row "K fails in the credential check" FAIL "a different step failed"
printf '%s' "$msg" | grep -q 'rejected the username or password' \
    && row "K banner names the rejected password" PASS "message carries 'rejected the username or password'" \
    || row "K banner names the rejected password" FAIL "status message was: $(printf '%s' "$msg" | head -c 200)"

# --- F: what the first window left in the workspace ------------------------------------
echo "[8/8] Path F: first-run audit and indicators in the workspace of path B, then a host restart (up to 65 min) ..."
cust=$(az monitor log-analytics workspace show -g "$RG_APP" -n "$WS" --query customerId -o tsv 2>/dev/null)
APP_B=$(az functionapp list -g "$RG_APP" --query "[0].name" -o tsv 2>/dev/null)
res=$(python3 - "$cust" "$RG_APP" "$APP_B" <<'PYEOF'
import json, os, subprocess, sys, time
from datetime import datetime, timezone
cust, rg, app = sys.argv[1], sys.argv[2], sys.argv[3]
POLL = int(os.environ.get("TEST_POLL", "30"))
def q(kql):
    r = subprocess.run(["az", "monitor", "log-analytics", "query", "-w", cust, "--analytics-query", kql, "-o", "json"],
                       capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None
def ts(v):
    v = v.rstrip("Z")
    if "." in v:
        a, b = v.split(".")
        v = a + "." + b[:6]
    return datetime.fromisoformat(v).replace(tzinfo=timezone.utc)
first_deadline = time.time() + int(os.environ.get("TEST_FIRST_RUN_WAIT", "1500"))
rows = None
made = []
while time.time() < first_deadline:
    rows = q("SOCRadar_TAXII_Audit_CL | project TimeGenerated, Status, IndicatorsCreated | order by TimeGenerated asc")
    if rows is not None:
        made = [r for r in rows if int(r.get("IndicatorsCreated") or 0) > 0]
        if made:
            break
    time.sleep(POLL)
if not made:
    print("UNREADABLE"); sys.exit(0)
first = int(made[0]["IndicatorsCreated"])
# A restart starts the host again, and a host start runs an import (run_on_startup). This is what
# a customer's later restart or scale-out does: it must not send the first import again.
restart_at = datetime.now(timezone.utc)
rr = subprocess.run(["az", "functionapp", "restart", "-g", rg, "-n", app], capture_output=True, text=True)
if rr.returncode != 0:
    print("NORESTART"); sys.exit(0)
later = []
second_deadline = time.time() + int(os.environ.get("TEST_RESTART_WAIT", "2400"))
while time.time() < second_deadline:
    rows = q("SOCRadar_TAXII_Audit_CL | project TimeGenerated, Status, IndicatorsCreated | order by TimeGenerated asc") or rows
    later = [r for r in rows if ts(r["TimeGenerated"]) > restart_at]
    if later:
        break
    time.sleep(POLL)
bad = sum(1 for r in rows if r["Status"] != "Success")
ti = None
t_deadline = time.time() + 300
while time.time() < t_deadline:
    ti = q("ThreatIntelIndicators | where SourceSystem == 'SOCRadar TAXII' | summarize n=count()")
    if ti and int(ti[0]["n"]) > 0:
        break
    time.sleep(POLL)
print("RESULT", first, sum(int(r.get("IndicatorsCreated") or 0) for r in later), bad, len(later), int(ti[0]["n"]) if ti else -1)
PYEOF
)
read -r tag first later_made bad later_rows ti_n <<< "$res"
if [ "$tag" != RESULT ]; then
    row "F first window readable" FAIL "the audit table never answered with an import row, or the restart failed: ${res:-<empty>}"
else
    [ "$bad" = 0 ] \
        && row "F no audit row is a failure" PASS "every row Success" \
        || row "F no audit row is a failure" FAIL "$bad audit row(s) not Success"
    [ "$ti_n" -gt 0 ] \
        && row "F indicators landed" PASS "$ti_n row(s) in ThreatIntelIndicators" \
        || row "F indicators landed" FAIL "no TAXII indicator in ThreatIntelIndicators"
    if [ "$later_rows" -ge 1 ]; then
        [ "$later_made" -lt "$first" ] \
            && row "F a host restart does not resend the import" PASS "first created $first, after the restart $later_made" \
            || row "F a host restart does not resend the import" FAIL "first created $first, after the restart $later_made"
    else
        row "F a host restart does not resend the import" FAIL "the restarted host wrote no audit row in the window, so the startup import was not observed"
    fi
fi

echo
if [ "$fails" -eq 0 ]; then
    echo "All seven deployment paths behaved as asserted."
else
    echo "$fails assertion(s) failed."
fi
exit $((fails == 0 ? 0 : 1))
