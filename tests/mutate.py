#!/usr/bin/env python3
"""Break the code on purpose and prove the tests notice.

Each entry below breaks one invariant, runs the test that should catch it, and
restores the file. A mutation that survives is BLIND and the run exits non-zero.

Bytecode is disabled for the child runs: a same-size mutation applied and
reverted inside one second leaves a .pyc that still looks current, and the next
run would execute the mutated bytecode.

    python3 tests/mutate.py
"""

import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRASH_MARKERS=("TimeoutExpired","ModuleNotFoundError","ImportError","SyntaxError","IndentationError")
MUTATIONS = [
 ("checkpoint advances anyway","FunctionApp/taxii_processor.py",
  '''            if page_failed:''','''            if False:''',
  "tests/test_upload_failure_keeps_checkpoint.py"),
 ("failed counted as skipped","FunctionApp/taxii_processor.py",
  '''        return 0, 0, len(indicators)''','''        return 0, len(indicators), 0''',
  "tests/test_upload_failure_keeps_checkpoint.py"),
 ("status always Success","FunctionApp/function_app.py",
  '''            if lost or not result["complete"]:''','''            if False:''',
  "tests/test_audit_status.py"),
 ("Retry-After ignored","FunctionApp/taxii_processor.py",
  '''            wait = min(float(retry_after), MAX_RETRY_SLEEP)''','''            wait = min(2 ** attempt, MAX_RETRY_SLEEP)''',
  "tests/test_retry_policy.py"),
 ("no retry at all","FunctionApp/taxii_processor.py",
  '''MAX_ATTEMPTS = 3''','''MAX_ATTEMPTS = 1''',
  "tests/test_retry_policy.py"),
 ("DCR column removed","azuredeploy.json",
  '''                            {
                                "name": "IndicatorsFailed",
                                "type": "int"
                            },
''','''''',
  "tests/test_audit_schema.py"),
 ("table column removed","azuredeploy.json",
  '''                        {
                            "name": "IndicatorsFailed",
                            "type": "int",
                            "description": "Indicators that never reached Microsoft Sentinel and will be fetched again"
                        },
''','''''',
  "tests/test_audit_schema.py"),
 ("nested table column removed","azuredeploy.json",
  '''                                        {
                                            "name": "IndicatorsFailed",
                                            "type": "int",
                                            "description": "Indicators that never reached Microsoft Sentinel and will be fetched again"
                                        },
''','''''',
  "tests/test_audit_schema.py"),
 ("Status description reverted","azuredeploy.json",
  '''"string",
                            "description": "Run status (Success, PartialSuccess, Failed)"''','''"string",
                            "description": "Run status (Success, Failed)"''',
  "tests/test_audit_schema.py"),
 ("Status description reverted (nested)","azuredeploy.json",
  '''"string",
                                            "description": "Run status (Success, PartialSuccess, Failed)"''','''"string",
                                            "description": "Run status (Success, Failed)"''',
  "tests/test_audit_schema.py"),
 ("failed page writes nothing","FunctionApp/taxii_processor.py",
  """                self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
                complete = False
                break

            # more=true with no cursor""","""                complete = False
                break

            # more=true with no cursor""",
  "tests/test_upload_failure_keeps_checkpoint.py"),
 ("revoked dropped before upload","FunctionApp/stix_parser.py",
  '''    if not stix_obj.get("pattern"):''','''    if not stix_obj.get("pattern") or stix_obj.get("revoked") is True:''',
  "tests/test_revoked_upload.py"),
 ("revoked flag stripped","FunctionApp/stix_parser.py",
  '''NON_STIX_FIELDS = {"date_added", "version", "threat_feed_source_name"}''','''NON_STIX_FIELDS = {"date_added", "version", "threat_feed_source_name", "revoked"}''',
  "tests/test_revoked_upload.py"),
 ("revoked counted when rejected","FunctionApp/taxii_processor.py",
  '''                revoked_ok = len(batch_revoked - rejected) if not failed else 0''','''                revoked_ok = len(batch_revoked) if not failed else 0''',
  "tests/test_revoked_upload.py"),
 ("revoked counted when failed","FunctionApp/taxii_processor.py",
  '''                revoked_ok = len(batch_revoked - rejected) if not failed else 0''','''                revoked_ok = len(batch_revoked - rejected)''',
  "tests/test_revoked_upload.py"),
 ("revoked counted as created","FunctionApp/taxii_processor.py",
  '''                created -= revoked_ok''','''                created -= 0''',
  "tests/test_revoked_upload.py"),
 ("last page keeps stale cursor","FunctionApp/taxii_processor.py",
  '''            elif not more and self._last_date_added:''','''            elif False:''',
  "tests/test_last_page_checkpoint.py"),
 ("marker ignored on fetch","FunctionApp/taxii_processor.py",
  '''                self._last_date_added = resp.headers.get("X-TAXII-Date-Added-Last", "") or ""''','''                self._last_date_added = ""''',
  "tests/test_last_page_checkpoint.py"),
 ("failed page advances cursor","FunctionApp/taxii_processor.py",
  """                self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
                complete = False
                break

            # more=true with no cursor""","""                self.save_checkpoint(next_cursor or cursor, added_after, total_created, pages_fetched)
                complete = False
                break

            # more=true with no cursor""",
  "tests/test_upload_failure_keeps_checkpoint.py"),
 ("pointer reading removed", "azuredeploy.json",
  '''staged() { [ \\"$(shape)\\" = blob ]; }; ''', '''''',
  "tests/test_package_push.py"),
 ("pointer echoed with its SAS", "azuredeploy.json",
  '''staged() { [ \\"$(shape)\\" = blob ]; }; ''', '''staged() { echo \\"$(pointer)\\"; [ \\"$(shape)\\" = blob ]; }; ''',
  "tests/test_package_push.py"),
 ("settings read not retried", "azuredeploy.json",
  '''for wait in $(seq 1 8); ''', '''for wait in $(seq 1 1); ''',
  "tests/test_package_push.py"),
 ("single push attempt", "azuredeploy.json",
  '''for attempt in $(seq 1 6); ''', '''for attempt in $(seq 1 1); ''',
  "tests/test_package_push.py"),
 ("index poll cut to one minute", "azuredeploy.json",
  '''for i in $(seq 1 40); ''', '''for i in $(seq 1 4); ''',
  "tests/test_package_push.py"),
 ("no restart after staging", "azuredeploy.json",
  '''az functionapp restart ''', '''true restart ''',
  "tests/test_package_push.py"),
 ("container log deleted on failure", "azuredeploy.json",
  '''"cleanupPreference": "OnSuccess"''', '''"cleanupPreference": "Always"''',
  "tests/test_package_push.py"),
 ("failed run's evidence expires in an hour", "azuredeploy.json",
  '''"retentionInterval": "PT26H"''', '''"retentionInterval": "PT1H"''',
  "tests/test_package_push.py"),
 ("checkpoint read error swallowed","FunctionApp/taxii_processor.py",
  '''        except ResourceNotFoundError:''','''        except Exception:''',
  "tests/test_checkpoint_read.py"),
 ("more without next keeps looping","FunctionApp/taxii_processor.py",
  '''            if more and not next_cursor:''','''            if False:''',
  "tests/test_last_page_checkpoint.py"),
 ("more without next writes no checkpoint","FunctionApp/taxii_processor.py",
  '''                self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
                complete = False
                break

            # Update cursor.''','''                complete = False
                break

            # Update cursor.''',
  "tests/test_last_page_checkpoint.py"),
 ("incomplete run claims lost indicators","FunctionApp/function_app.py",
  '''                if lost:''','''                if True:''',
  "tests/test_audit_status.py"),
 ("step 3 log claims lost indicators","FunctionApp/function_app.py",
  '''        if total_failed > 0:''','''        if True:''',
  "tests/test_audit_status.py"),
 ("audit post not guarded","FunctionApp/dcr_logger.py",
  '''        except Exception as e:
            logger.warning("DCR ingestion failed: %s", e)
            return''','''        except ZeroDivisionError as e:
            return''',
  "tests/test_audit_post_failure.py"),
 ("budget pause not reported by processor","FunctionApp/taxii_processor.py",
  '''                    paused = True
                    break''','''                    paused = False
                    break''',
  "tests/test_budget_pause.py"),
 ("budget pause not written to audit row","FunctionApp/function_app.py",
  '''                if result.get("paused"):''','''                if False:''',
  "tests/test_audit_status.py"),
 ("checkpoint not saved after a page","FunctionApp/taxii_processor.py",
  '''            self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
            logger.info("Checkpoint saved after page %d", page_num)''','''            logger.info("Checkpoint saved after page %d", page_num)''',
  "tests/test_budget_pause.py"),
 ("harness dedup assert disabled","scripts/portal_test.sh",
  '''if [ "$NOW" != "$BASE" ]; then''','''if false; then''',
  "tests/test_portal_dedup.py"),
 ("harness unseen run counts as a run","scripts/portal_test.sh",
  '''seen within ${MAX_WAIT}s"
    return 1''','''seen within ${MAX_WAIT}s"
    return 0''',
  "tests/test_portal_dedup.py"),
 ("harness unreadable read counts as zero","scripts/portal_test.sh",
  '''        printf 'UNREADABLE'
    fi''','''        printf '0 0'
    fi''',
  "tests/test_portal_dedup.py"),
 ("harness skips the catch-up drain","scripts/portal_test.sh",
  '''[ $DRAIN -lt "${DRAIN_MAX:-6}" ]''','''[ $DRAIN -lt 0 ]''',
  "tests/test_portal_dedup.py"),
 ("harness accepts an empty baseline","scripts/portal_test.sh",
  '''        0\\ *) CHECKPOINT_OK="FAIL (no indicator rows in Log Analytics, nothing to dedup against)" ;;
''','''''',
  "tests/test_portal_dedup.py"),
 ("harness failed run counts as a run","scripts/portal_test.sh",
  '''if [ "$ok" != "True" ]; then''','''if false; then''',
  "tests/test_portal_dedup.py"),
 ("harness ignores the Step 3 verdict","scripts/portal_test.sh",
  '''step3_clean "$step3" && return 0''','''return 0''',
  "tests/test_portal_dedup.py"),
 ("harness checks run 2 only","scripts/portal_test.sh",
  '''for n in 2 3; do''','''for n in 2; do''',
  "tests/test_portal_dedup.py"),
 ("harness unreadable checkpoint passes","scripts/portal_test.sh",
  '''CHECKPOINT_OK="FAIL (checkpoint table unreadable)"''','''CHECKPOINT_OK="PASS"''',
  "tests/test_portal_dedup.py"),
 ("harness not-caught-up passes","scripts/portal_test.sh",
  '''CHECKPOINT_OK="SKIPPED (collection not caught up after $DRAIN catch-up runs)"''','''CHECKPOINT_OK="PASS"''',
  "tests/test_portal_dedup.py"),
 ("harness refused trigger counts as a run","scripts/portal_test.sh",
  '''case "$code" in 200|202) ;; *) return 1 ;; esac''','''case "$code" in 200|202) ;; *) ;; esac''',
  "tests/test_portal_dedup.py"),
 ("harness settles on the first read","scripts/portal_test.sh",
  '''[ $eq -ge "${1:-2}" ]''','''[ $eq -ge 1 ]''',
  "tests/test_portal_dedup.py"),
 ("harness baseline settles on two reads","scripts/portal_test.sh",
  '''BASE=$(ti_settled 3 quiet)''','''BASE=$(ti_settled 2 quiet)''',
  "tests/test_portal_dedup.py"),
 ("harness After-run reads settle on two reads","scripts/portal_test.sh",
  '''NOW=$(ti_settled 3 quiet)''','''NOW=$(ti_settled 2 quiet)''',
  "tests/test_portal_dedup.py"),
 ("harness unsettled baseline fails","scripts/portal_test.sh",
  '''*UNSETTLED) CHECKPOINT_OK="CANNOT-MEASURE (Log Analytics did not settle: $BASE)" ;;''','''*UNSETTLED) CHECKPOINT_OK="FAIL (Log Analytics did not settle: $BASE)" ;;''',
  "tests/test_portal_dedup.py"),
 ('harness baseline read skips the quiet wait',"scripts/portal_test.sh",
  'BASE=$(ti_settled 3 quiet)','BASE=$(ti_settled 3)',
  "tests/test_portal_dedup.py"),
 ('harness After-run read skips the quiet wait',"scripts/portal_test.sh",
  'NOW=$(ti_settled 3 quiet)','NOW=$(ti_settled 3)',
  "tests/test_portal_dedup.py"),
 ('harness quiet condition removed',"scripts/portal_test.sh",
  'if [ "$rec" = 0 ] && [ "$arr" != 0 ] && [ "$arr" != UNREADABLE ]; then printf','if [ "$arr" != 0 ] && [ "$arr" != UNREADABLE ]; then printf',
  "tests/test_portal_dedup.py"),
 ('harness never takes the data as quiet',"scripts/portal_test.sh",
  'if [ "$rec" = 0 ] && [ "$arr" != 0 ] && [ "$arr" != UNREADABLE ]; then printf','if false; then printf',
  "tests/test_portal_dedup.py"),
 ('harness quiet wait has no ceiling',"scripts/portal_test.sh",
  '[ "$(date +%s)" -ge "$ceiling" ] && break','true',
  "tests/test_portal_dedup.py"),
 ('harness waits although nothing was created',"scripts/portal_test.sh",
  '$((LAST_RUN_CREATED + LAST_RUN_REVOKED)) -gt 0 ]; then LAST_CREATED_END','$((LAST_RUN_CREATED + LAST_RUN_REVOKED)) -ge 0 ]; then LAST_CREATED_END',
  "tests/test_portal_dedup.py"),
 ('harness ignores revoked rows when deciding to wait',"scripts/portal_test.sh",
  'if [ $((LAST_RUN_CREATED + LAST_RUN_REVOKED)) -gt 0 ]; then LAST_CREATED_END','if [ $((LAST_RUN_CREATED + 0)) -gt 0 ]; then LAST_CREATED_END',
  "tests/test_portal_dedup.py"),
 ('harness ignores LAW_LAG_SECONDS',"scripts/portal_test.sh",
  'LAW_LAG_SECONDS="${LAW_LAG_SECONDS:-900}"','LAW_LAG_SECONDS=900',
  "tests/test_portal_dedup.py"),
 ('harness quiet window ignores LAW_QUIET_MINUTES',"scripts/portal_test.sh",
  'ago(${LAW_QUIET_MINUTES}m)','ago(1m)',
  "tests/test_portal_dedup.py"),
 ('harness CANNOT-MEASURE exits 0',"scripts/portal_test.sh",
  '    SKIPPED*|CANNOT-MEASURE*) exit 3 ;;','    SKIPPED*|CANNOT-MEASURE*) exit 0 ;;',
  "tests/test_portal_dedup.py"),
 ('harness SKIPPED exits 0',"scripts/portal_test.sh",
  '    SKIPPED*|CANNOT-MEASURE*) exit 3 ;;','    CANNOT-MEASURE*) exit 3 ;;',
  "tests/test_portal_dedup.py"),
 ('harness FAIL row in the summary exits 0',"scripts/portal_test.sh",
  "grep -q '| FAIL' && exit 1","grep -q '| NEVER' && exit 1",
  "tests/test_portal_dedup.py"),
 ('harness unsettled baseline exits 1',"scripts/portal_test.sh",
  '($LAW_BEFORE)"; exit 3 ;;','($LAW_BEFORE)"; exit 1 ;;',
  "tests/test_portal_dedup.py"),
 ('harness unsettled After-run read passes',"scripts/portal_test.sh",
  'CHECKPOINT_OK="CANNOT-MEASURE (Log Analytics did not settle after run','CHECKPOINT_OK="PASS (Log Analytics did not settle after run',
  "tests/test_portal_dedup.py"),
 ('harness unreadable After-run read passes',"scripts/portal_test.sh",
  'CHECKPOINT_OK="FAIL (Log Analytics unreadable after run','CHECKPOINT_OK="PASS (Log Analytics unreadable after run',
  "tests/test_portal_dedup.py"),
 ('harness summary shows the stale Test 2 read',"scripts/portal_test.sh",
  '-> $LAW_LAST (last settled read)','-> $LAW_AFTER (last settled read)',
  "tests/test_portal_dedup.py"),
 ('harness arrival condition removed',"scripts/portal_test.sh",
  'if [ "$rec" = 0 ] && [ "$arr" != 0 ] && [ "$arr" != UNREADABLE ]; then printf','if [ "$rec" = 0 ]; then printf',
  "tests/test_portal_dedup.py"),
 ('harness unreadable arrival read counts as arrived',"scripts/portal_test.sh",
  '[ "$arr" != 0 ] && [ "$arr" != UNREADABLE ]; then printf','[ "$arr" != 0 ]; then printf',
  "tests/test_portal_dedup.py"),
 ('harness arrival asks for the wrong time',"scripts/portal_test.sh",
  'unixtime_seconds_todatetime($LAST_CREATED_END)','unixtime_seconds_todatetime(0)',
  "tests/test_portal_dedup.py"),
 ('harness dedup run loading rows does not fail on the log',"scripts/portal_test.sh",
  'if [ $LOADED -gt 0 ]; then CHECKPOINT_OK','if false; then CHECKPOINT_OK',
  "tests/test_portal_dedup.py"),
 ('harness dedup log check ignores revoked',"scripts/portal_test.sh",
  'LOADED=$((LAST_RUN_CREATED + LAST_RUN_REVOKED))','LOADED=$((LAST_RUN_CREATED + 0))',
  "tests/test_portal_dedup.py"),
 ("harness unseen dedup run ignored","scripts/portal_test.sh",
  'if ! run_import; then CHECKPOINT_OK="FAIL (run $n was not seen)"; break; fi','run_import || true',
  "tests/test_portal_dedup.py"),
 ("harness dedup log check tolerates one row","scripts/portal_test.sh",
  'if [ $LOADED -gt 0 ]; then CHECKPOINT_OK','if [ $LOADED -gt 1 ]; then CHECKPOINT_OK',
  "tests/test_portal_dedup.py"),
 ("onboarding id built with reference(concat(","azuredeploy.json",
  '''reference(extensionResourceId(parameters('WorkspaceResourceId'), 'Microsoft.SecurityInsights/onboardingStates', 'default'), ''',
  '''reference(concat(parameters('WorkspaceResourceId'), '/providers/Microsoft.SecurityInsights/onboardingStates/default'), ''',
  "tests/test_workspace_precheck.py"),
 ("harness waits less than the run budget","scripts/portal_test.sh",
  '''RUN_WAIT_SECONDS=$((RUN_BUDGET_SECONDS + RUN_OVERSHOOT_SECONDS + AI_LAG_SECONDS + INSTANCE_SWAP_SECONDS))''','''RUN_WAIT_SECONDS=420''',
  "tests/test_portal_dedup.py"),
 ("harness wait drops the ingestion lag","scripts/portal_test.sh",
  '''AI_LAG_SECONDS=180 ''','''AI_LAG_SECONDS=0 ''',
  "tests/test_portal_dedup.py"),
 ("harness ignores the pause line","scripts/portal_test.sh",
  '''[ "$LAST_RUN_PAUSED" = "yes" ] && return 0''','''[ "$LAST_RUN_PAUSED" = "never" ] && return 0''',
  "tests/test_portal_dedup.py"),
 ("harness reads the pause from other text","scripts/portal_test.sh",
  '''message has 'time budget reached' |''','''message has 'no such text' |''',
  "tests/test_portal_dedup.py"),
 ("harness ends the drain on an unseen run","scripts/portal_test.sh",
  '''run_import || echo "  Catch-up run $DRAIN was not seen; the checkpoint decides whether another is needed"''','''run_import || break''',
  "tests/test_portal_dedup.py"),
 ("harness takes an unseen catch-up as done","scripts/portal_test.sh",
  '''[ $DRAIN -gt 0 ] && [ "$LAST_RUN_PAUSED" = "unseen" ] && return 0''','''[ $DRAIN -gt 0 ] && [ "$LAST_RUN_PAUSED" = "never" ] && return 0''',
  "tests/test_portal_dedup.py"),
 ("harness cleanup never stops the app","scripts/portal_test.sh",
  '''    if ! az functionapp stop --subscription "$SUBSCRIPTION_ID" --name "$FUNC_APP_NAME" -g "$RESOURCE_GROUP"; then''','''    if ! true; then''',
  "tests/test_portal_dedup.py"),
 ("harness cleanup trap removed","scripts/portal_test.sh",
  '''trap cleanup EXIT
''','''''',
  "tests/test_portal_dedup.py"),
 ("harness stop drops --subscription","scripts/portal_test.sh",
  '''az functionapp stop --subscription "$SUBSCRIPTION_ID" --name''','''az functionapp stop --name''',
  "tests/test_portal_dedup.py"),
 ("harness skips the Stopped readback","scripts/portal_test.sh",
  '''    if [ "$FA_STATE" != "Stopped" ]; then''','''    if false; then''',
  "tests/test_portal_dedup.py"),
 ("harness stop failure not fatal","scripts/portal_test.sh",
  '''may still be billing"; bad=1''','''may still be billing"''',
  "tests/test_portal_dedup.py"),
 ("harness master key back in argv","scripts/portal_test.sh",
  '''-H @"$HDRFILE" -H "Content-Type''','''-H "x-functions-key: $key" -H "Content-Type''',
  "tests/test_portal_dedup.py"),
 ("harness xtrace guard removed","scripts/portal_test.sh",
  '''{ set +x; } 2>/dev/null
''','''''',
  "tests/test_portal_dedup.py"),
 ("harness curl without --max-time","scripts/portal_test.sh",
  '''curl -s --max-time 60 -o /dev/null''','''curl -s -o /dev/null''',
  "tests/test_portal_dedup.py"),
]
# pre-gate: replace(old,new,1) breaks the first hit, so an anchor that is not unique mutates the wrong place
bad=[(n,p,open(os.path.join(REPO,p),encoding='utf-8').read().count(o)) for n,p,o,_,_ in MUTATIONS]
bad=[b for b in bad if b[2]!=1]
if bad:
    for n,p,c in bad: print("ABORT %-28s anchor occurs %d times in %s (need exactly 1)"%(n,c,p))
    sys.exit(2)
blind=[]
for name,path,old,new,test in MUTATIONS:
    full=os.path.join(REPO,path)
    orig=open(full,encoding='utf-8').read()
    if old not in orig:
        print("SKIP  %-28s anchor not found in %s"%(name,path)); blind.append(name); continue
    mutant=orig.replace(old,new,1)
    # a mutant that is not valid shell is "caught" for the wrong reason
    if path.endswith('.sh') and subprocess.run(['bash','-n'],input=mutant,text=True,capture_output=True).returncode:
        print("INVALID %-26s mutant fails bash -n"%name); blind.append(name); continue
    try:
        open(full,'w',encoding='utf-8').write(mutant)
        try:
            r=subprocess.run([sys.executable,test],cwd=REPO,capture_output=True,text=True,timeout=300,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"))
            rc=r.returncode
            # a crash under load (timeout inside the test, import error) is not a catch
            if rc and any(m in (r.stdout+r.stderr) for m in CRASH_MARKERS):
                rc=125
        except subprocess.TimeoutExpired:
            rc=124
    finally:
        open(full,'w',encoding='utf-8').write(orig)
    if rc in (124,125):   # a timeout or a crash is not a catch
        print("ERROR %-28s %s timed out or crashed, not a catch"%(name,test)); blind.append(name); continue
    if rc==0:
        print("BLIND %-28s %s still passed"%(name,test)); blind.append(name)
    else:
        print("caught %-27s %s"%(name,test))
print("\nblind:",len(blind),"of",len(MUTATIONS))
sys.exit(1 if blind else 0)
