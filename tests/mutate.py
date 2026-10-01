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
  '''"description": "Run status (Success, PartialSuccess, Failed)"''','''"description": "Run status (Success, Failed)"''',
  "tests/test_audit_schema.py"),
 ("failed page writes nothing","FunctionApp/taxii_processor.py",
  """                self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
                complete = False""","""                complete = False""",
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
                complete = False""","""                self.save_checkpoint(next_cursor or cursor, added_after, total_created, pages_fetched)
                complete = False""",
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
  '''if [ "$cur" != "UNREADABLE" ] && [ "$cur" = "$prev" ]; then''','''if [ "$cur" != "UNREADABLE" ]; then''',
  "tests/test_portal_dedup.py"),
]
blind=[]
for name,path,old,new,test in MUTATIONS:
    full=os.path.join(REPO,path)
    orig=open(full,encoding='utf-8').read()
    if old not in orig:
        print("SKIP  %-28s anchor not found in %s"%(name,path)); blind.append(name); continue
    try:
        open(full,'w',encoding='utf-8').write(orig.replace(old,new,1))
        try:
            r=subprocess.run([sys.executable,test],cwd=REPO,capture_output=True,text=True,timeout=60,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"))
            rc=r.returncode
        except subprocess.TimeoutExpired:
            rc=124
    finally:
        open(full,'w',encoding='utf-8').write(orig)
    if rc==0:
        print("BLIND %-28s %s still passed"%(name,test)); blind.append(name)
    else:
        print("caught %-27s %s"%(name,test))
print("\nblind:",len(blind),"of",len(MUTATIONS))
sys.exit(1 if blind else 0)
