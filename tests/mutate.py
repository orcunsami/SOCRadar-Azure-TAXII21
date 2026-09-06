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
