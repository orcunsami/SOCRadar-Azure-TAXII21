#!/usr/bin/env python3
"""scripts/portal_test.sh must go red when the product re-uploads, and never green on a read it could not make.

The harness used to count indicators through Sentinel's queryIndicators API,
which stops at 1000 and shows the current state, so a product that loaded every
indicator again on every run still printed "Checkpoint Dedup PASS". The harness
now counts rows in Log Analytics (an append log: a re-upload adds rows). This
test runs the real script against a fake `az`, `curl` and `sleep` whose "product"
behaves in one of several ways and checks the verdict for each. The scenarios
run in parallel: each one starts the script in its own temp dir.
"""

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "portal_test.sh")

FAKE_AZ = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
line = " ".join(a)
st = json.load(open(os.environ["FAKE_STATE"]))
mode = st["mode"]
if "functionapp list" in line: print("socradar-taxii-test")
elif "functionapp show" in line: print("Running")
elif "functionapp keys" in line: print("k")
elif "account show" in line: print("tester")
elif "identity show" in line: print("pid")
elif "role assignment list" in line: print("Microsoft Sentinel Contributor")
elif "resource list" in line: print("socradar-taxii-ai-test")
elif "app-insights query" in line:
    if "traces" in line and "time budget reached" in line:
        rows = [["Step 2: x time budget reached after 85 pages, more pages pending, continues next run"]] if st.get("paused_last") else []
    elif "traces" in line:
        ok = "Step 3: Import complete - 30 created, 0 skipped, 0 failed, 0 revoked, 2 pages, 1/1 collections succeeded, 0 partial, 1000ms"
        bad = "Step 3: Import complete - 30 created, 0 skipped, 5 failed, 0 revoked, 2 pages, 0/1 collections succeeded, 1 partial, 1000ms"
        rows = [] if mode == "no_step3" else [[bad if mode == "step3_failed" else ok]]
    elif mode == "unseen": rows = []
    else:
        # A run that takes run_seconds: the script polls every 20 s (sleep is a no-op here, so count polls)
        st["polls"] = st.get("polls", 0) + 1
        json.dump(st, open(os.environ["FAKE_STATE"], "w"))
        if st["polls"] * 20 < st["run_seconds"] or (mode == "flag_unseen" and st["runs"] >= 2) or (mode == "flag_unseen_once" and st["runs"] == 2): rows = []
        else: rows = [["2026-10-01T00:00:00Z", mode != "run_failed", 1000]]
    print(json.dumps({"tables": [{"rows": rows}]}))
elif "log-analytics workspace show" in line: print("cid")
elif "log-analytics query" in line:
    if "Audit_CL" in line: print("T\tSuccess")
    elif mode == "unreadable_before" and st["runs"] == 0:
        sys.stderr.write("boom\n"); sys.exit(1)
    elif mode == "unreadable_after" and st["runs"] >= 1:
        sys.stderr.write("boom\n"); sys.exit(1)
    elif not st["table"]:
        sys.stderr.write("BadArgumentError: Failed to resolve table or column expression named 'ThreatIntelIndicators'\n"); sys.exit(1)
    else:
        r, i = st["rows"], st["ids"]
        if st.get("lag", 0) > 0:   # Log Analytics still shows the state from before the run
            r, i = st["stale"]; st["lag"] -= 1
            json.dump(st, open(os.environ["FAKE_STATE"], "w"))
        print("%d %d" % (r, i))
elif "storage account list" in line: print("srtaxiitest")
elif "storage entity query" in line:
    if "length(@)" in line:
        if "Cursor!=''" in line:
            if mode != "cp_unreadable": print(st["cursor_open"])
        else: print(1)
    else: print("table")
'''

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
if "/admin/functions/" not in " ".join(sys.argv): sys.exit(0)
path = os.environ["FAKE_STATE"]
st = json.load(open(path))
mode = st["mode"]; n = st["runs"] + 1; st["runs"] = n
if mode == "http500":
    json.dump(st, open(path, "w")); sys.stdout.write("500"); sys.exit(0)
st["stale"] = [st["rows"], st["ids"]]; st["lag"] = 1 if st.get("lagging") else 0
st["polls"] = 0
if mode == "paused":
    if n == 1: st.update(rows=st["rows"] + 20, ids=7, cursor_open=1, table=True)
    elif n == 2: st.update(rows=st["rows"] + 10, ids=10, cursor_open=0)
elif mode == "broken":
    st.update(rows=st["rows"] + 30, ids=10, table=True)
elif mode == "late_break":   # run 3 re-uploads, run 2 does not
    if n in (1, 3): st.update(rows=st["rows"] + 30, ids=10, table=True)
elif mode == "never_caught_up":
    st.update(rows=st["rows"] + 10, ids=10, cursor_open=1, table=True)
elif mode == "dead":   # a product that loads nothing, ever
    st.update(table=True)
elif mode in ("flag_only", "flag_unseen", "flag_unseen_once"):   # run 1 pauses but the checkpoint shows no cursor; run 2 (catch-up) loads the rest
    if n == 1: st.update(rows=st["rows"] + 20, ids=7, table=True)
    elif n == 2: st.update(rows=st["rows"] + 10, ids=10)
else:  # good, unseen, unreadable_*, run_failed, step3_failed, no_step3, cp_unreadable: run 1 loads, later runs load nothing
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
st["paused_last"] = bool(st["cursor_open"]) or (mode in ("flag_only", "flag_unseen", "flag_unseen_once") and n == 1)
json.dump(st, open(path, "w"))
sys.stdout.write("202")
'''

failures = []
CHECKS = 0


def check(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        failures.append(message)


def run(mode, table=True, lagging=False, rows0=0, ids0=0, run_seconds=0):
    with tempfile.TemporaryDirectory() as tmp:
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        for name, body in (("az", FAKE_AZ), ("curl", FAKE_CURL), ("sleep", "#!/bin/sh\nexit 0\n")):
            path = os.path.join(bin_dir, name)
            with open(path, "w") as handle:
                handle.write(body.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        state = os.path.join(tmp, "state.json")
        json.dump({"mode": mode, "runs": 0, "rows": rows0, "ids": ids0, "cursor_open": 0, "table": table,
                   "lagging": lagging, "run_seconds": run_seconds}, open(state, "w"))
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"], FAKE_STATE=state,
                   SUBSCRIPTION_ID="sub", RESOURCE_GROUP="rg", WORKSPACE_NAME="ws",
                   ENABLE_AUDIT_LOGGING="false")
        done = subprocess.run(["bash", SCRIPT], capture_output=True, text=True, env=env, timeout=120)
        return done.returncode, done.stdout + done.stderr


def verdict(out):
    for line in out.splitlines():
        if line.startswith("| Checkpoint Dedup"):
            return line
    return "(no verdict line)"


SCENARIOS = {
    "good": dict(mode="good", table=False),
    "paused": dict(mode="paused"),
    # a run that lasts its whole 9 minute budget (543 s, plus the Application Insights lag of up to 3 minutes): the default 48 hour lookback
    "slow_paused": dict(mode="paused", run_seconds=543 + 180),
    "slow_flag": dict(mode="flag_only", run_seconds=543 + 180),
    "flag_only": dict(mode="flag_only"),
    "flag_unseen": dict(mode="flag_unseen"),
    "flag_unseen_once": dict(mode="flag_unseen_once"),
    "broken": dict(mode="broken"),
    "unseen": dict(mode="unseen"),
    "unreadable_after": dict(mode="unreadable_after"),
    "unreadable_before": dict(mode="unreadable_before"),
    "dead": dict(mode="dead"),
    "run_failed": dict(mode="run_failed"),
    "step3_failed": dict(mode="step3_failed"),
    "no_step3": dict(mode="no_step3"),
    "http500": dict(mode="http500", rows0=5, ids0=3),
    "late_break": dict(mode="late_break"),
    "cp_unreadable": dict(mode="cp_unreadable"),
    "never_caught_up": dict(mode="never_caught_up"),
    "lag_good": dict(mode="good", lagging=True),
    "lag_broken": dict(mode="broken", lagging=True),
}
with ThreadPoolExecutor(max_workers=len(SCENARIOS)) as pool:
    futures = {name: pool.submit(run, **kw) for name, kw in SCENARIOS.items()}
    R = {name: f.result() for name, f in futures.items()}


def never_passes(name, what):
    rc, out = R[name]
    check(rc == 1 and "PASS" not in verdict(out), "%s (rc=%d): %s" % (what, rc, verdict(out)))


rc, out = R["good"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out,
      "a product that loads once then nothing did not pass (rc=%d): %s" % (rc, verdict(out)))

rc, out = R["paused"]
check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
      "a run paused on its budget was not caught up before the dedup check (rc=%d): %s" % (rc, verdict(out)))

# The wait must outlast a run that takes its whole budget: with a shorter one every paused run is
# "not seen", the catch-up gives up and the dedup check is skipped (seen live, 1 Oct 2026).
rc, out = R["slow_paused"]
check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
      "a run lasting its whole time budget was not waited for, so the dedup check did not run (rc=%d): %s" % (rc, verdict(out)))
check("The run paused on its time budget" in out,
      "the pause line of a run lasting its whole budget was not reported")

# The pause line alone, with no cursor in the checkpoint, still means "not caught up".
for name in ("flag_only", "slow_flag"):
    rc, out = R[name]
    check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
          "%s: a run that reported a pause was not caught up before the dedup check (rc=%d): %s" % (name, rc, verdict(out)))

# A catch-up run that is not seen neither ends the drain nor counts as caught up.
rc, out = R["flag_unseen"]
check(rc == 0 and "not seen; the checkpoint decides" in out and "| Checkpoint Dedup      | SKIPPED" in out,
      "catch-up runs that were never seen were taken as caught up (rc=%d): %s" % (rc, verdict(out)))
rc, out = R["flag_unseen_once"]
check(rc == 0 and "catch-up run 2" in out and "| Checkpoint Dedup      | PASS" in out,
      "one unseen catch-up run ended the drain instead of the next one finishing it (rc=%d): %s" % (rc, verdict(out)))

rc, out = R["broken"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "a product that re-uploads on every run did not fail the dedup check (rc=%d): %s" % (rc, verdict(out)))

never_passes("unseen", "runs that were never seen still produced a dedup verdict")
never_passes("unreadable_after", "an unreadable Log Analytics still produced a dedup PASS")
never_passes("unreadable_before", "an unreadable Log Analytics baseline was taken as zero rows")
never_passes("dead", "a product that loads nothing (0 0 -> 0 0 -> 0 0) still passed the dedup check")
never_passes("run_failed", "runs that Application Insights recorded as failed still produced a dedup verdict")
never_passes("step3_failed", "runs whose Step 3 line reports failed indicators or collections still produced a dedup verdict")
never_passes("no_step3", "runs with no Step 3 line (not shown to have finished) still produced a dedup verdict")
never_passes("http500", "a trigger the Function App refused (HTTP 500) still produced a dedup verdict")
never_passes("cp_unreadable", "an unreadable checkpoint table still produced a dedup PASS")

rc, out = R["late_break"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 3 changed" in out,
      "a product that re-uploads only on run 3 was not caught (rc=%d): %s" % (rc, verdict(out)))

rc, out = R["never_caught_up"]
check("| Checkpoint Dedup      | SKIPPED" in out and "PASS" not in verdict(out),
      "a collection that never caught up did not report SKIPPED (rc=%d): %s" % (rc, verdict(out)))

rc, out = R["lag_good"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out,
      "Log Analytics lag made a clean product fail (rc=%d): %s" % (rc, verdict(out)))

rc, out = R["lag_broken"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "Log Analytics lag hid a re-upload: the first read after a run was taken as settled (rc=%d): %s" % (rc, verdict(out)))

# The wait is built from the budget the function really has.
script = open(SCRIPT).read()
budget = re.search(r"^RUN_BUDGET_SECONDS=(\d+)", script, re.M)
check(budget and "total_budget_seconds = %s * 60" % (int(budget.group(1)) // 60) in open(os.path.join(REPO, "FunctionApp", "function_app.py")).read(),
      "portal_test.sh RUN_BUDGET_SECONDS no longer matches total_budget_seconds in function_app.py")
check(re.search(r"^RUN_WAIT_SECONDS=\$\(\(RUN_BUDGET_SECONDS \+ ", script, re.M) is not None,
      "portal_test.sh RUN_WAIT_SECONDS is not built on top of RUN_BUDGET_SECONDS")
check(not re.search(r"wait_for_completion\s+\d+", script),
      "portal_test.sh waits a hard-coded number of seconds for a run")

# The harness parses the Step 3 line the function writes; if that wording moves, the fake above lies.
source = open(os.path.join(REPO, "FunctionApp", "function_app.py")).read()
check("%d failed, %d revoked, " in source and "%d pages, %d/%d collections succeeded, %d partial" in source,
      "the Step 3 log format changed: portal_test.sh step3_clean and the fake trace above must follow")

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("portal_test.sh dedup verdict follows Log Analytics rows, not a capped API: OK (%d checks)" % CHECKS)
