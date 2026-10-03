#!/usr/bin/env python3
"""scripts/portal_test.sh must go red when the product re-uploads, and never green on a read it could not make.

The harness used to count indicators through Sentinel's queryIndicators API,
which stops at 1000 and shows the current state, so a product that loaded every
indicator again on every run still printed "Checkpoint Dedup PASS". The harness
now counts rows in Log Analytics (an append log: a re-upload adds rows). This
test runs the real script against a fake `az`, `curl`, `sleep` and `date` whose "product"
behaves in one of several ways and checks the verdict for each. The fake clock is virtual:
`sleep` advances it, `date +%s` reads it. Late rows are a trickle: the rows of a run land in steps
at set offsets, and the fake's ingestion_time count sees the steps inside the quiet window. The scenarios run in parallel: each one starts
the script in its own temp dir. Exit codes: 0 pass, 1 fail, 3 not measured (SKIPPED or CANNOT-MEASURE).
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
import json, os, re, sys
CLOCK = lambda: int(open(os.environ["FAKE_CLOCK"]).read())
a = sys.argv[1:]
line = " ".join(a)
st = json.load(open(os.environ["FAKE_STATE"]))
mode = st["mode"]
if "functionapp list" in line: print("socradar-taxii-test")
elif "functionapp show" in line: print("Stopped" if st.get("stopped") else "Running")
elif "functionapp stop" in line:   # record the argv; the app reads back Stopped afterwards unless the fake is told otherwise
    open(os.environ["FAKE_STOPLOG"], "a").write(line + "\n")
    if not st.get("stop_noop"):
        st["stopped"] = True
        json.dump(st, open(os.environ["FAKE_STATE"], "w"))
    if st.get("stop_fail"): sys.stderr.write("stop boom\n"); sys.exit(1)   # errors out although the app reads back Stopped: only the exit code of stop shows it
elif "functionapp keys" in line: print("CANARY-MASTER-KEY-0123456789")
elif "account show" in line: print("tester")
elif "identity show" in line: print("pid")
elif "role assignment list" in line: print("Microsoft Sentinel Contributor")
elif "resource list" in line: print("socradar-taxii-ai-test")
elif "app-insights query" in line:
    if "traces" in line and "time budget reached" in line:
        rows = [["Step 2: x time budget reached after 85 pages, more pages pending, continues next run"]] if st.get("paused_last") else []
    elif "traces" in line:
        c, r = (0, 0) if st.get("hide") and st["runs"] >= 2 else (st.get("created", 30), st.get("revoked", 0))   # hide: the log says 0 from run 2 on, only Log Analytics shows the rows
        ok = "Step 3: Import complete - %d created, 0 skipped, 0 failed, %d revoked, 2 pages, 1/1 collections succeeded, 0 partial, 1000ms" % (c, r)
        bad = "Step 3: Import complete - 0 created, 0 skipped, 5 failed, 0 revoked, 2 pages, 0/1 collections succeeded, 1 partial, 1000ms"
        rows = [] if mode == "no_step3" else [[bad if mode == "step3_failed" else ok]]
    elif mode == "unseen": rows = []
    else:
        # A run that takes run_seconds: the script polls every 20 s (sleep is a no-op here, so count polls)
        st["polls"] = st.get("polls", 0) + 1
        json.dump(st, open(os.environ["FAKE_STATE"], "w"))
        if st["polls"] * 20 < st["run_seconds"] or (mode == "flag_unseen" and st["runs"] >= 2) or (mode == "flag_unseen_once" and st["runs"] == 2) or (mode == "dedup_unseen" and st["runs"] >= 2): rows = []
        else: rows = [["2026-10-01T00:00:00Z", mode != "run_failed", 1000]]
    print(json.dumps({"tables": [{"rows": rows}]}))
elif "log-analytics workspace show" in line: print("cid")
elif "log-analytics query" in line:
    if "Audit_CL" in line: print("T\tSuccess")
    elif mode == "unreadable_before" and st["runs"] == 0:
        sys.stderr.write("boom\n"); sys.exit(1)
    elif (mode == "unreadable_after" and st["runs"] >= 1) or (mode == "unreadable_run2" and st["runs"] >= 2):
        sys.stderr.write("boom\n"); sys.exit(1)
    elif not st["table"]:
        sys.stderr.write("BadArgumentError: Failed to resolve table or column expression named 'ThreatIntelIndicators'\n"); sys.exit(1)
    elif "unixtime_seconds_todatetime" in line:   # rows ingested after the epoch second the script names
        if mode == "arrival_unreadable" and st["runs"] >= 1: sys.stderr.write("boom\n"); sys.exit(1)
        since = int(re.search(r"unixtime_seconds_todatetime\((\d+)\)", line).group(1))
        print(sum(1 for t in st.get("ing", []) if since < t <= CLOCK()))
    elif "ingestion_time" in line:   # rows ingested in the last N minutes
        minutes = int(re.search(r"ago\((\d+)m\)", line).group(1))
        if mode in ("never_quiet", "dead_busy") and st["runs"] >= 1: print(1)   # rows keep arriving, the totals do not move
        else: print(sum(1 for t, _, _ in st.get("sched", []) if CLOCK() - minutes * 60 < t <= CLOCK()))
    else:
        r, i = st["rows"], st["ids"]
        if st.get("sched"):   # a trickle: the value of the last step that has landed
            r, i = st["before"]
            for t, rr, ii in st["sched"]:
                if t <= CLOCK(): r, i = rr, ii
        if st.get("lag", 0) > 0:   # Log Analytics still shows the state from before the run
            r, i = st["stale"]; st["lag"] -= 1   # lagging=2: the stale value shows twice in a row, a plateau
            json.dump(st, open(os.environ["FAKE_STATE"], "w"))
        if (mode == "drift" and st["runs"] >= 1) or (mode == "drift_run2" and st["runs"] >= 2) or mode == "drift_before" and st["runs"] == 0:   # never settles
            st["reads"] = st.get("reads", 0) + 1; r += st["reads"]
            json.dump(st, open(os.environ["FAKE_STATE"], "w"))
        print("%d %d" % (r, i))
elif "storage account list" in line: print("srtaxiitest")
elif "storage entity query" in line:
    if "length(@)" in line:
        if "Cursor!=''" in line:
            if mode != "cp_unreadable": print(st["cursor_open"])
        else: print(0 if mode == "cp_empty" else 1)
    else: print("table")
'''

# The virtual clock is a plain file; sh keeps the many sleep/date calls cheap.
FAKE_SLEEP = "#!/bin/sh\necho $(( $(cat \"$FAKE_CLOCK\") + ${1%.*} )) > \"$FAKE_CLOCK\"\n"

FAKE_DATE = "#!/bin/sh\n[ \"$*\" = '+%s' ] && { cat \"$FAKE_CLOCK\"; exit 0; }\nexec /bin/date \"$@\"\n"

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys
CLOCK = lambda: int(open(os.environ["FAKE_CLOCK"]).read())
if "/admin/functions/" not in " ".join(sys.argv): sys.exit(0)
open(os.environ["FAKE_ARGLOG"], "a").write(" ".join(sys.argv[1:]) + "\n")
# the master key must come in through `-H @file` (0600), never as argv
args = sys.argv[1:]
hdr = args[args.index("-H") + 1] if "-H" in args else ""
ok = hdr.startswith("@") and os.path.isfile(hdr[1:]) and (os.stat(hdr[1:]).st_mode & 0o777) == 0o600 \
    and open(hdr[1:]).read() == "x-functions-key: CANARY-MASTER-KEY-0123456789\n" and "--max-time" in args and args[args.index("--max-time") + 1] == "60"
if not ok: sys.stdout.write("401"); sys.exit(0)
path = os.environ["FAKE_STATE"]
st = json.load(open(path))
mode = st["mode"]; n = st["runs"] + 1; st["runs"] = n
if mode == "http500":
    json.dump(st, open(path, "w")); sys.stdout.write("500"); sys.exit(0)
before = st["rows"]; before_ids = st["ids"]
st["stale"] = [st["rows"], st["ids"]]; st["before"] = st["stale"]; st["sched"] = []
st["lag"] = int(st.get("lagging") or 0)
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
elif mode == "revoked_only":   # run 1 only revokes: created 0, revoked 30, the rows are written all the same
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
elif mode == "late_reupload":   # run 2 re-uploads 2 rows; the first step of the trickle changes no total
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
    elif n == 2: st.update(rows=st["rows"] + 2)
elif mode == "revoked_dup":   # run 2 only revokes 2 (created 0, revoked 2)
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
    elif n == 2: st.update(rows=st["rows"] + 2)
elif mode == "delayed_dup":   # run 2 re-uploads 2 rows, and Log Analytics shows them only 50 minutes later
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
    elif n == 2: st.update(rows=st["rows"] + 2)
elif mode == "one_dup":   # run 2 loads exactly 1 row
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
    elif n == 2: st.update(rows=st["rows"] + 1)
elif mode in ("dead", "dead_busy", "dedup_unseen"):   # a product that loads nothing, ever
    st.update(table=True)
elif mode in ("flag_only", "flag_unseen", "flag_unseen_once"):   # run 1 pauses but the checkpoint shows no cursor; run 2 (catch-up) loads the rest
    if n == 1: st.update(rows=st["rows"] + 20, ids=7, table=True)
    elif n == 2: st.update(rows=st["rows"] + 10, ids=10)
else:  # good, unseen, unreadable_*, run_failed, step3_failed, no_step3, cp_unreadable: run 1 loads, later runs load nothing
    if n == 1: st.update(rows=st["rows"] + 30, ids=10, table=True)
st["created"] = st["rows"] - before; st["revoked"] = 0
if mode == "revoked_only" or (mode == "revoked_dup" and n == 2): st["created"], st["revoked"] = 0, st["rows"] - before
st.setdefault("ing", [])   # ingestion times of every row ever written (kept across runs)
if st["rows"] != before:
    if st.get("trickle"):   # the new rows land in steps, the first one now
        k = len(st["trickle"])
        st["sched"] = [[CLOCK() + off, before + (st["rows"] - before) * (j + 1) // k, before_ids + (st["ids"] - before_ids) * (j + 1) // k]
                       for j, off in enumerate(st["trickle"])]
        st["ing"] += [t for t, _, _ in st["sched"]]
    elif mode == "delayed_dup" and n == 2:
        st["sched"] = [[CLOCK() + 3000, st["rows"], st["ids"]]]; st["ing"].append(CLOCK() + 3000)
    else:   # the last rows of a run reach Log Analytics 5 minutes after the run ends (a lagging stats view: they are in, the view is stale)
        st["ing"].append(CLOCK() + st["run_seconds"] + (30 if st.get("lagging") else 300))
st["paused_last"] = bool(st["cursor_open"]) or (mode in ("flag_only", "flag_unseen", "flag_unseen_once") and n == 1)
json.dump(st, open(path, "w"))
sys.stdout.write("202")
'''

failures = []
CHECKS = 0
EXTRA = {}   # per scenario: the recorded `az functionapp stop` argv lines, the curl argv log, and whether the app ended Stopped


def check(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        failures.append(message)


def run(mode, table=True, lagging=False, rows0=0, ids0=0, run_seconds=0, trickle=None, lag_seconds=None, hide=False, name=None, xtrace=False, stop_fail=False, stop_noop=False):
    with tempfile.TemporaryDirectory() as tmp:
        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        for tool, body in (("az", FAKE_AZ), ("curl", FAKE_CURL), ("sleep", FAKE_SLEEP), ("date", FAKE_DATE)):
            path = os.path.join(bin_dir, tool)
            with open(path, "w") as handle:
                handle.write(body.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        state = os.path.join(tmp, "state.json")
        json.dump({"mode": mode, "runs": 0, "rows": rows0, "ids": ids0, "cursor_open": 0, "table": table,
                   "lagging": lagging, "run_seconds": run_seconds, "trickle": trickle, "hide": hide,
                   "stop_fail": stop_fail, "stop_noop": stop_noop,
                   "ing": [999900] if rows0 else []}, open(state, "w"))   # rows0: rows ingested 100 s before the script started
        open(os.path.join(tmp, "clock"), "w").write("1000000")
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"], FAKE_STATE=state, FAKE_CLOCK=os.path.join(tmp, "clock"),
                   FAKE_STOPLOG=os.path.join(tmp, "stoplog"), FAKE_ARGLOG=os.path.join(tmp, "arglog"),
                   SUBSCRIPTION_ID="sub", RESOURCE_GROUP="rg", WORKSPACE_NAME="ws",
                   ENABLE_AUDIT_LOGGING="false")
        if lag_seconds is not None:
            env["LAW_LAG_SECONDS"] = str(lag_seconds)
        done = subprocess.run(["bash"] + (["-x"] if xtrace else []) + [SCRIPT], capture_output=True, text=True, env=env, timeout=300)
        rd = lambda f: open(os.path.join(tmp, f)).read() if os.path.exists(os.path.join(tmp, f)) else ""
        EXTRA[name] = dict(stop=rd("stoplog").splitlines(), curl=rd("arglog"), stopped=json.load(open(state)).get("stopped"))
        return done.returncode, done.stdout + done.stderr, int(open(os.path.join(tmp, "clock")).read()) - 1000000


def verdict(out):
    for line in out.splitlines():
        if line.startswith("| Checkpoint Dedup"):
            return line
    return "(no verdict line)"


TRICKLE = [0, 200, 400, 600]
SCENARIOS = {
    "good": dict(mode="good", table=False),
    "paused": dict(mode="paused"),
    # a run that lasts its whole 9 minute budget (543 s, plus the Application Insights lag of up to 3 minutes): the default 48 hour lookback
    "slow_paused": dict(mode="paused", run_seconds=543 + 180),
    "slow_flag": dict(mode="flag_only", run_seconds=543 + 180),
    "flag_only": dict(mode="flag_only"),
    "flag_unseen": dict(mode="flag_unseen"),
    "flag_unseen_once": dict(mode="flag_unseen_once"),
    # hide=True: the function's log says 0 created from run 2 on, so only the Log Analytics comparison can see the re-upload
    "broken": dict(mode="broken", hide=True),
    # the log says what it loaded: the check fails on the function's own count, with no wait for Log Analytics
    "broken_log": dict(mode="broken"),
    "late_break_log": dict(mode="late_break"),
    "unseen": dict(mode="unseen"),
    "unreadable_after": dict(mode="unreadable_after"),
    "unreadable_before": dict(mode="unreadable_before"),
    "dead": dict(mode="dead"),
    "run_failed": dict(mode="run_failed"),
    "step3_failed": dict(mode="step3_failed"),
    "no_step3": dict(mode="no_step3"),
    "http500": dict(mode="http500", rows0=5, ids0=3),
    "late_break": dict(mode="late_break", hide=True),
    "cp_unreadable": dict(mode="cp_unreadable"),
    "cp_empty": dict(mode="cp_empty"),
    "never_caught_up": dict(mode="never_caught_up"),
    "lag_good": dict(mode="good", lagging=True),
    "lag_broken": dict(mode="broken", lagging=True, hide=True),
    # the stale value shows twice in a row before the loaded one lands: two equal reads are not "settled"
    "plateau_paused": dict(mode="paused", lagging=2),
    "plateau_broken": dict(mode="broken", lagging=2, hide=True),
    "drift": dict(mode="drift"),
    "drift_before": dict(mode="drift_before"),
    "drift_run2": dict(mode="drift_run2"),
    "unreadable_run2": dict(mode="unreadable_run2"),
    # the rows land in steps 200 s apart: three equal one-minute reads fit in a gap, a 4 minute quiet window does not
    "trickle_good": dict(mode="good", rows0=5, ids0=3, trickle=TRICKLE),
    "trickle_broken": dict(mode="broken", rows0=5, ids0=3, trickle=TRICKLE, hide=True, lag_seconds=3000),
    # run 1 only revokes (created 0, revoked 30): the rows still land late and the wait must still happen
    "trickle_revoked": dict(mode="revoked_only", rows0=5, ids0=3, trickle=TRICKLE),
    # rows keep arriving forever: the ceiling ends the wait, the verdict is CANNOT-MEASURE
    "never_quiet": dict(mode="never_quiet", rows0=5, ids0=3),
    "never_quiet_short": dict(mode="never_quiet", rows0=5, ids0=3, lag_seconds=300),
    # run 2 re-uploads 2 rows, the first trickle step moves no total: the After-run read must wait for quiet to see it
    "late_reupload": dict(mode="late_reupload", rows0=5, ids0=3, trickle=TRICKLE, hide=True, lag_seconds=3000),
    # (a) run 2 re-uploads 2 rows, the log says "2 created", Log Analytics shows them 50 minutes later (past every ceiling)
    "delayed_dup": dict(mode="delayed_dup", rows0=5, ids0=3),
    # (b) run 1's rows reach Log Analytics only after the ceiling: "quiet" is just "not yet", nothing arrived since run 1 ended
    # the arrival read fails: unknown is not "arrived"
    "arrival_unreadable": dict(mode="arrival_unreadable", rows0=5, ids0=3),
    # run 2 only revokes 2: revoked rows count as loaded
    "revoked_dup": dict(mode="revoked_dup"),
    # run 2 re-loads exactly 1 row
    "one_dup": dict(mode="one_dup"),
    # run 1 is seen and loads 0 (counts stay 0), the dedup runs are never seen: the stale 0 must not pass
    "dedup_unseen": dict(mode="dedup_unseen", rows0=5, ids0=3),
    "late_arrival": dict(mode="good", rows0=5, ids0=3, trickle=[3000]),
    # nothing is ever created while rows keep arriving: there is nothing to wait for, and no ceiling to hit
    "no_created": dict(mode="dead_busy", rows0=5, ids0=3),
    # cost control and the master key: the same good run under bash -x, and with a stop that fails or does nothing
    "good_xtrace": dict(mode="good", table=False, xtrace=True),
    "stop_fail": dict(mode="good", table=False, stop_fail=True),
    "stop_noop": dict(mode="good", table=False, stop_noop=True),
}
with ThreadPoolExecutor(max_workers=len(SCENARIOS)) as pool:
    futures = {name: pool.submit(run, name=name, **kw) for name, kw in SCENARIOS.items()}
    R = {name: f.result() for name, f in futures.items()}


def never_passes(name, what):
    rc, out, _ = R[name]
    check(rc == 1 and "PASS" not in verdict(out), "%s (rc=%d): %s" % (what, rc, verdict(out)))


rc, out, _ = R["good"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out,
      "a product that loads once then nothing did not pass (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["paused"]
check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
      "a run paused on its budget was not caught up before the dedup check (rc=%d): %s" % (rc, verdict(out)))

# The wait must outlast a run that takes its whole budget: with a shorter one every paused run is
# "not seen", the catch-up gives up and the dedup check is skipped (seen live, 1 Oct 2026).
rc, out, _ = R["slow_paused"]
check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
      "a run lasting its whole time budget was not waited for, so the dedup check did not run (rc=%d): %s" % (rc, verdict(out)))
check("The run paused on its time budget" in out,
      "the pause line of a run lasting its whole budget was not reported")

# The pause line alone, with no cursor in the checkpoint, still means "not caught up".
for name in ("flag_only", "slow_flag"):
    rc, out, _ = R[name]
    check(rc == 0 and "catch-up run 1" in out and "| Checkpoint Dedup      | PASS" in out,
          "%s: a run that reported a pause was not caught up before the dedup check (rc=%d): %s" % (name, rc, verdict(out)))

# A catch-up run that is not seen neither ends the drain nor counts as caught up.
rc, out, _ = R["flag_unseen"]
check(rc == 3 and "not seen; the checkpoint decides" in out and "| Checkpoint Dedup      | SKIPPED" in out,
      "catch-up runs that were never seen were taken as caught up (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["flag_unseen_once"]
check(rc == 0 and "catch-up run 2" in out and "| Checkpoint Dedup      | PASS" in out,
      "one unseen catch-up run ended the drain instead of the next one finishing it (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["broken"]
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

rc, out, _ = R["broken_log"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 loaded 30 new indicators (30 created, 0 revoked), expected 0" in out and "baseline:" in out,
      "a dedup run that logged 30 created did not fail on the function's own count (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["late_break_log"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 3 loaded 30 new indicators" in out,
      "run 3 logged 30 created and did not fail on the function's own count (rc=%d): %s" % (rc, verdict(out)))
# (a) The duplicate that Log Analytics shows after the ceiling: the log alone fails it, at run 2, without waiting.
rc, out, el = R["delayed_dup"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 loaded 2 new indicators" in out and "After run 2" not in out,
      "a duplicate Log Analytics shows only after the ceiling was not failed on the function's log (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["arrival_unreadable"]
check(rc == 3 and "| Checkpoint Dedup      | CANNOT-MEASURE" in out,
      "an unreadable arrival read was taken as arrived (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["one_dup"]
check(rc == 1 and "FAIL (run 2 loaded 1 new indicators (1 created, 0 revoked), expected 0" in out,
      "a dedup run that reloaded exactly 1 indicator did not fail on the function's own count (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["dedup_unseen"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 was not seen)" in out,
      "a dedup run that was never seen did not fail as not seen (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["revoked_dup"]
check(rc == 1 and "FAIL (run 2 loaded 2 new indicators (0 created, 2 revoked), expected 0" in out,
      "a dedup run that only revoked 2 did not fail on the function's own count (rc=%d): %s" % (rc, verdict(out)))
# (b) Nothing ingested since run 1 ended and the ceiling passed: "quiet" is not a measurement.
rc, out, _ = R["late_arrival"]
check(rc == 3 and "| Checkpoint Dedup      | CANNOT-MEASURE" in out and "after the last import ended: 0" in out,
      "a Log Analytics with no row since the last import ended was taken as quiet (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["late_break"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 3 changed" in out,
      "a product that re-uploads only on run 3 was not caught (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["never_caught_up"]
check(rc == 3 and "| Checkpoint Dedup      | SKIPPED" in out and "PASS" not in verdict(out),
      "a collection that never caught up did not report SKIPPED with exit 3 (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["lag_good"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out,
      "Log Analytics lag made a clean product fail (rc=%d): %s" % (rc, verdict(out)))

rc, out, _ = R["lag_broken"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "Log Analytics lag hid a re-upload: the first read after a run was taken as settled (rc=%d): %s" % (rc, verdict(out)))

# A baseline read on a two-read plateau (seen live, 2 Oct 2026) must not be taken as settled.
rc, out, _ = R["plateau_paused"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out,
      "a plateau in Log Analytics ingestion was taken as the baseline and failed a clean product (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["plateau_broken"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "a plateau in Log Analytics ingestion hid a re-upload (rc=%d): %s" % (rc, verdict(out)))
# A Log Analytics that never settles cannot be measured: neither PASS nor FAIL.
rc, out, _ = R["drift"]
check(rc == 3 and "| Checkpoint Dedup      | CANNOT-MEASURE" in out,
      "a Log Analytics that never settles did not report CANNOT-MEASURE with exit 3 (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["drift_run2"]
check(rc == 3 and "CANNOT-MEASURE (Log Analytics did not settle after run 2" in out,
      "a Log Analytics that stops settling after run 2 was not CANNOT-MEASURE / exit 3 (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["unreadable_run2"]
check(rc == 1 and "FAIL (Log Analytics unreadable after run 2" in out,
      "an unreadable Log Analytics after run 2 was not FAIL / exit 1 (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["drift_before"]
check(rc == 3 and "CANNOT-MEASURE: no stable baseline" in out,
      "a baseline that never settles was not CANNOT-MEASURE / exit 3 (rc=%d): %s" % (rc, out[-200:]))
rc, out, _ = R["unreadable_before"]
check(rc == 1, "an unreadable baseline did not exit 1 (rc=%d)" % rc)

# A trickle: the Test 4 reads wait until nothing was ingested in the last LAW_QUIET_MINUTES.
rc, out, _ = R["trickle_good"]
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out and "Log Analytics not settled" in out,
      "a clean product failed on rows that trickle in over ten minutes (rc=%d): %s" % (rc, verdict(out)))
check("\nLog Analytics (rows ids): 5 3 -> 35 10 (last settled read)" in out,
      "the summary line is not the last settled read: %s" % [l for l in out.splitlines() if l.startswith("Log Analytics")])
rc, out, _ = R["trickle_broken"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "a re-upload hidden by a trickle was not caught (rc=%d): %s" % (rc, verdict(out)))
# Run 1 revoked only (created 0): revoked rows are written to Log Analytics too, so the wait is still needed.
rc, out, _ = R["trickle_revoked"]
check("0 created, 0 skipped, 0 failed, 30 revoked" in out, "the revoked-only scenario did not report 30 revoked and 0 created")
check(rc == 0 and "| Checkpoint Dedup      | PASS" in out and "Log Analytics not settled" in out,
      "a run that only revoked did not wait for Log Analytics to go quiet (rc=%d): %s" % (rc, verdict(out)))
# Rows that never stop arriving: the ceiling (LAW_LAG_SECONDS) ends the wait, the verdict is CANNOT-MEASURE.
rc, out, long_elapsed = R["never_quiet"]
check(rc == 3 and "| Checkpoint Dedup      | CANNOT-MEASURE" in out,
      "rows that never stop arriving were not CANNOT-MEASURE with exit 3 (rc=%d): %s" % (rc, verdict(out)))
rc, out, short_elapsed = R["never_quiet_short"]
check(rc == 3 and "| Checkpoint Dedup      | CANNOT-MEASURE" in out and long_elapsed - short_elapsed >= 500,
      "LAW_LAG_SECONDS does not bound the wait: ceiling 900 took %ds, ceiling 300 took %ds" % (long_elapsed, short_elapsed))
check(long_elapsed < 1100, "the quiet wait went on long after the 900 s ceiling (%d s)" % long_elapsed)
# A Storage Checkpoint FAIL row is a failed check, whatever the dedup row says.
rc, out, _ = R["cp_empty"]
check(rc == 1 and "| Storage Checkpoint    | FAIL" in out and "| Checkpoint Dedup      | PASS" in out,
      "an empty checkpoint table did not exit 1 (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["late_reupload"]
check(rc == 1 and "| Checkpoint Dedup      | FAIL (run 2 changed" in out,
      "a re-upload whose first step moved no total was not caught at run 2 (rc=%d): %s" % (rc, verdict(out)))
rc, out, _ = R["no_created"]
check(rc == 0 and "Log Analytics not settled" not in out and "| Checkpoint Dedup      | PASS" in out,
      "waited for Log Analytics although no run created or revoked an indicator (rc=%d): %s" % (rc, verdict(out)))

# Cost control: whatever the exit code (0, 1, 3), the app is stopped in the right subscription and read back Stopped.
for name in SCENARIOS:
    if name in ("stop_fail", "stop_noop"):
        continue
    stops = EXTRA[name]["stop"]
    check(len(stops) >= 1 and all("--subscription sub" in l and "--name socradar-taxii-test" in l and "-g rg" in l for l in stops) and EXTRA[name]["stopped"],
          "%s (rc=%d): the cleanup did not stop the app with --subscription (stop calls: %s)" % (name, R[name][0], stops))
check({R[n][0] for n in ("good", "broken", "never_caught_up")} == {0, 1, 3}, "the exit 0/1/3 stop scenarios did not exit 0, 1 and 3")
# A stop that failed, or an app not read back as Stopped, is a non-zero exit even when every check was green.
rc, out, _ = R["stop_fail"]
check(rc == 1 and "functionapp stop failed" in out, "a failed stop did not make the exit code non-zero (rc=%d)" % rc)
rc, out, _ = R["stop_noop"]
check(rc == 1 and "not Stopped" in out, "an app not read back as Stopped did not make the exit code non-zero (rc=%d)" % rc)
# The master key never reaches argv (ps) or the output, not even under bash -x; curl gets it through a 0600 -H @file.
for name in SCENARIOS:
    check("CANARY-MASTER-KEY" not in R[name][1] and "CANARY-MASTER-KEY" not in EXTRA[name]["curl"],
          "%s: the master key reached the output or curl's argv" % name)
rc, out, _ = R["good_xtrace"]
check(rc == 0 and "-H @" in EXTRA["good_xtrace"]["curl"] and "--max-time 60" in EXTRA["good_xtrace"]["curl"] and "| Checkpoint Dedup      | PASS" in out,
      "curl did not get the key through -H @file with --max-time 60 (rc=%d): %s" % (rc, EXTRA["good_xtrace"]["curl"][:200]))

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
