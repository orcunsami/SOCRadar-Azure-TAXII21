#!/usr/bin/env python3
"""A run that stopped on its time budget must say so, and must not lose its place.

With the default 48 hour lookback a first run is longer than the 540 second
budget. The processor pauses and returns complete, so the audit row used to read
Success with an empty message: nobody watching the audit table could tell a
finished collection from one still catching up. The result now carries `paused`
(the audit row side is checked in test_audit_status.py), and the checkpoint the
pause leaves behind has to continue exactly where the run stopped.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


OK = [Response(200, {"errors": []})]

# 1. First run, default-style lookback, budget gone after the first page: the
#    run stops after one fetch, reports paused (and still complete: nothing was
#    lost), and pins the checkpoint to the NEXT cursor with the lookback
#    timestamp this run started from, so the next run continues, not restarts.
table = FakeTable()
stub = FakeRequests(get_responses=[Response(200, page(["1.1.1.1"], more=True, next_cursor="cursor-2"))],
                    post_responses=OK)
result = make_processor(stub, table=table, sleeps=[], initial_lookback_hours=48,
                        time_budget_seconds=1e-9).run()
asked = (stub.get_calls[0][1] or {}).get("added_after")
check(len(stub.get_calls) == 1, "the run kept fetching after its budget was gone: %d fetches" % len(stub.get_calls))
check(result.get("paused") is True, "a budget stop did not report paused: %r" % result.get("paused"))
check(result["complete"] is True, "a budget stop was reported as incomplete (nothing was lost): %r" % result["complete"])
check(bool(asked), "the first fetch carried no added_after lookback")
check(table.upserts and table.upserts[-1]["Cursor"] == "cursor-2",
      "the pause did not pin the next cursor: %r" % table.upserts)
check(table.upserts and table.upserts[-1]["AddedAfter"] == asked,
      "the pause moved or lost the lookback timestamp: %r vs %r" % (table.upserts[-1:] , asked))

# 1b. The next run starts from that checkpoint: cursor, no new lookback.
resumed = FakeTable(entity={"Cursor": "cursor-2", "AddedAfter": asked})
stub = FakeRequests(get_responses=[Response(200, page(["2.2.2.2"], more=False))], post_responses=OK)
result = make_processor(stub, table=resumed, sleeps=[], initial_lookback_hours=48).run()
params = stub.get_calls[0][1] or {}
check(params.get("next") == "cursor-2" and "added_after" not in params,
      "the run after a pause did not continue by cursor: %r" % params)
check(result.get("paused") is False, "a run that finished reported paused: %r" % result.get("paused"))

# 2. A run that finishes inside its budget is not paused, even with a budget.
stub = FakeRequests(get_responses=[Response(200, page(["3.3.3.3"], more=False))], post_responses=OK)
result = make_processor(stub, table=FakeTable(), sleeps=[], time_budget_seconds=540).run()
check(result.get("paused") is False, "a run inside its budget reported paused: %r" % result.get("paused"))

# 3. The last page and the budget arrive together: nothing is pending, so the
#    run is finished, not paused.
stub = FakeRequests(get_responses=[Response(200, page(["4.4.4.4"], more=False))], post_responses=OK)
result = make_processor(stub, table=FakeTable(), sleeps=[], time_budget_seconds=1e-9).run()
check(result.get("paused") is False, "a finished run was reported as paused: %r" % result.get("paused"))

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("a budget pause is reported and resumes where it stopped: OK (10 checks)")
