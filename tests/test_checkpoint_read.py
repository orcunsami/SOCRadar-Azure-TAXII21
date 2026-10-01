#!/usr/bin/env python3
"""A checkpoint that cannot be read must not look like a first run.

get_checkpoint swallowed every exception and answered "nothing saved yet".
A 503 or a role assignment that had not propagated made a running deployment
restart from 1970: with InitialLookbackHours=0 that reloads the whole history,
with the default 48 it silently skips anything older than two days that was
still waiting. Only "no such entity" means first run; every other failure has
to stop the collection so the checkpoint stays where it is.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


class BrokenTable(FakeTable):
    def get_entity(self, partition_key, row_key):
        raise ConnectionError("table service unavailable")


OK = [Response(200, {"errors": []})]

# 1. Read failure: the run raises and asks the TAXII server for nothing.
stub = FakeRequests(get_responses=[Response(200, page(["1.1.1.1"]))], post_responses=OK)
table = BrokenTable()
raised = None
try:
    make_processor(stub, table=table, sleeps=[]).run()
except ConnectionError as exc:
    raised = exc
check(raised is not None, "a failed checkpoint read did not stop the run")
check(not stub.get_calls, "a failed checkpoint read still fetched from 1970: %r" % stub.get_calls)
check(not table.upserts, "a failed checkpoint read overwrote the checkpoint: %r" % table.upserts)

# 2. A missing entity is the real first run and still works, with lookback.
stub = FakeRequests(get_responses=[Response(200, page(["2.2.2.2"]))], post_responses=OK)
table = FakeTable()
result = make_processor(stub, table=table, sleeps=[], initial_lookback_hours=48).run()
asked = (stub.get_calls[0][1] if stub.get_calls else None) or {}
check(result["indicators_created"] == 1, "first run did not import: %r" % result)
check(asked.get("added_after", "").startswith("20"), "first run ignored the lookback window: %r" % asked)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("an unreadable checkpoint stops the run, a missing one is a first run: OK (5 checks)")
