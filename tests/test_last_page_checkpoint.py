#!/usr/bin/env python3
"""The last page must not be fetched and re-uploaded on every later run.

A TAXII 2.1 server answers the last page with more=false and no next cursor.
The checkpoint used to keep the cursor that fetched that page, so each later
run asked for it again and re-uploaded it: the same 48 indicators were
reported as created four runs in a row (measured 6 Sep 2026). The server does
say where it stopped, in the X-TAXII-Date-Added-Last header, and the next run
has to continue from there.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


LAST = "2026-09-06T05:47:20.859487Z"
OK = [Response(200, {"errors": []})]

# 1. Last page with the marker: the checkpoint drops the cursor and pins
#    added_after to the marker, so the next run asks only for newer objects.
table = FakeTable(entity={"Cursor": "cursor-9", "AddedAfter": "2026-09-06T05:27:54.000Z"})
stub = FakeRequests(get_responses=[Response(200, page(["1.1.1.1"], more=False), headers={"X-TAXII-Date-Added-Last": LAST})],
                    post_responses=OK)
make_processor(stub, table=table, sleeps=[]).run()
check(table.upserts and table.upserts[-1]["Cursor"] == "", "the stale cursor was kept on the last page: %r" % table.upserts)
check(table.upserts and table.upserts[-1]["AddedAfter"] == LAST, "added_after was not moved to the marker: %r" % table.upserts)

# 1b. The next run then fetches with that added_after and no cursor.
resumed = FakeTable(entity={"Cursor": "", "AddedAfter": LAST})
stub = FakeRequests(get_responses=[Response(200, page([], more=False))], post_responses=OK)
make_processor(stub, table=resumed, sleeps=[]).run()
asked = stub.get_calls[0][1] or {}
check(asked.get("added_after") == LAST and "next" not in asked,
      "the resumed run did not continue from the marker: %r" % asked)

# 2. A middle page keeps advancing by cursor and leaves added_after alone.
table = FakeTable(entity={"Cursor": "cursor-1", "AddedAfter": "2026-09-06T05:27:54.000Z"})
stub = FakeRequests(get_responses=[Response(200, page(["2.2.2.2"], more=True, next_cursor="cursor-2"), headers={"X-TAXII-Date-Added-Last": LAST}),
                                   Response(200, page(["3.3.3.3"], more=False), headers={"X-TAXII-Date-Added-Last": LAST})],
                    post_responses=OK)
make_processor(stub, table=table, sleeps=[]).run()
check(table.upserts and table.upserts[0]["Cursor"] == "cursor-2" and table.upserts[0]["AddedAfter"] == "2026-09-06T05:27:54.000Z",
      "a page with a cursor did not advance by cursor: %r" % table.upserts[:1])

# 3. No marker from the server: the old behaviour stays (cursor kept), so an
#    unusual server never makes the run skip anything.
table = FakeTable(entity={"Cursor": "cursor-9", "AddedAfter": "2026-09-06T05:27:54.000Z"})
stub = FakeRequests(get_responses=[Response(200, page(["4.4.4.4"], more=False))], post_responses=OK)
make_processor(stub, table=table, sleeps=[]).run()
check(table.upserts and table.upserts[-1]["Cursor"] == "cursor-9", "without a marker the cursor was dropped: %r" % table.upserts)

# 4. A last page whose upload failed keeps the cursor that fetched it, so the
#    next run repeats the page instead of skipping past it.
table = FakeTable(entity={"Cursor": "cursor-9", "AddedAfter": "2026-09-06T05:27:54.000Z"})
stub = FakeRequests(get_responses=[Response(200, page(["5.5.5.5"], more=False), headers={"X-TAXII-Date-Added-Last": LAST})],
                    post_responses=[Response(500)])
make_processor(stub, table=table, sleeps=[]).run()
check(table.upserts and table.upserts[-1]["Cursor"] == "cursor-9", "a failed last page moved the checkpoint: %r" % table.upserts)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("the last page is not re-uploaded on later runs: OK (%d checks)" % 6)
