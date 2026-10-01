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

# 5. more=true with no next cursor is a server fault. The same page would be
#    fetched and re-uploaded until the time budget ran out, so the run stops
#    after one request and says it did not finish.
table = FakeTable(entity={"Cursor": "", "AddedAfter": "2026-09-06T05:27:54.000Z"})
stub = FakeRequests(get_responses=[Response(200, page(["6.6.6.6"], more=True, next_cursor=""),
                                            headers={"X-TAXII-Date-Added-Last": LAST})],
                    post_responses=OK)
try:
    result = make_processor(stub, table=table, sleeps=[]).run()
except AssertionError as exc:
    result = {}
    check(False, "more=true without next kept refetching the page: %s" % exc)
check(len(stub.get_calls) == 1, "more=true without next fetched %d times" % len(stub.get_calls))
check(result.get("complete") is False, "a run stuck on more=true without next reported complete: %r" % result)

# 5b. Same fault on the very first run, with no checkpoint row and a lookback
#     window. Stopping without writing leaves no row, so the next run would
#     start from its own clock minus the window and step over the older
#     indicators beyond page 1. The stop saves added_after like a failed page.
table = FakeTable(entity=None)
stub = FakeRequests(get_responses=[Response(200, page(["7.7.7.7"], more=True, next_cursor=""))], post_responses=OK)
result = make_processor(stub, table=table, sleeps=[], initial_lookback_hours=48).run()
check(result.get("complete") is False, "first run stuck on more=true without next reported complete: %r" % result)
check(len(table.upserts) == 1 and table.upserts[-1]["AddedAfter"] and table.upserts[-1]["Cursor"] == "",
      "more=true without next on a first run wrote no pinned checkpoint: %r" % table.upserts)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("the last page is not re-uploaded on later runs: OK (%d checks)" % 11)
