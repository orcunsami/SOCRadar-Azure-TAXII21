#!/usr/bin/env python3
"""An upload that never reached Microsoft Sentinel must not move the checkpoint.

Re-uploading a batch that already landed is safe (Sentinel updates the
indicator). Advancing past one that did not land is not recoverable. These
checks encode that asymmetry.

"Not moving" the checkpoint means writing the same position again, not writing
nothing. On the very first run there is no row at all, and skipping the write
leaves the next run to derive its window from its own clock: it would start
later than this one did and step over the oldest indicators on the page that
just failed. Writing pins the window where this run began.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def run_once(post_responses, table=None, get_responses=None, **kwargs):
    table = table if table is not None else FakeTable()
    stub = FakeRequests(
        get_responses=get_responses or [Response(200, page(["1.1.1.1", "2.2.2.2"], more=True, next_cursor="cursor-2"))],
        post_responses=post_responses,
    )
    sleeps = []
    processor = make_processor(stub, table=table, sleeps=sleeps, **kwargs)
    return processor.run(), table, stub, sleeps


# 1. Upload keeps failing on the first page: the checkpoint must not move past
#    it. The cursor stays at the value that fetched this page, so the next run
#    asks for the same page again.
result, table, stub, _ = run_once([Response(503, headers={"Retry-After": "0"})],
                                  initial_lookback_hours=48)
check(len(table.upserts) == 1, "the failed page left no checkpoint at all: %r" % table.upserts)
check(table.upserts and table.upserts[0]["Cursor"] == "",
      "the checkpoint moved past the page that never landed: %r" % table.upserts)
check(result["indicators_failed"] == 2, "failed indicators were not counted: %r" % result["indicators_failed"])
check(result["indicators_created"] == 0, "indicators were reported as created after a failed upload")
check(result["complete"] is False, "the run reported itself complete after losing indicators")

# 1b. That write also has to pin the lookback window. Without it the next run
#     is still a first run and recomputes added_after from its own clock, which
#     silently skips everything older than the gap between the two runs.
written = table.upserts[0]["AddedAfter"] if table.upserts else ""
check(written != "1970-01-01T00:00:00Z" and written != "",
      "the failed first run did not pin its lookback window: %r" % written)
resumed = FakeTable(entity={"Cursor": "", "AddedAfter": written})
_, _, resumed_stub, _ = run_once([Response(200, {"errors": []})], table=resumed,
                                 get_responses=[Response(200, page(["1.1.1.1"], more=False))],
                                 initial_lookback_hours=48)
asked_for = (resumed_stub.get_calls[0][1] or {}).get("added_after")
check(asked_for == written,
      "the resumed run did not fetch from the pinned window: asked %r, pinned %r"
      % (asked_for, written))

# 2. Upload succeeds: the checkpoint must move, otherwise the feed never advances.
ok_page = [Response(200, page(["3.3.3.3"], more=False))]
result, table, _, _ = run_once([Response(200, {"errors": []})], get_responses=ok_page)
check(len(table.upserts) == 1, "a successful page did not write a checkpoint")
check(table.upserts and table.upserts[0]["Cursor"] == "", "unexpected cursor written: %r" % table.upserts)
check(result["complete"] is True, "a clean run was reported as incomplete")
check(result["indicators_failed"] == 0, "a clean run reported failed indicators")

# 3. A 200 that rejects indicators is a different thing: those are skipped, not
#    failed. Retrying them changes nothing, so the checkpoint must still move.
result, table, _, _ = run_once([Response(200, {"errors": [{"recordIndex": 0}]})], get_responses=ok_page)
check(len(table.upserts) == 1, "a rejected-but-delivered indicator blocked the checkpoint")
check(result["indicators_skipped"] == 1, "rejected indicators were not counted as skipped")
check(result["indicators_failed"] == 0, "rejected indicators were miscounted as failed")
check(result["complete"] is True, "a delivered page with rejections was reported incomplete")

# 4. The failure must stop the run rather than march on to the next page. A
#    later page would otherwise write its own checkpoint and bury the gap.
stub = FakeRequests(
    get_responses=[Response(200, page(["4.4.4.4"], more=True, next_cursor="cursor-2"))],
    post_responses=[Response(500)],
)
table = FakeTable()
make_processor(stub, table=table, sleeps=[]).run()
check(len(stub.get_calls) == 1, "the run fetched another page after losing indicators: %d fetches" % len(stub.get_calls))

# 5. Mid-run failure: page 1 lands, page 2 does not. The checkpoint must end up
#    on the cursor that fetched page 2, not the one page 2 handed back, so the
#    next run repeats page 2 instead of jumping to page 3.
stub = FakeRequests(
    get_responses=[
        Response(200, page(["5.5.5.5"], more=True, next_cursor="cursor-2")),
        Response(200, page(["6.6.6.6"], more=True, next_cursor="cursor-3")),
    ],
    post_responses=[Response(200, {"errors": []}), Response(500)],
)
table = FakeTable()
result = make_processor(stub, table=table, sleeps=[]).run()
check(len(table.upserts) == 2, "expected a checkpoint per page, got %r" % table.upserts)
check(table.upserts and table.upserts[-1]["Cursor"] == "cursor-2",
      "the checkpoint skipped the page that never landed: %r" % table.upserts)
check(result["indicators_created"] == 1, "the page that did land was not counted: %r" % result)
check(result["complete"] is False, "a run that lost a page reported itself complete")

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("upload failure never advances the checkpoint: OK (%d checks)" % 20)
