#!/usr/bin/env python3
"""An upload that never reached Microsoft Sentinel must not move the checkpoint.

This is the defect that made the integration lose customer data silently. A
single 429 or 503 from the threat-intelligence upload API returned a swallowed
error, the run kept going, the checkpoint advanced past the page, and the audit
row said Success. Nothing in the workspace could show the gap afterwards,
because the checkpoint is the only record of where the feed had got to.

Re-uploading a batch that already landed is safe (Sentinel updates the
indicator). Advancing past one that did not land is not recoverable. These
checks encode that asymmetry.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def run_once(post_responses, table=None, get_responses=None):
    table = table if table is not None else FakeTable()
    stub = FakeRequests(
        get_responses=get_responses or [Response(200, page(["1.1.1.1", "2.2.2.2"], more=True, next_cursor="cursor-2"))],
        post_responses=post_responses,
    )
    sleeps = []
    processor = make_processor(stub, table=table, sleeps=sleeps)
    return processor.run(), table, stub, sleeps


# 1. Upload keeps failing: the checkpoint must stay where it was.
result, table, stub, _ = run_once([Response(503, headers={"Retry-After": "0"})])
check(table.upserts == [], "the checkpoint was written even though the upload never landed")
check(result["indicators_failed"] == 2, "failed indicators were not counted: %r" % result["indicators_failed"])
check(result["indicators_created"] == 0, "indicators were reported as created after a failed upload")
check(result["complete"] is False, "the run reported itself complete after losing indicators")

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

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("upload failure never advances the checkpoint: OK (%d checks)" % 14)
