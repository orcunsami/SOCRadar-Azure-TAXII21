#!/usr/bin/env python3
"""A revoked indicator must reach Microsoft Sentinel, flagged as revoked.

Sentinel learns that SOCRadar withdrew an indicator only when the withdrawn
version is uploaded with `revoked: true` (measured 6 Sep 2026 against the
upload API: the flag is stored and returned by queryIndicators). Dropping the
object before upload, as the code once did, left the indicator active. The
audit counter `IndicatorsRevoked` has to mean "revoked indicators Sentinel
accepted", so a revoked indicator that was rejected or never arrived is not
counted as revoked.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, indicator, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def run(objects, post_responses):
    stub = FakeRequests(
        get_responses=[Response(200, page([], objects=objects))],
        post_responses=post_responses,
    )
    table = FakeTable()
    result = make_processor(stub, table=table, sleeps=[]).run()
    return result, stub, table


live = indicator("1.1.1.1")
withdrawn = indicator("2.2.2.2", revoked=True, modified="2026-09-06T00:00:00.000Z")

# 1. Both are uploaded; the revoked one keeps its flag and is counted as
#    revoked rather than created.
result, stub, _ = run([live, withdrawn], [Response(200, {"errors": []})])
sent = stub.post_bodies[0].get("indicators", []) if stub.post_bodies else []
check(len(sent) == 2, "expected both indicators in the upload, got %d" % len(sent))
by_id = {i.get("id"): i for i in sent}
check(by_id.get(withdrawn["id"], {}).get("revoked") is True,
      "the revoked flag did not survive preparation: %r" % by_id.get(withdrawn["id"]))
check(by_id.get(live["id"], {}).get("revoked") is None, "a live indicator was marked revoked")
check("labels" in by_id.get(withdrawn["id"], {}) and "extensions" in by_id.get(withdrawn["id"], {}),
      "the revoked indicator was not prepared like the others")
check(result["indicators_revoked"] == 1, "revoked upload not counted: %r" % result["indicators_revoked"])
check(result["indicators_created"] == 1, "revoked upload was counted as created: %r" % result["indicators_created"])
check(result["indicators_skipped"] == 0 and result["indicators_failed"] == 0, "clean run reported losses")
check(result["complete"] is True, "clean run reported incomplete")

# 2. A revoked object without a pattern cannot be sent and is not counted.
broken = dict(withdrawn, id="indicator--broken")
del broken["pattern"]
result, stub, _ = run([live, broken], [Response(200, {"errors": []})])
sent = stub.post_bodies[0].get("indicators", []) if stub.post_bodies else []
check(len(sent) == 1 and sent[0]["id"] == live["id"], "a revoked object without a pattern was uploaded")
check(result["indicators_revoked"] == 0, "an unsendable revoked object was counted as revoked")

# 3. Sentinel rejects the revoked one: it is skipped, not revoked.
result, stub, _ = run([live, withdrawn], [Response(200, {"errors": [{"recordIndex": 1}]})])
check(result["indicators_revoked"] == 0, "a rejected revoked indicator was counted as revoked")
check(result["indicators_skipped"] == 1, "the rejection was not counted as skipped")
check(result["indicators_created"] == 1, "the live indicator was not counted as created")

# 3b. Sentinel rejects the live one: the revoked one still counts.
result, _, _ = run([live, withdrawn], [Response(200, {"errors": [{"recordIndex": 0}]})])
check(result["indicators_revoked"] == 1 and result["indicators_created"] == 0 and result["indicators_skipped"] == 1,
      "rejection of the live indicator was attributed to the revoked one: %r" % result)

# 4. The batch never lands: nothing is revoked, both are failed, checkpoint held.
result, _, table = run([live, withdrawn], [Response(500)])
check(result["indicators_revoked"] == 0, "a failed upload was counted as revoked")
check(result["indicators_failed"] == 2, "a failed upload did not count both indicators as failed")
check(table.upserts and table.upserts[-1]["Cursor"] == "", "the checkpoint moved past the failed page")

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("revoked indicators reach Sentinel flagged as revoked: OK (%d checks)" % 18)
