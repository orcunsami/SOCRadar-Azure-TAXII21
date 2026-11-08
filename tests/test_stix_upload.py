#!/usr/bin/env python3
"""The TAXII STIX upload wire contract fails closed on ambiguous 200 responses."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, indicator, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def records(count=3):
    return [indicator("198.51.100.%d" % n) for n in range(count)]


def upload(responses, batch=None, **kwargs):
    stub = FakeRequests(post_responses=responses)
    sleeps = []
    processor = make_processor(stub, sleeps=sleeps, **kwargs)
    return processor.upload_batch(batch or records()), stub, sleeps, processor


# Pin the exact product URL and new envelope, not merely that a POST occurred.
(created, skipped, failed, rejected), stub, _, _ = upload([Response(200, {"errors": []})])
check((created, skipped, failed, rejected) == (3, 0, 0, set()), "clean upload miscounted")
url = stub.post_calls[0][0] if stub.post_calls else ""
body = stub.post_bodies[0] if stub.post_bodies else {}
check(url == "https://api.ti.sentinel.azure.com/workspaces/workspace/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview",
      "wrong STIX upload URL: %r" % url)
check(set(body) == {"sourcesystem", "stixobjects"}, "wrong upload envelope: %r" % body)
check(body.get("sourcesystem") == "SOCRadar TAXII" and body.get("sourcesystem") != "Microsoft Sentinel",
      "source system drifted: %r" % body.get("sourcesystem"))
check(body.get("stixobjects") == records(), "STIX records were not sent intact: %r" % body)

for label, response in (
    ("empty", Response(200, ValueError("must not parse"), text="")),
    ("whitespace", Response(200, ValueError("must not parse"), text=" \t\n")),
):
    result, stub, _, _ = upload([response])
    check(result == (3, 0, 0, set()) and len(stub.post_calls) == 1,
          "%s 200 was not accepted as all-created: %r" % (label, result))

# A zero-based unique rejection set drives both counters and the revoked
# arithmetic used by run(); duplicated response rows must not double-count.
result, _, _, _ = upload([Response(200, {"errors": [
    {"recordIndex": 1, "errorMessages": ["bad"]},
    {"recordIndex": 1, "errorMessages": ["duplicate"]},
]})])
check(result == (2, 1, 0, {1}), "duplicate indexes changed rejection arithmetic: %r" % (result,))

# Live Sentinel uses validationErrorMessages rather than the documented
# errorMessages spelling; recordIndex remains the only required field.
result, _, _, _ = upload([Response(200, {"errors": [{
    "recordIndex": 1,
    "validationErrorMessages": ["Error for Property=id: Required property is missing. Actual value: NULL."],
}]})])
check(result == (2, 1, 0, {1}),
      "live validationErrorMessages rejection was not accepted: %r" % (result,))

invalid = [
    ("boolean response", True),
    ("array response", []),
    ("missing errors", {"status": "unknown"}),
    ("non-list errors", {"errors": {}}),
    ("non-dict error", {"errors": ["bad"]}),
    ("boolean index", {"errors": [{"recordIndex": True}]}),
    ("negative index", {"errors": [{"recordIndex": -1}]}),
    ("out-of-range index", {"errors": [{"recordIndex": 3}]}),
    ("missing index", {"errors": [{"errorMessages": ["bad"]}]}),
    ("non-json response", ValueError("not json")),
]
for label, payload in invalid:
    try:
        result, stub, _, _ = upload([Response(200, payload)])
        check(result == (0, 0, 3, set()), "%s was not failed closed: %r" % (label, result))
        check(len(stub.post_calls) == 1, "%s retried a 200 response" % label)
    except Exception as exc:
        failures.append("%s escaped as %r" % (label, exc))

result, stub, _, _ = upload([], records(101))
check(result == (0, 0, 101, set()) and not stub.post_calls,
      "101-object batch made HTTP calls or was miscounted: %r %r" % (result, stub.post_calls))

result, stub, sleeps, _ = upload([Response(503, headers={"Retry-After": "0"})])
check(result == (0, 0, 3, set()) and len(stub.post_calls) == 3 and sleeps == [0.0, 0.0],
      "retry cap changed: result=%r calls=%d sleeps=%r" % (result, len(stub.post_calls), sleeps))
stub = FakeRequests(post_responses=[Response(429, headers={"Retry-After": "30"})])
sleeps = []
processor = make_processor(stub, sleeps=sleeps, time_budget_seconds=5)
processor._run_start = time.time()
result = processor.upload_batch(records())
check(result == (0, 0, 3, set()) and len(stub.post_calls) == 1 and sleeps == [],
      "retry crossed the time budget: %r %d %r" % (result, len(stub.post_calls), sleeps))

# Fail-closed parsing must also preserve the real page checkpoint. A revoked
# accepted object is separately covered in test_revoked_upload.py; this check
# pins the opposite, malformed-response path.
table = FakeTable()
stub = FakeRequests(
    get_responses=[Response(200, page(["203.0.113.8"], more=True, next_cursor="next"))],
    post_responses=[Response(200, {"errors": [{"recordIndex": True}]})],
)
result = make_processor(stub, table=table, sleeps=[]).run()
check(result["indicators_failed"] == 1 and result["complete"] is False,
      "malformed 200 was reported as delivered: %r" % result)
check(table.upserts and table.upserts[-1]["Cursor"] == "",
      "malformed 200 advanced the TAXII checkpoint: %r" % table.upserts)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("STIX upload contract: OK")
