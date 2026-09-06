#!/usr/bin/env python3
"""Retries have to be bounded, and they have to end before the host kills us.

The Function App runs on a ten minute host timeout and gives each collection a
slice of a nine minute budget. A kill mid-sleep leaves no audit row at all, so
a retry that would sleep past the budget is worse than giving up and reporting
the failure. These checks pin all three edges: what is retried, how long it
waits, and when it refuses to wait.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeRequests, FakeTable, Response, make_processor, page

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def upload(responses, **kwargs):
    stub = FakeRequests(post_responses=responses)
    sleeps = []
    processor = make_processor(stub, sleeps=sleeps, **kwargs)
    created, skipped, failed, _ = processor.upload_batch([{"id": "indicator--1"}])
    return created, skipped, failed, sleeps, stub


# Retry-After is obeyed verbatim when the server sends it.
_, _, failed, sleeps, stub = upload([Response(429, headers={"Retry-After": "7"})])
check(sleeps == [7.0, 7.0], "Retry-After was not honoured: %r" % sleeps)
check(len(stub.post_calls) == 3, "expected 3 attempts, got %d" % len(stub.post_calls))
check(failed == 1, "a give-up after retries did not report the indicator as failed")

# Without the header, the wait backs off instead of hammering.
_, _, _, sleeps, _ = upload([Response(503)])
check(sleeps == [2, 4], "backoff without Retry-After changed: %r" % sleeps)

# An absurd Retry-After is capped rather than obeyed.
_, _, _, sleeps, _ = upload([Response(429, headers={"Retry-After": "3600"})])
check(sleeps == [60, 60], "Retry-After was not capped: %r" % sleeps)

# A 4xx that will never succeed is not retried at all.
_, _, failed, sleeps, stub = upload([Response(400)])
check(sleeps == [], "a non-retryable status was retried: %r" % sleeps)
check(len(stub.post_calls) == 1, "a 400 was sent more than once")
check(failed == 1, "a 400 did not report the indicator as failed")

# A wait longer than the remaining budget is refused, so the host timeout
# cannot kill the run mid-sleep and swallow the audit row.
stub = FakeRequests(post_responses=[Response(429, headers={"Retry-After": "30"})])
sleeps = []
processor = make_processor(stub, sleeps=sleeps, time_budget_seconds=5)
processor._run_start = __import__("time").time()
processor.upload_batch([{"id": "indicator--1"}])
check(sleeps == [], "a retry slept past the run's time budget: %r" % sleeps)

# The same policy protects the fetch side, which raises rather than returning.
stub = FakeRequests(
    get_responses=[Response(502)],
    post_responses=[Response(200, {"errors": []})],
)
sleeps = []
processor = make_processor(stub, sleeps=sleeps)
try:
    processor.fetch_page(added_after="1970-01-01T00:00:00Z")
    check(False, "a persistently failing fetch did not raise")
except RuntimeError:
    pass
check(len(stub.get_calls) == 3, "fetch did not retry: %d call(s)" % len(stub.get_calls))

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("retry policy is bounded, capped and budget-aware: OK (11 checks)")
