#!/usr/bin/env python3
"""Losing the audit row must not change what a collection reports.

dcr_logger posted outside any try block. After a collection had imported
everything and saved its checkpoint, a network error on the audit post raised
into the collection's own except branch: it was counted Failed, and when every
collection did the same the whole timer run failed. The audit table is a
report, not part of the import.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _harness import FakeCredential, FakeRequests

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


import dcr_logger


class Boom(FakeRequests):
    def post(self, url, **kwargs):
        raise ConnectionError("audit endpoint unreachable")


stub = Boom()
dcr_logger.requests = stub
logger = dcr_logger.DcrLogger(FakeCredential(), "https://dce.example", "dcr-1", "Custom-X")

raised = None
try:
    logger.log_audit({"api_root": "radar_alpha", "status": "Success"})
except Exception as exc:  # noqa: BLE001
    raised = exc
check(raised is None, "a failed audit post raised out of log_audit: %r" % raised)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("a failed audit post does not raise: OK (1 check)")
