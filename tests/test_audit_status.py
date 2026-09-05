#!/usr/bin/env python3
"""A run that lost indicators must not write Success into the audit table.

The audit table is the only place a customer can see what a run did. When the
processor swallowed an upload failure, the collection raised nothing, so the
function wrote Success and the loss became invisible. Status now has to follow
the counters, not the absence of an exception.
"""

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _harness  # noqa: F401  (installs the requests stub and the import path)

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


class FakeApp:
    def timer_trigger(self, **_kwargs):
        return lambda fn: fn


class FakeDcrLogger:
    def __init__(self):
        self.rows = []

    def log_audit(self, data):
        self.rows.append(data)


def load_function_app():
    functions = types.ModuleType("azure.functions")
    functions.FunctionApp = FakeApp
    functions.TimerRequest = object
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda *a, **k: _harness.FakeCredential()
    tables = types.ModuleType("azure.data.tables")
    tables.TableServiceClient = lambda **k: types.SimpleNamespace(
        get_table_client=lambda name: _harness.FakeTable()
    )
    azure = types.ModuleType("azure")
    sys.modules.update({
        "azure": azure, "azure.functions": functions,
        "azure.identity": identity, "azure.data.tables": tables,
    })
    sys.modules.pop("function_app", None)
    import function_app
    return function_app


def run_with(result, logger):
    module = load_function_app()

    class StubProcessor:
        def __init__(self, **_kwargs):
            pass

        def run(self):
            return dict(result)

    module.TaxiiProcessor = StubProcessor
    module.DcrLogger = types.SimpleNamespace(from_env=lambda credential: logger)
    os.environ.update({
        "API_ROOTS": "radar_alpha",
        "COLLECTION_IDS": "00000000-0000-0000-0000-000000000001",
        "STORAGE_ACCOUNT_NAME": "storage",
        "TAXII_USERNAME": "user",
        "TAXII_PASSWORD": "pass",
        "WORKSPACE_ID": "workspace",
    })
    module.socradar_taxii_import(types.SimpleNamespace(past_due=False))
    return logger.rows


base = {
    "api_root": "radar_alpha",
    "collection_id": "00000000-0000-0000-0000-000000000001",
    "indicators_created": 10,
    "indicators_skipped": 0,
    "indicators_failed": 0,
    "indicators_revoked": 0,
    "pages_fetched": 1,
    "type_stats": {},
    "complete": True,
}

rows = run_with(base, FakeDcrLogger())
check(len(rows) == 1 and rows[0]["status"] == "Success",
      "a clean run did not report Success: %r" % rows)

lost = dict(base, indicators_created=8, indicators_failed=2, complete=False)
rows = run_with(lost, FakeDcrLogger())
check(len(rows) == 1, "a partial run wrote %d audit rows" % len(rows))
if rows:
    check(rows[0]["status"] != "Success",
          "a run that lost 2 indicators still reported Success")
    check(rows[0]["status"] == "PartialSuccess",
          "expected PartialSuccess, got %r" % rows[0]["status"])
    check(rows[0]["indicators_failed"] == 2,
          "the failed count never reached the audit row: %r" % rows[0].get("indicators_failed"))
    check("next run" in rows[0]["error_message"],
          "the audit row does not say the indicators will be retried: %r" % rows[0]["error_message"])

# A partial collection must not raise: some indicators did land, and raising
# would mark the whole timer run failed and hide the ones that succeeded.
try:
    run_with(lost, FakeDcrLogger())
except Exception as exc:  # noqa: BLE001
    check(False, "a partial collection raised: %r" % exc)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("audit status follows the counters, not the absence of an exception: OK (7 checks)")
