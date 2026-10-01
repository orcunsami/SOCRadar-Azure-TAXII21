"""Shared stubs so the Function App code can run outside Azure.

The processor talks to exactly two things: the TAXII server and the Sentinel
upload API, both through `requests`. Replacing that one module is enough to
drive every path in this directory, including the failure paths that only
appear when a real server returns 429 or 503.
"""

import logging
import os
import sys
import types

logging.disable(logging.CRITICAL)

# `requests` is a deployment dependency, not a test dependency: every call it
# would make is stubbed below, so a placeholder module keeps the import working
# without pulling the real package into the test environment.
sys.modules.setdefault("requests", types.ModuleType("requests"))

# Same for azure-core: the processor only needs the "entity not found" class.
try:
    from azure.core.exceptions import ResourceNotFoundError
except ImportError:
    class ResourceNotFoundError(Exception):
        pass

    _azure = sys.modules.setdefault("azure", types.ModuleType("azure"))
    _core = types.ModuleType("azure.core")
    _exceptions = types.ModuleType("azure.core.exceptions")
    _exceptions.ResourceNotFoundError = ResourceNotFoundError
    _core.exceptions = _exceptions
    _azure.core = _core
    sys.modules.update({"azure.core": _core, "azure.core.exceptions": _exceptions})

FUNCTION_APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "FunctionApp")
if FUNCTION_APP not in sys.path:
    sys.path.insert(0, FUNCTION_APP)


class Response:
    def __init__(self, status_code, payload=None, headers=None, text=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}
        self.text = text if text is not None else "body"

    def json(self):
        return self._payload


class FakeRequests:
    """Serves scripted responses and records what was asked for."""

    def __init__(self, get_responses=None, post_responses=None):
        self.get_responses = list(get_responses or [])
        self.post_responses = list(post_responses or [])
        self.get_calls = []
        self.post_calls = []
        self.post_bodies = []

    # A page that keeps saying "more" would loop forever if the code under test
    # stopped honouring its stop conditions, so the stub refuses to serve an
    # unreasonable number of calls instead of hanging the run.
    MAX_CALLS = 20

    def _next(self, queue, calls, record):
        calls.append(record)
        if len(self.get_calls) + len(self.post_calls) > self.MAX_CALLS:
            raise AssertionError("the code under test never stopped requesting")
        if not queue:
            raise AssertionError("no scripted response left for %r" % (record,))
        item = queue[0] if len(queue) == 1 else queue.pop(0)
        return item

    def get(self, url, **kwargs):
        return self._next(self.get_responses, self.get_calls, (url, kwargs.get("params")))

    def post(self, url, **kwargs):
        self.post_bodies.append(kwargs.get("json") or {})
        return self._next(self.post_responses, self.post_calls, (url, len((kwargs.get("json") or {}).get("indicators", []))))


class FakeTable:
    """Azure Table stand-in that remembers whether the checkpoint moved."""

    def __init__(self, entity=None):
        self.entity = entity
        self.upserts = []

    def get_entity(self, partition_key, row_key):
        if self.entity is None:
            raise ResourceNotFoundError("no checkpoint")
        return self.entity

    def upsert_entity(self, entity):
        self.upserts.append(dict(entity))


class FakeCredential:
    def get_token(self, *_scopes):
        return types.SimpleNamespace(token="token")


def indicator(value, **extra):
    obj = {
        "type": "indicator",
        "id": "indicator--%s" % value,
        "pattern": "[ipv4-addr:value = '%s']" % value,
        "pattern_type": "stix",
    }
    obj.update(extra)
    return obj


def page(values, more=False, next_cursor="", objects=None):
    objects = objects if objects is not None else [indicator(v) for v in values]
    return {"objects": objects, "more": more, "next": next_cursor}


def make_processor(requests_stub, table=None, sleeps=None, **kwargs):
    import taxii_processor

    taxii_processor.requests = requests_stub
    if sleeps is not None:
        taxii_processor.time.sleep = sleeps.append

    options = dict(
        api_root="radar_alpha",
        collection_id="00000000-0000-0000-0000-000000000001",
        taxii_username="user",
        taxii_password="pass",
        workspace_id="workspace",
        credential=FakeCredential(),
        table_client=table if table is not None else FakeTable(),
        initial_lookback_hours=0,
    )
    options.update(kwargs)
    return taxii_processor.TaxiiProcessor(**options)
