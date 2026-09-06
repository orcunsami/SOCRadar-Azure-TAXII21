#!/usr/bin/env python3
"""Every audit field the code sends must be declared in the DCR and the table.

A Data Collection Rule silently drops any column it was not told about. The
record still ingests, the run still looks healthy, and the field simply is not
there when someone queries for it. That is how a new counter gets added, tested
against the code, and quietly lost in production.

So the three lists have to agree: what dcr_logger.log_audit builds, what the
DCR stream declares, and what the Log Analytics table stores.
"""

import ast
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(REPO, "azuredeploy.json")
LOGGER = os.path.join(REPO, "FunctionApp", "dcr_logger.py")

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def emitted_fields():
    """Read the record literal out of log_audit without importing Azure SDKs."""
    tree = ast.parse(open(LOGGER, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "log_audit":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict) and sub.keys and isinstance(sub.keys[0], ast.Constant):
                    return [k.value for k in sub.keys]
    return []


template = json.load(open(TEMPLATE, encoding="utf-8"))
table_columns = None
stream_columns = None
for resource in template["resources"]:
    if resource["type"] == "Microsoft.OperationalInsights/workspaces/tables":
        table_columns = [c["name"] for c in resource["properties"]["schema"]["columns"]]
    if resource["type"] == "Microsoft.Insights/dataCollectionRules":
        declarations = resource["properties"]["streamDeclarations"]
        stream_columns = [c["name"] for c in list(declarations.values())[0]["columns"]]

check(table_columns is not None, "no Log Analytics table resource found in the template")

# The same table is declared twice: once in this resource group and once inside
# the nested deployment that targets an external workspace resource group. Two
# copies of one decision drift, so the nested copy has to be byte-equal.
nested_schemas = [
    r["properties"]["schema"]
    for dep in template["resources"] if dep["type"] == "Microsoft.Resources/deployments"
    for r in dep["properties"]["template"]["resources"]
    if r["type"] == "Microsoft.OperationalInsights/workspaces/tables"
]
local_schema = next(r["properties"]["schema"] for r in template["resources"]
                    if r["type"] == "Microsoft.OperationalInsights/workspaces/tables")
check(len(nested_schemas) == 1, "expected exactly one audit table inside the nested deployment, found %d" % len(nested_schemas))
check(nested_schemas and nested_schemas[0] == local_schema,
      "the nested audit table drifted from the local one")
check(stream_columns is not None, "no data collection rule found in the template")

emitted = emitted_fields()
check(len(emitted) > 1, "could not read the audit record fields out of log_audit")

if table_columns and stream_columns and emitted:
    missing_stream = [f for f in emitted if f not in stream_columns]
    missing_table = [f for f in emitted if f not in table_columns]
    unused_stream = [c for c in stream_columns if c not in emitted]
    check(not missing_stream,
          "the code sends fields the DCR does not declare, they will be dropped silently: %s" % missing_stream)
    check(not missing_table,
          "the code sends fields the table has no column for: %s" % missing_table)
    check(not unused_stream,
          "the DCR declares columns nothing ever sends: %s" % unused_stream)
    check(sorted(table_columns) == sorted(stream_columns),
          "the table schema and the DCR stream disagree: table-only %s, stream-only %s"
          % ([c for c in table_columns if c not in stream_columns],
             [c for c in stream_columns if c not in table_columns]))

# The status vocabulary is documented where an operator will look for it.
status_columns = [c for c in template["resources"]
                  if c["type"] == "Microsoft.OperationalInsights/workspaces/tables"]
if status_columns:
    for column in status_columns[0]["properties"]["schema"]["columns"]:
        if column["name"] == "Status":
            check("PartialSuccess" in column.get("description", ""),
                  "the Status column description does not mention PartialSuccess: %r"
                  % column.get("description"))

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("audit fields, DCR stream and table schema agree: OK (%d fields)" % len(emitted))
