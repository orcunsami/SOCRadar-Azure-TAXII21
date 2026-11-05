#!/usr/bin/env python3
"""The threat hunting rules in `Analytic Rules/` and in the template must agree,
and each one must filter on what the indicator table really carries.

Two things go wrong silently with analytics rules:

* The rule filters on a field the indicators do not have (Recorded Future's
  `Data.description startswith ...` matches nothing here: the TAXII description
  is mostly "N/A"; its `'SHA-256'` hash key never matches `file:hashes.sha256`).
  The rule deploys, never fires, and nobody notices.
* The YAML and the template drift. The template is what a customer deploys, the
  YAML is what a reader reviews and what Content Hub would ship.

So this reads both and compares them, and pins the stamp and the keys measured
on a live workspace (progress evidence 01-stamp).
"""

import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULE_DIR = os.path.join(REPO, "Analytic Rules")
TEMPLATE = os.path.join(REPO, "azuredeploy.json")

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


# ---- a YAML reader for exactly the subset the rule files use -------------------
# (PyYAML is not a test dependency; the Function App runtime image has none.)

def scalar(text):
    text = text.strip()
    if text.startswith('"'):
        return json.loads(text)
    if text.startswith("'"):
        return text[1:-1].replace("''", "'")
    if text in ("true", "false"):
        return text == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def parse_yaml(text):
    lines = text.split("\n")
    state = {"i": 0}

    def indent_of(line):
        return len(line) - len(line.lstrip(" "))

    def skip_blank():
        while state["i"] < len(lines) and not lines[state["i"]].strip():
            state["i"] += 1

    def block(indent):
        skip_blank()
        if state["i"] >= len(lines):
            return None
        first = lines[state["i"]]
        if first.strip().startswith("- "):
            return sequence(indent_of(first))
        return mapping(indent_of(first))

    def mapping(indent):
        result = {}
        while True:
            skip_blank()
            if state["i"] >= len(lines):
                return result
            line = lines[state["i"]]
            if indent_of(line) != indent or line.strip().startswith("- "):
                return result
            key, _, rest = line.strip().partition(":")
            state["i"] += 1
            rest = rest.strip()
            if rest == "|":
                body = []
                while state["i"] < len(lines) and (not lines[state["i"]].strip() or indent_of(lines[state["i"]]) > indent):
                    body.append(lines[state["i"]])
                    state["i"] += 1
                width = min((indent_of(b) for b in body if b.strip()), default=0)
                result[key] = "\n".join(b[width:] for b in body).rstrip("\n") + "\n"
            elif rest == "":
                skip_blank()
                if state["i"] < len(lines) and indent_of(lines[state["i"]]) > indent:
                    result[key] = block(indent_of(lines[state["i"]]))
                elif state["i"] < len(lines) and indent_of(lines[state["i"]]) == indent and lines[state["i"]].strip().startswith("- "):
                    result[key] = sequence(indent)
                else:
                    result[key] = None
            else:
                result[key] = scalar(rest)

    def sequence(indent):
        items = []
        while True:
            skip_blank()
            if state["i"] >= len(lines):
                return items
            line = lines[state["i"]]
            if indent_of(line) != indent or not line.strip().startswith("- "):
                return items
            content = line.strip()[2:]
            if re.match(r"^[A-Za-z][A-Za-z0-9]*:( |$)", content):
                lines[state["i"]] = " " * (indent + 2) + content
                items.append(mapping(indent + 2))
            else:
                state["i"] += 1
                items.append(scalar(content))

    return block(0)


# ---- load ------------------------------------------------------------------------

KEYS = ["IP", "InboundIP", "Domain", "Url", "Hash", "ProcessHash"]
rules = {}
for key in KEYS:
    path = os.path.join(RULE_DIR, "SOCRadarTAXIIThreatHunt%s.yaml" % key)
    check(os.path.isfile(path), "missing rule file %s" % path)
    if os.path.isfile(path):
        rules[key] = parse_yaml(open(path, encoding="utf-8").read())

extra = sorted(f for f in os.listdir(RULE_DIR) if f.endswith(".yaml")) if os.path.isdir(RULE_DIR) else []
check(len(extra) == len(KEYS), "expected %d rule files, found %s" % (len(KEYS), extra))

template = json.load(open(TEMPLATE, encoding="utf-8"))
variable = {item["key"]: item for item in template["variables"].get("threatHuntRules", [])}
check(sorted(variable) == sorted(KEYS), "the template variable carries %s, expected %s" % (sorted(variable), sorted(KEYS)))

# What the live TAXII indicators carry (01-stamp.md, 13125 rows).
OBSERVED_KEYS = {"ipv4-addr:value", "domain-name:value", "url:value",
                 "file:hashes.sha256", "file:hashes.sha1", "file:hashes.md5",
                 "file:hashes.sha384", "file:hashes.ssdeep"}
MITRE_TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
                 "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
                 "Collection", "CommandAndControl", "Exfiltration", "Impact"}
ENTITY_IDENTIFIERS = {"IP": {"Address"}, "DNS": {"DomainName"}, "URL": {"Url"}, "Host": {"HostName"},
                      "File": {"Name", "Directory"}, "FileHash": {"Algorithm", "Value"},
                      "Account": {"Name"}, "Process": {"CommandLine", "ProcessId"}}
ASIM_PARSER = {"IP": "_Im_NetworkSession", "InboundIP": "_Im_NetworkSession", "Domain": "_Im_Dns",
               "Url": "_Im_WebSession", "Hash": "_Im_FileEvent", "ProcessHash": "_Im_ProcessCreate"}


def minutes(text):
    match = re.fullmatch(r"(\d+)([mhd])", text)
    return int(match.group(1)) * {"m": 1, "h": 60, "d": 1440}[match.group(2)]


def final_projection(query):
    last = [l for l in query.split("\n") if l.startswith("| project ")][-1]
    return [c.split("=")[0].strip() for c in last[len("| project "):].split(",")]


for key, rule in rules.items():
    where = "rule %s: " % key
    query = rule["query"].rstrip("\n")

    # the stamp and the filters that decide whether the rule can ever fire
    check('SourceSystem == "SOCRadar TAXII"' in query, where + "the query does not filter on SourceSystem == \"SOCRadar TAXII\"")
    check("Data.description" not in query, where + "the query filters on Data.description, which is \"N/A\" on most TAXII indicators")
    check("IsActive == true and ValidUntil > now()" in query, where + "the query does not drop inactive and expired indicators")
    check("summarize arg_max(TimeGenerated, *) by Id" in query, where + "the query does not take the latest row per indicator Id")
    check("SOCRadar Threat Feeds" not in query, where + "the query reads Feeds indicators")
    observed = re.findall(r'"((?:ipv4-addr|domain-name|url|file):[^"]+)"', query)
    check(observed, where + "the query names no observable key")
    check(all(o in OBSERVED_KEYS for o in observed), where + "unknown observable key %s" % [o for o in observed if o not in OBSERVED_KEYS])
    check("'SHA-256'" not in query and "contains 'file:hashes'" not in query, where + "uses a Recorded Future hash key that never matches TAXII")

    # ASIM parser: the unifying _Im_ function, not the imX alias that is missing from a fresh workspace
    check(ASIM_PARSER[key] + "(" in query, where + "does not read %s" % ASIM_PARSER[key])
    check(not re.search(r"(^|\n)\s*im[A-Z]\w+", query), where + "reads an im* parser that is not present in every workspace")

    # window
    check(rule["queryFrequency"] == "1h", where + "queryFrequency is %r" % rule["queryFrequency"])
    # Microsoft Sentinel rejects the rule at create time (the validate and what-if calls do not): 2 days or more of
    # lookback needs a run frequency of at least 1 hour (measured 5 Nov 2026, BadRequest on the first rule).
    check(minutes(rule["queryPeriod"]) < 2 * 1440 or minutes(rule["queryFrequency"]) >= 60,
          where + "queryPeriod of 2 days or more needs queryFrequency of 1 hour or more")
    check(5 <= minutes(rule["queryFrequency"]) <= 14 * 1440, where + "queryFrequency outside 5 minutes - 14 days")
    check(minutes(rule["queryFrequency"]) <= minutes(rule["queryPeriod"]) <= 14 * 1440, where + "queryPeriod outside the frequency - 14 days range")
    ioc = re.search(r"let ioc_lookBack = (\d+[mhd]);", query)
    dt = re.search(r"let dt_lookBack = (\d+[mhd]);", query)
    check(ioc and minutes(ioc.group(1)) <= minutes(rule["queryPeriod"]), where + "ioc_lookBack exceeds queryPeriod, the engine would clip it silently")
    check(dt and minutes(dt.group(1)) >= minutes(rule["queryFrequency"]), where + "dt_lookBack is shorter than queryFrequency, events fall between runs")
    check(dt and minutes(dt.group(1)) <= 2 * minutes(rule["queryFrequency"]), where + "dt_lookBack above twice the frequency re-alerts the same event many times")

    # KQL aliases first/last are reserved (SYN0002)
    check(not re.search(r"\b(first|last)\s*=", query), where + "uses a reserved alias (first/last)")

    # every column a rule consumes is produced by the final project
    projected = final_projection(query)
    check("TimeGenerated" in projected, where + "the projection drops TimeGenerated, the engine needs it")
    for column in rule["customDetails"].values():
        check(column in projected, where + "customDetails column %s is not projected" % column)
    check(len(rule["customDetails"]) <= 20, where + "more than 20 customDetails")
    for prop in rule["alertDetailsOverride"]["alertDynamicProperties"]:
        check(prop["value"] in projected, where + "alert property column %s is not projected" % prop["value"])
    for fmt in ("alertDisplayNameFormat", "alertDescriptionFormat"):
        # the service accepts at most 3 {{column}} parameters per format (measured: "defined 8 parameters ... maximum allowed is 3")
        check(len(re.findall(r"\{\{(\w+)\}\}", rule["alertDetailsOverride"][fmt])) <= 3, where + "%s uses more than 3 parameters" % fmt)
        for column in re.findall(r"\{\{(\w+)\}\}", rule["alertDetailsOverride"][fmt]):
            check(column in projected, where + "%s uses {{%s}} which is not projected" % (fmt, column))
    check(len(rule["entityMappings"]) <= 10, where + "more than 10 entity mappings")
    for entity in rule["entityMappings"]:
        allowed = ENTITY_IDENTIFIERS.get(entity["entityType"])
        check(allowed is not None, where + "unknown entity type %s" % entity["entityType"])
        for field in entity["fieldMappings"]:
            check(allowed and field["identifier"] in allowed, where + "%s has no identifier %s" % (entity["entityType"], field["identifier"]))
            check(field["columnName"] in projected, where + "entity column %s is not projected" % field["columnName"])

    # incident shape
    check(rule["eventGroupingSettings"]["aggregationKind"] == "AlertPerResult", where + "not AlertPerResult")
    group = rule["incidentConfiguration"]["groupingConfiguration"]
    check(group["enabled"] is True and group["matchingMethod"] == "AllEntities" and group["reopenClosedIncident"] is False,
          where + "incident grouping drifted from AllEntities / no reopen")
    check(rule["tactics"] and all(t in MITRE_TACTICS for t in rule["tactics"]), where + "unknown tactic %s" % rule["tactics"])
    check(rule["relevantTechniques"] and all(re.fullmatch(r"T\d{4}", t) for t in rule["relevantTechniques"]), where + "bad technique id")
    check(re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", str(rule["id"])), where + "id is not a GUID")
    check(rule["kind"] == "Scheduled", where + "not a Scheduled rule")

    # the template carries the same rule
    item = variable.get(key)
    if item:
        check(item["id"] == rule["id"], where + "template id differs from the YAML")
        check(item["displayName"] == rule["name"], where + "template displayName differs from the YAML")
        check(item["description"] == rule["description"].rstrip("\n"), where + "template description differs from the YAML")
        check(item["query"] == query, where + "template query is not byte-equal to the YAML query")
        check(item["tactics"] == rule["tactics"], where + "template tactics differ")
        check(item["techniques"] == rule["relevantTechniques"], where + "template techniques differ")
        check(item["customDetails"] == rule["customDetails"], where + "template customDetails differ")
        check(item["entityMappings"] == rule["entityMappings"], where + "template entityMappings differ")
        check(item["alertDetailsOverride"] == rule["alertDetailsOverride"], where + "template alertDetailsOverride differs")

ids = [r["id"] for r in rules.values()]
check(len(set(ids)) == len(ids), "two rules share an id")

# ---- the resources: once for the same resource group, once for the external one --

def alert_rules(resources):
    return [r for r in resources if r["type"] == "Microsoft.OperationalInsights/workspaces/providers/alertRules"]


local = alert_rules(template["resources"])
nested = [r for dep in template["resources"] if dep["type"] == "Microsoft.Resources/deployments"
          for r in alert_rules(dep["properties"]["template"]["resources"])] if template["resources"] else []
check(len(local) == 1, "expected one alertRules resource in this resource group, found %d" % len(local))
check(len(nested) == 1, "expected one alertRules resource inside the external-workspace deployment, found %d" % len(nested))

for label, resource in (("local", local[0] if local else None), ("nested", nested[0] if nested else None)):
    if not resource:
        continue
    where = "%s alertRules: " % label
    check(resource["kind"] == "Scheduled", where + "not Scheduled")
    check(resource["copy"]["count"] == "[length(variables('threatHuntRules'))]", where + "does not loop over the rule variable")
    check("variables('threatHuntRules')[copyIndex()].id" in resource["name"], where + "the name is not the YAML id")
    check("EnableThreatHuntRules" in resource["condition"], where + "no EnableThreatHuntRules switch")
    props = resource["properties"]
    check(props["queryFrequency"] == "PT1H" and props["queryPeriod"] == "P14D", where + "schedule is not PT1H / P14D")
    check(props["severity"] == "[parameters('ThreatHuntRuleSeverity')]", where + "severity is not the parameter")
    check(props["enabled"] is True, where + "rules are not enabled")
    check(props["eventGroupingSettings"]["aggregationKind"] == "AlertPerResult", where + "not AlertPerResult")
    check(props["incidentConfiguration"]["groupingConfiguration"]["matchingMethod"] == "AllEntities", where + "grouping drifted")
    for field in ("query", "tactics", "techniques", "customDetails", "entityMappings", "alertDetailsOverride", "displayName", "description"):
        check("variables('threatHuntRules')[copyIndex()]." + field in props[field], where + "%s is not read from the rule variable" % field)

if local:
    check("external" in local[0]["condition"].lower() and "not(" in local[0]["condition"], "the local rules are not skipped when the workspace is external (they would deploy twice)")
    depends = " ".join(local[0].get("dependsOn", []))
    check("onboardingStates" in depends, "the local rules do not wait for the Microsoft Sentinel onboarding state")

parameters = template["parameters"]
check(parameters.get("EnableThreatHuntRules", {}).get("defaultValue") is True, "EnableThreatHuntRules is missing or not on by default")
severity = parameters.get("ThreatHuntRuleSeverity", {})
check(severity.get("defaultValue") == "Medium" and severity.get("allowedValues") == ["Informational", "Low", "Medium", "High"],
      "ThreatHuntRuleSeverity is missing or wrong")

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("threat hunting rules: YAML, template and the measured indicator stamp agree: OK (%d rules)" % len(rules))
