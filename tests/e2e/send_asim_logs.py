#!/usr/bin/env python3
"""Send synthetic customer telemetry to the ASIM native tables of a workspace.

Used to prove the threat hunting rules end to end: it sends events that carry
real indicator values (taken from ThreatIntelIndicators) plus controls that must
NOT alert. The tables are ASimNetworkSessionLogs, ASimDnsActivityLogs,
ASimWebSessionLogs, ASimFileEventLogs and ASimProcessEventLogs. Nothing here is
part of the product; it creates a DCE and a DCR in the resource group you name.

    python3 tests/e2e/send_asim_logs.py setup  <resource-group> <workspace>
    python3 tests/e2e/send_asim_logs.py send   <resource-group> <indicators.json>
    python3 tests/e2e/send_asim_logs.py events <indicators.json>        (print only)

indicators.json: {"ip": ..., "ip_inbound": ..., "ip_denied": ..., "domain": ..., "url": ...,
                  "sha256": ..., "sha1": ..., "md5": ...} with live values from the workspace.

ASIM_TABLES=ASimDnsActivityLogs,... limits `send` to those tables.
ASIM_STAMP=2026-01-01T10:00:00.000Z gives every event that time, to send the same events twice.
Needs the Azure CLI, signed in, with permission to create a DCR and a role assignment.
"""

import datetime
import json
import os
import subprocess
import sys
import time
import urllib.request

DCE_NAME = "e2e-asim-dce"
DCR_NAME = "e2e-asim-dcr"
API = "2023-03-11"

COMMON = ["EventStartTime", "EventEndTime", "EventCount", "EventType", "EventResult", "EventProduct",
          "EventVendor", "EventSchema", "EventSchemaVersion", "Dvc", "DvcHostname"]
STREAMS = {
    "ASimNetworkSessionLogs": ["SrcIpAddr", "DstIpAddr", "DvcAction", "SrcHostname", "DstHostname"],
    "ASimDnsActivityLogs": ["DnsQuery", "SrcIpAddr", "SrcHostname"],
    "ASimWebSessionLogs": ["Url", "SrcIpAddr", "SrcHostname"],
    "ASimFileEventLogs": ["TargetFileSHA256", "TargetFileSHA1", "TargetFileMD5", "TargetFileName", "TargetFilePath",
                          "ActorUsername", "SrcIpAddr"],
    "ASimProcessEventLogs": ["TargetProcessSHA256", "TargetProcessSHA1", "TargetProcessMD5", "TargetProcessName",
                             "TargetProcessCommandLine", "ActorUsername"],
}
SCHEMA = {"ASimNetworkSessionLogs": ("NetworkSession", "0.2.7", "NetworkSession"),
          "ASimDnsActivityLogs": ("Dns", "0.1.7", "Query"),
          "ASimWebSessionLogs": ("WebSession", "0.2.7", "HTTPsession"),
          "ASimFileEventLogs": ("FileEvent", "0.2.1", "FileCreated"),
          "ASimProcessEventLogs": ("ProcessEvent", "0.1.4", "ProcessCreated")}


def az(*args, check=True):
    result = subprocess.run(["az", *args], capture_output=True, text=True)
    if check and result.returncode:
        sys.exit("az %s failed: %s" % (" ".join(args[:3]), result.stderr.strip()[:500]))
    return result.stdout.strip()


def columns_for(table):
    columns = [{"name": "TimeGenerated", "type": "datetime"}]
    for name in COMMON + STREAMS[table]:
        kind = "datetime" if name in ("EventStartTime", "EventEndTime") else "int" if name == "EventCount" else "string"
        columns.append({"name": name, "type": kind})
    return columns


def setup(rg, workspace):
    subscription = az("account", "show", "--query", "id", "-o", "tsv")
    location = az("group", "show", "-n", rg, "--query", "location", "-o", "tsv")
    workspace_id = az("resource", "show", "-g", rg, "-n", workspace, "--resource-type",
                      "Microsoft.OperationalInsights/workspaces", "--query", "id", "-o", "tsv")
    base = "https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Insights" % (subscription, rg)
    az("rest", "--method", "put", "--url", "%s/dataCollectionEndpoints/%s?api-version=%s" % (base, DCE_NAME, API),
       "--body", json.dumps({"location": location, "properties": {}}), "-o", "none")
    dce_id = "%s/dataCollectionEndpoints/%s" % (base.replace("https://management.azure.com", ""), DCE_NAME)
    declarations = {"Custom-" + t: {"columns": columns_for(t)} for t in STREAMS}
    flows = [{"streams": ["Custom-" + t], "destinations": ["law"], "transformKql": "source", "outputStream": "Microsoft-" + t}
             for t in STREAMS]
    body = {"location": location, "kind": "Direct",
            "properties": {"dataCollectionEndpointId": dce_id, "streamDeclarations": declarations,
                           "destinations": {"logAnalytics": [{"workspaceResourceId": workspace_id, "name": "law"}]},
                           "dataFlows": flows}}
    az("rest", "--method", "put", "--url", "%s/dataCollectionRules/%s?api-version=%s" % (base, DCR_NAME, API),
       "--body", json.dumps(body), "-o", "none")
    dcr_id = "%s/dataCollectionRules/%s" % (base.replace("https://management.azure.com", ""), DCR_NAME)
    oid = az("ad", "signed-in-user", "show", "--query", "id", "-o", "tsv")
    az("role", "assignment", "create", "--assignee-object-id", oid, "--assignee-principal-type", "User",
       "--role", "Monitoring Metrics Publisher", "--scope", dcr_id, "-o", "none", check=False)
    print("DCE and DCR created in %s; the role assignment can take a few minutes to take effect" % rg)


def events(ind):
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = os.environ.get("ASIM_STAMP") or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")   # fixed stamp resends the same events

    def row(table, **fields):
        schema, version, etype = SCHEMA[table]
        base = {"TimeGenerated": stamp, "EventStartTime": stamp, "EventEndTime": stamp, "EventCount": 1,
                "EventType": etype, "EventResult": "Success", "EventProduct": "E2E Synthetic", "EventVendor": "SOCRadar E2E",
                "EventSchema": schema, "EventSchemaVersion": version, "Dvc": "e2e-sensor-1", "DvcHostname": "e2e-sensor-1"}
        base.update(fields)
        return base

    net, dns, web, fil, proc = [], [], [], [], []
    # matches: one per rule
    net.append(row("ASimNetworkSessionLogs", SrcIpAddr="10.20.30.40", SrcHostname="e2e-client-out", DstIpAddr=ind["ip"], DvcAction="Allow"))
    net.append(row("ASimNetworkSessionLogs", SrcIpAddr=ind["ip_inbound"], DstIpAddr="10.20.30.41", DstHostname="e2e-server-in", DvcAction="Allow"))
    dns.append(row("ASimDnsActivityLogs", DnsQuery=ind["domain"].upper(), SrcIpAddr="10.20.30.42", SrcHostname="e2e-client-dns"))
    web.append(row("ASimWebSessionLogs", Url=ind["url"], SrcIpAddr="10.20.30.43", SrcHostname="e2e-client-web"))
    fil.append(row("ASimFileEventLogs", TargetFileSHA256=ind["sha256"].upper(), TargetFileName="invoice.exe", TargetFilePath="C:\\Users\\e2e\\invoice.exe",
                   ActorUsername="e2e.user", SrcIpAddr="10.20.30.44", DvcHostname="e2e-host-file"))
    if ind.get("sha1"):
        fil.append(row("ASimFileEventLogs", TargetFileSHA1=ind["sha1"], TargetFileName="update.bin", TargetFilePath="C:\\Temp\\update.bin",
                       ActorUsername="e2e.user", SrcIpAddr="10.20.30.45", DvcHostname="e2e-host-file-sha1"))
    if ind.get("md5"):
        proc.append(row("ASimProcessEventLogs", TargetProcessMD5=ind["md5"], TargetProcessName="agent.exe",
                        TargetProcessCommandLine="agent.exe -run", ActorUsername="e2e.user", DvcHostname="e2e-host-proc-md5"))
    proc.append(row("ASimProcessEventLogs", TargetProcessSHA256=ind["sha256"], TargetProcessName="invoice.exe",
                    TargetProcessCommandLine="invoice.exe /silent", ActorUsername="e2e.user", DvcHostname="e2e-host-proc"))
    # controls that must NOT alert: denied inbound, benign values
    net.append(row("ASimNetworkSessionLogs", SrcIpAddr=ind["ip_denied"], DstIpAddr="10.20.30.46", DstHostname="e2e-denied", DvcAction="Deny"))
    net.append(row("ASimNetworkSessionLogs", SrcIpAddr="10.20.30.47", DstIpAddr="93.184.216.34", DvcAction="Allow", SrcHostname="e2e-benign"))
    dns.append(row("ASimDnsActivityLogs", DnsQuery="example.com", SrcIpAddr="10.20.30.48", SrcHostname="e2e-benign"))
    web.append(row("ASimWebSessionLogs", Url="https://example.com/index.html", SrcIpAddr="10.20.30.49", SrcHostname="e2e-benign"))
    fil.append(row("ASimFileEventLogs", TargetFileSHA256="0" * 64, TargetFileName="benign.txt", SrcIpAddr="10.20.30.50", DvcHostname="e2e-benign"))
    proc.append(row("ASimProcessEventLogs", TargetProcessSHA256="f" * 64, TargetProcessName="benign.exe", DvcHostname="e2e-benign"))
    return {"ASimNetworkSessionLogs": net, "ASimDnsActivityLogs": dns, "ASimWebSessionLogs": web,
            "ASimFileEventLogs": fil, "ASimProcessEventLogs": proc}


def send(rg, ind):
    subscription = az("account", "show", "--query", "id", "-o", "tsv")
    base = "https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Insights" % (subscription, rg)
    dce = json.loads(az("rest", "--method", "get", "--url", "%s/dataCollectionEndpoints/%s?api-version=%s" % (base, DCE_NAME, API)))
    dcr = json.loads(az("rest", "--method", "get", "--url", "%s/dataCollectionRules/%s?api-version=%s" % (base, DCR_NAME, API)))
    endpoint = dce["properties"]["logsIngestion"]["endpoint"]
    immutable = dcr["properties"]["immutableId"]
    token = az("account", "get-access-token", "--resource", "https://monitor.azure.com", "--query", "accessToken", "-o", "tsv")
    only = [t for t in os.environ.get("ASIM_TABLES", "").split(",") if t]   # resend just these tables
    for table, rows in events(ind).items():
        if only and table not in only:
            continue
        url = "%s/dataCollectionRules/%s/streams/Custom-%s?api-version=2023-01-01" % (endpoint, immutable, table)
        for attempt in range(1, 9):
            request = urllib.request.Request(url, data=json.dumps(rows).encode(), method="POST",
                                             headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    print("%s: %d rows, HTTP %d" % (table, len(rows), response.status))
                    break
            except urllib.error.HTTPError as error:
                print("%s: attempt %d HTTP %d %s" % (table, attempt, error.code, error.read()[:200]))
                if error.code not in (401, 403):
                    break
                time.sleep(60)   # the role assignment has not propagated yet
        else:
            sys.exit("%s: still refused after 8 attempts" % table)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "setup" and len(sys.argv) == 4:
        setup(sys.argv[2], sys.argv[3])
    elif mode == "send" and len(sys.argv) == 4:
        send(sys.argv[2], json.load(open(sys.argv[3])))
    elif mode == "events" and len(sys.argv) == 3:
        print(json.dumps(events(json.load(open(sys.argv[2]))), indent=2))
    else:
        sys.exit(__doc__)
