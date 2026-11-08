# SOCRadar TAXII 2.1 for Microsoft Sentinel

Imports STIX 2.1 threat intelligence indicators from SOCRadar TAXII server into Microsoft Sentinel. Supports multiple API roots and collections in a single deployment.

## Deployment

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-TAXII21%2Fmaster%2Fazuredeploy.json)

Click the button above. Fill in the parameters and click **Create**. The function app and code are deployed automatically.

Or via CLI:

```bash
az deployment group create \
  --resource-group <YOUR_RG> \
  --template-file azuredeploy.json \
  --parameters \
    WorkspaceName=<YOUR_WORKSPACE> \
    ApiRoots=radar_alpha,radar_gamma \
    CollectionIds=fd3fec42-efee-4353-85b2-cb87f9acc4ef,f260cf45-85ef-4f86-9542-763061f11d50 \
    TAXIIUsername=<TAXII_USERNAME> \
    TAXIIPassword=<API_KEY>
```

If the workspace lives in another resource group, add `WorkspaceResourceGroup=<WORKSPACE_RG>`.

Step by step: [docs/setup-guide.md](docs/setup-guide.md).

`DeployNewWorkspace` defaults to `false`: the deployment uses your existing workspace and does not update the workspace itself, so its pricing tier (commitment tier included), retention and daily cap stay as they are. It does add the audit table under the workspace and enables Microsoft Sentinel on it if that is not done yet. If you do not have a workspace yet, add `DeployNewWorkspace=true` and the deployment creates one. Deploy in incremental mode (the default); complete mode deletes resources in the group that the template does not list.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `WorkspaceName` | Yes | - | Microsoft Sentinel workspace name |
| `DeployNewWorkspace` | No | `false` | `false` uses the workspace that already exists: the workspace itself is not updated, so its pricing tier, retention and daily cap are never changed, and a name that does not exist fails before anything is created. Set `true` only to create a new workspace named `WorkspaceName`; do not set it on an existing workspace that uses a commitment tier. |
| `WorkspaceResourceGroup` | No | deployment RG | Resource group of the workspace when it is not the one you deploy to. See [Workspace in another resource group](#workspace-in-another-resource-group). |
| `ApiRoots` | Yes | - | Comma-separated TAXII API root names (e.g., `radar_alpha,radar_gamma`) |
| `CollectionIds` | Yes | - | Comma-separated collection UUIDs matching API roots order |
| `TAXIIUsername` | Yes | - | TAXII username issued by SOCRadar, e.g. `radar_<company id>`, not the bare company ID |
| `TAXIIPassword` | Yes | - | SOCRadar Platform API Key. The deployment checks the username and password against the TAXII server and fails with a clear message if they are rejected (HTTP 401), instead of finishing with an app that imports nothing. |
| `PollingIntervalMinutes` | No | 60 | Polling interval, 5-1440 min. Use a divisor of 60 for minutes or a divisor of 24 for whole hours; other values fire unevenly (45 runs at :00 and :45, 90 runs hourly). |
| `InitialLookbackHours` | No | 48 | Hours of history on first run (0 = all history) |
| `EnableAuditLogging` | No | true | Log to SOCRadar_TAXII_Audit_CL |
| `EnableThreatHuntRules` | No | true | Create the six [threat hunting rules](#threat-hunting-rules) in Microsoft Sentinel. |
| `ThreatHuntRuleSeverity` | No | Medium | Severity of the alerts those rules raise (Informational, Low, Medium, High). |
| `PackageUri` | No | published release | Function App deployment package. Leave the default unless you are testing a build before it is released. |

Each API root position matches the corresponding collection ID position. For example, `radar_alpha,radar_gamma` with `fd3fec42-...,f260cf45-...` means radar_alpha uses fd3fec42 and radar_gamma uses f260cf45.

## SOCRadar TAXII API Roots

| API Root | Collection UUID |
|----------|-----------------|
| `radar_alpha` | `fd3fec42-efee-4353-85b2-cb87f9acc4ef` |
| `radar_gamma` | `f260cf45-85ef-4f86-9542-763061f11d50` |
| `radar_premium` | `cfcf66c0-3226-561e-a9d9-b54addca5dd1` |

Contact SOCRadar for your API root and collection details.

## Existing installations

Deployments made before `DeployNewWorkspace` existed stated a pricing tier on the workspace
resource, and a template overwrites every field it states. If the target workspace was on a
**commitment tier**, redeploying reset it to `PerGB2018` (pay-as-you-go).

Check the current tier:

```bash
az monitor log-analytics workspace show -g <resource-group> -n <workspace> \
  --query "{sku:sku.name, lastSkuUpdate:sku.lastSkuUpdate}" -o json
```

If `lastSkuUpdate` lines up with when you deployed this integration and the tier isn't the one
you picked, reset your commitment tier from **Log Analytics workspaces > Usage and estimated
costs > Pricing tier**. The current template does not update an existing workspace while
`DeployNewWorkspace` is at its default `false`, so redeploying cannot change its pricing
tier, retention or daily cap.

Redeploying over an installation made before September 2026 also adds a **Microsoft Sentinel Contributor** assignment scoped to the workspace; the earlier resource-group-scoped one stays and does no harm. Before that date revoked indicators were dropped instead of uploaded, so `IndicatorsRevoked` in older audit rows means "seen", not "uploaded".

## Workspace in another resource group

Set `WorkspaceResourceGroup` to the resource group that holds the workspace. Microsoft Sentinel must already be enabled on it (`DeployNewWorkspace` is ignored). The Function App and its storage, DCE, DCR and workbook land in the resource group you deploy to; the audit table and the **Microsoft Sentinel Contributor** assignment for the managed identity are created in the workspace resource group by a nested deployment, so the account running the deployment needs `Microsoft.Authorization/roleAssignments/write` there (Owner or User Access Administrator).

| Error | Cause |
|-------|-------|
| `LinkedResourceNotFound` / `ResourceNotFound` on the workspace | `WorkspaceName` does not exist in `WorkspaceResourceGroup` |
| `AuthorizationFailed` on `deploy-workspace-resources` | no role-assignment rights on the workspace resource group |
| `RoleAssignmentUpdateNotPermitted` on `deploy-workspace-resources` | a previous install against the same workspace left its role assignment behind -- see below |
| `not onboarded` in the function log | Microsoft Sentinel is not enabled on that workspace |

### Reinstalling cross-RG after deleting an install

The **Microsoft Sentinel Contributor** assignment lives on the workspace, which is in a
different resource group, so deleting the resource group you deployed to does not remove it.
Its name is derived from the workspace and the identity's *name*, not the identity itself, so a
reinstall tries to reuse that name with a new principal and Azure refuses.

Find the leftover -- its principal is blank because the identity is gone:

```bash
WS=$(az monitor log-analytics workspace show -g <workspace-rg> -n <workspace> --query id -o tsv)
az role assignment list --scope "$WS" -o json | python3 -c "
import json,sys
for a in json.load(sys.stdin):
    if not a.get('principalName'): print(a['name'], a['roleDefinitionName'])"
```

Then remove it and redeploy:

```bash
az role assignment delete --ids "$WS/providers/Microsoft.Authorization/roleAssignments/<name>"
```

## How the code gets there

The template creates the Function App empty (`WEBSITE_RUN_FROM_PACKAGE=1`) and a deployment
script downloads `PackageUri`, verifies it is a readable zip, uploads it to the storage account
this template creates, and points the app at that blob with a read-only token. Azure stopped
accepting the creation of a Linux consumption Function App whose `WEBSITE_RUN_FROM_PACKAGE` is
a URL that redirects, and a GitHub release download URL always redirects.

One consequence worth knowing: **an installation keeps the package it was installed with.** The
release URL is read once, at install time. A later release does not reach an existing
installation -- redeploy to pick it up. Before September 2026 the app read that URL on every
cold start, so a new release did arrive on its own.

If the deployment fails at `triggerFirstRun`, the message says which step: an unreachable
package URL, a download that is not a readable zip, a package that never reached the container
the app reloads from, or an app that indexed no function within the poll window. The script
retries the settings read until its role assignment is effective, retries the upload up to
six times, and restarts the app once the package is staged -- writing the pointer alone was
measured not to make the host reload it. If the deployment fails, the diagnostic container
and its storage account stay in the resource group for 26 hours -- the documented ceiling --
so the log can still be read the next morning; delete them once you are done. A successful
deployment leaves neither behind.

It reports success only when both readings agree: the package pointer names a blob in the
`function-releases` container **and** the app has indexed a function. The count alone is not
enough -- an app whose package was staged somewhere else keeps reporting a function to Azure
Resource Manager while its host answers 503 from the next restart onwards.

A redeploy rewrites the package pointer, so it has to push again. If every attempt fails there,
the deployment reports a failure **and the app is left with no code** -- it does not keep
serving the package it had. Recovery does not need a rebuild: the previous package is still in
the `function-releases` container of the app's storage account, and pointing
`WEBSITE_RUN_FROM_PACKAGE` back at that blob brings the app back while you retry.
Rotating the storage account keys invalidates the read token inside that pointer, so the app
loses its code at the next restart -- issue a new token for the same blob and write the
pointer back.

One red row in **Resource group -> Deployments** is not ours and is harmless:
`Failure-Anomalies-Alert-Rule-Deployment-*`. Azure creates it by itself when the
Application Insights component appears, and it fails on a subscription that has
not registered the `Microsoft.AlertsManagement` provider (measured 7 Sep 2026).
Nothing in this template refers to it and the integration works without it;
register that provider if you want the smart-detection alert.

## What Gets Deployed

- **Azure Function App** (Python 3.11, Consumption plan) - Polls TAXII server on schedule
- **Application Insights** - Monitoring with step-by-step logging (workspace-based, 30 day retention)
- **Storage Account** - Checkpoint state per collection for cursor-based pagination
- **User-Assigned Managed Identity** - Secure access to Microsoft Sentinel and Storage
- **DCE + DCR + Audit Table** (optional) - Audit logging to SOCRadar_TAXII_Audit_CL with per-collection entries
- **Workbook** (optional) - SOCRadar TAXII 2.1 Dashboard with indicator analytics and audit monitoring
- **Six analytics rules** (optional) - threat hunting rules that match the indicators against your network, DNS, web, file and process logs
- **Deployment Script** - Automatically triggers first import after deployment

## Key Features

- Multi-collection support (multiple API roots in one deployment)
- STIX 2.1 indicator parsing (IP, domain, URL, file hash, email)
- Cursor-based pagination with per-collection checkpoint storage
- Batch upload to Microsoft Sentinel TI (100 indicators/batch)
- Per-collection error handling (one failure doesn't stop others)
- Managed Identity access to Microsoft Sentinel, Table storage and Azure Monitor (the TAXII password and the storage key are stored as app settings)
- Automatic first run after deployment

## Post-Deployment

The function automatically runs after deployment via a deployment script. By default, the first run fetches indicators from the last 48 hours. Set `InitialLookbackHours=0` to fetch all history (large collections sync incrementally via checkpoints). Subsequent runs poll on the configured schedule. Each collection keeps a checkpoint (cursor, then `added_after`) and the next run continues from it, so a page that loaded is not fetched again. A page that failed to load, or a run that stopped early (see `PartialSuccess` below), leaves the checkpoint where it was and that page is fetched again on the next run.

A run has a time budget of nine minutes, split across the collections. A first run with the default 48 hour lookback can be longer than that. It then pauses, keeps its place in the checkpoint and continues on the next run; the audit row says so (see `Status` below).

### Managing Collections

To add or remove collections after deployment:

1. Go to **Function App** > **Configuration** > **Application Settings**
2. Edit `API_ROOTS` and `COLLECTION_IDS` (comma-separated, same order)
3. Save and restart

New collections start from the configured lookback window. Removed collections leave harmless orphan checkpoints in Table Storage.

### Monitoring Logs

To view real-time execution logs:

1. Go to your **Function App** in Azure Portal
2. Navigate to **Monitoring > Log stream** for real-time logs
3. Or go to **Application Insights > Logs** and run:

```kql
traces
| where timestamp > ago(1h)
| where message has "Step"
| order by timestamp desc
```

Each run logs step-by-step progress per collection (Step 1: init, Step 2: per-collection fetch, Step 3: complete).

## Where to see it in the Microsoft Defender portal

Microsoft Sentinel in the Azure portal is supported until 31 March 2027; after that it is available only in the Microsoft Defender portal.

| What | Defender portal |
|---|---|
| Incidents raised by the threat hunting rules | Investigation & response > Incidents & alerts > Incidents |
| Indicators and audit data in KQL | Investigation & response > Hunting > Advanced hunting: `ThreatIntelIndicators`, `SOCRadar_TAXII_Audit_CL` (if audit logging is enabled); select the workspace at the top right, including a secondary workspace |
| Indicators in the TI page | Threat intelligence > Intel management (in tenants with the consolidated Threat Intelligence Explorer: Threat intelligence > Intel explorer > Indicators; shows the primary workspace) |
| SOCRadar TAXII 2.1 Dashboard | Microsoft Sentinel > Threat management > Workbooks. The Workbooks page shows data from the primary workspace only. |

In the Azure portal, indicators are under **Microsoft Sentinel > Threat management > Threat intelligence**, and both tables are under **Log Analytics > Logs**. Query indicators with `ThreatIntelIndicators | where SourceSystem == "SOCRadar TAXII"`. Both tables are also visualized in the **SOCRadar TAXII 2.1 Dashboard** workbook (Azure portal: Microsoft Sentinel > Workbooks).

**The same indicator more than once.** The checkpoint stops runs from re-fetching, but inside one fetch the TAXII server can send the same indicator on several pages (measured 1 Oct 2026 on one collection: 3552 indicator objects for 1268 distinct STIX ids, 2.8 times each). The import does not collapse them: every copy is uploaded. So `IndicatorsCreated` counts uploads Microsoft Sentinel accepted, not distinct indicators, and `ThreatIntelIndicators` in Log Analytics is an append log with one row per upload. `count()` over it overstates, and the workbook tiles that use `count()` (Indicators by Type, by Source, over time) count rows. For the number of different indicators count the ids:

```kql
ThreatIntelIndicators
| where SourceSystem == "SOCRadar TAXII"
| summarize Rows = count() by Id
| summarize Rows = sum(Rows), DistinctIndicators = count()
```

**Revoked indicators.** When SOCRadar withdraws an indicator, the TAXII feed carries the object again with `revoked: true`. The import uploads it like any other indicator, so Microsoft Sentinel stores the revoked flag and stops matching on it. `IndicatorsRevoked` in the audit table counts the revoked indicators Microsoft Sentinel accepted in that run.

**Audit logs** (if enabled) are stored in the `SOCRadar_TAXII_Audit_CL` custom table. Each import run creates one record per collection with indicators created, skipped, failed and revoked, duration, and status. Query with:

```kql
SOCRadar_TAXII_Audit_CL
| order by TimeGenerated desc
```

`Status` is one of:

| Status | Meaning |
|--------|---------|
| `Success` | Every indicator fetched reached Microsoft Sentinel. When the run paused on its time budget, `ErrorMessage` reads `time budget reached after N pages, more pages pending, continues next run`: the collection is still catching up and the checkpoint points at the next page. The server does not say how many pages remain, so none is claimed. Catching up is normal and not an alert, which is why the status stays `Success`. An empty `ErrorMessage` means the collection is caught up. |
| `PartialSuccess` | The run did not finish its collection, for one of two reasons. Some indicators did not reach Microsoft Sentinel: the run left its checkpoint where it was, so the next run fetches those pages again, and `IndicatorsFailed` is the count. Or the TAXII server sent `more=true` without a `next` cursor: the run stopped early, the checkpoint stayed where it was, and `IndicatorsFailed` can be 0. |
| `Failed` | The collection could not be read at all. Nothing was checkpointed. `ErrorMessage` carries the reason. |

To list the collections that are still catching up:

```kql
SOCRadar_TAXII_Audit_CL
| where ErrorMessage has "time budget reached"
| order by TimeGenerated desc
```

`IndicatorsSkipped` is different from `IndicatorsFailed`. Skipped indicators
reached Microsoft Sentinel and were rejected by it, so fetching them again
would change nothing. Failed indicators never arrived.

A run that reports `PartialSuccess` repeatedly for the same collection is not
recovering on its own. If `IndicatorsFailed` is 0, the server keeps sending
`more=true` without a `next` cursor and the fault is on the TAXII server side.
Otherwise the import will keep re-fetching the same page rather
than skip past it, which is the intended trade: a delayed indicator is
recoverable, a dropped one is not. Retries cover a transient 429 or 5xx from
the upload API; a persistent 4xx needs the cause fixed. The
`SOCRadar TAXII indicators did not reach Microsoft Sentinel` analytic rule
(Content Hub) reports this.

## Threat hunting rules

Six scheduled analytics rules compare the indicators this product writes with your own logs, through the ASIM parsers that every Microsoft Sentinel workspace has. Each match raises one alert. Alerts for the same entities within an hour join one incident (the domain rule groups by client IP, host and domain). The rules are in `Analytic Rules/` as YAML and in `azuredeploy.json` with the same queries.

| Rule | Reads | Matches |
|------|-------|---------|
| IP address contacted | `_Im_NetworkSession` | `DstIpAddr` against IP indicators |
| Inbound connection from IP address | `_Im_NetworkSession` | `SrcIpAddr` against IP indicators, only sessions the device allowed |
| Domain queried | `_Im_Dns` | `DnsQuery` against domain indicators |
| URL requested | `_Im_WebSession` | `Url` against URL indicators |
| File hash seen | `_Im_FileEvent` | SHA-256, SHA-1 and MD5 of the file against hash indicators |
| Process started from a known hash | `_Im_ProcessEvent` (ProcessCreated) | SHA-256, SHA-1 and MD5 of the process against hash indicators |

- Only indicators with `SourceSystem == "SOCRadar TAXII"` that are active and not past `ValidUntil` are used.
- The rules run every hour over the last 14 days of indicators and the last 2 hours of your logs. Microsoft Sentinel does not allow a lookback of 2 days or more with a run frequency below 1 hour, and 14 days is its maximum. An indicator that was not written again in the last 14 days is no longer matched.
- An event raises one alert. Each alert records an `EventKey` (indicator, host and event time), and later runs skip events whose key is already in `SecurityAlert` from the last 4 hours. Microsoft Sentinel reads every table about 5 minutes behind, so an alert is only skipped once it is older than that.
- Alerts carry the SOCRadar collection, confidence, valid-until date, threat labels and indicator id as custom details.
- SHA-384 and ssdeep indicators are imported but not matched: ASIM has no field for them.
- A rule only fires when the matching ASIM table has data. With no firewall, DNS, proxy or endpoint logs in ASIM, the rules stay quiet.
- To stop them, set `EnableThreatHuntRules` to `false` when you deploy and delete the six rules under **Microsoft Sentinel > Configuration > Analytics** (a redeploy does not delete rules). `tests/e2e/send_asim_logs.py` sends sample events to the ASIM tables to try the rules.

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Support:** integration@socradar.io
