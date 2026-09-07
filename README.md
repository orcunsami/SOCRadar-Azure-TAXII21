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
    TAXIIUsername=<COMPANY_ID> \
    TAXIIPassword=<API_KEY>
```

If the workspace lives in another resource group, add `WorkspaceResourceGroup=<WORKSPACE_RG>`.

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `WorkspaceName` | Yes | - | Microsoft Sentinel workspace name |
| `DeployNewWorkspace` | No | `false` | Create `WorkspaceName` instead of using an existing one. Set `true` for a greenfield deploy into an empty resource group; leave `false` to attach to your existing workspace without touching its pricing tier, retention or daily cap. |
| `WorkspaceResourceGroup` | No | deployment RG | Resource group of the workspace when it is not the one you deploy to. See [Workspace in another resource group](#workspace-in-another-resource-group). |
| `ApiRoots` | Yes | - | Comma-separated TAXII API root names (e.g., `radar_alpha,radar_gamma`) |
| `CollectionIds` | Yes | - | Comma-separated collection UUIDs matching API roots order |
| `TAXIIUsername` | Yes | - | SOCRadar Company ID |
| `TAXIIPassword` | Yes | - | SOCRadar Platform API Key |
| `PollingIntervalMinutes` | No | 60 | Polling interval (5-1440 min) |
| `InitialLookbackHours` | No | 48 | Hours of history on first run (0 = all history) |
| `EnableAuditLogging` | No | true | Log to SOCRadar_TAXII_Audit_CL |
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
costs > Pricing tier**. The current template states no workspace-level settings at all, so
redeploying -- even with `DeployNewWorkspace=true` set by mistake -- cannot change its pricing
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
- **Deployment Script** - Automatically triggers first import after deployment

## Key Features

- Multi-collection support (multiple API roots in one deployment)
- STIX 2.1 indicator parsing (IP, domain, URL, file hash, email)
- Cursor-based pagination with per-collection checkpoint storage
- Batch upload to Microsoft Sentinel TI (100 indicators/batch)
- Per-collection error handling (one failure doesn't stop others)
- Managed Identity authentication (no stored credentials for Azure)
- Automatic first run after deployment

## Post-Deployment

The function automatically runs after deployment via a deployment script. By default, the first run fetches indicators from the last 48 hours. Set `InitialLookbackHours=0` to fetch all history (large collections sync incrementally via checkpoints). Subsequent runs poll on the configured schedule. Only new indicators are imported (cursor-based deduplication per collection).

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

### Where Data Appears

**Threat Intelligence indicators** are uploaded to the `ThreatIntelIndicators` table in Log Analytics. You can view them in:

- **Microsoft Sentinel > Threat Intelligence** blade
- **Log Analytics > Logs** with query: `ThreatIntelIndicators | where SourceSystem == "SOCRadar TAXII"`

**Revoked indicators.** When SOCRadar withdraws an indicator, the TAXII feed carries the object again with `revoked: true`. The import uploads it like any other indicator, so Microsoft Sentinel stores the revoked flag and stops matching on it. `IndicatorsRevoked` in the audit table counts the revoked indicators Microsoft Sentinel accepted in that run.

**Audit logs** (if enabled) are stored in the `SOCRadar_TAXII_Audit_CL` custom table. Each import run creates one record per collection with indicators created, skipped, failed and revoked, duration, and status. Query with:

```kql
SOCRadar_TAXII_Audit_CL
| order by TimeGenerated desc
```

`Status` is one of:

| Status | Meaning |
|--------|---------|
| `Success` | Every page was fetched and every indicator reached Microsoft Sentinel. |
| `PartialSuccess` | Some indicators did not reach Microsoft Sentinel. The run left its checkpoint where it was, so the next run fetches those pages again. `IndicatorsFailed` is the count. |
| `Failed` | The collection could not be read at all. Nothing was checkpointed. `ErrorMessage` carries the reason. |

`IndicatorsSkipped` is different from `IndicatorsFailed`. Skipped indicators
reached Microsoft Sentinel and were rejected by it, so fetching them again
would change nothing. Failed indicators never arrived.

A run that reports `PartialSuccess` repeatedly for the same collection is not
recovering on its own. The import will keep re-fetching the same page rather
than skip past it, which is the intended trade: a delayed indicator is
recoverable, a dropped one is not. Retries cover a transient 429 or 5xx from
the upload API; a persistent 4xx needs the cause fixed. The
`SOCRadar TAXII indicators did not reach Microsoft Sentinel` analytic rule
(Content Hub) reports this.

Both tables are also visualized in the **SOCRadar TAXII 2.1 Dashboard** workbook (Microsoft Sentinel > Workbooks).

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
