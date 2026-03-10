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

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `WorkspaceName` | Yes | - | Microsoft Sentinel workspace name |
| `ApiRoots` | Yes | - | Comma-separated TAXII API root names (e.g., `radar_alpha,radar_gamma`) |
| `CollectionIds` | Yes | - | Comma-separated collection UUIDs matching API roots order |
| `TAXIIUsername` | Yes | - | SOCRadar Company ID |
| `TAXIIPassword` | Yes | - | SOCRadar Platform API Key |
| `PollingIntervalMinutes` | No | 60 | Polling interval (5-1440 min) |
| `InitialLookbackHours` | No | 48 | Hours of history on first run (0 = all history) |
| `EnableAuditLogging` | No | true | Log to SOCRadar_TAXII_Audit_CL |

Each API root position matches the corresponding collection ID position. For example, `radar_alpha,radar_gamma` with `fd3fec42-...,f260cf45-...` means radar_alpha uses fd3fec42 and radar_gamma uses f260cf45.

## SOCRadar TAXII API Roots

| API Root | Collection UUID |
|----------|-----------------|
| `radar_alpha` | `fd3fec42-efee-4353-85b2-cb87f9acc4ef` |
| `radar_gamma` | `f260cf45-85ef-4f86-9542-763061f11d50` |
| `radar_premium` | `cfcf66c0-3226-561e-a9d9-b54addca5dd1` |

Contact SOCRadar for your API root and collection details.

## What Gets Deployed

- **Azure Function App** (Python 3.11, Consumption plan) - Polls TAXII server on schedule
- **Application Insights** - Monitoring with step-by-step logging (workspace-based, 30 day retention)
- **Storage Account** - Checkpoint state per collection for cursor-based pagination
- **User-Assigned Managed Identity** - Secure access to Microsoft Sentinel and Storage
- **DCE + DCR + Audit Table** (optional) - Audit logging to SOCRadar_TAXII_Audit_CL with per-collection entries
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

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
