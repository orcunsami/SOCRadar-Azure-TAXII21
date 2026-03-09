# SOCRadar TAXII 2.1 for Microsoft Sentinel

Imports STIX 2.1 threat intelligence indicators from SOCRadar TAXII server into Microsoft Sentinel.

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
    TAXIIServerURL=https://taxii2.socradar.com/radar_alpha \
    TAXIIUsername=<COMPANY_ID> \
    TAXIIPassword=<API_KEY> \
    CollectionId=<COLLECTION_UUID>
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `WorkspaceName` | Yes | - | Microsoft Sentinel workspace name |
| `TAXIIServerURL` | Yes | - | TAXII server URL with API root |
| `TAXIIUsername` | Yes | - | SOCRadar Company ID |
| `TAXIIPassword` | Yes | - | SOCRadar Platform API Key |
| `CollectionId` | Yes | - | TAXII collection UUID |
| `PollingIntervalMinutes` | No | 60 | Polling interval (5-1440 min) |
| `MinConfidence` | No | 0 | Minimum confidence score (0-100) |
| `MaxPagesPerRun` | No | 100 | Max TAXII pages per cycle |
| `EnableAuditLogging` | No | true | Log to SOCRadar_TAXII_Audit_CL |

## SOCRadar TAXII API Roots

| API Root | URL | Collection UUID |
|----------|-----|-----------------|
| Alpha | `https://taxii2.socradar.com/radar_alpha` | `fd3fec42-efee-4353-85b2-cb87f9acc4ef` |
| Gamma | `https://taxii2.socradar.com/radar_gamma` | `f260cf45-85ef-4f86-9542-763061f11d50` |
| Premium | `https://taxii2.socradar.com/radar_premium` | `cfcf66c0-3226-561e-a9d9-b54addca5dd1` |

Contact SOCRadar for your API root and collection details.

## What Gets Deployed

- **Azure Function App** (Python 3.11, Consumption plan) - Polls TAXII server on schedule
- **Application Insights** - Monitoring with step-by-step logging (workspace-based, 30 day retention)
- **Storage Account** - Checkpoint state for cursor-based pagination
- **User-Assigned Managed Identity** - Secure access to Microsoft Sentinel and Storage
- **DCE + DCR + Audit Table** (optional) - Audit logging to SOCRadar_TAXII_Audit_CL
- **Deployment Script** - Automatically triggers first import after deployment

## Key Features

- STIX 2.1 indicator parsing (IP, domain, URL, file hash, email)
- Cursor-based pagination with checkpoint storage
- Batch upload to Microsoft Sentinel TI (100 indicators/batch)
- Confidence score filtering
- Managed Identity authentication (no stored credentials for Azure)
- Automatic first run after deployment

## Post-Deployment

The function automatically runs after deployment via a deployment script. Subsequent runs poll on the configured schedule. Only new indicators are imported (cursor-based deduplication).

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

Each run logs step-by-step progress (Step 1: init, Step 2: fetch pages, Step 3: complete, Step 4: audit).

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
