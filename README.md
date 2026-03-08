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
- **Storage Account** - Checkpoint state for cursor-based pagination
- **DCE + DCR + Audit Table** (optional) - Audit logging to SOCRadar_TAXII_Audit_CL

## Key Features

- STIX 2.1 indicator parsing (IP, domain, URL, file hash, email)
- Cursor-based pagination with checkpoint storage
- Batch upload to Sentinel TI (100 indicators/batch)
- Confidence score filtering
- Managed Identity authentication (no stored credentials for Azure)

## Post-Deployment

Function polls on the configured schedule. First run processes all available indicators from the TAXII collection. Subsequent runs continue from the saved cursor position.

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
