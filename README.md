# SOCRadar TAXII 2.1 for Microsoft Sentinel

Imports STIX threat intelligence indicators from SOCRadar TAXII 2.1 server into Microsoft Sentinel.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-TAXII21%2Fmaster%2Fazuredeploy.json)

## Prerequisites

- Microsoft Sentinel workspace
- SOCRadar TAXII credentials (username + password)

## Configuration

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `WorkspaceName` | Your Sentinel workspace name |
| `TAXIIServerURL` | SOCRadar TAXII server URL |
| `TAXIIUsername` | TAXII authentication username |
| `TAXIIPassword` | TAXII authentication password |
| `CollectionId` | TAXII collection ID |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PollingIntervalMinutes` | 15 | How often to poll for new indicators |
| `MinConfidence` | 0 | Minimum confidence score (0-100) |
| `MaxPagesPerRun` | 100 | Maximum TAXII pages per polling cycle |
| `EnableAuditLogging` | false | Log operations to Log Analytics |

## What Gets Deployed

- **SOCRadar-TAXII-Import** - Logic App that polls TAXII server and imports indicators
- **Azure Function (ParseSTIXIndicators)** - Parses STIX bundles into Sentinel TI format
- **Storage Account** - Checkpoint state for pagination
- **SOCRadar-TAXII-Infrastructure** - Audit logging infrastructure (optional)

## Key Features

- STIX 2.1 indicator parsing (IP, domain, URL, file hash, email)
- Stateful pagination with checkpoint storage
- Indicator revocation support
- Exponential backoff retry on transient failures
- Confidence score filtering

## Post-Deployment

Logic App starts 3 minutes after deployment to allow Azure role propagation.

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
