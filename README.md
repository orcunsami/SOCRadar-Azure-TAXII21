# SOCRadar TAXII 2.1 for Microsoft Sentinel

Ingests STIX 2.1 threat indicators from SOCRadar's TAXII 2.1 server into Microsoft Sentinel Threat Intelligence.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Forcunsami%2FSOCRadar-Azure-TAXII21%2Fmaster%2Fazuredeploy.json)

## Prerequisites

- Microsoft Sentinel workspace
- SOCRadar API Key (used as TAXII password)
- SOCRadar TAXII Collection ID

## Configuration

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `TAXIIServerUrl` | TAXII 2.1 server URL (e.g., `https://platform.socradar.com/taxii2`) |
| `CollectionId` | TAXII collection ID to poll |
| `TAXIIUsername` | TAXII username (usually your SOCRadar Company ID) |
| `TAXIIPassword` | TAXII password (your SOCRadar API Key) |
| `WorkspaceName` | Your Sentinel workspace name |

### Optional Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PollingIntervalMinutes` | 15 | How often to poll TAXII server (5-1440 min) |
| `MinConfidence` | 0 | Minimum STIX confidence score to import (0-100) |
| `MaxPagesPerRun` | 100 | Maximum TAXII pages per polling cycle |
| `EnableAuditLogging` | false | Log operations to SOCRadar_TAXII_Import_CL table |

## What Gets Deployed

- **SOCRadar-TAXII-Import** - Logic App that orchestrates TAXII polling and Sentinel TI upload
- **Azure Function** - Parses STIX 2.1 indicator patterns into Sentinel TI format
- **Storage Account** - Table Storage for TAXII cursor/state persistence
- **Application Insights** - Function App monitoring

## Architecture

Logic App (orchestrator) + Azure Function (STIX parser) hybrid:

1. Logic App polls TAXII 2.1 server with cursor-based pagination
2. Fetches only latest versions (`match[version]=last`)
3. Azure Function parses STIX 2.1 patterns (simple, compound OR/AND)
4. Revoked indicators are automatically removed from Sentinel
5. Parsed indicators uploaded to Sentinel TI via ARM API
6. Cursor state saved to Table Storage for incremental polling

### Supported Indicator Types

| STIX Type | Example Pattern |
|-----------|----------------|
| IPv4 | `[ipv4-addr:value = '1.2.3.4']` |
| IPv6 | `[ipv6-addr:value = '::1']` |
| Domain | `[domain-name:value = 'evil.com']` |
| URL | `[url:value = 'https://evil.com/path']` |
| File Hash | `[file:hashes.'SHA-256' = 'abc...']` |
| Email | `[email-addr:value = 'bad@evil.com']` |

Compound patterns like `[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']` are split into individual Sentinel indicators.

## Post-Deployment

Logic App starts 3 minutes after deployment to allow Azure role propagation. No manual action required.

## Audit Logging (Optional)

Deploy the Infrastructure template separately for audit logging:

```
Playbooks/SOCRadar-TAXII-Infrastructure/azuredeploy.json
```

This creates:
- `SOCRadar_TAXII_Import_CL` custom table
- Data Collection Endpoint and Rules

## Redeployment

Role assignments use deployment-scoped unique identifiers. Safe to delete and redeploy without `RoleAssignmentUpdateNotPermitted` errors.

## Azure Function

The STIX parser function is deployed as part of the template. Source code is in `azure-function/ParseSTIXIndicators/`.

If you need to update the function code independently:
1. Navigate to the Function App in Azure Portal
2. Use the built-in code editor or deploy via VS Code / Azure CLI

## About SOCRadar

SOCRadar is an Extended Threat Intelligence (XTI) platform that provides actionable threat intelligence, digital risk protection, and external attack surface management.

Learn more at [socradar.io](https://socradar.io)

## Support

- **Documentation:** [docs.socradar.io](https://docs.socradar.io)
- **Support:** support@socradar.io
