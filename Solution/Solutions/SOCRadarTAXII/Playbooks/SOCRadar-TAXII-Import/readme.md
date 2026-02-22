# SOCRadar-TAXII-Import

Imports threat intelligence indicators from SOCRadar TAXII 2.1 feeds into Microsoft Sentinel.

## What It Does

1. Connects to SOCRadar TAXII 2.1 server
2. Fetches indicators with cursor-based pagination
3. Parses STIX 2.1 patterns via Azure Function
4. Uploads indicators to Sentinel Threat Intelligence
5. Saves state to Table Storage for reliable resumption

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| TAXIIServerURL | SOCRadar TAXII 2.1 server URL | - |
| TAXIIUsername | TAXII authentication username | - |
| TAXIIPassword | TAXII authentication password | - |
| CollectionID | TAXII collection ID to poll | - |
| PollingIntervalMinutes | How often to check for new indicators | 15 |
| MinConfidence | Minimum confidence score to import (0-100) | 50 |
| EnableAuditLogging | Log import runs to custom table | false |

## Deployed Resources

- Storage Account (Table Storage for state + Function App storage)
- App Service Plan (Consumption Y1)
- Application Insights
- Function App (Python 3.11 STIX parser)
- Logic App (orchestrator, Managed Identity)
- Role Assignments (Sentinel Contributor, Storage Table Data Contributor)

## Prerequisites

- SOCRadar TAXII 2.1 credentials
- Microsoft Sentinel workspace

## Post-Deployment

The Logic App deploys in Disabled state. Enable it after verifying role assignments have propagated (2-3 minutes).
