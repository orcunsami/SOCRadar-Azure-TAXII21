# SOCRadar-TAXII-Infrastructure

Creates custom log table and data collection infrastructure for TAXII import audit logging.

## What It Creates

- **Data Collection Endpoint** (SOCRadar-TAXII-DCE)
- **Custom Log Table** (SOCRadar_TAXII_Import_CL) with columns:
  - TimeGenerated, CollectionID, RunID
  - IndicatorsProcessed, IndicatorsCreated, IndicatorsFailed
  - PagesFetched, DurationMs, Status, ErrorMessage
- **Data Collection Rule** (SOCRadar-TAXII-Import-DCR)

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| WorkspaceName | Log Analytics Workspace name | - |
| WorkspaceLocation | Workspace location | Resource group location |
| RetentionDays | Log retention (7-730 days) | 30 |

## Prerequisites

- Existing Log Analytics Workspace with Microsoft Sentinel
- Deploy this before enabling audit logging in SOCRadar-TAXII-Import
