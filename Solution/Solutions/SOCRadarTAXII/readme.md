# SOCRadar TAXII Solution for Microsoft Sentinel

Ingests threat intelligence indicators (IOCs) from SOCRadar via TAXII 2.1 protocol into Microsoft Sentinel.

## Components

- **SOCRadar-TAXII-Import** - Logic App with Azure Function for TAXII 2.1 ingestion. Handles pagination, STIX parsing, and Sentinel TI upload.
- **SOCRadar-TAXII-Infrastructure** - Creates custom log table and data collection infrastructure for audit logging.
- **Workbook** - Dashboard showing indicator types, confidence levels, ingestion trends, and health metrics.
- **Hunting Queries** - IOC overview and ingestion health monitoring.

## Architecture

Uses a hybrid approach:
- Logic App handles orchestration (TAXII pagination, state management, Sentinel upload)
- Azure Function handles STIX 2.1 pattern parsing (requires regex, not available in Logic Apps)
- Table Storage for cursor-based state persistence across runs

## Prerequisites

- SOCRadar TAXII 2.1 credentials (server URL, username, password, collection ID)
- Microsoft Sentinel workspace
- Contributor access to the resource group

## Deployment

Deploy the Import playbook first, then optionally deploy Infrastructure for audit logging.
