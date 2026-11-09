# ARM-TTK exceptions, 9 November 2026

Scope: standalone TAXII template. Hardcoded URI and resource location failures were fixed. Python token scopes remain public-cloud scoped. No ARM-TTK test is skipped.

`apiVersions Should Be Recent` remains a reported failure. Its ten diagnostics are retained below. This template-only compatibility change retains the previously greenfield-tested resource schemas; changing those schemas is a separate validation task. The exception is a recorded limitation, not a claim that an old API is current or approved by Microsoft.

| Diagnostic resource | API | Individual reason for retaining it |
|---|---|---|
| precheck-workspace-exists deployment | 2021-04-01 | Existing nested deployment scope and precheck output contract; API migration is outside the URL/location fix. |
| precheck-external-workspace deployment | 2021-04-01 | Cross-RG precheck expression scope must retain its independently tested behavior. |
| workspaces | 2023-09-01 | Pricing, retention and existing-workspace protection are unchanged; no workspace schema migration is claimed. |
| dataCollectionEndpoints | 2023-03-11 | Retain the tested logs-ingestion endpoint reference contract. |
| workspaces/tables | 2022-10-01 | Retain the tested audit schema and table plan contract in both local/nested copies. |
| external audit resources deployment | 2021-04-01 | Retain the cross-RG table/RBAC nested deployment evaluation scope. |
| dataCollectionRules | 2023-03-11 | Stream declaration/dataFlow contract remains unchanged; the new regression gate covers stream equality. |
| userAssignedIdentities | 2023-01-31 | Retain identity resource creation behavior. The clientId reference already uses 2024-11-30 and is separately pinned by a test. |
| serverfarms | 2023-12-01 | Retain Linux consumption plan provisioning behavior; this task changes only its location source. |
| sites | 2023-12-01 | Retain Function host and app-settings provisioning behavior; published FunctionApp code/package are unchanged. |

Owner: Azure integration maintainer. Revisit these individual APIs in a separately measured compatibility change before removing this exception.

The tool also emits a nested-template JSON conversion error at the escaped analytic-rule name expression. The same diagnostic exists at baseline 74b68e8; the template parses as JSON in CI. This is preserved as a tool limitation, not silently counted as a successful nested-template analysis. Greenfield deployment acceptance is a separate gate.
