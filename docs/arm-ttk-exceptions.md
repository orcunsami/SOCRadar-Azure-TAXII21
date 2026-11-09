# ARM-TTK status, 9 November 2026

The old API-version exception is closed in task 0116. No test is skipped or excluded.

| Resource type | API |
|---|---|
| Microsoft.Resources/deployments | 2025-04-01 |
| Microsoft.OperationalInsights/workspaces | 2025-02-01 |
| Microsoft.OperationalInsights/workspaces/tables | 2025-02-01 |
| Microsoft.Insights/dataCollectionEndpoints | 2024-03-11 |
| Microsoft.Insights/dataCollectionRules | 2025-05-11 |
| Microsoft.ManagedIdentity/userAssignedIdentities | 2024-11-30 |
| Microsoft.Web/serverfarms, Microsoft.Web/sites | 2025-03-01 |

These versions were present in the Azure provider inventory on 9 November 2026.
The endpoint version is the provider's latest stable version. Resource properties,
Function code and package are unchanged. Full-repository ARM-TTK returned 33 PASS,
0 FAIL with toolkit commit `0ec9a41a4503e970a0ec8efb0cd08415cc172175`.

The toolkit still emits the baseline nested-template expansion error at the
analytic-rule name expression. The 33 passing records do not prove successful
analysis of that nested template. New greenfield deployment and same-parameter
redeployment remain pending an authorized test slot. No live compatibility or
independent review acceptance is claimed by this static result.
