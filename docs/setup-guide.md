# Setup guide

You fill in one Azure deployment form. Nothing is entered in SOCRadar.
Order: find your workspace (1), deploy (2), check that indicators arrive (3).

## 0. What you need

| Value | Where you find it | Section |
|-------|-------------------|---------|
| Workspace name | Log Analytics workspaces, the workspace where Microsoft Sentinel is enabled | 1.0 |
| Resource group of the workspace | Same page. Only needed when it is not the group you deploy to | 1.0, 4 |
| `TAXIIUsername` | From SOCRadar, e.g. `radar_<company id>`, not the bare company ID | 2.1 |
| `TAXIIPassword` | Your SOCRadar Platform API key | 2.1 |
| `ApiRoots` and `CollectionIds` | From SOCRadar, see the table in the README | 2.1 |

The workspace must already exist and Microsoft Sentinel must be enabled on it.
You need Owner or User Access Administrator on the resource group you deploy to (the template assigns roles to the app's identity).

## 1.0 Find the workspace name

Azure portal > Log Analytics workspaces. Copy the name of the workspace Microsoft Sentinel runs on (the name, not the workspace ID).

## 2.0 Deploy to Azure

Click the button in the README. The form opens with the right template already loaded.

## 2.1 Fill the form

Choose the resource group (or create one), then fill in:

- `WorkspaceName`: the name from step 1.0.
- `DeployNewWorkspace`: leave `false`. The deployment does not update your workspace, so its pricing tier, retention and daily cap stay as they are. A misspelled name fails the deployment before anything is created. Set `true` only when you do not have a workspace and want the deployment to create one.
- `ApiRoots`, `CollectionIds`, `TAXIIUsername`, `TAXIIPassword`: the values from SOCRadar. The first API root uses the first collection ID, the second uses the second.

Leave the other fields at their defaults and click **Review + create**, then **Create**.

## 2.2 Deployment complete

It takes about 5 minutes. When it says "Your deployment is complete", the first import has already been started.

If the deployment fails, open **Resource group > Deployments**, click the red row and read the error. The README lists the common ones.

## 3.0 Check the Function App

Resource group > the Function App > Functions. You should see one function. The import runs on the schedule you set (every 60 minutes by default).

## 3.1 Audit table

Log Analytics workspace > Logs:

```kql
SOCRadar_TAXII_Audit_CL
| order by TimeGenerated desc
```

One row per collection per run. `Status` should be `Success`. A first run with the 48 hour default can pause on its time budget; the row then says `time budget reached`, and the next run continues.

## 3.2 Indicators

```kql
ThreatIntelIndicators
| where SourceSystem == "SOCRadar TAXII"
| take 10
```

The first rows can take a few minutes after the first run. They also show under Microsoft Sentinel > Threat Intelligence.

## 4. Workspace in another resource group

Set `WorkspaceResourceGroup` to the group that holds the workspace. You also need Owner or User Access Administrator there. See "Workspace in another resource group" in the README.

## 5. Check your pricing tier (existing installs)

Installs made before September 2026 could reset a workspace on a commitment tier to pay-as-you-go. Check yours:

```bash
az monitor log-analytics workspace show -g <resource-group> -n <workspace> \
  --query "{sku:sku.name, lastSkuUpdate:sku.lastSkuUpdate}" -o json
```

If `lastSkuUpdate` lines up with the day you deployed and the tier is not the one you chose, set it again under Log Analytics workspaces > Usage and estimated costs > Pricing tier.

## 6. Remove

Delete the resource group you deployed to, or the resources the template created (Function App, storage account, Application Insights, managed identity, data collection endpoint and rule, workbook). Your workspace is not part of that list. If the workspace was in another resource group, remove the role assignment of the deleted identity on the workspace.
