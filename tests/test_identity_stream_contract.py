#!/usr/bin/env python3
"""Pin the stream consumed by the logger and the selected managed identity."""
import ast
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
template = json.loads((ROOT / 'azuredeploy.json').read_text())
parameter_table = (ROOT / 'README.md').read_text().split('## Parameters\n', 1)[1].split('\n## ', 1)[0]
documented = set(re.findall(r'^\|\s*`([^`]+)`\s*\|', parameter_table, re.M))
assert documented == set(template['parameters']), 'README parameter names differ from template: missing %s, extra %s' % (sorted(set(template['parameters']) - documented), sorted(documented - set(template['parameters'])))

support_types = {
    'microsoft.storage/storageaccounts',
    'microsoft.managedidentity/userassignedidentities',
    'microsoft.web/serverfarms',
    'microsoft.insights/components',
    'microsoft.web/sites',
    'microsoft.resources/deploymentscripts',
}
found_types = set()

def check_cloud_contract(value, path='$'):
    if isinstance(value, dict):
        resource_type = str(value.get('type', '')).lower()
        if resource_type in support_types:
            found_types.add(resource_type)
            assert value.get('location') == "[parameters('location')]", 'resource location must use location parameter: ' + resource_type
        for key, child in value.items():
            if key != '$schema':
                check_cloud_contract(key, path + '.<key>')
                check_cloud_contract(child, path + '.' + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_cloud_contract(child, path + '[%d]' % index)
    elif isinstance(value, str):
        assert not any(host in value.lower() for host in ('core.windows.net', 'management.azure.com', 'blob.core')), 'hardcoded Azure endpoint at ' + path

check_cloud_contract(template)
assert found_types == support_types, 'missing supporting resource types'
resources = template['resources']
script = next(r for r in resources if r['type'] == 'Microsoft.Resources/deploymentScripts')['properties']
script_env = {s['name']: s.get('value') for s in script['environmentVariables']}
assert script_env.get('RESOURCE_MANAGER') == '[environment().resourceManager]'
assert script_env.get('STORAGE_SUFFIX') == '[environment().suffixes.storage]'
assert '${RESOURCE_MANAGER%/}/subscriptions/$SUB_ID' in script['scriptContent']
assert '$SA.blob.$STORAGE_SUFFIX/function-releases/' in script['scriptContent']
site = next(r for r in resources if r['type'] == 'Microsoft.Web/sites')
settings = {s['name']: s['value'] for s in site['properties']['siteConfig']['appSettings']}
dcr = next(r for r in resources if r['type'] == 'Microsoft.Insights/dataCollectionRules')['properties']

def resolve(value):
    if value.startswith("[variables('") and value.endswith("')]"):
        return template['variables'][value[12:-3]]
    return value

stream = template['variables']['AuditStreamName']
assert resolve(settings['AUDIT_STREAM_NAME']) == stream, 'app audit stream drifted'
assert [resolve(k) for k in dcr['streamDeclarations']] == [stream], 'DCR declaration stream drifted'
for flow in dcr['dataFlows']:
    assert [resolve(s) for s in flow['streams']] == [stream], 'DCR input stream drifted'
    assert resolve(flow['outputStream']) == stream, 'DCR output stream drifted'

# Inspect the actual from_env expression without importing Azure dependencies.
tree = ast.parse((ROOT / 'FunctionApp/dcr_logger.py').read_text())
method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'from_env')
call = next(n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'cls')
arg = next(k.value for k in call.keywords if k.arg == 'audit_stream')
assert isinstance(arg, ast.Call) and ast.unparse(arg.func) == 'os.environ.get'
assert [ast.literal_eval(a) for a in arg.args] == ['AUDIT_STREAM_NAME', stream], 'logger environment name/default drifted'
ingest = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'log_audit')
assert any(isinstance(n, ast.Call) and ast.unparse(n.func) == 'self._ingest'
           and len(n.args) == 4 and ast.unparse(n.args[2]) == 'self.audit_stream'
           for n in ast.walk(ingest)), 'logger no longer sends the selected stream'

identity_id = "[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', variables('managedIdentityName'))]"
assert site['identity']['type'] == 'UserAssigned'
assert list(site['identity']['userAssignedIdentities']) == [identity_id], 'site identity drifted'
assert settings.get('AZURE_CLIENT_ID') == "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', variables('managedIdentityName')), '2024-11-30').clientId]", 'AZURE_CLIENT_ID must select the attached UAMI clientId'
assert any(r['type'] == 'Microsoft.ManagedIdentity/userAssignedIdentities'
           and r['name'] == "[variables('managedIdentityName')]" for r in resources)
print('audit stream declaration/settings/logger and UAMI selection: OK')
