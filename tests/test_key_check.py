#!/usr/bin/env python3
"""Rejected TAXII credentials fail the deployment instead of a green deploy that imports nothing.

The deploymentScript asks the TAXII server for the first collection with the username and
password. Only a 401 stops the deployment; a timeout, a 403 (Cloudflare turns away clients
it does not know) or a 5xx continues, because the credentials are not known to be bad.
The credentials reach curl on stdin, never on argv, and arrive as a secure environment value.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "azuredeploy.json")
PASSWORD = "PASS-SECRET-0123456789"
USER = "radar_user"

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


tmpl = json.load(open(TEMPLATE))
script_res = [r for r in tmpl["resources"] if r.get("type", "").endswith("deploymentScripts")][0]["properties"]
script = script_res["scriptContent"]
env_vars = {e["name"]: e for e in script_res["environmentVariables"]}

check("TAXII_PASSWORD" in env_vars and "secureValue" in env_vars["TAXII_PASSWORD"]
      and "value" not in env_vars["TAXII_PASSWORD"], "the password must be a secureValue environment variable")
check("TAXIIPassword" in env_vars.get("TAXII_PASSWORD", {}).get("secureValue", ""), "the password env var is not wired to TAXIIPassword")
check("TAXIIUsername" in env_vars.get("TAXII_USERNAME", {}).get("value", ""), "the username env var is not wired to TAXIIUsername")
check("ApiRoots" in env_vars.get("API_ROOT", {}).get("value", ""), "API_ROOT is not taken from ApiRoots")
check("CollectionIds" in env_vars.get("COLLECTION_ID", {}).get("value", ""), "COLLECTION_ID is not taken from CollectionIds")
check("set -x" not in script, "xtrace would print the password")
check("# key check" in script and script.index("# key check") < script.index("PACKAGE_URL"),
      "the credential check must run before the package is downloaded")

block = script[script.index("# key check"):script.index("# end key check")]

SHIM = '''#!/bin/bash
echo "$@" >> "$FAKE_ARGV"
cat > "$FAKE_STDIN"
[ "$FAKE_CODE" = 000 ] && { printf 000; exit 7; }
printf %s "$FAKE_CODE"
'''


def run(code, user=USER, password=PASSWORD, root="radar_alpha", collection="fd3fec42-efee-4353-85b2-cb87f9acc4ef"):
    with tempfile.TemporaryDirectory() as tmp:
        shim = os.path.join(tmp, "curl")
        open(shim, "w").write(SHIM)
        os.chmod(shim, 0o755)
        env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"], FAKE_CODE=code,
                   FAKE_ARGV=os.path.join(tmp, "argv"), FAKE_STDIN=os.path.join(tmp, "stdin"),
                   TAXII_USERNAME=user, TAXII_PASSWORD=password, API_ROOT=root, COLLECTION_ID=collection)
        r = subprocess.run(["bash", "-c", "set -e\n" + block + "\necho REACHED_NEXT_STEP"], env=env,
                           capture_output=True, text=True)
        argv = open(env["FAKE_ARGV"]).read() if os.path.exists(env["FAKE_ARGV"]) else None
        stdin = open(env["FAKE_STDIN"]).read() if os.path.exists(env["FAKE_STDIN"]) else None
        return r, argv, stdin


r, argv, stdin = run("200")
check(r.returncode == 0 and "REACHED_NEXT_STEP" in r.stdout, "good credentials must continue: %r" % r.stdout)
check(argv is not None and PASSWORD not in argv, "the password is on curl's command line")
check(stdin is not None and PASSWORD in stdin and USER in stdin, "the credentials did not reach curl on stdin")
check(argv and "taxii2.socradar.com/radar_alpha/collections/fd3fec42-efee-4353-85b2-cb87f9acc4ef/" in argv,
      "wrong URL: %r" % argv)

# a quote or backslash in the password must not break the curl config line
r, _, stdin = run("200", password='pa"ss\\word')
check(stdin is not None and 'pa\\"ss\\\\word' in stdin, "quote and backslash must be escaped in the curl config: %r" % stdin)

r, _, _ = run("401")
check(r.returncode != 0 and "REACHED_NEXT_STEP" not in r.stdout, "a 401 must stop the deployment")
check("rejected" in r.stderr and PASSWORD not in r.stdout + r.stderr,
      "the 401 message must be on stderr (the portal shows only stderr as the error) and not leak the password: %r / %r"
      % (r.stdout, r.stderr))

for code in ("500", "403", "000"):
    r, _, _ = run(code)
    check(r.returncode == 0 and "REACHED_NEXT_STEP" in r.stdout, "HTTP %s must not stop the deployment: %r" % (code, r.stdout))

for kw in (dict(user=""), dict(password=""), dict(root=""), dict(collection="")):
    r, argv, _ = run("401", **kw)
    check(r.returncode == 0 and argv is None, "nothing to check, curl must not be called: %r" % kw)

if failures:
    for line in failures:
        print("FAIL " + line)
    sys.exit(1)
print("credential check in the deployment script: OK (%d checks)" % checks)
