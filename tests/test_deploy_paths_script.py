#!/usr/bin/env python3
"""scripts/test_deploy_paths.sh needs credentials the TAXII server accepts, and keeps them off argv.

The deployment checks the credentials (a 401 fails it), so placeholders no longer deploy. Without
the four TEST_* variables the script must stop before it touches Azure. The password travels in a
0600 parameter file, the rejected-credentials path K uses its own file, and nothing says "placeholder".
"""

import os
import re
import stat
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "test_deploy_paths.sh")
text = open(SCRIPT).read()

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


VARS = ("TEST_TAXII_USERNAME", "TEST_TAXII_PASSWORD", "TEST_API_ROOT", "TEST_COLLECTION_ID")


def run(env_extra):
    with tempfile.TemporaryDirectory() as tmp:
        az = os.path.join(tmp, "az")
        open(az, "w").write('#!/bin/sh\necho "$@" >> "%s"\nexit 1\n' % os.path.join(tmp, "calls"))
        os.chmod(az, os.stat(az).st_mode | stat.S_IXUSR)
        env = {k: v for k, v in os.environ.items() if k not in VARS}
        env.update(PATH=tmp + os.pathsep + os.environ["PATH"], **env_extra)
        try:
            r = subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            # a script that got past the guard keeps going (resource groups, waits); that is the failure
            r = subprocess.CompletedProcess(SCRIPT, 0, "", "still running after 20s: the guard did not stop it")
        calls = open(os.path.join(tmp, "calls")).read() if os.path.exists(os.path.join(tmp, "calls")) else ""
        return r, calls


# any one missing variable stops the run before az is called
full = dict(TEST_TAXII_USERNAME="u", TEST_TAXII_PASSWORD="p", TEST_API_ROOT="radar_alpha", TEST_COLLECTION_ID="c")
for missing in VARS:
    env = {k: v for k, v in full.items() if k != missing}
    r, calls = run(env)
    check(r.returncode != 0 and "TEST_TAXII_USERNAME" in r.stdout + r.stderr and calls == "",
          "without %s the script went on or did not say what to set (rc=%s, az calls: %r)" % (missing, r.returncode, calls[:80]))

check("placeholder" not in text.lower().replace("placeholders no longer", ""),
      "a placeholder credential would be rejected by the deployment")
check(not re.search(r"TAXIIPassword=", text.replace('"TAXIIPassword"', "")), "the password is on the az command line")
check('--parameters @"${PARAM_FILE:-$CRED_FILE}"' in text, "credentials must come from the parameter file")
check("umask 077" in text and text.index("umask 077") < text.index("CRED_FILE=$(mktemp)"), "the parameter file must be created 0600")
check('PARAM_FILE="$DEAD_FILE" deploy "$RG_K" path-k' in text, "path K must deploy with the rejected password")
check('rm -f "$CRED_FILE" "$DEAD_FILE"' in text, "the credential files are left behind")
check("rejected the username or password" in text and "triggerFirstRun" in text, "path K must check the banner text and the failing step")

if failures:
    for f in failures:
        print("FAIL " + f)
    sys.exit(1)
print("test_deploy_paths.sh needs real credentials and keeps them off argv: OK (%d checks)" % checks)
