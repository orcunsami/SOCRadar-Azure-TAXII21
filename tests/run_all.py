#!/usr/bin/env python3
"""Run every test in this directory and report a single verdict."""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = sorted(f for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py"))

# Never leave .pyc files behind. A cached module is keyed on the source's
# mtime in whole seconds and its size, so a mutation check that swaps a byte
# and restores it inside the same second leaves a stale cache that silently
# feeds the mutated code to every later run.
env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

failed = []
for name in TESTS:
    result = subprocess.run([sys.executable, os.path.join(HERE, name)],
                            capture_output=True, text=True, env=env)
    sys.stdout.write(result.stdout)
    if result.returncode:
        sys.stdout.write(result.stderr)
        failed.append(name)

print()
if failed:
    print("FAILED: %s" % ", ".join(failed))
    sys.exit(1)
print("%d test file(s) passed" % len(TESTS))
