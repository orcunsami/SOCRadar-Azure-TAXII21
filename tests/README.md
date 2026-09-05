# Tests

Plain Python scripts, no framework. Each one exits non-zero on failure and
prints what it checked.

```bash
python3.11 tests/run_all.py
```

Use Python 3.11. That is what the Function App runs (`linuxFxVersion` is
`Python|3.11`) and a newer interpreter reports failures the deployed runtime
would never see.

| File | What it protects |
|------|------------------|
| `test_upload_failure_keeps_checkpoint.py` | An upload that never reached Microsoft Sentinel must not move the checkpoint. Losing that guarantee loses indicators permanently and silently. |
| `test_retry_policy.py` | Retries are bounded, honour `Retry-After`, cap the wait, skip statuses that will never succeed, and refuse to sleep past the run's time budget. |
| `test_audit_schema.py` | Every audit field the code sends is declared in both the data collection rule and the Log Analytics table. An undeclared column is dropped without an error. |
| `test_audit_status.py` | A run that lost indicators reports `PartialSuccess`, not `Success`, and does not raise. |

`_harness.py` holds the stubs. The Function App only talks to the outside world
through `requests`, so replacing that one module drives every path, including
the failure paths a live server would rarely produce on demand.

## Mutation checking

A test that cannot fail protects nothing. Before trusting these, break the
thing each one guards and confirm it goes red:

- make the checkpoint save unconditional
- return failed indicators as skipped
- write `Success` regardless of the counters
- ignore `Retry-After`
- set `MAX_ATTEMPTS = 1`
- delete a column from the DCR stream or the table schema

## mutate.py

`python3 tests/mutate.py` breaks the code on purpose, ten times, and checks that
the matching test file fails each time. A mutation that survives is reported as
BLIND and the run exits non-zero: that means the gate is decorative, not that
the code is fine.

It runs the child processes with bytecode disabled. A same-byte-size mutation
applied and reverted inside one second leaves a `.pyc` whose (mtime, size) key
still looks current, and later runs would execute the mutated bytecode instead
of the source — that cost a full round of false results once already.
