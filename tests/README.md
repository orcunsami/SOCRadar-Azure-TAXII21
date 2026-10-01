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
| `test_audit_status.py` | A run that lost indicators, or stopped early, reports `PartialSuccess`, not `Success`, and does not raise. A run paused on its time budget stays `Success` but its `ErrorMessage` says data is pending. |
| `test_budget_pause.py` | A run that stops on its time budget reports `paused`, pins the checkpoint to the next cursor with its original lookback, and the next run continues from there. |
| `test_portal_dedup.py` | `scripts/portal_test.sh` runs against a fake `az`/`curl`: it fails when the product re-uploads on later runs, waits long enough for a run that lasts its whole 9 minute budget, catches a paused collection up first (pause line or leftover cursor; an unseen catch-up run does not end the drain), and never passes on a run that failed, has no clean `Step 3` line or was refused, a baseline with no rows, an unreadable Log Analytics or checkpoint, or a first read taken before Log Analytics caught up. |
| `test_audit_post_failure.py` | A failed audit post does not raise, so it cannot turn a finished import into a failed collection. |
| `test_checkpoint_read.py` | An unreadable checkpoint stops the run; only a missing one counts as a first run. |
| `test_last_page_checkpoint.py` | The last page is not re-fetched on every run, and `more=true` with no `next` cursor stops instead of looping. |
| `test_revoked_upload.py` | Revoked indicators are sent flagged as revoked, and counted separately. |
| `test_package_push.py` | The package is staged as a blob and re-pushed on redeploy. |
| `test_workspace_precheck.py` | The workspace pre-check exists, can fail, and runs before anything is created, and the template has no `reference(concat(` (ARM-TTK). |

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
- drop the budget-pause signal from the audit row
- disable the dedup assert in `scripts/portal_test.sh`
- cut the harness wait below the run budget, ignore the pause line, end the drain on an unseen catch-up
- build the onboarding id with `reference(concat(` again
- set `MAX_ATTEMPTS = 1`
- delete a column from the DCR stream or the table schema

## mutate.py

`python3 tests/mutate.py` breaks the code on purpose, once per entry in its
`MUTATIONS` list, and checks that the matching test file fails each time. A mutation that survives is reported as
BLIND and the run exits non-zero: that means the gate is decorative, not that
the code is fine.

It runs the child processes with bytecode disabled. A same-byte-size mutation
applied and reverted inside one second leaves a `.pyc` whose (mtime, size) key
still looks current, and later runs would execute the mutated bytecode instead
of the source — that cost a full round of false results once already.
