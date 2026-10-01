"""
SOCRadar TAXII 2.1 Import - Azure Function
Timer-triggered function to import STIX threat intelligence from SOCRadar TAXII server into Microsoft Sentinel.
Supports multiple API root + collection pairs in a single deployment.
"""

import os
import logging
import time
import azure.functions as func

from azure.identity import DefaultAzureCredential
from azure.data.tables import TableServiceClient

from taxii_processor import TaxiiProcessor
from dcr_logger import DcrLogger

app = func.FunctionApp()

logger = logging.getLogger(__name__)


@app.timer_trigger(
    schedule="%POLLING_SCHEDULE%",
    arg_name="timer",
    run_on_startup=True
)
def socradar_taxii_import(timer: func.TimerRequest) -> None:
    start_time = time.time()
    logger.info("=== SOCRadar TAXII Import started ===")

    if timer.past_due:
        logger.warning("Timer is past due, running anyway")

    # Parse multi-collection config
    api_roots = [r.strip() for r in os.environ["API_ROOTS"].split(",") if r.strip()]
    collection_ids = [c.strip() for c in os.environ["COLLECTION_IDS"].split(",") if c.strip()]

    if len(api_roots) != len(collection_ids):
        raise ValueError(
            "API_ROOTS ({}) and COLLECTION_IDS ({}) must have same count".format(
                len(api_roots), len(collection_ids)
            )
        )

    logger.info("Step 1: %d collection(s) to process: %s",
                len(api_roots),
                ", ".join("{}/{}".format(r, c[:8]) for r, c in zip(api_roots, collection_ids)))

    # Shared resources (created once)
    credential = DefaultAzureCredential()
    storage_account_name = os.environ["STORAGE_ACCOUNT_NAME"]
    table_url = "https://{}.table.core.windows.net".format(storage_account_name)
    table_client = TableServiceClient(
        endpoint=table_url, credential=credential
    ).get_table_client("TAXIIState")

    enable_audit = os.environ.get("ENABLE_AUDIT_LOGGING", "true").lower() == "true"
    dcr_logger = DcrLogger.from_env(credential) if enable_audit else None

    # Shared config
    taxii_username = os.environ["TAXII_USERNAME"]
    taxii_password = os.environ["TAXII_PASSWORD"]
    workspace_id = os.environ["WORKSPACE_ID"]
    initial_lookback_hours = int(os.environ.get("INITIAL_LOOKBACK_HOURS", "48"))

    # Time budget: 9 min total (1 min safety margin from 10 min timeout), split equally
    total_budget_seconds = 9 * 60
    budget_per_collection = total_budget_seconds // len(api_roots)
    logger.info("Step 1: Time budget %ds per collection", budget_per_collection)

    # Aggregate totals
    total_created = 0
    total_skipped = 0
    total_failed = 0
    total_revoked = 0
    total_pages = 0
    collections_succeeded = 0
    collections_partial = 0
    collections_failed = 0
    errors = []

    for api_root, collection_id in zip(api_roots, collection_ids):
        collection_start = time.time()
        logger.info("Step 2: Processing %s / %s", api_root, collection_id)

        try:
            processor = TaxiiProcessor(
                api_root=api_root,
                collection_id=collection_id,
                taxii_username=taxii_username,
                taxii_password=taxii_password,
                workspace_id=workspace_id,
                credential=credential,
                table_client=table_client,
                dcr_logger=dcr_logger,
                time_budget_seconds=budget_per_collection,
                initial_lookback_hours=initial_lookback_hours,
            )
            result = processor.run()

            collection_ms = int((time.time() - collection_start) * 1000)
            total_created += result["indicators_created"]
            total_skipped += result["indicators_skipped"]
            total_failed += result["indicators_failed"]
            total_revoked += result["indicators_revoked"]
            total_pages += result["pages_fetched"]

            # A collection that lost indicators is not a success, even though it
            # raised nothing. Reporting it as one is what hid this class of data
            # loss: the run stayed green while the checkpoint moved past the gap.
            lost = result["indicators_failed"]
            if lost or not result["complete"]:
                collections_partial += 1
                status = "PartialSuccess"
                if lost:
                    message = ("{} indicator(s) did not reach Microsoft Sentinel; the "
                               "checkpoint was left in place and they will be fetched "
                               "again on the next run").format(lost)
                else:
                    message = ("the TAXII server reported more data without a next "
                               "cursor; the run stopped early")
                logger.error("Step 2: %s/%s PARTIAL - %s", api_root, collection_id[:8], message)
            else:
                collections_succeeded += 1
                status = "Success"
                message = ""
                if result.get("paused"):
                    # Catch-up is normal, so the Status stays Success; the
                    # message is what tells it apart from a finished run. The
                    # server does not say how many pages remain, so none is
                    # claimed.
                    message = ("time budget reached after {} pages, more pages pending, "
                               "continues next run").format(result["pages_fetched"])
                    logger.info("Step 2: %s/%s %s", api_root, collection_id[:8], message)
                logger.info("Step 2: %s/%s done - %d created, %dms",
                            api_root, collection_id[:8],
                            result["indicators_created"], collection_ms)

            # Per-collection audit log
            if dcr_logger:
                dcr_logger.log_audit({
                    "api_root": api_root,
                    "collection_id": collection_id,
                    "indicators_created": result["indicators_created"],
                    "indicators_skipped": result["indicators_skipped"],
                    "indicators_failed": result["indicators_failed"],
                    "indicators_revoked": result["indicators_revoked"],
                    "pages_fetched": result["pages_fetched"],
                    "duration_ms": collection_ms,
                    "status": status,
                    "error_message": message,
                })

        except Exception as e:
            collection_ms = int((time.time() - collection_start) * 1000)
            collections_failed += 1
            error_msg = "{}/{}: {}".format(api_root, collection_id[:8], str(e))
            errors.append(error_msg)
            logger.error("Step 2: %s/%s FAILED after %dms: %s",
                         api_root, collection_id[:8], collection_ms, e)

            # Per-collection failure audit
            if dcr_logger:
                try:
                    dcr_logger.log_audit({
                        "api_root": api_root,
                        "collection_id": collection_id,
                        "indicators_created": 0,
                        "indicators_skipped": 0,
                        "indicators_failed": 0,
                        "indicators_revoked": 0,
                        "pages_fetched": 0,
                        "duration_ms": collection_ms,
                        "status": "Failed",
                        "error_message": str(e)[:500],
                    })
                except Exception:
                    pass

    elapsed_ms = int((time.time() - start_time) * 1000)

    logger.info(
        "Step 3: Import complete - %d created, %d skipped, %d failed, %d revoked, "
        "%d pages, %d/%d collections succeeded, %d partial, %dms",
        total_created, total_skipped, total_failed, total_revoked, total_pages,
        collections_succeeded, len(api_roots), collections_partial, elapsed_ms
    )

    if collections_failed > 0:
        logger.error("Step 3: %d collection(s) failed: %s",
                     collections_failed, "; ".join(errors))

    if collections_partial > 0:
        logger.error("Step 3: %d collection(s) partial", collections_partial)
        if total_failed > 0:
            logger.error(
                "Step 3: %d indicator(s) did not reach Microsoft Sentinel and "
                "will be retried on the next run", total_failed
            )

    logger.info("=== SOCRadar TAXII Import finished (%dms) ===", elapsed_ms)

    # If ALL collections failed, raise to mark the function run as failed
    if collections_failed == len(api_roots):
        raise RuntimeError("All {} collections failed: {}".format(
            len(api_roots), "; ".join(errors)
        ))
