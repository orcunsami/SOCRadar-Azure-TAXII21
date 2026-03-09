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

    # Aggregate totals
    total_created = 0
    total_revoked = 0
    total_pages = 0
    collections_succeeded = 0
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
            )
            result = processor.run()

            collection_ms = int((time.time() - collection_start) * 1000)
            total_created += result["indicators_created"]
            total_revoked += result["indicators_revoked"]
            total_pages += result["pages_fetched"]
            collections_succeeded += 1

            logger.info("Step 2: %s/%s done - %d created, %dms",
                        api_root, collection_id[:8],
                        result["indicators_created"], collection_ms)

            # Per-collection audit log
            if dcr_logger:
                dcr_logger.log_audit({
                    "api_root": api_root,
                    "collection_id": collection_id,
                    "indicators_created": result["indicators_created"],
                    "indicators_revoked": result["indicators_revoked"],
                    "pages_fetched": result["pages_fetched"],
                    "duration_ms": collection_ms,
                    "status": "Success",
                    "error_message": "",
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
        "Step 3: Import complete - %d created, %d revoked, %d pages, "
        "%d/%d collections succeeded, %dms",
        total_created, total_revoked, total_pages,
        collections_succeeded, len(api_roots), elapsed_ms
    )

    if collections_failed > 0:
        logger.error("Step 3: %d collection(s) failed: %s",
                     collections_failed, "; ".join(errors))

    logger.info("=== SOCRadar TAXII Import finished (%dms) ===", elapsed_ms)

    # If ALL collections failed, raise to mark the function run as failed
    if collections_failed == len(api_roots):
        raise RuntimeError("All {} collections failed: {}".format(
            len(api_roots), "; ".join(errors)
        ))
