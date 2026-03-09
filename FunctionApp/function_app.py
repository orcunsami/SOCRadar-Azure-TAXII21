"""
SOCRadar TAXII 2.1 Import - Azure Function
Timer-triggered function to import STIX threat intelligence from SOCRadar TAXII server into Microsoft Sentinel.
"""

import logging
import time
import azure.functions as func

from taxii_processor import TaxiiProcessor

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

    processor = None
    try:
        logger.info("Step 1: Initializing processor from environment")
        processor = TaxiiProcessor.from_env()
        logger.info("Step 1: Done - collection=%s, min_confidence=%d, max_pages=%d",
                     processor.collection_id, processor.min_confidence, processor.max_pages)

        logger.info("Step 2: Running TAXII import")
        result = processor.run()

        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.info(
            "Step 3: Import complete - %d created, %d skipped, %d revoked, %d pages, %dms",
            result["indicators_created"],
            result["indicators_skipped"],
            result["indicators_revoked"],
            result["pages_fetched"],
            elapsed_ms,
        )

        logger.info("Step 4: Sending audit log")
        processor.log_audit(
            indicators_created=result["indicators_created"],
            indicators_skipped=result["indicators_skipped"],
            indicators_revoked=result["indicators_revoked"],
            pages_fetched=result["pages_fetched"],
            duration_ms=elapsed_ms,
            status="Success",
            error_message="",
        )
        logger.info("Step 4: Done")
        logger.info("=== SOCRadar TAXII Import finished successfully (%dms) ===", elapsed_ms)

    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.error("=== SOCRadar TAXII Import FAILED after %dms: %s ===", elapsed_ms, e)
        if processor:
            try:
                processor.log_audit(
                    indicators_created=0,
                    indicators_skipped=0,
                    indicators_revoked=0,
                    pages_fetched=0,
                    duration_ms=elapsed_ms,
                    status="Failed",
                    error_message=str(e),
                )
            except Exception:
                pass
        raise
