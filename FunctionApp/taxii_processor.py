"""
SOCRadar TAXII 2.1 Processor
Fetches STIX indicators from TAXII server, uploads to Microsoft Sentinel TI in batches.
"""

import os
import logging
from datetime import datetime, timezone
from typing import List, Tuple

import requests
from azure.identity import DefaultAzureCredential
from azure.data.tables import TableServiceClient

from stix_parser import prepare_for_sentinel
from dcr_logger import DcrLogger

logger = logging.getLogger(__name__)

SENTINEL_UPLOAD_URL = "https://sentinelus.azure-api.net/workspaces/{workspace_id}/threatintelligenceindicators:upload"
BATCH_SIZE = 100
PAGE_LIMIT = 100


class TaxiiProcessor:

    def __init__(self, config: dict):
        self.taxii_server_url = config["taxii_server_url"].rstrip("/")
        self.taxii_username = config["taxii_username"]
        self.taxii_password = config["taxii_password"]
        self.collection_id = config["collection_id"]
        self.min_confidence = config.get("min_confidence", 0)
        self.max_pages = config.get("max_pages", 100)
        self.workspace_id = config["workspace_id"]
        self.storage_account_name = config["storage_account_name"]
        self.enable_audit_logging = config.get("enable_audit_logging", False)

        self.credential = DefaultAzureCredential()
        self._mgmt_token = None

        table_url = "https://{}.table.core.windows.net".format(self.storage_account_name)
        self.table_client = TableServiceClient(
            endpoint=table_url, credential=self.credential
        ).get_table_client("TAXIIState")

        self.dcr_logger = None
        if self.enable_audit_logging:
            self.dcr_logger = DcrLogger.from_env(self.credential)

    @classmethod
    def from_env(cls) -> "TaxiiProcessor":
        return cls({
            "taxii_server_url": os.environ["TAXII_SERVER_URL"],
            "taxii_username": os.environ["TAXII_USERNAME"],
            "taxii_password": os.environ["TAXII_PASSWORD"],
            "collection_id": os.environ["COLLECTION_ID"],
            "min_confidence": int(os.environ.get("MIN_CONFIDENCE", "0")),
            "max_pages": int(os.environ.get("MAX_PAGES", "100")),
            "workspace_id": os.environ["WORKSPACE_ID"],
            "storage_account_name": os.environ["STORAGE_ACCOUNT_NAME"],
            "enable_audit_logging": os.environ.get("ENABLE_AUDIT_LOGGING", "true").lower() == "true",
        })

    def _get_mgmt_token(self) -> str:
        if not self._mgmt_token:
            token = self.credential.get_token("https://management.azure.com/.default")
            self._mgmt_token = token.token
        return self._mgmt_token

    def fetch_page(self, added_after=None, cursor=None) -> dict:
        """Fetch one page from TAXII 2.1 server."""
        url = "{}/collections/{}/objects/".format(self.taxii_server_url, self.collection_id)
        params = {"limit": PAGE_LIMIT}

        if cursor:
            params["next"] = cursor
        elif added_after:
            params["added_after"] = added_after

        headers = {"Accept": "application/taxii+json;version=2.1"}

        resp = requests.get(
            url, headers=headers, params=params,
            auth=(self.taxii_username, self.taxii_password),
            timeout=60
        )

        if resp.status_code != 200:
            raise RuntimeError(
                "TAXII fetch failed: HTTP {} - {}".format(resp.status_code, resp.text[:500])
            )

        return resp.json()

    def get_checkpoint(self) -> dict:
        """Get saved cursor and added_after from Azure Table Storage."""
        try:
            entity = self.table_client.get_entity(
                partition_key=self.collection_id, row_key="state"
            )
            return {
                "cursor": entity.get("Cursor", ""),
                "added_after": entity.get("AddedAfter", "1970-01-01T00:00:00Z"),
            }
        except Exception:
            return {"cursor": "", "added_after": "1970-01-01T00:00:00Z"}

    def save_checkpoint(self, cursor, added_after, total_indicators, pages_fetched):
        """Save pagination state to Azure Table Storage."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        entity = {
            "PartitionKey": self.collection_id,
            "RowKey": "state",
            "Cursor": cursor or "",
            "AddedAfter": added_after,
            "TotalIndicators": total_indicators,
            "PagesFetched": pages_fetched,
            "LastRun": now,
        }
        self.table_client.upsert_entity(entity)

    def upload_batch(self, indicators: List[dict]) -> Tuple[int, int]:
        """Upload a batch of STIX indicators to Sentinel TI."""
        token = self._get_mgmt_token()
        url = SENTINEL_UPLOAD_URL.format(workspace_id=self.workspace_id)
        url += "?api-version=2022-07-01"

        headers = {
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/json",
        }
        body = {
            "sourcesystem": "SOCRadar TAXII",
            "indicators": indicators,
        }

        resp = requests.post(url, headers=headers, json=body, timeout=60)

        if resp.status_code == 200:
            result = resp.json() if resp.text else {}
            errors = result.get("errors", [])
            skipped = len(errors)
            created = len(indicators) - skipped
            if errors:
                logger.warning("Step 2.5: Upload batch had %d errors: %s", skipped, str(errors[:3])[:500])
            return created, skipped
        else:
            logger.error("Step 2.5: Upload failed: %d %s", resp.status_code, resp.text[:500])
            return 0, len(indicators)

    def run(self) -> dict:
        """Main loop: fetch TAXII pages, filter indicators, upload to Sentinel."""
        logger.info("Step 2.1: Loading checkpoint")
        checkpoint = self.get_checkpoint()
        cursor = checkpoint["cursor"]
        added_after = checkpoint["added_after"]
        is_first_run = added_after == "1970-01-01T00:00:00Z" and not cursor

        total_created = 0
        total_skipped = 0
        total_revoked = 0
        pages_fetched = 0
        type_stats = {}

        logger.info(
            "Step 2.2: Starting fetch - collection=%s, cursor=%s, added_after=%s%s",
            self.collection_id,
            cursor[:30] if cursor else "NONE",
            added_after,
            " (first run)" if is_first_run else ""
        )

        for page_num in range(1, self.max_pages + 1):
            if cursor:
                data = self.fetch_page(cursor=cursor)
            else:
                data = self.fetch_page(added_after=added_after)

            objects = data.get("objects", [])
            more = data.get("more", False)
            next_cursor = data.get("next", "")
            pages_fetched += 1

            logger.info("Step 2.3: Page %d/%d: %d objects, more=%s",
                        page_num, self.max_pages, len(objects), more)

            if not objects:
                logger.info("Step 2.3: Page %d empty, stopping", page_num)
                break

            # Filter and prepare indicators
            indicators = []
            page_revoked = 0
            page_skipped = 0
            for obj in objects:
                obj_type = obj.get("type", "unknown")
                type_stats[obj_type] = type_stats.get(obj_type, 0) + 1

                if obj.get("revoked") is True:
                    total_revoked += 1
                    page_revoked += 1
                    continue

                prepared = prepare_for_sentinel(obj, self.collection_id)
                if not prepared:
                    continue

                confidence = prepared.get("confidence", 0)
                if isinstance(confidence, (int, float)) and confidence < self.min_confidence:
                    total_skipped += 1
                    page_skipped += 1
                    continue

                indicators.append(prepared)

            logger.info("Step 2.4: Page %d filtered: %d to upload, %d revoked, %d below confidence",
                        page_num, len(indicators), page_revoked, page_skipped)

            # Batch upload
            total_batches = (len(indicators) + BATCH_SIZE - 1) // BATCH_SIZE if indicators else 0
            for i in range(0, len(indicators), BATCH_SIZE):
                batch = indicators[i:i + BATCH_SIZE]
                batch_num = (i // BATCH_SIZE) + 1
                logger.info("Step 2.5: Uploading batch %d/%d (%d indicators)",
                            batch_num, total_batches, len(batch))
                created, skipped = self.upload_batch(batch)
                total_created += created
                total_skipped += skipped
                logger.info("Step 2.5: Batch %d result: %d created, %d skipped",
                            batch_num, created, skipped)

            # Update cursor
            if next_cursor:
                cursor = next_cursor

            # Save checkpoint after each page for crash resilience
            self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
            logger.info("Step 2.6: Checkpoint saved after page %d", page_num)

            if not more:
                logger.info("Step 2.6: No more pages, stopping")
                break

        logger.info(
            "Step 2.7: Fetch complete - %d created, %d skipped, %d revoked, %d pages, types=%s",
            total_created, total_skipped, total_revoked, pages_fetched, type_stats
        )

        return {
            "indicators_created": total_created,
            "indicators_skipped": total_skipped,
            "indicators_revoked": total_revoked,
            "pages_fetched": pages_fetched,
            "type_stats": type_stats,
        }

    def log_audit(self, **kwargs):
        if self.enable_audit_logging and self.dcr_logger:
            self.dcr_logger.log_audit(kwargs)
