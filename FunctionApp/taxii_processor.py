"""
SOCRadar TAXII 2.1 Processor
Fetches STIX indicators from TAXII server, uploads to Microsoft Sentinel TI in batches.
"""

import logging
import time
from datetime import datetime, timezone
from typing import List, Tuple

import requests

from stix_parser import prepare_for_sentinel

logger = logging.getLogger(__name__)

TAXII_BASE_URL = "https://taxii2.socradar.com"
SENTINEL_UPLOAD_URL = "https://sentinelus.azure-api.net/workspaces/{workspace_id}/threatintelligenceindicators:upload"
BATCH_SIZE = 100
PAGE_LIMIT = 100


class TaxiiProcessor:

    def __init__(self, api_root, collection_id, taxii_username, taxii_password,
                 workspace_id, credential=None, table_client=None, dcr_logger=None,
                 time_budget_seconds=0):
        self.api_root = api_root
        self.collection_id = collection_id
        self.taxii_username = taxii_username
        self.taxii_password = taxii_password
        self.workspace_id = workspace_id

        self.credential = credential
        self.table_client = table_client
        self.dcr_logger = dcr_logger
        self.time_budget_seconds = time_budget_seconds
        self._mgmt_token = None

    def _get_mgmt_token(self) -> str:
        if not self._mgmt_token:
            token = self.credential.get_token("https://management.azure.com/.default")
            self._mgmt_token = token.token
        return self._mgmt_token

    def _checkpoint_key(self) -> str:
        return "{}_{}".format(self.api_root, self.collection_id)

    def fetch_page(self, added_after=None, cursor=None) -> dict:
        """Fetch one page from TAXII 2.1 server."""
        url = "{}/{}/collections/{}/objects/".format(
            TAXII_BASE_URL, self.api_root, self.collection_id
        )
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
                partition_key=self._checkpoint_key(), row_key="state"
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
            "PartitionKey": self._checkpoint_key(),
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
                logger.warning("Upload batch had %d errors: %s", skipped, str(errors[:3])[:500])
            return created, skipped
        else:
            logger.error("Upload failed: %d %s", resp.status_code, resp.text[:500])
            return 0, len(indicators)

    def run(self) -> dict:
        """Main loop: fetch TAXII pages, filter indicators, upload to Sentinel."""
        logger.info("Loading checkpoint for %s / %s", self.api_root, self.collection_id)
        checkpoint = self.get_checkpoint()
        cursor = checkpoint["cursor"]
        added_after = checkpoint["added_after"]
        is_first_run = added_after == "1970-01-01T00:00:00Z" and not cursor

        total_created = 0
        total_revoked = 0
        pages_fetched = 0
        type_stats = {}
        run_start = time.time()

        logger.info(
            "Starting fetch - %s/%s, cursor=%s, added_after=%s%s",
            self.api_root,
            self.collection_id,
            cursor[:30] if cursor else "NONE",
            added_after,
            " (first run)" if is_first_run else ""
        )

        page_num = 0
        while True:
            page_num += 1
            if cursor:
                data = self.fetch_page(cursor=cursor)
            else:
                data = self.fetch_page(added_after=added_after)

            objects = data.get("objects", [])
            more = data.get("more", False)
            next_cursor = data.get("next", "")
            pages_fetched += 1

            logger.info("Page %d: %d objects, more=%s",
                        page_num, len(objects), more)

            if not objects:
                logger.info("Page %d empty, stopping", page_num)
                break

            # Filter and prepare indicators
            indicators = []
            page_revoked = 0
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

                indicators.append(prepared)

            logger.info("Page %d filtered: %d to upload, %d revoked",
                        page_num, len(indicators), page_revoked)

            # Batch upload
            total_batches = (len(indicators) + BATCH_SIZE - 1) // BATCH_SIZE if indicators else 0
            for i in range(0, len(indicators), BATCH_SIZE):
                batch = indicators[i:i + BATCH_SIZE]
                batch_num = (i // BATCH_SIZE) + 1
                logger.info("Uploading batch %d/%d (%d indicators)",
                            batch_num, total_batches, len(batch))
                created, skipped = self.upload_batch(batch)
                total_created += created
                logger.info("Batch %d result: %d created, %d skipped",
                            batch_num, created, skipped)

            # Update cursor
            if next_cursor:
                cursor = next_cursor

            # Save checkpoint after each page for crash resilience
            self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
            logger.info("Checkpoint saved after page %d", page_num)

            if not more:
                logger.info("No more pages, stopping")
                break

            # Time budget check
            if self.time_budget_seconds > 0:
                elapsed = time.time() - run_start
                if elapsed >= self.time_budget_seconds:
                    logger.info("Time budget exhausted (%.0fs/%.0fs), pausing for next run",
                                elapsed, self.time_budget_seconds)
                    break

        logger.info(
            "Fetch complete for %s/%s - %d created, %d revoked, %d pages, types=%s",
            self.api_root, self.collection_id,
            total_created, total_revoked, pages_fetched, type_stats
        )

        return {
            "api_root": self.api_root,
            "collection_id": self.collection_id,
            "indicators_created": total_created,
            "indicators_revoked": total_revoked,
            "pages_fetched": pages_fetched,
            "type_stats": type_stats,
        }
