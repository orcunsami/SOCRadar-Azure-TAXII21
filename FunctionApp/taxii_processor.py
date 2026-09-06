"""
SOCRadar TAXII 2.1 Processor
Fetches STIX indicators from TAXII server, uploads to Microsoft Sentinel TI in batches.
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import requests

from stix_parser import prepare_for_sentinel

logger = logging.getLogger(__name__)

TAXII_BASE_URL = "https://taxii2.socradar.com"
SENTINEL_UPLOAD_URL = "https://sentinelus.azure-api.net/workspaces/{workspace_id}/threatintelligenceindicators:upload"
BATCH_SIZE = 100
PAGE_LIMIT = 100

# A 429 or 5xx means the request never landed. Retrying it is the difference
# between a delayed indicator and a lost one, so both the fetch and the upload
# retry, bounded, and both honour Retry-After when the server sends it.
RETRYABLE_STATUS = (429, 500, 502, 503, 504)
MAX_ATTEMPTS = 3
MAX_RETRY_SLEEP = 60


class TaxiiProcessor:

    def __init__(self, api_root, collection_id, taxii_username, taxii_password,
                 workspace_id, credential=None, table_client=None, dcr_logger=None,
                 time_budget_seconds=0, initial_lookback_hours=48):
        self.api_root = api_root
        self.collection_id = collection_id
        self.taxii_username = taxii_username
        self.taxii_password = taxii_password
        self.workspace_id = workspace_id

        self.credential = credential
        self.table_client = table_client
        self.dcr_logger = dcr_logger
        self.time_budget_seconds = time_budget_seconds
        self.initial_lookback_hours = initial_lookback_hours
        self._mgmt_token = None
        self._run_start = None

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

        for attempt in range(1, MAX_ATTEMPTS + 1):
            resp = requests.get(
                url, headers=headers, params=params,
                auth=(self.taxii_username, self.taxii_password),
                timeout=60
            )
            if resp.status_code == 200:
                return resp.json()
            if not self._sleep_before_retry(resp, attempt, "TAXII fetch"):
                break

        raise RuntimeError(
            "TAXII fetch failed: HTTP {} - {}".format(resp.status_code, resp.text[:500])
        )

    def _sleep_before_retry(self, resp, attempt, what) -> bool:
        """Sleep before the next attempt. False means stop retrying.

        Stops on a non-retryable status, on the last attempt, and when the wait
        would run past the run's time budget. The last case matters: the host
        kills the function at its own timeout without writing an audit row, so
        it is better to give up early and report the failure than to sleep into
        a silent kill.
        """
        if resp.status_code not in RETRYABLE_STATUS or attempt >= MAX_ATTEMPTS:
            return False

        retry_after = resp.headers.get("Retry-After", "")
        try:
            wait = min(float(retry_after), MAX_RETRY_SLEEP)
        except (TypeError, ValueError):
            wait = min(2 ** attempt, MAX_RETRY_SLEEP)

        if self.time_budget_seconds > 0 and self._run_start is not None:
            remaining = self.time_budget_seconds - (time.time() - self._run_start)
            if wait >= remaining:
                logger.warning(
                    "%s got HTTP %d but the %.0fs wait exceeds the remaining budget",
                    what, resp.status_code, wait
                )
                return False

        logger.warning("%s got HTTP %d, retrying in %.0fs (attempt %d/%d)",
                       what, resp.status_code, wait, attempt, MAX_ATTEMPTS)
        time.sleep(wait)
        return True

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

    def upload_batch(self, indicators: List[dict]) -> Tuple[int, int, int, set]:
        """Upload a batch of STIX indicators to Sentinel TI.

        Returns (created, skipped, failed, rejected). Skipped and failed are not
        the same thing. Skipped indicators came back inside a successful
        response: Sentinel read them and rejected them, so sending them again
        changes nothing. Failed indicators never reached Sentinel at all, and
        the caller must keep the checkpoint where it is so the next run fetches
        them again. `rejected` holds the batch positions of the skipped ones,
        so the caller can tell a revoked indicator that landed from one that
        did not.
        """
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

        for attempt in range(1, MAX_ATTEMPTS + 1):
            resp = requests.post(url, headers=headers, json=body, timeout=60)

            if resp.status_code == 200:
                result = resp.json() if resp.text else {}
                errors = result.get("errors", [])
                skipped = len(errors)
                created = len(indicators) - skipped
                rejected = {e.get("recordIndex") for e in errors
                            if isinstance(e, dict) and isinstance(e.get("recordIndex"), int)}
                if errors:
                    logger.warning("Upload batch had %d errors: %s", skipped, str(errors[:3])[:500])
                return created, skipped, 0, rejected

            if not self._sleep_before_retry(resp, attempt, "Sentinel upload"):
                break

        logger.error("Upload failed after %d attempt(s): %d %s",
                     attempt, resp.status_code, resp.text[:500])
        return 0, 0, len(indicators), set()

    def run(self) -> dict:
        """Main loop: fetch TAXII pages, filter indicators, upload to Sentinel."""
        logger.info("Loading checkpoint for %s / %s", self.api_root, self.collection_id)
        checkpoint = self.get_checkpoint()
        cursor = checkpoint["cursor"]
        added_after = checkpoint["added_after"]
        is_first_run = added_after == "1970-01-01T00:00:00Z" and not cursor

        # Apply initial lookback on first run
        if is_first_run and self.initial_lookback_hours > 0:
            lookback_dt = datetime.now(timezone.utc) - timedelta(hours=self.initial_lookback_hours)
            added_after = lookback_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            logger.info("First run: lookback %d hours, added_after=%s", self.initial_lookback_hours, added_after)

        total_created = 0
        total_skipped = 0
        total_failed = 0
        total_revoked = 0
        pages_fetched = 0
        type_stats = {}
        run_start = time.time()
        self._run_start = run_start

        logger.info(
            "Starting fetch - %s/%s, cursor=%s, added_after=%s%s",
            self.api_root,
            self.collection_id,
            cursor[:30] if cursor else "NONE",
            added_after,
            " (first run)" if is_first_run else ""
        )

        page_num = 0
        complete = True
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

            # Filter and prepare indicators. A revoked indicator is sent like
            # any other, with its revoked flag: Sentinel stores the flag and
            # keeps the indicator out of matching. Dropping it here, as the
            # code once did, left an indicator SOCRadar had withdrawn active
            # in the customer's workspace.
            indicators = []
            revoked_flags = []
            page_revoked = 0
            for obj in objects:
                obj_type = obj.get("type", "unknown")
                type_stats[obj_type] = type_stats.get(obj_type, 0) + 1

                prepared = prepare_for_sentinel(obj, self.collection_id)
                if not prepared:
                    if obj_type == "indicator" and obj.get("revoked") is True:
                        logger.warning("Revoked indicator %s has no pattern and cannot be sent",
                                       obj.get("id"))
                    continue

                is_revoked = prepared.get("revoked") is True
                page_revoked += 1 if is_revoked else 0
                indicators.append(prepared)
                revoked_flags.append(is_revoked)

            logger.info("Page %d filtered: %d to upload (%d of them revoked)",
                        page_num, len(indicators), page_revoked)

            # Batch upload
            page_failed = 0
            total_batches = (len(indicators) + BATCH_SIZE - 1) // BATCH_SIZE if indicators else 0
            for i in range(0, len(indicators), BATCH_SIZE):
                batch = indicators[i:i + BATCH_SIZE]
                batch_revoked = {n for n, flag in enumerate(revoked_flags[i:i + BATCH_SIZE]) if flag}
                batch_num = (i // BATCH_SIZE) + 1
                logger.info("Uploading batch %d/%d (%d indicators)",
                            batch_num, total_batches, len(batch))
                created, skipped, failed, rejected = self.upload_batch(batch)
                # A revoked indicator Sentinel accepted counts as revoked, not
                # created. One it rejected is skipped like any other, and one
                # that never arrived is failed like any other.
                revoked_ok = len(batch_revoked - rejected) if not failed else 0
                created -= revoked_ok
                total_revoked += revoked_ok
                total_created += created
                total_skipped += skipped
                total_failed += failed
                page_failed += failed
                logger.info("Batch %d result: %d created, %d revoked, %d skipped, %d failed",
                            batch_num, created, revoked_ok, skipped, failed)

            # A page that lost indicators must not move the checkpoint. Leaving
            # it where it is costs a re-upload of the batches that did land,
            # which Sentinel treats as an update; advancing it would drop those
            # indicators for good and no table would ever show the gap.
            if page_failed:
                logger.error(
                    "Page %d: %d indicator(s) never reached Sentinel, holding the "
                    "checkpoint at this page so the next run fetches it again",
                    page_num, page_failed
                )
                # Written with the cursor that fetched THIS page, not the next
                # one, so the next run repeats it. Writing rather than skipping
                # matters on the very first run: with no checkpoint at all the
                # next run would start its lookback window from its own clock
                # and step over the oldest indicators on the page that just
                # failed. Saving pins added_after where this run started.
                self.save_checkpoint(cursor, added_after, total_created, pages_fetched)
                complete = False
                break

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
            "Fetch %s for %s/%s - %d created, %d skipped, %d failed, %d revoked, "
            "%d pages, types=%s",
            "complete" if complete else "incomplete",
            self.api_root, self.collection_id,
            total_created, total_skipped, total_failed, total_revoked,
            pages_fetched, type_stats
        )

        return {
            "api_root": self.api_root,
            "collection_id": self.collection_id,
            "indicators_created": total_created,
            "indicators_skipped": total_skipped,
            "indicators_failed": total_failed,
            "indicators_revoked": total_revoked,
            "pages_fetched": pages_fetched,
            "type_stats": type_stats,
            "complete": complete,
        }
