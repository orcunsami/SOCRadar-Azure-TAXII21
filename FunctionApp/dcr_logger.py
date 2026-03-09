"""
DCR (Data Collection Rule) ingestion for SOCRadar TAXII audit logging.
Logs to SOCRadar_TAXII_Audit_CL via Azure Monitor Ingestion API.
"""

import os
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)


class DcrLogger:

    def __init__(self, credential, audit_endpoint="", audit_dcr_id="", audit_stream=""):
        self.credential = credential
        self.audit_endpoint = audit_endpoint
        self.audit_dcr_id = audit_dcr_id
        self.audit_stream = audit_stream
        self._monitor_token = None

    @classmethod
    def from_env(cls, credential) -> "DcrLogger":
        return cls(
            credential=credential,
            audit_endpoint=os.environ.get("AUDIT_DCR_ENDPOINT", ""),
            audit_dcr_id=os.environ.get("AUDIT_DCR_IMMUTABLE_ID", ""),
            audit_stream=os.environ.get("AUDIT_STREAM_NAME", "Custom-SOCRadar_TAXII_Audit_CL"),
        )

    def _get_monitor_token(self) -> str:
        if not self._monitor_token:
            token = self.credential.get_token("https://monitor.azure.com/.default")
            self._monitor_token = token.token
        return self._monitor_token

    def _ingest(self, endpoint, dcr_id, stream, data):
        if not endpoint or not dcr_id:
            return
        url = "{}/dataCollectionRules/{}/streams/{}?api-version=2023-01-01".format(
            endpoint, dcr_id, stream
        )
        headers = {
            "Authorization": "Bearer {}".format(self._get_monitor_token()),
            "Content-Type": "application/json",
        }
        resp = requests.post(url, headers=headers, json=data, timeout=30)
        if resp.status_code not in (200, 204):
            logger.warning("DCR ingestion failed: %d %s", resp.status_code, resp.text[:200])

    def log_audit(self, data):
        record = {
            "TimeGenerated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "ApiRoot": data.get("api_root", ""),
            "CollectionId": data.get("collection_id", ""),
            "IndicatorsCreated": data.get("indicators_created", 0),
            "IndicatorsRevoked": data.get("indicators_revoked", 0),
            "PagesFetched": data.get("pages_fetched", 0),
            "DurationMs": data.get("duration_ms", 0),
            "Status": data.get("status", ""),
            "ErrorMessage": data.get("error_message", ""),
        }
        self._ingest(self.audit_endpoint, self.audit_dcr_id, self.audit_stream, [record])
