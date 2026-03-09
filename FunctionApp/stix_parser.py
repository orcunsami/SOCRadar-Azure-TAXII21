"""
STIX 2.1 Parser for SOCRadar TAXII indicators.
Prepares STIX indicators for Microsoft Sentinel TI uploadIndicators API.
"""

import re
import logging

logger = logging.getLogger(__name__)

STIX_PATTERN_RE = re.compile(
    r"(\w+(?:-\w+)*)"             # object type (ipv4-addr, domain-name, etc.)
    r":"
    r"([\w.]+(?:'[^']*')?[\w.]*)"  # property path (value, hashes.MD5, hashes.'SHA-256')
    r"\s*=\s*"
    r"'([^']+)'"                   # quoted value
)

SENTINEL_EXTENSION_ID = "extension-definition--322b8e5b-0498-40e6-aa48-38913bae9e37"

# Non-standard fields added by SOCRadar TAXII server (not part of STIX 2.1 spec)
NON_STIX_FIELDS = {"date_added", "version", "threat_feed_source_name"}


def parse_stix_pattern(pattern):
    """Extract type and value from STIX pattern string. Used for stats/logging."""
    if not pattern:
        return []
    matches = STIX_PATTERN_RE.findall(pattern)
    results = []
    for obj_type, prop, value in matches:
        result = {"type": obj_type, "property": prop.replace("'", ""), "value": value}
        if obj_type == "file" and "hashes" in prop:
            parts = prop.replace("'", "").split(".")
            if len(parts) >= 2:
                result["hash_type"] = parts[-1]
        results.append(result)
    return results


def prepare_for_sentinel(stix_obj, collection_id=""):
    """
    Prepare a STIX 2.1 indicator for Sentinel TI uploadIndicators API.
    Adds Sentinel extension and SOCRadar labels. Strips non-STIX fields.
    Returns enriched indicator dict, or None if not a valid indicator.
    """
    if stix_obj.get("type") != "indicator":
        return None

    if stix_obj.get("revoked") is True:
        return None

    if not stix_obj.get("pattern"):
        return None

    indicator = dict(stix_obj)

    # Strip non-standard fields from SOCRadar TAXII server
    for field in NON_STIX_FIELDS:
        indicator.pop(field, None)

    # Add Sentinel TI extension
    extensions = dict(indicator.get("extensions", {}))
    extensions[SENTINEL_EXTENSION_ID] = {"extension_type": "property-extension"}
    indicator["extensions"] = extensions

    # Add SOCRadar labels
    labels = list(indicator.get("labels", []))
    for tag in ["SOCRadar", "TAXII"]:
        if tag not in labels:
            labels.append(tag)
    if collection_id:
        col_tag = "collection-{}".format(collection_id[:50])
        if col_tag not in labels:
            labels.append(col_tag)
    indicator["labels"] = labels

    return indicator
