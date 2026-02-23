"""
SOCRadar TAXII STIX Parser - Azure Function
Parses STIX 2.1 indicator objects and transforms them to Microsoft Sentinel
Threat Intelligence format for upload via createIndicator API.
"""

import azure.functions as func
import json
import re
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# STIX pattern regex: extracts ALL type:property = 'value' assignments
# Handles simple, OR, AND patterns and quoted property names like hashes.'SHA-256'
STIX_PATTERN_RE = re.compile(
    r"(\w+(?:-\w+)*)"             # object type (e.g., ipv4-addr, domain-name)
    r":"                           # separator
    r"([\w.]+(?:'[^']*')?[\w.]*)"  # property path (value, hashes.MD5, hashes.'SHA-256')
    r"\s*=\s*"                     # operator
    r"'([^']+)'"                   # quoted value
)

# Map STIX object types to Sentinel TI pattern types
STIX_TO_SENTINEL_TYPE = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "file": "file",
    "email-addr": "email-addr",
}

# Map STIX indicator_types to Sentinel threatTypes
STIX_TO_THREAT_TYPES = {
    "malicious-activity": "Malware",
    "anomalous-activity": "Malware",
    "attribution": "Malware",
    "benign": "Malware",
    "compromised": "Malware",
    "unknown": "Malware",
}


def parse_stix_pattern(pattern):
    """
    Parse a STIX 2.1 indicator pattern and extract IOC values and types.
    Handles simple, OR, and AND compound patterns.

    Args:
        pattern: STIX pattern string, e.g. "[ipv4-addr:value = '1.2.3.4']"
                 or "[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']"

    Returns:
        list of dicts with indicatorType, objectType, property, value (and hashType for files)
        or empty list if pattern cannot be parsed
    """
    if not pattern:
        return []

    matches = STIX_PATTERN_RE.findall(pattern)
    if not matches:
        logger.warning("Could not parse STIX pattern: %s", pattern[:200])
        return []

    results = []
    for obj_type, property_path, value in matches:
        if obj_type not in STIX_TO_SENTINEL_TYPE:
            logger.info("Unsupported STIX object type in pattern: %s", obj_type)
            continue

        # Clean quoted property names (e.g., hashes.'SHA-256' -> hashes.SHA-256)
        clean_prop = property_path.replace("'", "")

        result = {
            "indicatorType": STIX_TO_SENTINEL_TYPE[obj_type],
            "objectType": obj_type,
            "property": clean_prop,
            "value": value,
        }

        if obj_type == "file" and "hashes" in clean_prop:
            parts = clean_prop.split(".")
            if len(parts) >= 2:
                result["hashType"] = parts[-1]

        results.append(result)

    return results


def transform_to_sentinel_ti(stix_obj, collection_id):
    """
    Transform a STIX 2.1 indicator object to Microsoft Sentinel
    Threat Intelligence createIndicator format.

    Handles compound patterns (OR/AND) by creating one indicator per IOC.

    Args:
        stix_obj: STIX 2.1 indicator object (dict)
        collection_id: TAXII collection ID for tagging

    Returns:
        list of dicts in Sentinel TI createIndicator format, or empty list if invalid
    """
    if stix_obj.get("type") != "indicator":
        return []

    pattern = stix_obj.get("pattern", "")
    parsed_list = parse_stix_pattern(pattern)
    if not parsed_list:
        return []

    # Common fields shared across all IOCs from this indicator
    stix_id = stix_obj.get("id", "")

    # Map confidence (STIX 0-100 to Sentinel 0-100)
    confidence = stix_obj.get("confidence", 50)
    if not isinstance(confidence, (int, float)):
        confidence = 50
    confidence = max(0, min(100, int(confidence)))

    # Map threat types
    stix_types = stix_obj.get("indicator_types", [])
    threat_types = []
    for st in stix_types:
        mapped = STIX_TO_THREAT_TYPES.get(st, "Malware")
        if mapped not in threat_types:
            threat_types.append(mapped)
    if not threat_types:
        threat_types = ["Malware"]

    # Validity dates
    valid_from = stix_obj.get("valid_from", "")
    if not valid_from:
        valid_from = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")

    valid_until = stix_obj.get("valid_until", "")

    # Build labels
    labels = ["SOCRadar", "TAXII"]
    stix_labels = stix_obj.get("labels", [])
    for label in stix_labels:
        if label not in labels and len(label) <= 100:
            labels.append(label)
    if collection_id:
        labels.append("collection-{}".format(collection_id[:50]))

    description = (stix_obj.get("description", "") or "")[:5000]
    base_name = stix_obj.get("name", "")

    results = []
    for idx, parsed in enumerate(parsed_list):
        # Build display name
        name = base_name
        if not name:
            name = "{} - {}".format(parsed["indicatorType"], parsed["value"][:50])

        # externalId: use STIX ID directly for single IOC, add suffix for compound
        ext_id = stix_id
        if len(parsed_list) > 1:
            ext_id = "{}/{}".format(stix_id, idx)

        properties = {
            "source": "SOCRadar TAXII",
            "displayName": name[:256],
            "description": description,
            "patternType": parsed["indicatorType"],
            "pattern": "[{}:{} = '{}']".format(parsed["objectType"], parsed["property"], parsed["value"]),
            "threatTypes": threat_types,
            "validFrom": valid_from,
            "confidence": confidence,
            "labels": labels,
            "threatIntelligenceTags": labels,
            "externalId": ext_id,
        }

        if valid_until:
            properties["validUntil"] = valid_until

        results.append({"kind": "indicator", "properties": properties})

    return results


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function HTTP trigger entry point.

    Expects POST with JSON body:
    {
        "objects": [...STIX 2.1 objects...],
        "collectionId": "collection-uuid"
    }

    Returns:
    {
        "indicators": [...Sentinel TI format...],
        "stats": {"total": N, "parsed": N, "skipped": N, "types": {...}}
    }
    """
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    objects = body.get("objects", [])
    collection_id = body.get("collectionId", "")

    if not isinstance(objects, list):
        return func.HttpResponse(
            json.dumps({"error": "objects must be an array"}),
            status_code=400,
            mimetype="application/json",
        )

    indicators = []
    revoked_indicators = []
    stats = {
        "total": len(objects),
        "parsed": 0,
        "skipped": 0,
        "revoked": 0,
        "types": {},
        "type_breakdown": {},
    }

    for obj in objects:
        if not isinstance(obj, dict):
            stats["skipped"] += 1
            continue

        obj_type = obj.get("type", "unknown")
        stats["type_breakdown"][obj_type] = stats["type_breakdown"].get(obj_type, 0) + 1

        if obj_type != "indicator":
            stats["skipped"] += 1
            continue

        # Check if indicator is revoked
        if obj.get("revoked") is True:
            stix_id = obj.get("id", "")
            if stix_id:
                revoked_indicators.append({
                    "stixId": stix_id,
                    "displayName": obj.get("name", stix_id),
                })
            stats["revoked"] += 1
            continue

        transformed = transform_to_sentinel_ti(obj, collection_id)
        if transformed:
            indicators.extend(transformed)
            stats["parsed"] += len(transformed)
            for ind in transformed:
                itype = ind["properties"].get("patternType", "unknown")
                stats["types"][itype] = stats["types"].get(itype, 0) + 1
        else:
            stats["skipped"] += 1

    logger.info(
        "Parsed %d/%d indicators (%d revoked) from collection %s",
        stats["parsed"],
        stats["total"],
        stats["revoked"],
        collection_id,
    )

    return func.HttpResponse(
        json.dumps({
            "indicators": indicators,
            "revoked_indicators": revoked_indicators,
            "stats": stats,
        }),
        status_code=200,
        mimetype="application/json",
    )
