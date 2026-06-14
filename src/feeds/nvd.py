"""Fetch recent CVEs from the NVD 2.0 JSON API."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import List
import logging

from ._http import get_json
from .models import Advisory

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity_from_metrics(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData", {})
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
            if sev:
                return sev.upper()
    return "UNKNOWN"


def fetch(max_items: int = 30, days: int = 7) -> List[Advisory]:
    """Pull CVEs published in the last `days` days."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(max_items, 200),
    }
    data = get_json(NVD_URL, params=params, timeout=45)
    if not isinstance(data, dict):
        log.warning("NVD feed returned no data")
        return []

    items: List[Advisory] = []
    for vuln in (data.get("vulnerabilities") or [])[:max_items]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "CVE-?")
        descs = cve.get("descriptions") or []
        desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        affected = []
        for cfg in cve.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for cpe in node.get("cpeMatch") or []:
                    crit = cpe.get("criteria", "")
                    # cpe:2.3:a:vendor:product:version:...
                    parts = crit.split(":")
                    if len(parts) > 4 and parts[4]:
                        affected.append(parts[4])
        items.append(
            Advisory(
                id=cve_id,
                source="nvd",
                title=cve_id + ": " + (desc[:120] + "..." if len(desc) > 120 else desc),
                description=desc,
                severity=_severity_from_metrics(cve.get("metrics", {})),
                published=cve.get("published", ""),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                affected_products=sorted(set(affected))[:10],
            )
        )
    log.info("NVD: %d advisories", len(items))
    return items
