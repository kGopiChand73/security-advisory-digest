"""Fetch CISA Known Exploited Vulnerabilities catalog (JSON)."""
from __future__ import annotations
from typing import List
import logging

from ._http import get_json
from .models import Advisory

log = logging.getLogger(__name__)

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(max_items: int = 30) -> List[Advisory]:
    data = get_json(CISA_URL, timeout=30)
    if not isinstance(data, dict):
        log.warning("CISA feed returned no data")
        return []

    vulns = data.get("vulnerabilities") or []
    # Most-recent first by dateAdded
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

    items: List[Advisory] = []
    for v in vulns[:max_items]:
        cve_id = v.get("cveID", "CVE-?")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        affected = [p for p in (vendor, product) if p]
        items.append(
            Advisory(
                id=cve_id,
                source="cisa",
                title=f"{cve_id}: {vendor} {product} - {v.get('vulnerabilityName', '')}".strip(),
                description=v.get("shortDescription", ""),
                severity="HIGH",  # CISA KEV = actively exploited, treat as HIGH at minimum
                published=v.get("dateAdded", ""),
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                affected_products=affected,
            )
        )
    log.info("CISA: %d advisories", len(items))
    return items
