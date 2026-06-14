"""Fetch GitHub Security Advisories via the public REST API (no auth required for read)."""
from __future__ import annotations
from typing import List
import logging

from ._http import get_json
from .models import Advisory

log = logging.getLogger(__name__)

GITHUB_URL = "https://api.github.com/advisories"


def fetch(max_items: int = 30) -> List[Advisory]:
    """Pull recent advisories from GitHub. Public endpoint, no token needed."""
    params = {"per_page": min(max_items, 100)}
    headers = {"Accept": "application/vnd.github+json"}
    data = get_json(GITHUB_URL, params=params, headers=headers, timeout=30)
    if not isinstance(data, list):
        log.warning("GitHub feed returned no data")
        return []

    items: List[Advisory] = []
    for a in data[:max_items]:
        affected = []
        for v in a.get("vulnerabilities") or []:
            pkg = (v or {}).get("package") or {}
            name = pkg.get("name")
            if name:
                affected.append(name)
        items.append(
            Advisory(
                id=a.get("ghsa_id") or a.get("cve_id") or "GHSA-?",
                source="github",
                title=a.get("summary") or "",
                description=a.get("description") or "",
                severity=(a.get("severity") or "UNKNOWN").upper(),
                published=a.get("published_at") or "",
                url=a.get("html_url") or "",
                affected_products=affected,
            )
        )
    log.info("GitHub: %d advisories", len(items))
    return items
