"""Tiny stdlib-only HTTP helper used by the feed fetchers.

Replaces `requests` with `urllib` and tolerates the corporate-proxy /
self-signed-CA cases by retrying with an unverified TLS context if the
first attempt fails with an SSL error. Set INSECURE_SSL=1 to skip the
verified attempt entirely.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": "sec-advisory-digest/1.0 (+stdlib)",
    "Accept": "application/json",
}


def _build_url(url: str, params: Optional[Dict[str, Any]]) -> str:
    if not params:
        return url
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{qs}"


def _open(url: str, headers: Dict[str, str], timeout: int, ctx: ssl.SSLContext):
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def get_json(
    url: str,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
) -> Optional[Any]:
    """GET a URL and return parsed JSON, or None on any failure."""
    full_url = _build_url(url, params)
    hdrs = dict(DEFAULT_HEADERS)
    if headers:
        hdrs.update(headers)

    insecure = os.getenv("INSECURE_SSL", "").strip() in ("1", "true", "yes")
    contexts = []
    if not insecure:
        contexts.append(("verified", ssl.create_default_context()))
    contexts.append(("unverified", ssl._create_unverified_context()))  # type: ignore[attr-defined]

    last_err: Optional[BaseException] = None
    for label, ctx in contexts:
        try:
            with _open(full_url, hdrs, timeout, ctx) as resp:
                raw = resp.read()
            if label == "unverified":
                log.warning("Fetched %s with TLS verification disabled", url)
            return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            log.warning("HTTP %s for %s", e.code, full_url)
            return None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            last_err = e
            # Only retry on SSL-style failures
            msg = str(e).lower()
            if "ssl" in msg or "certificate" in msg:
                continue
            log.warning("Network error for %s: %s", full_url, e)
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("Unexpected error for %s: %s", full_url, e)
            return None

    log.warning("All TLS attempts failed for %s: %s", full_url, last_err)
    return None
