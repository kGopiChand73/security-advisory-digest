"""CLI entry point: `python -m src.main`.

Thin wrapper around `src.processor.run_digest()` for terminal use.
The Streamlit UI in `app.py` calls the same function.
"""
from __future__ import annotations

import logging
import os
import sys

# Make 'src.' imports work when run as `python src/main.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.processor import run_digest

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("digest")


def main() -> int:
    log.info("=== Security Advisory Digest ===")
    try:
        _, path, stats = run_digest()
    except Exception as e:  # noqa: BLE001
        log.exception("Pipeline failed: %s", e)
        return 1
    print(f"\n[OK] Digest ready: {path}")
    print(f"     Provider: {stats['provider']} | "
          f"Advisories: {stats['advisories']} | "
          f"Matches: {stats['matches']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
