"""End-to-end orchestrator for the Security Advisory Digest.

This module exposes a single function `run_digest()` that executes the
full pipeline and returns the matches plus the path of the written
Markdown file. Both the CLI (`src/main.py`) and the Streamlit UI
(`app.py`) call into this function.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.feeds import cisa, github_advisories, nvd
from src.feeds.models import Advisory
from src.llm_helper import active_provider, judge
from src.output.markdown_writer import write as write_markdown
from src.rag.stack_loader import load_stack
from src.rag.vector_store import AdvisoryVectorStore
from src.utils import load_dotenv

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_all(max_per_feed: int) -> List[Advisory]:
    advisories: List[Advisory] = []
    advisories += github_advisories.fetch(max_items=max_per_feed)
    advisories += nvd.fetch(max_items=max_per_feed)
    advisories += cisa.fetch(max_items=max_per_feed)
    return advisories


def _config(overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    overrides = overrides or {}
    return {
        "max_per_feed": int(overrides.get(
            "max_per_feed", os.getenv("MAX_ITEMS_PER_FEED", "30"))),
        "top_k": int(overrides.get(
            "top_k", os.getenv("TOP_K", "3"))),
        "threshold": float(overrides.get(
            "threshold", os.getenv("SIMILARITY_THRESHOLD", "0.05"))),
        "stack_path": str(overrides.get("stack_path", "stack.yaml")),
        "out_dir": str(overrides.get("out_dir", "outputs")),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_digest(
    overrides: Optional[Dict[str, Any]] = None,
    advisories: Optional[List[Advisory]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Tuple[List[Dict[str, Any]], str, Dict[str, Any]]:
    """Run the digest pipeline.

    Args:
        overrides: optional config overrides (max_per_feed, top_k,
            threshold, stack_path, out_dir).
        advisories: pre-fetched advisories (used by tests to avoid HTTP).
        progress: optional callback receiving human-readable status lines.

    Returns:
        (matches, output_path, stats)
    """
    load_dotenv()
    cfg = _config(overrides)

    def _say(msg: str) -> None:
        log.info(msg)
        if progress:
            progress(msg)

    _say(f"Provider: {active_provider()}")

    # Step 1 - fetch
    if advisories is None:
        _say("Step 1/5: fetching advisories from 3 feeds...")
        advisories = _fetch_all(cfg["max_per_feed"])
    else:
        _say(f"Step 1/5: using {len(advisories)} pre-supplied advisories")
    _say(f"Total advisories: {len(advisories)}")

    # Step 2 - stack
    _say("Step 2/5: loading stack...")
    stack = load_stack(cfg["stack_path"])
    _say(f"Stack items: {len(stack)}")

    # Step 3 - index
    _say("Step 3/5: indexing advisories (TF-IDF)...")
    store = AdvisoryVectorStore()
    store.add(advisories)

    # Step 4 - retrieve + judge
    _say("Step 4/5: RAG retrieval + LLM judgement per stack item...")
    matches: List[Dict[str, Any]] = []
    seen_pairs = set()
    for item in stack:
        hits = store.query(item["query"], top_k=cfg["top_k"])
        for h in hits:
            sim = h.get("similarity", 0.0)
            if sim < cfg["threshold"]:
                continue
            key = (item["name"], h.get("id"))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            verdict = judge(item, h)
            if not verdict.affects:
                continue
            matches.append({
                "stack_item": item,
                "advisory": h,
                "similarity": sim,
                "verdict": verdict,
            })
    _say(f"Confirmed matches affecting stack: {len(matches)}")

    # Step 5 - write
    _say("Step 5/5: writing Markdown digest...")
    path = write_markdown(matches, out_dir=cfg["out_dir"])
    _say(f"Digest written to: {path}")

    stats = {
        "advisories": len(advisories),
        "stack_items": len(stack),
        "matches": len(matches),
        "provider": active_provider(),
        "config": cfg,
    }
    return matches, path, stats
