"""Happy-path tests for the Security Advisory Digest.

Runs without external dependencies. Compatible with both:
    pytest tests/
    python -m unittest discover tests

The tests use the offline sample fixture in `data/sample_advisories.json`
so no network calls are made.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make `src.*` imports work
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.feeds.models import Advisory
from src.llm_helper import judge
from src.processor import run_digest
from src.rag.stack_loader import load_stack
from src.rag.vector_store import AdvisoryVectorStore


def _load_sample_advisories() -> list[Advisory]:
    path = ROOT / "data" / "sample_advisories.json"
    with open(path, "r", encoding="utf-8") as f:
        items = json.load(f)
    return [Advisory(**item) for item in items]


class TestStackLoader(unittest.TestCase):
    """Stack YAML parsing produces the expected items."""

    def test_loads_sample_stack(self) -> None:
        path = ROOT / "data" / "sample_input.yaml"
        items = load_stack(str(path))
        self.assertGreater(len(items), 0, "stack should have items")
        names = {i["name"] for i in items}
        self.assertIn("log4j", names)
        self.assertIn("django", names)


class TestVectorStore(unittest.TestCase):
    """RAG retrieval returns relevant advisories for stack queries."""

    def test_log4j_query_finds_log4shell(self) -> None:
        store = AdvisoryVectorStore()
        store.add(_load_sample_advisories())
        hits = store.query("vulnerability in log4j 2.20", top_k=3)
        self.assertTrue(hits, "expected at least one hit")
        ids = [h["id"] for h in hits]
        self.assertIn("CVE-2021-44228", ids,
                      "Log4Shell should appear in top results for log4j query")

    def test_unrelated_query_has_lower_similarity(self) -> None:
        store = AdvisoryVectorStore()
        store.add(_load_sample_advisories())
        hits = store.query("vulnerability in wordpress 5.0", top_k=1)
        if hits:
            self.assertLess(hits[0]["similarity"], 1.0)


class TestJudge(unittest.TestCase):
    """The mock LLM judge correctly identifies obvious matches."""

    def test_mock_judge_says_affects_when_name_matches(self) -> None:
        os.environ["LLM_PROVIDER"] = "mock"
        stack_item = {"name": "log4j", "version": "2.20",
                      "category": "libraries"}
        advisory = {
            "id": "CVE-2021-44228",
            "title": "Apache Log4j2 RCE",
            "description": "log4j-core versions through 2.14.1 allow RCE.",
            "affected": "log4j-core",
            "severity": "CRITICAL",
        }
        verdict = judge(stack_item, advisory)
        self.assertTrue(verdict.affects)
        self.assertGreater(verdict.confidence, 0.5)

    def test_mock_judge_rejects_unrelated_advisory(self) -> None:
        os.environ["LLM_PROVIDER"] = "mock"
        stack_item = {"name": "django", "version": "4.2",
                      "category": "frameworks"}
        advisory = {
            "id": "CVE-2024-9999",
            "title": "WordPress plugin XSS",
            "description": "XSS in a WordPress plugin.",
            "affected": "wordpress",
            "severity": "MEDIUM",
        }
        verdict = judge(stack_item, advisory)
        self.assertFalse(verdict.affects)


class TestEndToEnd(unittest.TestCase):
    """Happy-path: run the full pipeline against sample data offline."""

    def test_pipeline_with_sample_data(self) -> None:
        os.environ["LLM_PROVIDER"] = "mock"
        with tempfile.TemporaryDirectory() as tmp:
            matches, out_path, stats = run_digest(
                overrides={
                    "stack_path": str(ROOT / "data" / "sample_input.yaml"),
                    "out_dir": tmp,
                    "threshold": 0.05,
                    "top_k": 3,
                },
                advisories=_load_sample_advisories(),
            )

            # Pipeline produced an output file
            self.assertTrue(os.path.exists(out_path))

            # Stats are populated
            self.assertEqual(stats["advisories"], 5)
            self.assertGreater(stats["stack_items"], 0)
            self.assertGreaterEqual(stats["matches"], 1,
                                    "at least one match expected")

            # Log4Shell should be among the matches
            ids = [m["advisory"]["id"] for m in matches]
            self.assertIn("CVE-2021-44228", ids,
                          "Log4Shell should match log4j 2.20")

            # Markdown output contains expected sections
            with open(out_path, "r", encoding="utf-8") as f:
                md = f.read()
            self.assertIn("Security Advisory Digest", md)
            self.assertIn("CVE-2021-44228", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
