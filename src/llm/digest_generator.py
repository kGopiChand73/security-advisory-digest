"""Backward-compatibility shim. Real implementation now lives in
`src.llm_helper`. New code should import `judge` and `Verdict` from there.
"""
from src.llm_helper import Verdict, judge  # noqa: F401

__all__ = ["judge", "Verdict"]
