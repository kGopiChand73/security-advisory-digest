"""LLM judge wrapper.

Picks the LLM provider based on the LLM_PROVIDER env var:
  * mock    -> rule-based, no network, no key (default)
  * gemini  -> Google Gemini free tier (needs `google-generativeai` package
               and GEMINI_API_KEY)
  * openai  -> OpenAI (needs `openai` package and OPENAI_API_KEY)

All providers share the same Verdict contract. The function gracefully
falls back to mock if the configured provider fails for any reason, so
the pipeline always produces a result.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass
from typing import Dict, Optional

log = logging.getLogger(__name__)


@dataclass
class Verdict:
    affects: bool
    impact: str
    action: str
    confidence: float

    def to_dict(self) -> Dict:
        return asdict(self)


SYSTEM_PROMPT = (
    "You are a senior security analyst. Given ONE security advisory and ONE "
    "tech-stack item, decide whether the advisory genuinely affects this "
    "stack item. Be strict: if the advisory is about a different product "
    "that merely shares a keyword, answer false. "
    "Respond ONLY with compact JSON matching this exact schema: "
    '{"affects": true|false, "impact": "<one short sentence>", '
    '"action": "<one short remediation>", "confidence": 0.0-1.0}.'
)


def build_user_prompt(stack_item: Dict, advisory: Dict) -> str:
    return (
        "Stack item:\n"
        f"  name: {stack_item.get('name')}\n"
        f"  version: {stack_item.get('version')}\n"
        f"  category: {stack_item.get('category')}\n\n"
        "Advisory:\n"
        f"  id: {advisory.get('id')}\n"
        f"  source: {advisory.get('source')}\n"
        f"  severity: {advisory.get('severity')}\n"
        f"  affected: {advisory.get('affected')}\n"
        f"  title: {advisory.get('title')}\n"
        f"  description: {advisory.get('description')}\n"
    )


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _mock_verdict(stack_item: Dict, advisory: Dict) -> Verdict:
    """Rule-based offline judge."""
    name = (stack_item.get("name") or "").lower()
    haystack = " ".join(
        [
            (advisory.get("affected") or "").lower(),
            (advisory.get("title") or "").lower(),
            (advisory.get("description") or "").lower(),
        ]
    )
    affects = bool(name) and name in haystack
    sev = (advisory.get("severity") or "UNKNOWN").upper()
    impact = (
        f"{advisory.get('id')} ({sev}) appears to affect "
        f"{stack_item.get('name')} {stack_item.get('version')}."
        if affects
        else "No direct match by name; flagged via semantic similarity only."
    )
    action = (
        f"Review {advisory.get('id')} and patch "
        f"{stack_item.get('name')} if applicable."
    )
    return Verdict(
        affects=affects,
        impact=impact,
        action=action,
        confidence=0.7 if affects else 0.2,
    )


def _parse_json_verdict(text: str) -> Optional[Verdict]:
    text = (text or "").strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    return Verdict(
        affects=bool(data.get("affects", False)),
        impact=str(data.get("impact", "")).strip(),
        action=str(data.get("action", "")).strip(),
        confidence=float(data.get("confidence", 0.5)),
    )


def _gemini_verdict(stack_item: Dict, advisory: Dict) -> Optional[Verdict]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        log.warning("GEMINI_API_KEY not set; cannot use Gemini")
        return None
    try:
        import google.generativeai as genai  # type: ignore
    except ImportError:
        log.warning("google-generativeai package not installed; install with "
                    "`pip install google-generativeai`")
        return None

    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=SYSTEM_PROMPT,
        )
        resp = model.generate_content(
            build_user_prompt(stack_item, advisory),
            generation_config={"response_mime_type": "application/json",
                               "temperature": 0},
        )
        return _parse_json_verdict(resp.text)
    except Exception as e:  # noqa: BLE001
        log.warning("Gemini call failed: %s", e)
        return None


def _openai_verdict(stack_item: Dict, advisory: Dict) -> Optional[Verdict]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI  # type: ignore
    except ImportError:
        log.warning("openai package not installed")
        return None

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    try:
        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",
                 "content": build_user_prompt(stack_item, advisory)},
            ],
        )
        return _parse_json_verdict(resp.choices[0].message.content or "{}")
    except Exception as e:  # noqa: BLE001
        log.warning("OpenAI call failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def judge(stack_item: Dict, advisory: Dict) -> Verdict:
    """Top-level entry point used by the pipeline."""
    provider = (os.getenv("LLM_PROVIDER") or "mock").lower()
    if provider == "gemini":
        v = _gemini_verdict(stack_item, advisory)
        if v is not None:
            return v
    elif provider == "openai":
        v = _openai_verdict(stack_item, advisory)
        if v is not None:
            return v
    return _mock_verdict(stack_item, advisory)


def active_provider() -> str:
    """Returns the provider that will actually be used (for UI display)."""
    return (os.getenv("LLM_PROVIDER") or "mock").lower()
