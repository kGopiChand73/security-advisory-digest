"""Lightweight TF-IDF vector store for advisories (no external deps).

Drop-in replacement for the ChromaDB + sentence-transformers backend.
For this PoC the corpus is small (a few hundred advisories at most) and
matches are dominated by package-name token overlap, so plain TF-IDF
cosine similarity works well and runs instantly with zero dependencies.
"""
from __future__ import annotations
from typing import Any, Dict, List
import logging
import math
import re

from src.feeds.models import Advisory

log = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
    "has", "have", "in", "is", "it", "its", "of", "on", "or", "that",
    "the", "this", "to", "via", "was", "were", "with", "vulnerability",
    "vulnerabilities", "issue", "allows", "could", "may", "when",
}


def _tokenize(text: str) -> List[str]:
    return [
        t.lower()
        for t in _TOKEN_RE.findall(text or "")
        if t.lower() not in _STOPWORDS and len(t) > 1
    ]


def _term_freq(tokens: List[str]) -> Dict[str, float]:
    tf: Dict[str, float] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0.0) + 1.0
    if tf:
        max_f = max(tf.values())
        for k in tf:
            tf[k] /= max_f
    return tf


def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    # iterate over the smaller dict
    if len(a) > len(b):
        a, b = b, a
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    if dot == 0.0:
        return 0.0
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class AdvisoryVectorStore:
    """In-memory TF-IDF index over Advisory objects."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self._docs: List[Dict[str, Any]] = []
        self._idf: Dict[str, float] = {}
        self._vectors: List[Dict[str, float]] = []

    def add(self, advisories: List[Advisory]) -> None:
        if not advisories:
            return

        # Build corpus token lists and document frequencies.
        token_lists: List[List[str]] = []
        df: Dict[str, int] = {}
        for a in advisories:
            tokens = _tokenize(a.embedding_text())
            token_lists.append(tokens)
            for term in set(tokens):
                df[term] = df.get(term, 0) + 1

        n_docs = len(advisories)
        self._idf = {
            term: math.log((1 + n_docs) / (1 + freq)) + 1.0
            for term, freq in df.items()
        }

        for a, tokens in zip(advisories, token_lists):
            tf = _term_freq(tokens)
            vec = {term: tf_val * self._idf.get(term, 1.0) for term, tf_val in tf.items()}
            self._vectors.append(vec)
            self._docs.append(
                {
                    "id": a.id,
                    "source": a.source,
                    "title": a.title,
                    "severity": a.severity,
                    "published": a.published,
                    "url": a.url,
                    "affected": ", ".join(a.affected_products),
                    "description": a.description[:1000],
                }
            )

        log.info("Indexed %d advisories (TF-IDF, %d unique terms)",
                 n_docs, len(self._idf))

    def query(self, text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self._vectors:
            return []
        q_tokens = _tokenize(text)
        if not q_tokens:
            return []
        q_tf = _term_freq(q_tokens)
        q_vec = {term: tf_val * self._idf.get(term, 1.0) for term, tf_val in q_tf.items()}

        scored: List[tuple[float, int]] = []
        for i, vec in enumerate(self._vectors):
            sim = _cosine(q_vec, vec)
            if sim > 0.0:
                scored.append((sim, i))

        scored.sort(key=lambda p: p[0], reverse=True)
        out: List[Dict[str, Any]] = []
        for sim, i in scored[:top_k]:
            out.append({**self._docs[i], "similarity": float(sim)})
        return out
