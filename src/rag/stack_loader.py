"""Loads stack.yaml and turns it into RAG query strings.

Uses a small purpose-built parser (no PyYAML dependency) that handles the
simple structure used in stack.yaml: top-level keys mapping to lists of
`{name, version}` dicts. Comments (`#`) and blank lines are ignored.
"""
from __future__ import annotations
from typing import Dict, List, Optional


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _parse_simple_yaml(text: str) -> Dict[str, List[Dict[str, str]]]:
    """Parse the limited YAML subset used by stack.yaml.

    Supported structure:
        category:
          - name: foo
            version: "1.2"
          - name: bar
    """
    data: Dict[str, List[Dict[str, str]]] = {}
    current_cat: str = ""
    current_item: Optional[Dict[str, str]] = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if indent == 0 and stripped.endswith(":"):
            current_cat = stripped[:-1].strip()
            data[current_cat] = []
            current_item = None
            continue

        if not current_cat:
            continue

        if stripped.startswith("- "):
            current_item = {}
            data[current_cat].append(current_item)
            stripped = stripped[2:].lstrip()
            if not stripped:
                continue

        if current_item is None or ":" not in stripped:
            continue

        key, _, value = stripped.partition(":")
        current_item[key.strip()] = _strip_quotes(value)

    return data


def load_stack(path: str = "stack.yaml") -> List[Dict[str, str]]:
    """Returns a flat list of {category, name, version, query} entries."""
    with open(path, "r", encoding="utf-8") as f:
        raw = _parse_simple_yaml(f.read())

    items: List[Dict[str, str]] = []
    for category, entries in raw.items():
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                continue
            name = str(e.get("name", "")).strip()
            version = str(e.get("version", "")).strip()
            if not name:
                continue
            query = f"vulnerability in {name} {version}".strip()
            items.append(
                {"category": category, "name": name, "version": version, "query": query}
            )
    return items
