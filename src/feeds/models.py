"""Common Advisory data model used across feed fetchers."""
from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class Advisory:
    id: str                       # e.g. CVE-2026-1234 or GHSA-xxxx
    source: str                   # github | nvd | cisa
    title: str
    description: str
    severity: str = "UNKNOWN"     # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    published: str = ""           # ISO date string
    url: str = ""
    affected_products: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def embedding_text(self) -> str:
        """Text used to build the vector embedding."""
        parts = [self.title, self.description]
        if self.affected_products:
            parts.append("Affected: " + ", ".join(self.affected_products))
        return "\n".join(p for p in parts if p)
