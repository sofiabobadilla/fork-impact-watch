from __future__ import annotations

from dataclasses import dataclass, field

# likely: the pattern matches the advisory's risky shape closely.
# possible: a red flag that needs a human to look at the surrounding code.
CONFIDENCE_ORDER = {"likely": 0, "possible": 1}


@dataclass
class Finding:
    rule: str
    advisory: str
    path: str
    line: int
    confidence: str
    message: str
    snippet: str = ""
    notes: list[str] = field(default_factory=list)

    def sort_key(self):
        return (CONFIDENCE_ORDER[self.confidence], self.advisory, self.path, self.line)
