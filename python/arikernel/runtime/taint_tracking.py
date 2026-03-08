"""Taint label creation, propagation, and merging."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TaintLabel:
    source: str  # web, rag, email, retrieved-doc, model-generated, user-provided, tool-output
    origin: str
    confidence: float = 1.0
    added_at: str = ""
    propagated_from: str | None = None

    def __post_init__(self):
        self.confidence = max(0.0, min(1.0, self.confidence))
        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        # Serialize confidence as int when it's a whole number (matches JS JSON.stringify behavior)
        conf: int | float = int(self.confidence) if self.confidence == int(self.confidence) else self.confidence
        d: dict[str, Any] = {
            "source": self.source,
            "origin": self.origin,
            "confidence": conf,
            "addedAt": self.added_at,
        }
        if self.propagated_from is not None:
            d["propagatedFrom"] = self.propagated_from
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TaintLabel:
        return cls(
            source=d["source"],
            origin=d["origin"],
            confidence=d.get("confidence", 1.0),
            added_at=d.get("addedAt", ""),
            propagated_from=d.get("propagatedFrom"),
        )


def create_taint_label(source: str, origin: str, confidence: float = 1.0) -> TaintLabel:
    return TaintLabel(source=source, origin=origin, confidence=confidence)


def merge_labels(*label_sets: list[TaintLabel]) -> list[TaintLabel]:
    """Merge and deduplicate taint labels by source:origin key."""
    seen: dict[str, TaintLabel] = {}
    for labels in label_sets:
        for label in labels:
            key = f"{label.source}:{label.origin}"
            if key not in seen:
                seen[key] = label
    return list(seen.values())


class TaintTracker:
    """Track and propagate taint labels across tool call chains."""

    def propagate(self, input_labels: list[TaintLabel], call_id: str) -> list[TaintLabel]:
        """Propagate input taints to output, adding a tool-output label."""
        propagated = [
            TaintLabel(
                source=label.source,
                origin=label.origin,
                confidence=label.confidence,
                propagated_from=call_id,
            )
            for label in input_labels
        ]
        propagated.append(
            TaintLabel(source="tool-output", origin=call_id, confidence=1.0)
        )
        return merge_labels(propagated)
