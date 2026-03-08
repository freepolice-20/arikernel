"""AutoScope — deterministic keyword-based task-to-preset classifier."""

from __future__ import annotations

from typing import Any

from .spec_loader import get_autoscope_config


def classify_scope(task: str) -> dict[str, Any]:
    """Classify a task description into a preset.

    Returns:
        {"preset": str, "confidence": float, "scores": dict}
    """
    config = get_autoscope_config()
    rules = config["rules"]
    fallback = config.get("fallback", "safe-research")
    min_confidence = config.get("minConfidence", 0.3)

    lower = task.lower()
    scores: dict[str, float] = {}

    for rule in rules:
        score = sum(1 for kw in rule["keywords"] if kw in lower)
        scores[rule["preset"]] = score

    best_preset = fallback
    best_score = 0.0
    total_score = sum(scores.values())

    for rule in rules:
        score = scores[rule["preset"]]
        if score > best_score:
            best_score = score
            best_preset = rule["preset"]

    confidence = best_score / total_score if total_score > 0 else 0.0

    if best_score == 0 or confidence < min_confidence:
        return {
            "preset": fallback,
            "confidence": 0.0,
            "scores": scores,
        }

    return {
        "preset": best_preset,
        "confidence": confidence,
        "scores": scores,
    }
