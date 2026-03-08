"""Load the shared arikernel-policy.json spec file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_spec_cache: dict[str, Any] | None = None


def _find_spec_file() -> Path:
    """Walk up from this file to find arikernel-policy.json."""
    current = Path(__file__).resolve().parent
    for _ in range(10):
        candidate = current / "arikernel-policy.json"
        if candidate.exists():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise FileNotFoundError("Could not find arikernel-policy.json in any parent directory")


def load_spec() -> dict[str, Any]:
    global _spec_cache
    if _spec_cache is None:
        _spec_cache = json.loads(_find_spec_file().read_text(encoding="utf-8"))
    return _spec_cache


def get_policy_fragments() -> dict[str, dict[str, Any]]:
    return load_spec()["policyFragments"]


def resolve_policy(entry: str | dict[str, Any]) -> dict[str, Any]:
    """Resolve a policy entry: string -> fragment lookup, dict -> passthrough."""
    if isinstance(entry, str):
        fragments = get_policy_fragments()
        if entry not in fragments:
            raise ValueError(f"Unknown policy fragment: {entry!r}")
        return fragments[entry]
    return entry


def get_preset(preset_id: str) -> dict[str, Any]:
    spec = load_spec()
    raw = spec["presets"].get(preset_id)
    if not raw:
        available = ", ".join(spec["presets"].keys())
        raise ValueError(f'Unknown preset: "{preset_id}". Available: {available}')
    return {
        "id": raw["id"],
        "name": raw["name"],
        "description": raw["description"],
        "capabilities": raw["capabilities"],
        "policies": [resolve_policy(p) for p in raw["policies"]],
    }


def get_defaults() -> dict[str, Any]:
    spec = load_spec()
    defaults = spec["defaults"]
    return {
        "capabilities": defaults["capabilities"],
        "policies": [resolve_policy(p) for p in defaults["policies"]],
    }


def get_constants() -> dict[str, Any]:
    return load_spec()["constants"]


def get_autoscope_config() -> dict[str, Any]:
    return load_spec()["autoScope"]


def get_behavioral_rules_config() -> dict[str, Any]:
    return load_spec()["behavioralRules"]


def get_capability_classes() -> dict[str, dict[str, Any]]:
    return load_spec()["capabilityClasses"]
