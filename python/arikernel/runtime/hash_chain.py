"""SHA-256 hash chain for tamper-evident audit logging.

Compatible with the TypeScript runtime's hash chain format.
"""

from __future__ import annotations

import hashlib

GENESIS_HASH = "0" * 64


def compute_hash(data: str, previous_hash: str) -> str:
    """Compute SHA-256 hash: update(previousHash) then update(data).

    This matches the TypeScript implementation exactly:
        createHash('sha256').update(previousHash).update(data).digest('hex')
    """
    h = hashlib.sha256()
    h.update(previous_hash.encode("utf-8"))
    h.update(data.encode("utf-8"))
    return h.hexdigest()


def verify_chain(
    events: list[dict],
) -> dict:
    """Verify a chain of events.

    Args:
        events: List of dicts with 'hash', 'previousHash', 'data' keys.

    Returns:
        {"valid": True} or {"valid": False, "brokenAt": index}
    """
    for i, event in enumerate(events):
        expected = compute_hash(event["data"], event["previousHash"])
        if expected != event["hash"]:
            return {"valid": False, "brokenAt": i}
        if i > 0 and event["previousHash"] != events[i - 1]["hash"]:
            return {"valid": False, "brokenAt": i}
    return {"valid": True}
