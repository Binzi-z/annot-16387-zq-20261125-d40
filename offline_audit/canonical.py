from __future__ import annotations

import hashlib
import json
from typing import Any

CANONICAL_FORMAT = "offline-audit-canonical-json/v1"
ZERO_DIGEST = "0" * 64


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic JSON bytes.

    Sorting keys and using separated ASCII output means another standard-
    library tool (Python, Node, etc.) can reproduce the exact signed bytes
    without relying on this implementation.
    """

    text = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("ascii")


def domain_digest(domain: str, value: Any) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_bytes(value))
    return h.hexdigest()


def record_preimage(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": record.get("v", 1),
        "partition": record["partition"],
        "seq": record["seq"],
        "segment": record["segment"],
        "prev": record["prev"],
        "payload": record["payload"],
    }


def record_digest(record: dict[str, Any]) -> str:
    return domain_digest("audit-record-v1", record_preimage(record))


def receipt_signing_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": receipt.get("v", 1),
        "receipt_id": receipt["receipt_id"],
        "partition": receipt["partition"],
        "seq": receipt["seq"],
        "segment": receipt["segment"],
        "record_digest": receipt["record_digest"],
        "identity_id": receipt["identity_id"],
    }
