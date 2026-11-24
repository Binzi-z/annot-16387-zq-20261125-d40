from __future__ import annotations

import hmac
import secrets
from typing import Any, Iterable

from .canonical import canonical_bytes, receipt_signing_payload

RECEIPT_DOMAIN = b"audit-receipt-v1"


class HmacKeyring:
    """Trusted witness registry and stdlib-only receipt authenticator.

    HMAC is used instead of an asymmetric signature because the task constrains
    the implementation to the Python standard library.  The keyring is the
    out-of-band trust anchor: controllers and signing identities are registered
    there before reconciliation.  Evidence bundles contain controller/epoch
    metadata but never contain HMAC secrets.
    """

    def __init__(self, data: dict[str, Any] | None = None):
        self.data: dict[str, Any] = data or {"controllers": {}, "identities": {}}
        self.data.setdefault("controllers", {})
        self.data.setdefault("identities", {})

    @classmethod
    def synthetic(cls, controllers: dict[str, Iterable[tuple[str, list[dict[str, Any]]]]],
                  seed: str = "synthetic-audit") -> "HmacKeyring":
        """Create deterministic local keys for tests and synthetic demos."""

        ring = cls()
        for controller_id, identities in controllers.items():
            ring.add_controller(controller_id)
            for identity_id, epochs in identities:
                secret = hmac.new(
                    seed.encode("utf-8"), identity_id.encode("utf-8"), "sha256"
                ).hexdigest()
                ring.add_identity(identity_id, controller_id, secret, epochs)
        return ring

    def add_controller(self, controller_id: str, metadata: dict[str, Any] | None = None) -> None:
        self.data["controllers"][controller_id] = metadata or {}

    def add_identity(
        self,
        identity_id: str,
        controller_id: str,
        secret: str | bytes | None = None,
        epochs: list[dict[str, Any]] | None = None,
    ) -> str:
        if controller_id not in self.data["controllers"]:
            self.add_controller(controller_id)
        if secret is None:
            secret = secrets.token_hex(32)
        if isinstance(secret, bytes):
            secret = secret.hex()
        self.data["identities"][identity_id] = {
            "controller": controller_id,
            "secret": secret,
            "epochs": epochs or [{"partition": "*", "first_segment": 0, "last_segment": None}],
        }
        return secret

    def controller_of(self, identity_id: str) -> str | None:
        identity = self.data["identities"].get(identity_id)
        return None if identity is None else identity["controller"]

    def secret_bytes(self, identity_id: str) -> bytes | None:
        identity = self.data["identities"].get(identity_id)
        if identity is None:
            return None
        secret = identity["secret"]
        return bytes.fromhex(secret) if all(c in "0123456789abcdefABCDEF" for c in secret) and len(secret) % 2 == 0 else secret.encode("utf-8")

    def epoch_allows(self, identity_id: str, partition: str, segment: int) -> bool:
        identity = self.data["identities"].get(identity_id)
        if identity is None:
            return False
        epochs = identity.get("epochs") or []
        for epoch in epochs:
            if epoch.get("partition", "*") not in ("*", partition):
                continue
            first = int(epoch.get("first_segment", 0))
            last = epoch.get("last_segment")
            if first <= segment and (last is None or segment <= int(last)):
                return True
        return False

    def mac_for(self, receipt: dict[str, Any]) -> str | None:
        key = self.secret_bytes(receipt["identity_id"])
        if key is None:
            return None
        body = RECEIPT_DOMAIN + b"\x00" + canonical_bytes(receipt_signing_payload(receipt))
        return hmac.new(key, body, "sha256").hexdigest()

    def sign(self, receipt: dict[str, Any]) -> dict[str, Any]:
        receipt = dict(receipt)
        receipt["mac"] = self.mac_for(receipt)
        if receipt["mac"] is None:
            raise KeyError(f"unknown signing identity {receipt['identity_id']!r}")
        return receipt

    def verify(self, receipt: dict[str, Any]) -> bool:
        expected = self.mac_for(receipt)
        supplied = receipt.get("mac")
        if expected is None or not isinstance(supplied, str):
            return False
        return hmac.compare_digest(expected, supplied)

    def public_data(self) -> dict[str, Any]:
        """Return registry/epoch data with secrets removed."""

        identities = {}
        for kid, item in self.data["identities"].items():
            identities[kid] = {
                "controller": item["controller"],
                "epochs": item.get("epochs", []),
            }
        return {
            "controllers": dict(self.data["controllers"]),
            "identities": identities,
        }


def sign_receipt(keyring: HmacKeyring, **fields: Any) -> dict[str, Any]:
    receipt = {
        "v": 1,
        "receipt_id": fields.pop("receipt_id"),
        "partition": fields.pop("partition"),
        "seq": fields.pop("seq"),
        "segment": fields.pop("segment"),
        "record_digest": fields.pop("record_digest"),
        "identity_id": fields.pop("identity_id"),
    }
    if fields:
        raise TypeError(f"unexpected receipt fields: {sorted(fields)}")
    return keyring.sign(receipt)
