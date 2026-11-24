#!/usr/bin/env python3
"""Independent standard-library verifier for minimal audit evidence.

This file is intentionally self-contained: it does not import or read the
reconciliation package.  Another implementation can audit this file and use it
as the executable specification for the evidence format.

Example (Windows PowerShell or cmd, from the workspace root):

    python verify_evidence.py artifacts\\demo-evidence\\evidence.json ^
        --keyring artifacts\\demo-evidence\\trusted-keyring.json
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ZERO_DIGEST = "0" * 64
REQUIRED_FORMAT = "offline-audit-minimal-evidence/v1"
RECEIPT_DOMAIN = b"audit-receipt-v1"


# --------------------------------------------------------------------- JSON/hash
def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def domain_digest(domain: str, value: Any) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical_bytes(value))
    return digest.hexdigest()


def record_digest(record: dict[str, Any]) -> str:
    preimage = {
        "v": record.get("v", 1),
        "partition": record["partition"],
        "seq": record["seq"],
        "segment": record["segment"],
        "prev": record["prev"],
        "payload": record["payload"],
    }
    return domain_digest("audit-record-v1", preimage)


def receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "v": receipt.get("v", 1),
        "receipt_id": receipt["receipt_id"],
        "partition": receipt["partition"],
        "seq": receipt["seq"],
        "segment": receipt["segment"],
        "record_digest": receipt["record_digest"],
        "identity_id": receipt["identity_id"],
    }


# --------------------------------------------------------------------- keyring
class TrustedKeyring:
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.identities = data.get("identities", {})
        self.controllers = data.get("controllers", {})

    def public_data(self) -> dict[str, Any]:
        return {
            "controllers": self.controllers,
            "identities": {
                kid: {"controller": item["controller"], "epochs": item.get("epochs", [])}
                for kid, item in self.identities.items()
            },
        }

    def controller_of(self, identity_id: str) -> str | None:
        item = self.identities.get(identity_id)
        return None if item is None else item.get("controller")

    def secret_bytes(self, identity_id: str) -> bytes | None:
        item = self.identities.get(identity_id)
        if item is None:
            return None
        secret = item["secret"]
        if isinstance(secret, bytes):
            return secret
        try:
            return bytes.fromhex(secret)
        except ValueError:
            return secret.encode("utf-8")

    def epoch_allows(self, identity_id: str, partition: str, segment: int) -> bool:
        item = self.identities.get(identity_id)
        if item is None:
            return False
        for epoch in item.get("epochs", []):
            if epoch.get("partition", "*") not in ("*", partition):
                continue
            first = int(epoch.get("first_segment", 0))
            last = epoch.get("last_segment")
            if first <= segment and (last is None or segment <= int(last)):
                return True
        return False

    def verify_mac(self, receipt: dict[str, Any]) -> bool:
        key = self.secret_bytes(receipt["identity_id"])
        supplied = receipt.get("mac")
        if key is None or not isinstance(supplied, str):
            return False
        body = RECEIPT_DOMAIN + b"\x00" + canonical_bytes(receipt_payload(receipt))
        expected = hmac.new(key, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, supplied)


# --------------------------------------------------------------------- graph
def build_graph(records: list[dict[str, Any]], segment_size: int) -> dict[str, Any]:
    by_digest: dict[str, dict[str, Any]] = {}
    for record in records:
        digest = record["digest"]
        if digest in by_digest and by_digest[digest] != record:
            raise AssertionError(f"conflicting records claim same digest {digest}")
        by_digest[digest] = record

    by_seq: dict[int, set[str]] = defaultdict(set)
    children: dict[str, set[str]] = defaultdict(set)
    for digest, record in by_digest.items():
        by_seq[int(record["seq"])].add(digest)
        children[record["prev"]].add(digest)

    status: dict[str, str] = {}
    reasons: dict[str, str] = {}
    for digest in sorted(by_digest, key=lambda d: (int(by_digest[d]["seq"]), d)):
        record = by_digest[digest]
        seq = int(record["seq"])
        if record_digest(record) != digest:
            status[digest] = "invalid"
            reasons[digest] = "digest-mismatch"
        elif int(record["segment"]) != seq // segment_size:
            status[digest] = "invalid"
            reasons[digest] = "segment-index-mismatch"
        elif seq == 0:
            if record["prev"] != ZERO_DIGEST:
                status[digest] = "invalid"
                reasons[digest] = "bad-genesis"
            else:
                status[digest] = "valid"
        else:
            parent = by_digest.get(record["prev"])
            if parent is None:
                status[digest] = "incomplete"
                reasons[digest] = "missing-parent"
            elif status.get(record["prev"]) != "valid":
                status[digest] = "incomplete"
                reasons[digest] = "parent-not-valid"
            elif int(parent["seq"]) != seq - 1:
                status[digest] = "invalid"
                reasons[digest] = "nonconsecutive-seq"
            else:
                status[digest] = "valid"

    return {"by_digest": by_digest, "by_seq": by_seq, "children": children,
            "status": status, "reasons": reasons}


def ancestor_closure(graph: dict[str, Any], target: str) -> set[str]:
    result: set[str] = set()
    current = target
    by_digest = graph["by_digest"]
    while current != ZERO_DIGEST:
        if current in result or current not in by_digest:
            break
        result.add(current)
        current = by_digest[current]["prev"]
    return result


def unique_prefix(graph: dict[str, Any]) -> tuple[int, str]:
    genesis = [
        d for d in graph["by_seq"].get(0, set())
        if graph["status"].get(d) == "valid"
        and graph["by_digest"][d]["prev"] == ZERO_DIGEST
    ]
    if len(genesis) != 1:
        return -1, ZERO_DIGEST
    current = genesis[0]
    height = 0
    while True:
        kids = [d for d in graph["children"].get(current, set())
                if graph["status"].get(d) == "valid"]
        if len(kids) != 1:
            return height, current
        current = kids[0]
        height += 1


def earliest_fork(graph: dict[str, Any]) -> dict[str, Any] | None:
    candidates = []
    for parent, kids in graph["children"].items():
        valid_kids = sorted(d for d in kids if graph["status"].get(d) == "valid")
        if len(valid_kids) < 2:
            continue
        fork_seq = int(graph["by_digest"][valid_kids[0]]["seq"])
        candidates.append({
            "fork_seq": fork_seq,
            "common_tip_digest": parent,
            "conflicting_digests": valid_kids,
        })
    return min(candidates, key=lambda f: (f["fork_seq"], f["common_tip_digest"]), default=None)


# --------------------------------------------------------------------- votes
def revocation_applies(rev: dict[str, Any], segment: int) -> bool:
    effective = rev.get("effective_segment", rev.get("at_segment"))
    if effective is None:
        return True
    if segment >= int(effective):
        return True
    return bool(rev.get("retroactive", False))


def evaluate_votes(
    bundle: dict[str, Any],
    keyring: TrustedKeyring,
    graph: dict[str, Any],
    receipts: list[dict[str, Any]] | None = None,
) -> dict[tuple[int, str], dict[str, Any]]:
    receipts = bundle["receipts"] if receipts is None else receipts
    revocations = bundle.get("revocations", [])
    revoked_receipt_ids = {r["target"] for r in revocations if r.get("kind") == "receipt"}
    quarantined_receipt_ids = set(bundle.get("quarantined_receipt_ids", []))
    controller_revs = [r for r in revocations if r.get("kind") == "controller"]
    identity_revs = [r for r in revocations if r.get("kind") == "identity"]

    eligible: list[dict[str, Any]] = []
    for receipt in receipts:
        kid = receipt["identity_id"]
        controller = keyring.controller_of(kid)
        target = graph["by_digest"].get(receipt["record_digest"])
        ok = (
            keyring.verify_mac(receipt)
            and keyring.epoch_allows(kid, bundle["partition"], int(receipt["segment"]))
            and receipt["receipt_id"] not in revoked_receipt_ids
            and receipt["receipt_id"] not in quarantined_receipt_ids
            and controller is not None
            and target is not None
            and graph["status"].get(receipt["record_digest"]) == "valid"
            and int(target["seq"]) == int(receipt["seq"])
            and int(target["segment"]) == int(receipt["segment"])
        )
        if ok:
            for rev in identity_revs:
                if rev.get("target") == kid and revocation_applies(rev, int(receipt["segment"])):
                    ok = False
                    break
        if ok and controller is not None:
            for rev in controller_revs:
                if rev.get("target") == controller and revocation_applies(rev, int(receipt["segment"])):
                    ok = False
                    break
        if ok:
            eligible.append({
                "receipt_id": receipt["receipt_id"],
                "identity_id": kid,
                "controller_id": controller,
                "seq": int(receipt["seq"]),
                "digest": receipt["record_digest"],
            })

    positions: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for vote in eligible:
        positions[vote["seq"]][vote["controller_id"]].add(vote["digest"])
    equivocal = {
        (seq, controller)
        for seq, controllers in positions.items()
        for controller, digests in controllers.items()
        if len(digests) > 1
    }

    grouped: dict[tuple[int, str], dict[str, Any]] = {}
    for vote in eligible:
        if (vote["seq"], vote["controller_id"]) in equivocal:
            continue
        bucket = grouped.setdefault((vote["seq"], vote["digest"]), {
            "seq": vote["seq"], "digest": vote["digest"], "controllers": set(),
            "receipt_ids": [],
        })
        bucket["controllers"].add(vote["controller_id"])
        bucket["receipt_ids"].append(vote["receipt_id"])
    for bucket in grouped.values():
        bucket["independent_votes"] = len(bucket["controllers"])
        bucket["certified"] = bucket["independent_votes"] >= int(
            bundle["required_independent_controllers"]
        )
    return grouped


def tombstoned(graph: dict[str, Any], bundle: dict[str, Any]) -> dict[str, bool]:
    tombstones = {r["target"] for r in bundle.get("revocations", []) if r.get("kind") == "branch"}
    tainted: dict[str, bool] = {}
    for digest in sorted(graph["by_digest"], key=lambda d: (int(graph["by_digest"][d]["seq"]), d)):
        record = graph["by_digest"][digest]
        tainted[digest] = digest in tombstones or bool(tainted.get(record["prev"], False))
    return tainted


# --------------------------------------------------------------------- verify
def verify(evidence_path: Path, keyring_path: Path) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    bundle = json.loads(evidence_path.read_text(encoding="utf-8"))
    keyring_data = json.loads(keyring_path.read_text(encoding="utf-8"))
    keyring = TrustedKeyring(keyring_data)
    summary: dict[str, Any] = {"checks": []}

    def check(name: str, condition: bool, detail: str = "") -> None:
        summary["checks"].append({"name": name, "ok": bool(condition), "detail": detail})
        if not condition:
            errors.append(f"{name}: {detail or 'failed'}")

    check("format", bundle.get("format") == REQUIRED_FORMAT, str(bundle.get("format")))
    unsigned = {k: v for k, v in bundle.items() if k != "bundle_digest"}
    check(
        "bundle-digest",
        domain_digest("evidence-bundle-v1", unsigned) == bundle.get("bundle_digest"),
        "evidence bundle digest does not match",
    )
    check(
        "witness-registry-matches-keyring",
        canonical_bytes(bundle.get("witness_registry")) == canonical_bytes(keyring.public_data()),
        "evidence controller/epoch registry differs from trusted keyring",
    )

    segment_size = int(bundle["segment_size"])
    graph = build_graph(bundle.get("records", []), segment_size)
    check("all-record-hashes", all(
        record_digest(r) == r.get("digest") for r in bundle.get("records", [])
    ))

    claim = bundle["claim"]
    needed: set[str] = set()
    if claim.get("committed_digest"):
        check("committed-target-present", claim["committed_digest"] in graph["by_digest"])
        needed |= ancestor_closure(graph, claim["committed_digest"])
    elif claim.get("common_prefix_digest") != ZERO_DIGEST:
        needed |= ancestor_closure(graph, claim["common_prefix_digest"])

    claimed_fork = claim.get("earliest_provable_fork")
    if claimed_fork:
        for digest in claimed_fork["conflicting_digests"]:
            check(f"fork-child-present:{digest[:12]}", digest in graph["by_digest"])
            needed |= ancestor_closure(graph, digest)

    for isolation in claim.get("isolated_branch_checks", []):
        target = isolation["tip_digest"]
        check(f"isolation-target-present:{target[:12]}", target in graph["by_digest"])
        needed |= ancestor_closure(graph, target)

    for replay in claim.get("replay_non_revival_checks", []):
        target = replay["candidate_digest"]
        check(f"replay-target-present:{target[:12]}", target in graph["by_digest"])
        needed |= ancestor_closure(graph, target)

    actual_records = set(graph["by_digest"])
    manifest_required = set(bundle.get("minimality_manifest", {}).get("required_record_digests", []))
    check("minimal-record-closure", actual_records == needed == manifest_required,
          f"actual={len(actual_records)} closure={len(needed)} manifest={len(manifest_required)}")
    check(
        "minimal-receipt-manifest",
        int(bundle.get("minimality_manifest", {}).get("receipt_count", -1)) == len(bundle.get("receipts", [])),
    )
    check(
        "minimal-revocation-manifest",
        int(bundle.get("minimality_manifest", {}).get("revocation_count", -1)) == len(bundle.get("revocations", [])),
    )

    computed_fork = earliest_fork(graph)
    if claimed_fork is None:
        check("earliest-fork-absent", computed_fork is None)
    elif computed_fork is None:
        check("earliest-fork-present", False, "claimed fork cannot be reconstructed")
    else:
        check("earliest-fork-seq", computed_fork["fork_seq"] == claimed_fork["fork_seq"],
              f"{computed_fork['fork_seq']} != {claimed_fork['fork_seq']}")
        check("earliest-fork-digests",
              computed_fork["conflicting_digests"] == claimed_fork["conflicting_digests"])
        check("earliest-fork-common",
              computed_fork["common_tip_digest"] == claimed_fork["common_tip_digest"])

    prefix_height, prefix_digest = unique_prefix(graph)
    check("common-prefix-height", prefix_height == claim["common_prefix_height"],
          f"{prefix_height} != {claim['common_prefix_height']}")
    check("common-prefix-digest", prefix_digest == claim["common_prefix_digest"])

    votes = evaluate_votes(bundle, keyring, graph)
    tainted = tombstoned(graph, bundle)
    prefix_digests = set()
    current = prefix_digest
    while current != ZERO_DIGEST and current in graph["by_digest"]:
        prefix_digests.add(current)
        current = graph["by_digest"][current]["prev"]

    committable = [
        bucket for (seq, digest), bucket in votes.items()
        if bucket["certified"] and digest in prefix_digests and not tainted.get(digest, False)
    ]
    computed_watermark = max((b["seq"] for b in committable), default=None)
    computed_digest = None
    if computed_watermark is not None:
        computed_digest = next(iter(b["digest"] for b in committable if b["seq"] == computed_watermark))
    check("max-committable-watermark",
          computed_watermark == claim["max_committable_watermark"],
          f"{computed_watermark} != {claim['max_committable_watermark']}")
    check("committed-digest", computed_digest == claim.get("committed_digest"),
          f"{computed_digest} != {claim.get('committed_digest')}")

    committable_digests = {bucket["digest"] for bucket in committable}
    for isolation in claim.get("isolated_branch_checks", []):
        target = isolation["tip_digest"]
        check(
            f"claimed-isolated-branch-not-committable:{target[:12]}",
            target not in committable_digests,
            "an allegedly isolated branch reached quorum on the unique prefix",
        )

    # Explicit replay simulation: duplicate every named old receipt and rerun.
    for replay in claim.get("replay_non_revival_checks", []):
        target = replay["candidate_digest"]
        rev_id = replay["branch_revocation_id"]
        matching_rev = [r for r in bundle["revocations"]
                        if r.get("revocation_id") == rev_id and r.get("kind") == "branch"
                        and r.get("target") == target]
        check(f"branch-revocation-present:{rev_id}", bool(matching_rev))
        check(f"branch-tombstoned:{target[:12]}", tainted.get(target, target in {
            r['target'] for r in bundle['revocations'] if r.get('kind') == 'branch'
        }))
        old = [r for r in bundle["receipts"] if r["receipt_id"] in replay["replayed_receipt_ids"]]
        check(f"all-replay-receipts-present:{rev_id}",
              {r["receipt_id"] for r in old} == set(replay["replayed_receipt_ids"]))
        replayed = list(bundle["receipts"]) + [dict(r) for r in old]
        replayed_votes = evaluate_votes(bundle, keyring, graph, receipts=replayed)
        candidate_committable = any(
            digest == target and bucket.get("certified")
            and digest in prefix_digests and not tainted.get(digest, False)
            for (seq, digest), bucket in replayed_votes.items()
        )
        check(f"replay-does-not-revive:{target[:12]}", not candidate_committable)

    summary["computed"] = {
        "common_prefix_height": prefix_height,
        "earliest_provable_fork": computed_fork,
        "max_committable_watermark": computed_watermark,
        "committed_digest": computed_digest,
        "record_count": len(bundle.get("records", [])),
        "receipt_count": len(bundle.get("receipts", [])),
    }
    return not errors, errors, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="path to evidence.json")
    parser.add_argument("--keyring", type=Path, required=True, help="trusted-keyring.json")
    args = parser.parse_args(argv)

    ok, errors, summary = verify(args.evidence, args.keyring)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if ok:
        print("INDEPENDENT_EVIDENCE_VERIFICATION=PASS")
        return 0
    print("INDEPENDENT_EVIDENCE_VERIFICATION=FAIL", file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
