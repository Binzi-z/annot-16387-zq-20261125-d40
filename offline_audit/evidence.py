from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import ZERO_DIGEST, canonical_bytes, domain_digest
from .engine import ReconciliationSession


def _closure(graph: dict[str, Any], target_digest: str) -> set[str]:
    """Return target and every available hash-chain ancestor."""

    by_digest = graph["by_digest"]
    result: set[str] = set()
    current = target_digest
    while current != ZERO_DIGEST:
        if current in result:
            break
        record = by_digest.get(current)
        if record is None:
            break
        result.add(current)
        current = record["prev"]
    return result


def build_evidence_bundle(session: ReconciliationSession) -> dict[str, Any]:
    """Prune a session to the minimum replayable proof for its report.

    The bundle deliberately contains no HMAC secrets.  Those live in the
    out-of-band trusted keyring written by :func:`write_evidence_set`.  An
    independent verifier takes both files.
    """

    report = session.report()
    graph = session.evaluate_graph()
    by_digest = graph["by_digest"]

    needed: set[str] = set()

    # Positive proof for the maximum committable watermark.  If no quorum
    # exists, include the unique prefix tip so the verifier can see the limit.
    committed_digest = report["committed_digest"]
    if committed_digest:
        needed |= _closure(graph, committed_digest)
    elif report["common_prefix_digest"] != ZERO_DIGEST and report["common_prefix_height"] >= 0:
        needed |= _closure(graph, report["common_prefix_digest"])

    fork = report["earliest_provable_fork"]
    fork_proof: dict[str, Any] | None = None
    if fork is not None:
        needed.add(fork["common_tip_digest"]) if fork["common_tip_digest"] != ZERO_DIGEST else None
        for digest in fork["conflicting_digests"]:
            needed |= _closure(graph, digest)
        fork_proof = {
            "fork_seq": fork["fork_seq"],
            "common_tip_digest": fork["common_tip_digest"],
            "conflicting_digests": list(fork["conflicting_digests"]),
        }

    # Include every reported tip.  This lets the independent verifier check
    # that branches marked isolated cannot secretly reach committable quorum.
    isolation_checks: list[dict[str, Any]] = []
    for branch in report["branches"]:
        needed |= _closure(graph, branch["tip_digest"])
        if branch["isolated"]:
            isolation_checks.append(
                {
                    "tip_digest": branch["tip_digest"],
                    "seq": branch["seq"],
                    "must_remain_isolated": True,
                    "independent_votes": branch["independent_votes"],
                    "reasons": branch["reasons"],
                }
            )

    # Permanent branch tombstones and their chain closures prove that replayed
    # old receipts cannot restore a revoked candidate.
    replay_checks: list[dict[str, Any]] = []
    for rev in session.active_revocations():
        if rev.get("kind") != "branch":
            continue
        target = rev["target"]
        needed |= _closure(graph, target)
        old_receipt_ids = [
            receipt["receipt_id"]
            for receipt in session.receipts
            if receipt.get("record_digest") == target
        ]
        replay_checks.append(
            {
                "candidate_digest": target,
                "branch_revocation_id": rev["revocation_id"],
                "replayed_receipt_ids": old_receipt_ids,
                "must_remain_isolated": True,
            }
        )

    records = [by_digest[d] for d in sorted(needed, key=lambda x: (int(by_digest[x]["seq"]), x))]

    # Include receipts touching any proof record, plus receipts explicitly
    # revoked by ID.  This retains duplicate controller identities so an
    # independent verifier can see that they collapse to one vote.
    revoked_receipt_ids = {r["target"] for r in session.revocations if r.get("kind") == "receipt"}
    receipts = [
        receipt
        for receipt in sorted(session.receipts, key=lambda r: r["receipt_id"])
        if receipt.get("record_digest") in needed or receipt["receipt_id"] in revoked_receipt_ids
    ]
    included_receipt_ids = {r["receipt_id"] for r in receipts}

    relevant_revocations = []
    receipt_identities = {r["identity_id"] for r in receipts}
    receipt_controllers = {
        session.keyring.controller_of(kid) for kid in receipt_identities
    }
    for rev in sorted(session.active_revocations(), key=lambda r: r["revocation_id"]):
        kind = rev.get("kind")
        target = rev.get("target")
        if kind == "branch" and target in needed:
            relevant_revocations.append(rev)
        elif kind == "receipt" and target in included_receipt_ids:
            relevant_revocations.append(rev)
        elif kind == "identity" and target in receipt_identities:
            relevant_revocations.append(rev)
        elif kind == "controller" and target in receipt_controllers:
            relevant_revocations.append(rev)

    commit_proof = None
    for candidate in report["committable_candidates"]:
        if candidate["seq"] == report["max_committable_watermark"]:
            commit_proof = {
                "watermark_seq": candidate["seq"],
                "digest": candidate["record_digest"],
                "controllers": candidate["controllers"],
                "identities": candidate["identities"],
                "receipt_ids": candidate["receipt_ids"],
            }
            break

    keyring_public = session.keyring.public_data()
    bundle = {
        "format": "offline-audit-minimal-evidence/v1",
        "canonical_format": "offline-audit-canonical-json/v1",
        "partition": session.partition,
        "segment_size": session.segment_size,
        "required_independent_controllers": session.required_controllers,
        "witness_registry": keyring_public,
        "records": records,
        "receipts": receipts,
        "revocations": relevant_revocations,
        "quarantined_receipt_ids": sorted(session.quarantined_receipt_ids),
        "quarantined_revocation_ids": sorted(session.quarantined_revocation_ids),
        "claim": {
            "common_prefix_height": report["common_prefix_height"],
            "common_prefix_digest": report["common_prefix_digest"],
            "earliest_provable_fork": fork_proof,
            "max_committable_watermark": report["max_committable_watermark"],
            "committed_digest": report["committed_digest"],
            "max_certified_watermark": report["max_certified_watermark"],
            "isolated_branch_checks": isolation_checks,
            "replay_non_revival_checks": replay_checks,
        },
        "minimality_manifest": {
            "record_count": len(records),
            "receipt_count": len(receipts),
            "revocation_count": len(relevant_revocations),
            "required_record_digests": sorted(needed),
            "commit_receipt_ids": [] if commit_proof is None else commit_proof["receipt_ids"],
            "note": (
                "Every record must belong to the ancestor closure of the "
                "committed tip, a fork child, or a revoked replay target."
            ),
        },
    }
    bundle["bundle_digest"] = domain_digest("evidence-bundle-v1", _unsigned_bundle(bundle))
    return bundle


def _unsigned_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in bundle.items() if k != "bundle_digest"}


def write_evidence_set(
    session: ReconciliationSession,
    directory: str | Path,
    *,
    keyring_name: str = "trusted-keyring.json",
) -> dict[str, Path]:
    """Write evidence plus the out-of-band trusted HMAC keyring."""

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    evidence_path = directory / "evidence.json"
    keyring_path = directory / keyring_name
    bundle = build_evidence_bundle(session)
    evidence_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    keyring_path.write_text(
        json.dumps(session.keyring.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return {"evidence": evidence_path, "keyring": keyring_path}


def bundle_canonical_bytes(bundle: dict[str, Any]) -> bytes:
    return canonical_bytes(_unsigned_bundle(bundle))
