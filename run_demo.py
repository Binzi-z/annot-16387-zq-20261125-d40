#!/usr/bin/env python3
"""Run the small three-site divergence demo and export minimal evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_audit.engine import ReconciliationSession  # noqa: E402
from offline_audit.evidence import write_evidence_set  # noqa: E402
from offline_audit.synthetic import make_small_world  # noqa: E402


def main() -> int:
    world = make_small_world()
    session = ReconciliationSession(
        world["partition"], world["segment_size"], keyring=world["keyring"]
    )
    for record in world["records"]:
        session.ingest_record(record)
    for receipt in world["receipts"]:
        session.ingest_receipt(receipt)

    # Adversarial/order-tolerant case: revoke the third witness and the branch
    # it supported, then replay its old receipt.
    a_tip = world["branch_a"][-1]["digest"]
    session.revoke_witness("watch", "revoke-watch", reason="synthetic key compromise")
    session.revoke_branch(a_tip, "revoke-branch-a", reason="witness support revoked")
    old_watch_receipt = next(r for r in world["receipts"] if r["identity_id"] == "watch-key")
    session.ingest_receipt(dict(old_watch_receipt))

    report = session.report()
    out_dir = ROOT / "artifacts" / "demo-evidence"
    paths = write_evidence_set(session, out_dir)

    summary = {
        "partition": report["partition"],
        "earliest_provable_fork": report["earliest_provable_fork"],
        "max_committable_watermark": report["max_committable_watermark"],
        "committed_digest": report["committed_digest"],
        "isolated_branches": [
            {
                "seq": branch["seq"],
                "tip_digest": branch["tip_digest"],
                "independent_votes": branch["independent_votes"],
                "reasons": branch["reasons"],
            }
            for branch in report["isolated_branches"]
        ],
        "evidence_files": {name: str(path) for name, path in paths.items()},
        "verify_command": (
            f'python verify_evidence.py "{paths["evidence"]}" '
            f'--keyring "{paths["keyring"]}"'
        ),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
