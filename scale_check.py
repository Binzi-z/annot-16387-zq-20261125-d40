#!/usr/bin/env python3
"""Sixty-thousand-record sparse segment revision check.

Run with:

    python scale_check.py

The script builds 60,000 hash-chained records in 60 segments, removes segments
17, 38 and 52 from the local store, fetches each from a simulated remote site,
and advances reconciliation incrementally.  It records every segment read and
compares the final sparse/incremental report with a from-scratch full replay.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_audit.engine import ReconciliationSession  # noqa: E402
from offline_audit.segments import CachingSegmentLoader  # noqa: E402
from offline_audit.synthetic import make_scale_world  # noqa: E402


def run_scale_check() -> dict[str, Any]:
    world = make_scale_world()
    partition = world["partition"]
    segment_size = world["segment_size"]
    missing = list(world["missing_segments"])
    store = world["local_store"]
    remote = world["remote"]

    session = ReconciliationSession(
        partition,
        segment_size,
        required_controllers=world["required_controllers"],
        keyring=world["keyring"],
    )
    # Receipts may all be present before their target segments arrive.
    for receipt in world["receipts"]:
        session.ingest_receipt(receipt)

    loader = CachingSegmentLoader(store, session.ingest_record, segment_size)
    stages: list[dict[str, Any]] = []

    def snapshot(label: str, supplied: int | None, newly: list[int]) -> None:
        report = session.report()
        stages.append({
            "stage": label,
            "supplied_segment": supplied,
            "newly_loaded_segments": newly,
            "newly_loaded_range": [newly[0], newly[-1]] if newly else [],
            "actual_accessed_segments": store.accessed_indices(),
            "access_counts": dict(sorted(store.access_counts.items())),
            "max_committable_watermark": report["max_committable_watermark"],
            "common_prefix_height": report["common_prefix_height"],
            "first_missing_segment": loader.first_missing_segment(),
        })

    initial = loader.advance()
    snapshot("initial-local-prefix", None, initial)
    expected_new = [list(range(0, missing[0]))]
    expected_watermarks = [missing[0] * segment_size - 1]

    for index, segment_index in enumerate(missing):
        segment = remote.fetch(segment_index)
        store.put(segment)
        newly = loader.advance()
        next_gap = missing[index + 1] if index + 1 < len(missing) else 60
        expected_new.append(list(range(segment_index, next_gap)))
        expected_watermarks.append(next_gap * segment_size - 1 if next_gap < 60 else 59_999)
        snapshot(f"after-supplying-segment-{segment_index}", segment_index, newly)

    for stage, expected_segments, expected_watermark in zip(stages, expected_new, expected_watermarks):
        actual_new = stage["newly_loaded_segments"]
        assert actual_new == expected_segments, (stage, expected_segments)
        assert stage["max_committable_watermark"] == expected_watermark, stage

    assert store.accessed_indices() == list(range(60))
    assert set(store.access_counts.values()) == {1}, "caching loader reread a segment"
    assert remote.requested_indices() == missing

    sparse_report = session.report()

    full_session = ReconciliationSession(
        partition,
        segment_size,
        required_controllers=world["required_controllers"],
        keyring=world["keyring"],
    )
    for record in world["records"]:
        full_session.ingest_record(record)
    for receipt in world["receipts"]:
        full_session.ingest_receipt(receipt)
    full_report = full_session.report()

    comparison_keys = [
        "partition",
        "segment_size",
        "common_prefix_height",
        "common_prefix_digest",
        "earliest_provable_fork",
        "sequence_conflicts",
        "max_certified_watermark",
        "max_committable_watermark",
        "committed_digest",
        "certified_nodes",
        "committable_candidates",
        "branches",
        "isolated_branches",
        "receipt_evaluations",
        "revocations",
        "stats",
    ]
    differences = {
        key: {"sparse": sparse_report[key], "full": full_report[key]}
        for key in comparison_keys
        if sparse_report[key] != full_report[key]
    }
    assert not differences, f"sparse and full reports differ: {sorted(differences)}"
    assert sparse_report["max_committable_watermark"] == 59_999
    assert sparse_report["common_prefix_height"] == 59_999
    assert sparse_report["earliest_provable_fork"] is None

    return {
        "record_count": len(world["records"]),
        "segment_count": len(world["segments"]),
        "missing_segments": missing,
        "remote_requested_segments": remote.requested_indices(),
        "actually_accessed_segments": store.accessed_indices(),
        "each_segment_accessed_once": set(store.access_counts.values()) == {1},
        "stage_count": len(stages),
        "stages": stages,
        "full_result_matches_sparse_revision": not differences,
        "max_committable_watermark": sparse_report["max_committable_watermark"],
        "committed_digest": sparse_report["committed_digest"],
    }


def main() -> int:
    result = run_scale_check()
    compact = {k: v for k, v in result.items() if k != "stages"}
    compact["stage_watermarks"] = [
        {
            "stage": stage["stage"],
            "newly_loaded_range": stage["newly_loaded_range"],
            "watermark": stage["max_committable_watermark"],
        }
        for stage in result["stages"]
    ]
    print(json.dumps(compact, indent=2, ensure_ascii=False))
    print("SCALE_SPARSE_REVISION_CHECK=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
