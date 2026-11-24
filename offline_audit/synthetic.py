from __future__ import annotations

from typing import Any

from .canonical import ZERO_DIGEST, record_digest
from .segments import RemoteSegmentSource, SegmentStore, build_segment
from .witnesses import HmacKeyring, sign_receipt


def build_linear_records(
    partition: str,
    count: int,
    segment_size: int,
    *,
    start_seq: int = 0,
    prev: str | None = None,
    label: str = "record",
    site: str = "synthetic",
) -> list[dict[str, Any]]:
    """Build ``count`` consecutive hash-chained records.

    With the default ``start_seq=0`` and ``prev=None`` this creates a genesis
    whose previous digest is the all-zero anchor.
    """

    if count < 0:
        raise ValueError("count must be non-negative")
    if prev is None:
        if start_seq != 0:
            raise ValueError("prev is required when start_seq != 0")
        prev = ZERO_DIGEST

    records: list[dict[str, Any]] = []
    previous = prev
    for offset in range(count):
        seq = start_seq + offset
        record = {
            "v": 1,
            "partition": partition,
            "seq": seq,
            "segment": seq // segment_size,
            "prev": previous,
            "payload": {"label": label, "site": site, "offset": offset, "seq": seq},
        }
        digest = record_digest(record)
        record["digest"] = digest
        records.append(record)
        previous = digest
    return records


def records_to_segments(
    partition: str, records: list[dict[str, Any]], segment_size: int
) -> dict[int, dict[str, Any]]:
    chunks: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        chunks.setdefault(int(record["seq"]) // segment_size, []).append(record)
    return {index: build_segment(partition, index, chunk) for index, chunk in sorted(chunks.items())}


def make_small_world(sign: bool = True) -> dict[str, Any]:
    """A compact three-site divergence with interleaved witness rotations."""

    partition = "audit-small"
    segment_size = 2
    common = build_linear_records(partition, 4, segment_size, label="common")
    fork_seq = 4
    branch_a = build_linear_records(
        partition,
        2,
        segment_size,
        start_seq=fork_seq,
        prev=common[fork_seq - 1]["digest"],
        label="branch-a",
        site="site-1",
    )
    branch_b = build_linear_records(
        partition,
        2,
        segment_size,
        start_seq=fork_seq,
        prev=common[fork_seq - 1]["digest"],
        label="branch-b-different-payload",
        site="site-2",
    )
    # A third site carries branch A, giving the three disconnected sites.
    records = common + branch_a + branch_b

    keyring = HmacKeyring.synthetic(
        {
            "north": [
                ("north-old", [{"partition": "*", "first_segment": 0, "last_segment": 0}]),
                ("north-new", [{"partition": "*", "first_segment": 1, "last_segment": None}]),
                # Rollover overlap/alias for the same upstream controller.
                ("north-alias", [{"partition": "*", "first_segment": 1, "last_segment": 1}]),
            ],
            "south": [
                ("south-old", [{"partition": "*", "first_segment": 0, "last_segment": 1}]),
                ("south-new", [{"partition": "*", "first_segment": 2, "last_segment": None}]),
            ],
            "watch": [
                ("watch-key", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
            ],
        }
    )

    receipts: list[dict[str, Any]] = []
    if sign:
        tip = common[3]
        for receipt_id, kid in [
            ("rcpt-north-new-common", "north-new"),
            ("rcpt-north-alias-common", "north-alias"),
            ("rcpt-south-old-common", "south-old"),
        ]:
            receipts.append(
                sign_receipt(
                    keyring,
                    receipt_id=receipt_id,
                    partition=partition,
                    seq=tip["seq"],
                    segment=tip["segment"],
                    record_digest=tip["digest"],
                    identity_id=kid,
                )
            )

        a_tip = branch_a[-1]
        for receipt_id, kid in [
            ("rcpt-south-new-a", "south-new"),
            ("rcpt-watch-a", "watch-key"),
        ]:
            receipts.append(
                sign_receipt(
                    keyring,
                    receipt_id=receipt_id,
                    partition=partition,
                    seq=a_tip["seq"],
                    segment=a_tip["segment"],
                    record_digest=a_tip["digest"],
                    identity_id=kid,
                )
            )

    common_segments = records_to_segments(partition, common, segment_size)
    branch_segments = {
        "a": records_to_segments(partition, branch_a, segment_size),
        "b": records_to_segments(partition, branch_b, segment_size),
    }
    return {
        "format": "synthetic-small-world/v1",
        "partition": partition,
        "segment_size": segment_size,
        "required_controllers": 2,
        "keyring": keyring,
        "records": records,
        "receipts": receipts,
        "revocations": [],
        "common_segments": common_segments,
        "branch_segments": branch_segments,
        "site_ledgers": {
            "site-1": [r["digest"] for r in common + branch_a],
            "site-2": [r["digest"] for r in common + branch_b],
            "site-3": [r["digest"] for r in common + branch_a],
        },
        "common": common,
        "branch_a": branch_a,
        "branch_b": branch_b,
    }


def _scale_identity_for_segment(keyring: HmacKeyring, controller: str, segment: int) -> str:
    for kid, item in keyring.data["identities"].items():
        if item["controller"] != controller:
            continue
        for epoch in item["epochs"]:
            first = int(epoch.get("first_segment", 0))
            last = epoch.get("last_segment")
            if first <= segment and (last is None or segment <= int(last)):
                return kid
    raise KeyError(f"no identity for controller {controller} segment {segment}")


def make_scale_world(
    n: int = 60_000,
    segment_size: int = 1000,
    missing_segments: tuple[int, ...] = (17, 38, 52),
) -> dict[str, Any]:
    """Create the 60k-record sparse-revision benchmark world."""

    partition = "audit-scale-60k"
    records = build_linear_records(partition, n, segment_size, label="scale")
    segments = records_to_segments(partition, records, segment_size)

    keyring = HmacKeyring.synthetic(
        {
            "controller-a": [
                ("a-gen1", [{"partition": "*", "first_segment": 0, "last_segment": 19}]),
                ("a-gen2", [{"partition": "*", "first_segment": 20, "last_segment": 44}]),
                ("a-gen3", [{"partition": "*", "first_segment": 45, "last_segment": None}]),
            ],
            "controller-b": [
                ("b-gen1", [{"partition": "*", "first_segment": 0, "last_segment": 29}]),
                ("b-gen2", [{"partition": "*", "first_segment": 30, "last_segment": None}]),
            ],
        },
        seed="scale-world",
    )

    boundaries = sorted(
        set(
            [min(n - 1, (m * segment_size) - 1) for m in missing_segments]
            + [n - 1]
        )
    )
    receipts = []
    for seq in boundaries:
        record = records[seq]
        segment = seq // segment_size
        for controller, prefix in [("controller-a", "a"), ("controller-b", "b")]:
            kid = _scale_identity_for_segment(keyring, controller, segment)
            receipts.append(
                sign_receipt(
                    keyring,
                    receipt_id=f"rcpt-{prefix}-{seq}",
                    partition=partition,
                    seq=seq,
                    segment=segment,
                    record_digest=record["digest"],
                    identity_id=kid,
                )
            )

    missing = tuple(sorted(missing_segments))
    local_store = SegmentStore(partition)
    remote = RemoteSegmentSource()
    remote_sites: dict[str, int] = {}
    for index, segment in segments.items():
        if index in missing:
            site = f"remote-site-for-segment-{index}"
            remote.add_site_segment(site, segment)
            remote_sites[site] = index
        else:
            local_store.put(segment)

    return {
        "format": "synthetic-scale-world/v1",
        "partition": partition,
        "segment_size": segment_size,
        "required_controllers": 2,
        "keyring": keyring,
        "records": records,
        "receipts": receipts,
        "revocations": [],
        "segments": segments,
        "missing_segments": missing,
        "boundaries": boundaries,
        "local_store": local_store,
        "remote": remote,
        "remote_sites": remote_sites,
    }
