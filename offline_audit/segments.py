from __future__ import annotations

from collections import Counter
from typing import Any, Callable

from .canonical import domain_digest


class MissingSegment(KeyError):
    def __init__(self, partition: str, index: int):
        super().__init__(f"missing segment {partition}#{index}")
        self.partition = partition
        self.index = index


def build_segment(partition: str, index: int, records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("a segment must contain at least one record")
    seqs = [int(r["seq"]) for r in records]
    expected_segment = index
    for record in records:
        if int(record["segment"]) != expected_segment:
            raise ValueError("record assigned to wrong segment")
    if seqs != list(range(seqs[0], seqs[0] + len(seqs))):
        raise ValueError("segment records must be consecutive")

    record_digests = [r["digest"] for r in records]
    header = {
        "v": 1,
        "partition": partition,
        "index": index,
        "start_seq": seqs[0],
        "end_seq": seqs[-1],
        "record_digests": record_digests,
    }
    segment_digest = domain_digest("audit-segment-v1", header)
    return {**header, "segment_digest": segment_digest, "records": records}


class SegmentStore:
    """In-memory segment store with actual read-access accounting."""

    def __init__(self, partition: str):
        self.partition = partition
        self.segments: dict[int, dict[str, Any]] = {}
        self.access_counts: Counter[int] = Counter()

    def put(self, segment: dict[str, Any]) -> None:
        if segment["partition"] != self.partition:
            raise ValueError("wrong segment partition")
        self.segments[int(segment["index"])] = segment

    def has(self, index: int) -> bool:
        return int(index) in self.segments

    def get(self, index: int) -> dict[str, Any]:
        index = int(index)
        if index not in self.segments:
            raise MissingSegment(self.partition, index)
        self.access_counts[index] += 1
        return self.segments[index]

    def available_indices(self) -> list[int]:
        return sorted(self.segments)

    def accessed_indices(self) -> list[int]:
        return sorted(self.access_counts)


class RemoteSegmentSource:
    """Simulates one or more remote sites, each with selected segments."""

    def __init__(self, sites: dict[str, dict[int, dict[str, Any]]] | None = None):
        self.sites = sites or {}
        self.requested: list[tuple[str | None, int]] = []

    def add_site_segment(self, site: str, segment: dict[str, Any]) -> None:
        self.sites.setdefault(site, {})[int(segment["index"])] = segment

    def fetch(self, index: int, site: str | None = None) -> dict[str, Any]:
        index = int(index)
        candidates = [site] if site is not None else list(self.sites)
        for candidate in candidates:
            if candidate is None:
                continue
            segment = self.sites.get(candidate, {}).get(index)
            if segment is not None:
                self.requested.append((candidate, index))
                return segment
        raise MissingSegment("remote", index)

    def requested_indices(self) -> list[int]:
        return sorted({index for _, index in self.requested})


class CachingSegmentLoader:
    """Load a hash-chained ledger prefix while reading each segment once.

    The loader feeds records into a callback (usually
    ``ReconciliationSession.ingest_record``).  It starts at segment zero and
    stops at the first absent segment.  When that segment is later supplied,
    :meth:`advance` continues from the cached frontier without rereading old
    segments.
    """

    def __init__(
        self,
        store: SegmentStore,
        ingest_record: Callable[[dict[str, Any]], Any],
        segment_size: int,
    ):
        self.store = store
        self.ingest_record = ingest_record
        self.segment_size = int(segment_size)
        self.next_segment = 0
        self.loaded_segments: list[int] = []

    def advance(self) -> list[int]:
        newly_loaded: list[int] = []
        while self.store.has(self.next_segment):
            segment = self.store.get(self.next_segment)
            for record in segment["records"]:
                self.ingest_record(record)
            newly_loaded.append(self.next_segment)
            self.loaded_segments.append(self.next_segment)
            self.next_segment += 1
        return newly_loaded

    def first_missing_segment(self) -> int:
        return self.next_segment
