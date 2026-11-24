from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from .canonical import ZERO_DIGEST, canonical_bytes, record_digest
from .witnesses import HmacKeyring


def coerce_keyring(keyring: HmacKeyring | dict[str, Any] | None) -> HmacKeyring:
    if keyring is None:
        return HmacKeyring({})
    if isinstance(keyring, HmacKeyring):
        return keyring
    if isinstance(keyring, dict):
        return HmacKeyring(keyring)
    raise TypeError("keyring must be HmacKeyring, dict, or None")


class ReconciliationSession:
    """Order-tolerant offline reconciliation state for one audit partition."""

    def __init__(
        self,
        partition: str,
        segment_size: int = 1000,
        required_controllers: int = 2,
        keyring: HmacKeyring | dict[str, Any] | None = None,
    ):
        self.partition = partition
        self.segment_size = int(segment_size)
        self.required_controllers = int(required_controllers)
        self.keyring = coerce_keyring(keyring)

        self.records: list[dict[str, Any]] = []
        self.receipts: list[dict[str, Any]] = []
        self.revocations: list[dict[str, Any]] = []

        self._record_by_digest: dict[str, dict[str, Any]] = {}
        self._receipt_by_id: dict[str, dict[str, Any]] = {}
        self._revocation_by_id: dict[str, dict[str, Any]] = {}
        self.duplicate_records = 0
        self.replayed_receipts = 0
        self.duplicate_revocations = 0
        self.digest_aliases: list[dict[str, Any]] = []
        self.receipt_id_conflicts: list[dict[str, Any]] = []
        self.revocation_id_conflicts: list[dict[str, Any]] = []
        self.quarantined_receipt_ids: set[str] = set()
        self.quarantined_revocation_ids: set[str] = set()

    # ------------------------------------------------------------------ input
    def ingest(self, event: dict[str, Any]) -> "ReconciliationSession":
        kind = event.get("kind") or event.get("type")
        if kind == "record":
            self.ingest_record(event["record"] if "record" in event else event)
        elif kind == "receipt":
            self.ingest_receipt(event["receipt"] if "receipt" in event else event)
        elif kind == "revocation":
            rev = event["revocation"] if "revocation" in event else event
            self.ingest_revocation(rev)
        else:
            raise ValueError(f"unknown event kind: {kind!r}")
        return self

    def ingest_many(self, events: Iterable[dict[str, Any]]) -> "ReconciliationSession":
        for event in events:
            self.ingest(event)
        return self

    def ingest_record(self, record: dict[str, Any]) -> bool:
        if record.get("partition") != self.partition:
            raise ValueError(
                f"record partition {record.get('partition')!r} != session {self.partition!r}"
            )
        claimed = record.get("digest")
        actual = record_digest(record)
        if claimed is not None and claimed != actual:
            # Keep the malformed record for reporting, but do not index it as a
            # valid ledger node.  A fresh object avoids caller mutation aliases.
            bad = dict(record)
            bad["digest"] = claimed
            bad["_actual_digest"] = actual
            self.records.append(bad)
            self.digest_aliases.append(
                {"claimed_digest": claimed, "actual_digest": actual, "seq": record.get("seq")}
            )
            return False

        clean = dict(record)
        clean["digest"] = actual
        existing = self._record_by_digest.get(actual)
        if existing is not None:
            if record_digest(existing) != actual:
                self.digest_aliases.append({"digest": actual, "seq": record.get("seq")})
            self.duplicate_records += 1
            return False

        self._record_by_digest[actual] = clean
        self.records.append(clean)
        return True

    def ingest_receipt(self, receipt: dict[str, Any]) -> bool:
        receipt_id = receipt["receipt_id"]
        existing = self._receipt_by_id.get(receipt_id)
        if existing is not None:
            if _receipt_identity(existing) != _receipt_identity(receipt) or existing.get("mac") != receipt.get("mac"):
                if receipt_id not in self.quarantined_receipt_ids:
                    self.quarantined_receipt_ids.add(receipt_id)
                    self.receipt_id_conflicts.append(
                        {
                            "receipt_id": receipt_id,
                            "reason": "same-receipt-id-with-different-body",
                        }
                    )
            else:
                self.replayed_receipts += 1
            return False

        clean = dict(receipt)
        self._receipt_by_id[receipt_id] = clean
        self.receipts.append(clean)
        return True

    def ingest_revocation(self, revocation: dict[str, Any]) -> bool:
        revocation_id = revocation["revocation_id"]
        existing = self._revocation_by_id.get(revocation_id)
        if existing is not None:
            if existing != revocation:
                if revocation_id not in self.quarantined_revocation_ids:
                    self.quarantined_revocation_ids.add(revocation_id)
                    self.revocation_id_conflicts.append(
                        {
                            "revocation_id": revocation_id,
                            "reason": "same-revocation-id-with-different-body",
                        }
                    )
            else:
                self.duplicate_revocations += 1
            return False
        clean = dict(revocation)
        self._revocation_by_id[revocation_id] = clean
        self.revocations.append(clean)
        return True

    def revoke_witness(
        self,
        target: str,
        revocation_id: str,
        *,
        kind: str | None = None,
        reason: str = "known witness revoked",
        effective_segment: int | None = None,
        retroactive: bool | None = None,
    ) -> dict[str, Any]:
        if kind is None:
            kind = "controller" if target in self.keyring.data.get("controllers", {}) else "identity"
        rev: dict[str, Any] = {
            "revocation_id": revocation_id,
            "kind": kind,
            "target": target,
            "reason": reason,
        }
        if effective_segment is not None:
            rev["effective_segment"] = effective_segment
        if retroactive is not None:
            rev["retroactive"] = retroactive
        self.ingest_revocation(rev)
        return rev

    def revoke_branch(self, target_digest: str, revocation_id: str, reason: str) -> dict[str, Any]:
        rev = {
            "revocation_id": revocation_id,
            "kind": "branch",
            "target": target_digest,
            "reason": reason,
        }
        self.ingest_revocation(rev)
        return rev

    # ------------------------------------------------------------- evaluation
    def evaluate_graph(self) -> dict[str, Any]:
        valid_records = [r for r in self.records if "_actual_digest" not in r]
        by_digest = {r["digest"]: r for r in valid_records}
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
            expected_segment = seq // self.segment_size
            if int(record.get("segment", expected_segment)) != expected_segment:
                status[digest] = "invalid"
                reasons[digest] = "segment-index-mismatch"
                continue
            if record_digest(record) != digest:
                status[digest] = "invalid"
                reasons[digest] = "digest-mismatch"
                continue
            if seq == 0:
                if record["prev"] != ZERO_DIGEST:
                    status[digest] = "invalid"
                    reasons[digest] = "genesis-prev-not-zero"
                else:
                    status[digest] = "valid"
                continue

            parent_digest = record["prev"]
            parent = by_digest.get(parent_digest)
            if parent is None:
                status[digest] = "incomplete"
                reasons[digest] = "missing-parent-or-segment"
                continue
            parent_status = status.get(parent_digest)
            if parent_status != "valid":
                status[digest] = "invalid" if parent_status == "invalid" else "incomplete"
                reasons[digest] = f"parent-{parent_status}"
                continue
            if int(parent["seq"]) != seq - 1:
                status[digest] = "invalid"
                reasons[digest] = "nonconsecutive-sequence"
                continue
            status[digest] = "valid"

        tainted: dict[str, bool] = {}
        tombstones = self.tombstone_digests()
        for digest in sorted(by_digest, key=lambda d: (int(by_digest[d]["seq"]), d)):
            record = by_digest[digest]
            if digest in tombstones:
                tainted[digest] = True
                continue
            parent_digest = record["prev"]
            tainted[digest] = bool(tainted.get(parent_digest, False))

        return {
            "by_digest": by_digest,
            "by_seq": by_seq,
            "children": children,
            "status": status,
            "reasons": reasons,
            "tainted": tainted,
        }

    def active_revocations(self) -> list[dict[str, Any]]:
        """Revocations whose IDs do not have conflicting bodies.

        A reused ID with two incompatible bodies is quarantined rather than
        letting ingestion order decide which policy wins.
        """

        return [
            revocation
            for revocation in self.revocations
            if revocation["revocation_id"] not in self.quarantined_revocation_ids
        ]

    def tombstone_digests(self) -> set[str]:
        return {r["target"] for r in self.active_revocations() if r.get("kind") == "branch"}

    def _revocation_applies(self, revocation: dict[str, Any], segment: int) -> bool:
        effective = revocation.get("effective_segment", revocation.get("at_segment"))
        if effective is None:
            return True
        effective = int(effective)
        if segment >= effective:
            return True
        return bool(revocation.get("retroactive", False))

    def receipt_statuses(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        by_digest = graph["by_digest"]
        status = graph["status"]
        active_revocations = self.active_revocations()
        revoked_receipt_ids = {
            r["target"] for r in active_revocations if r.get("kind") == "receipt"
        }
        controller_revocations = [r for r in active_revocations if r.get("kind") == "controller"]
        identity_revocations = [r for r in active_revocations if r.get("kind") == "identity"]

        results: list[dict[str, Any]] = []
        for receipt in sorted(self.receipts, key=lambda r: r["receipt_id"]):
            receipt_id = receipt["receipt_id"]
            if receipt_id in self.quarantined_receipt_ids:
                # Do not let ingestion order choose which conflicting body is
                # displayed or evaluated.
                results.append(
                    {
                        "receipt_id": receipt_id,
                        "identity_id": None,
                        "controller_id": None,
                        "seq": None,
                        "segment": None,
                        "record_digest": None,
                        "eligible": False,
                        "reasons": ["receipt-id-body-conflict"],
                    }
                )
                continue

            kid = receipt["identity_id"]
            controller = self.keyring.controller_of(kid)
            target = by_digest.get(receipt["record_digest"])
            reasons: list[str] = []

            if not self.keyring.verify(receipt):
                reasons.append("bad-mac-or-unknown-identity")
            if not self.keyring.epoch_allows(kid, self.partition, int(receipt["segment"])):
                reasons.append("identity-not-valid-in-segment")
            if receipt["receipt_id"] in revoked_receipt_ids:
                reasons.append("receipt-revoked")

            for rev in identity_revocations:
                if rev.get("target") == kid and self._revocation_applies(rev, int(receipt["segment"])):
                    reasons.append("identity-revoked")
            if controller is None:
                reasons.append("controller-unregistered")
            else:
                for rev in controller_revocations:
                    if rev.get("target") == controller and self._revocation_applies(rev, int(receipt["segment"])):
                        reasons.append("controller-revoked")

            if target is None:
                reasons.append("target-record-missing")
            else:
                if int(target["seq"]) != int(receipt["seq"]):
                    reasons.append("receipt-seq-mismatch")
                if int(target["segment"]) != int(receipt["segment"]):
                    reasons.append("receipt-segment-mismatch")
                if status.get(receipt["record_digest"]) != "valid":
                    reasons.append(f"target-{status.get(receipt['record_digest'], 'missing')}")

            results.append(
                {
                    "receipt_id": receipt["receipt_id"],
                    "identity_id": kid,
                    "controller_id": controller,
                    "seq": int(receipt["seq"]),
                    "segment": int(receipt["segment"]),
                    "record_digest": receipt["record_digest"],
                    "eligible": not reasons,
                    "reasons": reasons,
                }
            )
        return results

    def _votes(self, receipt_statuses: list[dict[str, Any]]) -> dict[tuple[int, str], dict[str, Any]]:
        # Detect one controller signing two different digests at the same seq.
        positions: dict[int, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        for vote in receipt_statuses:
            if vote["eligible"] and vote["controller_id"] is not None:
                positions[vote["seq"]][vote["controller_id"]].add(vote["record_digest"])

        equivocal: set[tuple[int, str]] = set()
        for seq, controllers in positions.items():
            for controller, digests in controllers.items():
                if len(digests) > 1:
                    equivocal.add((seq, controller))

        grouped: dict[tuple[int, str], dict[str, Any]] = {}
        for vote in receipt_statuses:
            if not vote["eligible"] or vote["controller_id"] is None:
                continue
            if (vote["seq"], vote["controller_id"]) in equivocal:
                vote["eligible"] = False
                vote["reasons"].append("controller-equivocation-at-seq")
                continue
            key = (vote["seq"], vote["record_digest"])
            bucket = grouped.setdefault(
                key,
                {
                    "seq": vote["seq"],
                    "record_digest": vote["record_digest"],
                    "controllers": set(),
                    "identities": set(),
                    "receipt_ids": [],
                    "representative_receipt_ids": [],
                },
            )
            # Every receipt is retained in evidence.  Quorum, however, is the
            # size of the controller set, so two identities under one upstream
            # controller still contribute exactly one independent vote.
            bucket["receipt_ids"].append(vote["receipt_id"])
            if vote["controller_id"] not in bucket["controllers"]:
                bucket["representative_receipt_ids"].append(vote["receipt_id"])
            bucket["controllers"].add(vote["controller_id"])
            bucket["identities"].add(vote["identity_id"])

        result = {}
        for key, bucket in grouped.items():
            bucket["controllers"] = sorted(bucket["controllers"])
            bucket["identities"] = sorted(bucket["identities"])
            bucket["independent_votes"] = len(bucket["controllers"])
            bucket["certified"] = bucket["independent_votes"] >= self.required_controllers
            result[key] = bucket
        return result

    def _unique_prefix(self, graph: dict[str, Any]) -> tuple[int, str]:
        by_seq = graph["by_seq"]
        children = graph["children"]
        status = graph["status"]

        genesis = [
            d for d in by_seq.get(0, set())
            if status.get(d) == "valid" and graph["by_digest"][d]["prev"] == ZERO_DIGEST
        ]
        if len(genesis) != 1:
            return -1, ZERO_DIGEST

        current = genesis[0]
        height = 0
        while True:
            kids = [d for d in children.get(current, set()) if status.get(d) == "valid"]
            if len(kids) != 1:
                return height, current
            current = kids[0]
            height += 1

    def earliest_fork(self, graph: dict[str, Any]) -> dict[str, Any] | None:
        children = graph["children"]
        status = graph["status"]
        by_digest = graph["by_digest"]
        forks: list[dict[str, Any]] = []
        for parent, kids in children.items():
            valid_kids = sorted(d for d in kids if status.get(d) == "valid")
            if len(valid_kids) < 2:
                continue
            parent_record = by_digest.get(parent)
            fork_seq = int(by_digest[valid_kids[0]]["seq"])
            forks.append(
                {
                    "fork_seq": fork_seq,
                    "common_tip_seq": fork_seq - 1,
                    "common_tip_digest": parent if parent_record is not None else ZERO_DIGEST,
                    "conflicting_digests": valid_kids,
                    "provable": parent_record is not None or parent == ZERO_DIGEST,
                }
            )
        if not forks:
            return None
        return min(forks, key=lambda f: (f["fork_seq"], f["common_tip_digest"]))

    def report(self) -> dict[str, Any]:
        graph = self.evaluate_graph()
        receipt_statuses = self.receipt_statuses(graph)
        votes = self._votes(receipt_statuses)
        prefix_height, prefix_digest = self._unique_prefix(graph)
        fork = self.earliest_fork(graph)
        sequence_conflicts = self._sequence_conflicts(graph)

        prefix_digests: dict[int, str] = {}
        if prefix_height >= 0:
            digest = prefix_digest
            by_digest = graph["by_digest"]
            while digest != ZERO_DIGEST and digest in by_digest:
                record = by_digest[digest]
                prefix_digests[int(record["seq"])] = digest
                digest = record["prev"]

        first_tombstoned_prefix_seq: int | None = None
        for seq, digest in prefix_digests.items():
            if graph["tainted"].get(digest):
                first_tombstoned_prefix_seq = seq if first_tombstoned_prefix_seq is None else min(first_tombstoned_prefix_seq, seq)

        committable_candidates: list[dict[str, Any]] = []
        certified_nodes: list[dict[str, Any]] = []
        for (seq, digest), vote in sorted(votes.items()):
            if not vote["certified"]:
                continue
            item = {
                "seq": seq,
                "record_digest": digest,
                "segment": seq // self.segment_size,
                "controllers": vote["controllers"],
                "identities": vote["identities"],
                "receipt_ids": vote["receipt_ids"],
                "tainted": bool(graph["tainted"].get(digest, digest in self.tombstone_digests())),
            }
            certified_nodes.append(item)
            if seq in prefix_digests and prefix_digests[seq] == digest and not item["tainted"]:
                if first_tombstoned_prefix_seq is None or seq < first_tombstoned_prefix_seq:
                    committable_candidates.append(item)

        max_committable = max((x["seq"] for x in committable_candidates), default=None)
        committed_digest = None
        if max_committable is not None:
            committed_digest = prefix_digests[max_committable]

        safe_certified = [x for x in certified_nodes if not x["tainted"]]
        max_certified = max((x["seq"] for x in safe_certified), default=None)

        branches = self._branch_reports(graph, votes, fork, prefix_digests)
        gaps = self._gap_reports(graph)

        return {
            "format": "offline-audit-reconciliation-report/v1",
            "partition": self.partition,
            "segment_size": self.segment_size,
            "required_independent_controllers": self.required_controllers,
            "common_prefix_height": prefix_height,
            "common_prefix_digest": prefix_digest,
            "earliest_provable_fork": fork,
            "sequence_conflicts": sequence_conflicts,
            "max_certified_watermark": max_certified,
            "max_committable_watermark": max_committable,
            "committed_digest": committed_digest,
            "missing_or_incomplete_points": gaps,
            "certified_nodes": certified_nodes,
            "committable_candidates": committable_candidates,
            "branches": branches,
            "isolated_branches": [b for b in branches if b["isolated"]],
            "receipt_evaluations": receipt_statuses,
            "revocations": sorted(self.active_revocations(), key=lambda r: r["revocation_id"]),
            "quarantined_receipt_ids": sorted(self.quarantined_receipt_ids),
            "quarantined_revocation_ids": sorted(self.quarantined_revocation_ids),
            "stats": {
                "records_seen": len(self.records),
                "unique_valid_records": len(graph["by_digest"]),
                "duplicate_records": self.duplicate_records,
                "malformed_digest_aliases": len(self.digest_aliases),
                "receipts_seen": len(self.receipts),
                "replayed_receipts": self.replayed_receipts,
                "receipt_id_conflicts": len(self.receipt_id_conflicts),
                "revocations_seen": len(self.revocations),
                "duplicate_revocations": self.duplicate_revocations,
            },
            "diagnostics": {
                "digest_aliases": sorted(self.digest_aliases, key=canonical_bytes),
                "receipt_id_conflicts": sorted(
                    self.receipt_id_conflicts, key=lambda x: x["receipt_id"]
                ),
                "revocation_id_conflicts": sorted(
                    self.revocation_id_conflicts, key=lambda x: x["revocation_id"]
                ),
                "graph_reasons": dict(sorted(graph["reasons"].items())),
            },
        }

    def _branch_reports(
        self,
        graph: dict[str, Any],
        votes: dict[tuple[int, str], dict[str, Any]],
        fork: dict[str, Any] | None,
        prefix_digests: dict[int, str],
    ) -> list[dict[str, Any]]:
        by_digest = graph["by_digest"]
        children = graph["children"]
        status = graph["status"]
        tainted = graph["tainted"]
        prefix_digest_set = set(prefix_digests.values())

        tips = sorted(
            (d for d in by_digest if not children.get(d)),
            key=lambda d: (int(by_digest[d]["seq"]), d),
        )
        reports = []
        fork_seq = None if fork is None else fork["fork_seq"]
        for digest in tips:
            record = by_digest[digest]
            seq = int(record["seq"])
            vote = votes.get((seq, digest))
            independent_votes = 0 if vote is None else vote["independent_votes"]
            controllers = [] if vote is None else vote["controllers"]
            identities = [] if vote is None else vote["identities"]
            receipt_ids = [] if vote is None else vote["receipt_ids"]
            chain_status = status.get(digest, "unknown")
            is_prefix_tip = digest == prefix_digests.get(seq) and seq == max(prefix_digests, default=-1)

            reasons: list[str] = []
            isolated = False
            if chain_status != "valid":
                isolated = True
                reasons.append(graph["reasons"].get(digest, chain_status))
            if tainted.get(digest):
                isolated = True
                reasons.append("revoked-tombstone-in-ancestry")
            if fork_seq is not None and seq >= fork_seq and digest not in prefix_digest_set:
                isolated = True
                reasons.append("contested-after-earliest-fork")
            if independent_votes < self.required_controllers:
                # Lack of quorum makes a contested branch unprovable.  It does
                # not by itself isolate the unique common-prefix tip.
                if isolated or (fork_seq is not None and seq >= fork_seq):
                    isolated = True
                reasons.append("insufficient-independent-witness-quorum")
            if chain_status == "valid" and not isolated and not is_prefix_tip:
                # A valid non-tip? Here digest is a tip, so this is another
                # unique chain not connected to genesis; keep it isolated.
                if digest not in prefix_digest_set:
                    isolated = True
                    reasons.append("outside-confirmed-common-prefix")

            reports.append(
                {
                    "tip_digest": digest,
                    "seq": seq,
                    "segment": int(record["segment"]),
                    "chain_status": chain_status,
                    "status_reason": graph["reasons"].get(digest),
                    "tainted": bool(tainted.get(digest, digest in self.tombstone_digests())),
                    "independent_votes": independent_votes,
                    "controllers": controllers,
                    "identities": identities,
                    "receipt_ids": receipt_ids,
                    "quorum": independent_votes >= self.required_controllers,
                    "is_common_prefix_tip": is_prefix_tip,
                    "isolated": isolated,
                    "reasons": reasons,
                }
            )
        return reports

    def _sequence_conflicts(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        conflicts = []
        by_digest = graph["by_digest"]
        for seq, digests in sorted(graph["by_seq"].items()):
            ordered = sorted(digests)
            if len(ordered) < 2:
                continue
            prevs = {by_digest[d]["prev"] for d in ordered}
            valid = [d for d in ordered if graph["status"].get(d) == "valid"]
            same_prev = len(prevs) == 1
            parent_digest = next(iter(prevs)) if same_prev else None
            provable = (
                len(valid) >= 2
                and same_prev
                and (parent_digest == ZERO_DIGEST or graph["status"].get(parent_digest) == "valid")
            )
            conflicts.append(
                {
                    "seq": int(seq),
                    "digests": ordered,
                    "prevs": sorted(prevs),
                    "same_prev": same_prev,
                    "provable_fork": provable,
                    "statuses": {d: graph["status"].get(d, "unknown") for d in ordered},
                }
            )
        return conflicts

    def _gap_reports(self, graph: dict[str, Any]) -> list[dict[str, Any]]:
        gaps = []
        for digest, state in graph["status"].items():
            if state == "incomplete":
                record = graph["by_digest"][digest]
                gaps.append(
                    {
                        "after_digest": record["prev"],
                        "blocking_seq": int(record["seq"]),
                        "needed_segment": int(record["seq"] - 1) // self.segment_size,
                        "downstream_digest": digest,
                        "reason": graph["reasons"].get(digest),
                    }
                )
        # Deduplicate by missing parent / needed segment.
        dedup = {}
        for gap in gaps:
            key = (gap["after_digest"], gap["needed_segment"])
            dedup[key] = gap
        return sorted(dedup.values(), key=lambda g: (g["needed_segment"], g["blocking_seq"]))


def _receipt_identity(receipt: dict[str, Any]) -> dict[str, Any]:
    from .canonical import receipt_signing_payload

    return receipt_signing_payload(receipt) | {"mac": receipt.get("mac")}


def reconcile_world(
    world: dict[str, Any], keyring: HmacKeyring | dict[str, Any] | None = None
) -> dict[str, dict[str, Any]]:
    """Reconcile every partition found in a synthetic world dict."""

    if keyring is None:
        keyring = world.get("keyring")
    keyring = coerce_keyring(keyring)

    partitions = set(world.get("partitions", []))
    records = world.get("records", [])
    receipts = world.get("receipts", [])
    revocations = world.get("revocations", [])
    partitions.update(r["partition"] for r in records)
    partitions.update(r["partition"] for r in receipts)

    reports: dict[str, dict[str, Any]] = {}
    for partition in sorted(partitions):
        segment_size = int(world.get("segment_size", 1000))
        session = ReconciliationSession(
            partition=partition,
            segment_size=segment_size,
            required_controllers=int(world.get("required_controllers", 2)),
            keyring=keyring,
        )
        for record in records:
            if record.get("partition") == partition:
                session.ingest_record(record)
        for receipt in receipts:
            if receipt.get("partition") == partition:
                session.ingest_receipt(receipt)
        for rev in revocations:
            p = rev.get("partition")
            if p is None or p == partition:
                session.ingest_revocation(rev)
        reports[partition] = session.report()
    return reports
