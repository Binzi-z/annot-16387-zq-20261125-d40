from __future__ import annotations

import itertools
import json
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_audit.canonical import canonical_bytes, record_digest  # noqa: E402
from offline_audit.engine import ReconciliationSession  # noqa: E402
from offline_audit.synthetic import build_linear_records, make_small_world  # noqa: E402
from offline_audit.witnesses import HmacKeyring, sign_receipt  # noqa: E402


def event(kind: str, value: dict[str, Any]) -> dict[str, Any]:
    key = {"record": "record", "receipt": "receipt", "revocation": "revocation"}[kind]
    return {"kind": kind, key: value}


def stable_report(report: dict[str, Any]) -> str:
    return canonical_bytes(report).decode("ascii")


def assert_every_permutation_identical(
    test: unittest.TestCase,
    events: list[dict[str, Any]],
    session_factory: Callable[[], ReconciliationSession],
    check: Callable[[ReconciliationSession, dict[str, Any]], None] | None = None,
) -> None:
    """Exhaustively replay every ordering and require the same final report."""

    first: str | None = None
    count = 0
    for ordering in itertools.permutations(events):
        session = session_factory()
        session.ingest_many(list(ordering))
        report = session.report()
        encoded = stable_report(report)
        if first is None:
            first = encoded
        else:
            test.assertEqual(encoded, first, "report changed with input event order")
        if check is not None:
            check(session, report)
        count += 1
    test.assertGreater(count, 0)


class ExhaustiveSmallLedgerTests(unittest.TestCase):
    def test_all_orders_duplicate_controller_identity_and_fork(self) -> None:
        partition = "exhaustive-fork"
        segment_size = 2
        common = build_linear_records(partition, 2, segment_size, label="common")
        child_a = build_linear_records(
            partition, 1, segment_size, start_seq=2,
            prev=common[1]["digest"], label="a",
        )
        child_b = build_linear_records(
            partition, 1, segment_size, start_seq=2,
            prev=common[1]["digest"], label="b-different",
        )
        records = common + child_a + child_b
        keyring = HmacKeyring.synthetic({
            "upstream": [
                ("upstream-id-1", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
                ("upstream-id-2", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
            ],
            "independent": [
                ("independent-id", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
            ],
        })
        tip = common[1]
        receipts = [
            sign_receipt(
                keyring, receipt_id="r-up-1", partition=partition, seq=1, segment=0,
                record_digest=tip["digest"], identity_id="upstream-id-1",
            ),
            sign_receipt(
                keyring, receipt_id="r-up-2", partition=partition, seq=1, segment=0,
                record_digest=tip["digest"], identity_id="upstream-id-2",
            ),
            sign_receipt(
                keyring, receipt_id="r-ind", partition=partition, seq=1, segment=0,
                record_digest=tip["digest"], identity_id="independent-id",
            ),
        ]
        events = [event("record", r) for r in records]
        events += [event("receipt", r) for r in receipts]

        def factory() -> ReconciliationSession:
            return ReconciliationSession(partition, segment_size, keyring=keyring)

        def check(_session: ReconciliationSession, report: dict[str, Any]) -> None:
            self.assertEqual(report["common_prefix_height"], 1)
            self.assertEqual(report["max_committable_watermark"], 1)
            self.assertIsNotNone(report["earliest_provable_fork"])
            self.assertEqual(report["earliest_provable_fork"]["fork_seq"], 2)
            conflict = report["sequence_conflicts"][0]
            self.assertEqual(conflict["seq"], 2)
            self.assertEqual(len(conflict["digests"]), 2)
            self.assertTrue(conflict["provable_fork"])

        assert_every_permutation_identical(self, events, factory, check)

    def test_two_identities_same_controller_are_one_vote(self) -> None:
        partition = "one-controller"
        records = build_linear_records(partition, 2, 1)
        keyring = HmacKeyring.synthetic({
            "same-controller": [
                ("sign-id-a", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
                ("sign-id-b", [{"partition": "*", "first_segment": 0, "last_segment": None}]),
            ]
        })
        receipts = [
            sign_receipt(
                keyring, receipt_id="ra", partition=partition, seq=1, segment=1,
                record_digest=records[1]["digest"], identity_id="sign-id-a",
            ),
            sign_receipt(
                keyring, receipt_id="rb", partition=partition, seq=1, segment=1,
                record_digest=records[1]["digest"], identity_id="sign-id-b",
            ),
        ]
        session = ReconciliationSession(partition, 1, keyring=keyring)
        session.ingest_many([event("record", r) for r in records])
        session.ingest_many([event("receipt", r) for r in receipts])
        report = session.report()
        self.assertIsNone(report["max_committable_watermark"])
        node = report["certified_nodes"]
        self.assertEqual(node, [])
        votes = session._votes(session.receipt_statuses(session.evaluate_graph()))
        bucket = votes[(1, records[1]["digest"])]
        self.assertEqual(bucket["independent_votes"], 1)
        self.assertEqual(bucket["controllers"], ["same-controller"])
        self.assertEqual(set(bucket["identities"]), {"sign-id-a", "sign-id-b"})

    def test_exhaustive_interleaved_rotation_boundaries_and_orders(self) -> None:
        partition = "rotations"
        segment_size = 1
        target_seq = 2
        records = build_linear_records(partition, target_seq + 1, segment_size)

        for boundary_a in range(0, 5):
            for boundary_b in range(0, 5):
                controllers = {
                    "controller-a": _rotation_identities("a", boundary_a),
                    "controller-b": _rotation_identities("b", boundary_b),
                }
                keyring = HmacKeyring.synthetic(controllers, seed=f"{boundary_a}-{boundary_b}")
                kid_a = "a-old" if boundary_a > target_seq else "a-new"
                kid_b = "b-old" if boundary_b > target_seq else "b-new"
                receipts = [
                    sign_receipt(
                        keyring, receipt_id="ra", partition=partition, seq=target_seq,
                        segment=target_seq, record_digest=records[-1]["digest"], identity_id=kid_a,
                    ),
                    sign_receipt(
                        keyring, receipt_id="rb", partition=partition, seq=target_seq,
                        segment=target_seq, record_digest=records[-1]["digest"], identity_id=kid_b,
                    ),
                ]
                events = [event("record", r) for r in records]
                events += [event("receipt", r) for r in receipts]

                def factory(k: HmacKeyring = keyring) -> ReconciliationSession:
                    return ReconciliationSession(partition, segment_size, keyring=k)

                def check(_s: ReconciliationSession, report: dict[str, Any]) -> None:
                    self.assertEqual(report["max_committable_watermark"], target_seq)
                    self.assertIsNone(report["earliest_provable_fork"])

                assert_every_permutation_identical(self, events, factory, check)

    def test_same_sequence_different_digest_all_orders(self) -> None:
        partition = "same-seq-digest"
        segment_size = 1
        genesis = build_linear_records(partition, 1, segment_size, label="genesis")
        first = build_linear_records(
            partition, 1, segment_size, start_seq=1,
            prev=genesis[0]["digest"], label="first-payload",
        )[0]
        second = dict(first)
        second["payload"] = {"label": "second-different-payload"}
        second["digest"] = record_digest(second)
        records = genesis + [first, second]

        keyring = HmacKeyring.synthetic({
            "a": [("a1", [{"partition": "*", "first_segment": 0, "last_segment": None}])],
            "b": [("b1", [{"partition": "*", "first_segment": 0, "last_segment": None}])],
        })
        receipts = [
            sign_receipt(
                keyring, receipt_id="ga", partition=partition, seq=0, segment=0,
                record_digest=genesis[0]["digest"], identity_id="a1",
            ),
            sign_receipt(
                keyring, receipt_id="gb", partition=partition, seq=0, segment=0,
                record_digest=genesis[0]["digest"], identity_id="b1",
            ),
        ]
        events = [event("record", r) for r in records]
        events += [event("receipt", r) for r in receipts]

        def factory() -> ReconciliationSession:
            return ReconciliationSession(partition, segment_size, keyring=keyring)

        def check(_s: ReconciliationSession, report: dict[str, Any]) -> None:
            self.assertEqual(report["max_committable_watermark"], 0)
            self.assertEqual(report["common_prefix_height"], 0)
            conflict = report["sequence_conflicts"][0]
            self.assertEqual(conflict["seq"], 1)
            self.assertEqual(len(set(conflict["digests"])), 2)
            self.assertTrue(conflict["same_prev"])
            self.assertTrue(conflict["provable_fork"])
            self.assertEqual(report["earliest_provable_fork"]["fork_seq"], 1)
            self.assertEqual(len(report["isolated_branches"]), 2)

        assert_every_permutation_identical(self, events, factory, check)

    def test_same_sequence_with_disconnected_prev_is_not_provable_fork(self) -> None:
        partition = "same-seq-orphan"
        segment_size = 1
        genesis = build_linear_records(partition, 1, segment_size)[0]

        def orphan(label: str, prev: str) -> dict[str, Any]:
            record = {
                "v": 1, "partition": partition, "seq": 4, "segment": 4,
                "prev": prev, "payload": {"label": label},
            }
            record["digest"] = record_digest(record)
            return record

        fake_a = "a" * 64
        fake_b = "b" * 64
        records = [genesis, orphan("x", fake_a), orphan("y", fake_b)]
        session = ReconciliationSession(partition, segment_size)
        for record in reversed(records):  # deliberately adverse order
            session.ingest_record(record)
        report = session.report()
        conflict = report["sequence_conflicts"][0]
        self.assertEqual(conflict["seq"], 4)
        self.assertFalse(conflict["same_prev"])
        self.assertFalse(conflict["provable_fork"])
        self.assertIsNone(report["earliest_provable_fork"])
        self.assertGreaterEqual(len(report["missing_or_incomplete_points"]), 1)

    def test_missing_segment_blocks_then_fill_advances(self) -> None:
        world = make_small_world()
        partition = world["partition"]
        session = ReconciliationSession(
            partition, world["segment_size"], keyring=world["keyring"]
        )
        missing_seq_values = {2, 3}
        initially_visible = [r for r in world["records"] if r["seq"] not in missing_seq_values]
        for record in initially_visible:
            session.ingest_record(record)
        for receipt in world["receipts"]:
            session.ingest_receipt(receipt)

        blocked = session.report()
        self.assertEqual(blocked["common_prefix_height"], 1)
        self.assertIsNone(blocked["earliest_provable_fork"])
        self.assertIsNone(blocked["max_committable_watermark"])
        self.assertTrue(blocked["missing_or_incomplete_points"])

        for record in world["records"]:
            if record["seq"] in missing_seq_values:
                session.ingest_record(record)
        advanced = session.report()
        self.assertEqual(advanced["common_prefix_height"], 3)
        self.assertEqual(advanced["max_committable_watermark"], 3)
        self.assertEqual(advanced["earliest_provable_fork"]["fork_seq"], 4)

    def test_revoked_witness_and_replayed_receipt_never_revives_branch_all_orders(self) -> None:
        partition = "revocation-replay"
        segment_size = 1
        records = build_linear_records(partition, 2, segment_size)
        keyring = HmacKeyring.synthetic({
            "controller-a": [("a-key", [{"partition": "*", "first_segment": 0, "last_segment": None}])],
            "controller-b": [("b-key", [{"partition": "*", "first_segment": 0, "last_segment": None}])],
        })
        receipt_a = sign_receipt(
            keyring, receipt_id="ra", partition=partition, seq=1, segment=1,
            record_digest=records[1]["digest"], identity_id="a-key",
        )
        receipt_b = sign_receipt(
            keyring, receipt_id="rb", partition=partition, seq=1, segment=1,
            record_digest=records[1]["digest"], identity_id="b-key",
        )

        before = ReconciliationSession(partition, segment_size, keyring=keyring)
        before.ingest_many([event("record", r) for r in records])
        before.ingest_receipt(receipt_a)
        before.ingest_receipt(receipt_b)
        self.assertEqual(before.report()["max_committable_watermark"], 1)

        rev_witness = {
            "revocation_id": "revoke-b",
            "kind": "controller",
            "target": "controller-b",
            "reason": "known witness revoked",
        }
        rev_branch = {
            "revocation_id": "revoke-candidate",
            "kind": "branch",
            "target": records[1]["digest"],
            "reason": "candidate revoked after witness compromise",
        }
        events = [event("record", r) for r in records]
        events += [event("receipt", receipt_a), event("receipt", dict(receipt_b))]
        events += [event("receipt", dict(receipt_b))]  # explicit old-receipt replay
        events += [event("revocation", rev_witness), event("revocation", rev_branch)]

        def factory() -> ReconciliationSession:
            return ReconciliationSession(partition, segment_size, keyring=keyring)

        def check(_s: ReconciliationSession, report: dict[str, Any]) -> None:
            self.assertIsNone(report["max_committable_watermark"])
            tip = next(b for b in report["branches"] if b["tip_digest"] == records[1]["digest"])
            self.assertTrue(tip["isolated"])
            self.assertTrue(any("revoked-tombstone" in reason for reason in tip["reasons"]))
            evaluation = next(r for r in report["receipt_evaluations"] if r["receipt_id"] == "rb")
            self.assertFalse(evaluation["eligible"])
            self.assertIn("controller-revoked", evaluation["reasons"])
            self.assertEqual(report["stats"]["replayed_receipts"], 1)

        assert_every_permutation_identical(self, events, factory, check)


def _rotation_identities(prefix: str, boundary: int) -> list[tuple[str, list[dict[str, Any]]]]:
    identities: list[tuple[str, list[dict[str, Any]]]] = []
    if boundary > 0:
        identities.append((
            f"{prefix}-old",
            [{"partition": "*", "first_segment": 0, "last_segment": boundary - 1}],
        ))
    identities.append((
        f"{prefix}-new",
        [{"partition": "*", "first_segment": boundary, "last_segment": None}],
    ))
    return identities


if __name__ == "__main__":
    unittest.main(verbosity=2)
