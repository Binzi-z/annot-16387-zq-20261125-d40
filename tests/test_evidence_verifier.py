from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from offline_audit.canonical import domain_digest  # noqa: E402
from offline_audit.engine import ReconciliationSession  # noqa: E402
from offline_audit.evidence import write_evidence_set  # noqa: E402
from offline_audit.synthetic import make_small_world  # noqa: E402


class IndependentEvidenceVerifierTests(unittest.TestCase):
    def _session_after_replay_revocation(self) -> tuple[dict, ReconciliationSession]:
        world = make_small_world()
        session = ReconciliationSession(
            world["partition"], world["segment_size"], keyring=world["keyring"]
        )
        for record in world["records"]:
            session.ingest_record(record)
        for receipt in world["receipts"]:
            session.ingest_receipt(receipt)

        a_tip = world["branch_a"][-1]["digest"]
        session.revoke_witness(
            "watch", "revoke-watch", reason="synthetic known-witness revocation"
        )
        session.revoke_branch(
            a_tip, "revoke-branch-a", "support collapsed; candidate remains isolated"
        )
        watch_receipt = next(r for r in world["receipts"] if r["identity_id"] == "watch-key")
        session.ingest_receipt(dict(watch_receipt))  # old receipt replay
        return world, session

    def test_standalone_verifier_accepts_minimal_bundle(self) -> None:
        _world, session = self._session_after_replay_revocation()
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_evidence_set(session, tmp)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "verify_evidence.py"),
                    str(paths["evidence"]),
                    "--keyring",
                    str(paths["keyring"]),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("PASS", result.stdout)

            bundle = json.loads(paths["evidence"].read_text(encoding="utf-8"))
            # The minimal small-world proof contains only chain/proof records,
            # not arbitrary file envelopes or site-private payload stores.
            self.assertLessEqual(bundle["minimality_manifest"]["record_count"], 8)
            self.assertTrue(bundle["claim"]["replay_non_revival_checks"])

    def test_standalone_verifier_rejects_recomputed_false_watermark_claim(self) -> None:
        _world, session = self._session_after_replay_revocation()
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_evidence_set(session, tmp)
            bundle = json.loads(paths["evidence"].read_text(encoding="utf-8"))
            bundle["claim"]["max_committable_watermark"] = 5
            bundle["claim"]["committed_digest"] = "f" * 64
            bundle["bundle_digest"] = domain_digest(
                "evidence-bundle-v1",
                {k: v for k, v in bundle.items() if k != "bundle_digest"},
            )
            bad = Path(tmp) / "bad-evidence.json"
            bad.write_text(json.dumps(bundle), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "verify_evidence.py"),
                    str(bad),
                    "--keyring",
                    str(paths["keyring"]),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("max-committable-watermark", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
