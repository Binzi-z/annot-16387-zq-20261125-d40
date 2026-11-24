from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scale_check import run_scale_check  # noqa: E402


class ScaleSparseRevisionTests(unittest.TestCase):
    def test_60k_records_three_remote_missing_segments(self) -> None:
        result = run_scale_check()
        self.assertEqual(result["record_count"], 60_000)
        self.assertEqual(result["segment_count"], 60)
        self.assertEqual(result["missing_segments"], [17, 38, 52])
        self.assertEqual(result["remote_requested_segments"], [17, 38, 52])
        self.assertEqual(result["actually_accessed_segments"], list(range(60)))
        self.assertTrue(result["each_segment_accessed_once"])
        self.assertTrue(result["full_result_matches_sparse_revision"])
        self.assertEqual(result["max_committable_watermark"], 59_999)

        watermarks = [stage["max_committable_watermark"] for stage in result["stages"]]
        self.assertEqual(watermarks, [16_999, 37_999, 51_999, 59_999])


if __name__ == "__main__":
    unittest.main(verbosity=2)
