"""Offline reconciliation for divergent synthetic audit ledgers.

The package uses only the Python 3.12 standard library.  The canonical JSON
and digest routines are also part of the evidence format specification; the
standalone verifier intentionally repeats the small verification primitives so
that it does not have to trust this package's reconciliation result.
"""

from .canonical import CANONICAL_FORMAT, canonical_bytes, domain_digest
from .engine import ReconciliationSession, reconcile_world
from .evidence import build_evidence_bundle, write_evidence_set
from .segments import CachingSegmentLoader, MissingSegment, SegmentStore, build_segment
from .synthetic import (
    build_linear_records,
    make_scale_world,
    make_small_world,
)
from .witnesses import HmacKeyring, sign_receipt

__all__ = [
    "CANONICAL_FORMAT",
    "CachingSegmentLoader",
    "HmacKeyring",
    "MissingSegment",
    "ReconciliationSession",
    "SegmentStore",
    "build_evidence_bundle",
    "build_linear_records",
    "build_segment",
    "canonical_bytes",
    "domain_digest",
    "make_scale_world",
    "make_small_world",
    "reconcile_world",
    "sign_receipt",
    "write_evidence_set",
]
