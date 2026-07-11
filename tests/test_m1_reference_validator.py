"""Smoke tests for the M1 reference-aware validator."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security.reference_aware_validator import GROUP_PATHS, validate_reference_fields


def load_first_transaction():
    path = ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl"
    with path.open("r", encoding="utf-8") as handle:
        return json.loads(next(line for line in handle if line.strip()))


def main():
    reference = load_first_transaction()
    proposed = deepcopy(reference)

    complete = validate_reference_fields(reference, proposed, checked_paths=GROUP_PATHS["carrier"])
    assert complete["valid"], complete

    proposed["carrier"]["dot_number"] = "0000000"
    detected = validate_reference_fields(reference, proposed, checked_paths=GROUP_PATHS["carrier"])
    assert not detected["valid"], detected
    assert any("carrier.dot_number:mismatch" in item for item in detected["findings"])

    partial = validate_reference_fields(reference, proposed, checked_paths=["carrier.carrier_id"])
    assert partial["valid"], partial

    missing = validate_reference_fields(reference, proposed, checked_paths=[])
    assert missing["valid"], missing
    assert missing["checked_paths"] == []

    stale = deepcopy(reference)
    stale["carrier"]["dot_number"] = "0000000"
    stale_result = validate_reference_fields(stale, proposed, checked_paths=GROUP_PATHS["carrier"])
    assert stale_result["valid"], stale_result

    print("M1 reference-aware validator tests passed.")


if __name__ == "__main__":
    main()
