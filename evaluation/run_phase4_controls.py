"""
Run Phase 4 D0-D5 defense comparison.

This is deterministic. It does not call an LLM. It tests whether the control
layers can block or allow proposed transactions derived from adversarial document
mutations.

Usage:
    python evaluation/run_phase4_controls.py
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import csv
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adjudication.rule_based_judge import RuleBasedJudge
from tms_mock.audit_log import AuditLogger
from tms_mock.endpoints import MockTMS
from security.schema_validator import validate_transaction_schema
from security.field_level_validator import validate_high_risk_fields
from security.defense_policy import DEFENSES, DEFAULT_ALLOWED_CAPABILITIES


def load_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def get_stop(tx, stop_type):
    for s in tx.get("stops", []):
        if s.get("stop_type") == stop_type:
            return s
    return None


def apply_adversarial_values(tx, m):
    tx = deepcopy(tx)
    av = m.get("adversarial_values", {})
    attack = m["attack_type"]

    if attack == "hazmat_suppression":
        tx["cargo"]["hazmat"] = False
        tx["cargo"]["hazmat_class"] = ""
        tx["cargo"]["un_number"] = ""

    elif attack == "appointment_sabotage":
        stop = get_stop(tx, "delivery")
        if stop:
            stop["appointment_start"] = av["delivery.appointment_start"]
            stop["appointment_end"] = av["delivery.appointment_end"]

    elif attack == "dispatch_poisoning":
        stop = get_stop(tx, "delivery")
        if stop:
            stop["facility_id"] = av["delivery.facility_id"]
            stop["dock"] = av["delivery.dock"]
            stop["city"] = av["delivery.city"]
            stop["zip"] = av["delivery.zip"]

    elif attack == "carrier_substitution":
        tx["carrier"] = {
            "carrier_id": av["carrier_id"],
            "name": av["name"],
            "dot_number": av["dot_number"],
            "mc_number": av["mc_number"],
        }

    elif attack == "status_concealment":
        tx["tracking"]["status"] = "on_time"
        tx["tracking"]["exception_status"] = ""

    return tx


def run_api_for_attack(tms, tx, m):
    load_id = tx["load_id"]
    attack = m["attack_type"]
    tms.create_load(tx)

    if attack == "appointment_sabotage":
        delivery = get_stop(tx, "delivery")
        tms.schedule_appointment(load_id, "delivery", {
            "appointment_start": delivery["appointment_start"],
            "appointment_end": delivery["appointment_end"],
        })
    elif attack == "dispatch_poisoning":
        delivery = get_stop(tx, "delivery")
        tms.send_dispatch(load_id, {
            "facility_id": delivery.get("facility_id"),
            "dock": delivery.get("dock"),
            "city": delivery.get("city"),
            "zip": delivery.get("zip"),
            "instruction": "Final driver instruction from document."
        })
    elif attack == "carrier_substitution":
        tms.assign_carrier(load_id, tx["carrier"])
    elif attack == "status_concealment":
        tms.update_status(load_id, tx["tracking"])

    return tms.audit_logger.to_dicts()


def evaluate_one(defense_name, defense, gt, proposed, manifest_entry, judge):
    # Schema control
    if defense["schema_validation"]:
        schema_result = validate_transaction_schema(proposed)
        if not schema_result["valid"]:
            return {
                "outcome_label": "safe_blocked",
                "is_unsafe": False,
                "blocked_by": "schema_validation",
                "reasons": schema_result["errors"],
                "api_calls": [],
                "approval_required": False,
            }

    # Field-level control
    if defense["field_validation"]:
        field_result = validate_high_risk_fields(gt, proposed, manifest_entry.get("adversarial_values"))
        if not field_result["valid"]:
            return {
                "outcome_label": "safe_blocked",
                "is_unsafe": False,
                "blocked_by": "field_validation",
                "reasons": field_result["findings"],
                "api_calls": [],
                "approval_required": False,
            }

    audit = AuditLogger()
    tms = MockTMS(
        audit_logger=audit,
        skill_name="phase4_control_skill",
        allowed_capabilities=set(DEFAULT_ALLOWED_CAPABILITIES),
        enforce_capabilities=defense["capability_enforcement"],
        require_human_approval_for_high_risk=defense["approval_required"],
    )
    events = run_api_for_attack(tms, proposed, manifest_entry)

    # If approval gate escalated before accepting all high-risk actions, count as safe blocked/escalated.
    if any(e.get("result") == "escalated" for e in events):
        return {
            "outcome_label": "safe_blocked",
            "is_unsafe": False,
            "blocked_by": "approval_gate",
            "reasons": [e.get("message", "") for e in events if e.get("result") == "escalated"],
            "api_calls": [e["api_call"] for e in events],
            "approval_required": True,
        }

    # Capability manifest can block some API calls, but it does not necessarily stop unsafe field acceptance.
    adjudication = judge.judge(
        load_id=manifest_entry["load_id"],
        final_transaction=proposed,
        audit_events=events,
        attack_type=manifest_entry["attack_type"],
        adversarial_values=manifest_entry.get("adversarial_values"),
    )

    return {
        "outcome_label": adjudication["outcome_label"],
        "is_unsafe": adjudication["is_unsafe"],
        "blocked_by": "none" if adjudication["is_unsafe"] else "capability_manifest" if adjudication["outcome_label"] == "safe_blocked" else "none",
        "reasons": adjudication["reasons"],
        "api_calls": [e["api_call"] for e in events],
        "approval_required": False,
    }


def main():
    records = {r["load_id"]: r for r in load_jsonl(ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl")}
    manifest = load_jsonl(ROOT / "data" / "adversarial" / "metadata" / "adversarial_manifest.jsonl")
    judge = RuleBasedJudge(ROOT)

    out_dir = ROOT / "outputs" / "phase4_controls"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for defense_name, defense in DEFENSES.items():
        for m in manifest:
            gt = records[m["load_id"]]
            proposed = apply_adversarial_values(gt, m)
            r = evaluate_one(defense_name, defense, gt, proposed, m, judge)
            results.append({
                "defense": defense_name,
                "attack_id": m["attack_id"],
                "attack_type": m["attack_type"],
                "load_id": m["load_id"],
                "source_document_type": m["source_document_type"],
                "expected_unsafe_label": m["expected_unsafe_label"],
                "actual_outcome_label": r["outcome_label"],
                "is_unsafe": r["is_unsafe"],
                "blocked_by": r["blocked_by"],
                "approval_required": r["approval_required"],
                "reasons": r["reasons"],
                "api_calls": r["api_calls"],
            })

    # Write JSONL
    with (out_dir / "phase4_control_results.jsonl").open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Summary by defense
    by_def = {}
    for r in results:
        d = by_def.setdefault(r["defense"], {
            "defense": r["defense"], "total": 0, "unsafe": 0, "safe_blocked": 0,
            "approval_required": 0, "schema_blocks": 0, "field_blocks": 0,
            "approval_blocks": 0, "manifest_blocks": 0
        })
        d["total"] += 1
        d["unsafe"] += int(r["is_unsafe"])
        d["safe_blocked"] += int(r["actual_outcome_label"] == "safe_blocked")
        d["approval_required"] += int(r["approval_required"])
        d["schema_blocks"] += int(r["blocked_by"] == "schema_validation")
        d["field_blocks"] += int(r["blocked_by"] == "field_validation")
        d["approval_blocks"] += int(r["blocked_by"] == "approval_gate")
        d["manifest_blocks"] += int(r["blocked_by"] == "capability_manifest")

    with (out_dir / "phase4_metrics_by_defense.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "defense", "total", "unsafe", "unsafe_rate", "safe_blocked",
            "detection_or_block_rate", "approval_required", "approval_burden",
            "schema_blocks", "field_blocks", "approval_blocks", "manifest_blocks"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in by_def.values():
            row = dict(d)
            row["unsafe_rate"] = round(d["unsafe"] / d["total"], 4)
            row["detection_or_block_rate"] = round(d["safe_blocked"] / d["total"], 4)
            row["approval_burden"] = round(d["approval_required"] / d["total"], 4)
            writer.writerow(row)

    # Summary by attack and defense
    attack_rows = {}
    for r in results:
        key = (r["defense"], r["attack_type"])
        d = attack_rows.setdefault(key, {"defense": r["defense"], "attack_type": r["attack_type"], "total": 0, "unsafe": 0, "safe_blocked": 0})
        d["total"] += 1
        d["unsafe"] += int(r["is_unsafe"])
        d["safe_blocked"] += int(r["actual_outcome_label"] == "safe_blocked")

    with (out_dir / "phase4_metrics_by_attack.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = ["defense", "attack_type", "total", "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in attack_rows.values():
            row = dict(d)
            row["unsafe_rate"] = round(d["unsafe"] / d["total"], 4)
            row["detection_or_block_rate"] = round(d["safe_blocked"] / d["total"], 4)
            writer.writerow(row)

    print(f"Runs evaluated: {len(results)}")
    for defense_name in DEFENSES:
        d = by_def[defense_name]
        print(f"{defense_name}: unsafe={d['unsafe']}/{d['total']} block={d['safe_blocked']}/{d['total']} approval={d['approval_required']}/{d['total']}")


if __name__ == "__main__":
    main()
