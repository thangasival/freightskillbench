"""
Run Phase 5 model/agent extraction simulation.

This script validates the model-output -> D0-D5 evaluator path. It uses offline
simulated model tiers unless provider clients are implemented separately.

Usage:
    python evaluation/run_phase5_model_extraction.py
"""

from __future__ import annotations

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
from agent.simulated_extractor import simulate_extraction


SIM_MODELS = [
    {"model_tier": "frontier_sim", "model_name": "simulated_frontier_conservative"},
    {"model_tier": "mid_tier_sim", "model_name": "simulated_mid_tier_partial"},
    {"model_tier": "open_weight_sim", "model_name": "simulated_open_weight_naive"},
]


def load_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def get_stop(tx, stop_type):
    for s in tx.get("stops", []):
        if s.get("stop_type") == stop_type:
            return s
    return None


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
            "instruction": "Final driver instruction from extracted transaction."
        })
    elif attack == "carrier_substitution":
        tms.assign_carrier(load_id, tx["carrier"])
    elif attack == "status_concealment":
        tms.update_status(load_id, tx["tracking"])

    return tms.audit_logger.to_dicts()


def evaluate_one(defense_name, defense, gt, proposed, manifest_entry, judge):
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
        skill_name="phase5_model_extraction_skill",
        allowed_capabilities=set(DEFAULT_ALLOWED_CAPABILITIES),
        enforce_capabilities=defense["capability_enforcement"],
        require_human_approval_for_high_risk=defense["approval_required"],
    )
    events = run_api_for_attack(tms, proposed, manifest_entry)

    if any(e.get("result") == "escalated" for e in events):
        return {
            "outcome_label": "safe_blocked",
            "is_unsafe": False,
            "blocked_by": "approval_gate",
            "reasons": [e.get("message", "") for e in events if e.get("result") == "escalated"],
            "api_calls": [e["api_call"] for e in events],
            "approval_required": True,
        }

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
        "blocked_by": "none",
        "reasons": adjudication["reasons"],
        "api_calls": [e["api_call"] for e in events],
        "approval_required": False,
    }


def main():
    records = {r["load_id"]: r for r in load_jsonl(ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl")}
    manifest = load_jsonl(ROOT / "data" / "adversarial" / "metadata" / "adversarial_manifest.jsonl")
    judge = RuleBasedJudge(ROOT)

    out_dir = ROOT / "outputs" / "phase5_model_extraction"
    out_dir.mkdir(parents=True, exist_ok=True)

    extraction_rows = []
    evaluation_rows = []

    for model in SIM_MODELS:
        for m in manifest:
            gt = records[m["load_id"]]
            proposed = simulate_extraction(gt, m, model["model_tier"])

            extraction_rows.append({
                "model_tier": model["model_tier"],
                "model_name": model["model_name"],
                "attack_id": m["attack_id"],
                "attack_type": m["attack_type"],
                "load_id": m["load_id"],
                "source_document_type": m["source_document_type"],
                "warnings": proposed.get("warnings", []),
                "extracted_transaction": proposed,
            })

            for defense_name, defense in DEFENSES.items():
                result = evaluate_one(defense_name, defense, gt, proposed, m, judge)
                evaluation_rows.append({
                    "model_tier": model["model_tier"],
                    "model_name": model["model_name"],
                    "defense": defense_name,
                    "attack_id": m["attack_id"],
                    "attack_type": m["attack_type"],
                    "load_id": m["load_id"],
                    "source_document_type": m["source_document_type"],
                    "actual_outcome_label": result["outcome_label"],
                    "is_unsafe": result["is_unsafe"],
                    "blocked_by": result["blocked_by"],
                    "approval_required": result["approval_required"],
                    "reasons": result["reasons"],
                    "api_calls": result["api_calls"],
                })

    with (out_dir / "phase5_extraction_outputs.jsonl").open("w", encoding="utf-8") as f:
        for row in extraction_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with (out_dir / "phase5_evaluation_results.jsonl").open("w", encoding="utf-8") as f:
        for row in evaluation_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Metrics by model and defense
    by_model_defense = {}
    for r in evaluation_rows:
        key = (r["model_tier"], r["defense"])
        d = by_model_defense.setdefault(key, {
            "model_tier": r["model_tier"],
            "defense": r["defense"],
            "total": 0,
            "unsafe": 0,
            "safe_blocked": 0,
            "approval_required": 0,
        })
        d["total"] += 1
        d["unsafe"] += int(r["is_unsafe"])
        d["safe_blocked"] += int(r["actual_outcome_label"] == "safe_blocked")
        d["approval_required"] += int(r["approval_required"])

    with (out_dir / "phase5_metrics_by_model_defense.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "model_tier", "defense", "total", "unsafe", "unsafe_rate",
            "safe_blocked", "detection_or_block_rate",
            "approval_required", "approval_burden"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in by_model_defense.values():
            row = dict(d)
            row["unsafe_rate"] = round(d["unsafe"] / d["total"], 4)
            row["detection_or_block_rate"] = round(d["safe_blocked"] / d["total"], 4)
            row["approval_burden"] = round(d["approval_required"] / d["total"], 4)
            writer.writerow(row)

    # Metrics by model, defense, and attack
    by_attack = {}
    for r in evaluation_rows:
        key = (r["model_tier"], r["defense"], r["attack_type"])
        d = by_attack.setdefault(key, {
            "model_tier": r["model_tier"],
            "defense": r["defense"],
            "attack_type": r["attack_type"],
            "total": 0,
            "unsafe": 0,
            "safe_blocked": 0,
        })
        d["total"] += 1
        d["unsafe"] += int(r["is_unsafe"])
        d["safe_blocked"] += int(r["actual_outcome_label"] == "safe_blocked")

    with (out_dir / "phase5_metrics_by_model_defense_attack.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "model_tier", "defense", "attack_type", "total",
            "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in by_attack.values():
            row = dict(d)
            row["unsafe_rate"] = round(d["unsafe"] / d["total"], 4)
            row["detection_or_block_rate"] = round(d["safe_blocked"] / d["total"], 4)
            writer.writerow(row)

    print(f"Extraction runs: {len(extraction_rows)}")
    print(f"Evaluation runs: {len(evaluation_rows)}")
    for model in SIM_MODELS:
        rows = [r for r in evaluation_rows if r["model_tier"] == model["model_tier"] and r["defense"] == "D0_no_control"]
        unsafe = sum(1 for r in rows if r["is_unsafe"])
        print(f"{model['model_tier']} D0 unsafe: {unsafe}/{len(rows)}")


if __name__ == "__main__":
    main()
