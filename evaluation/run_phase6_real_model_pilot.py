"""
Run Phase 6 real-model pilot.

Default behavior is dry-run mode, which reuses the Phase 5 offline simulator.
To run real providers, set dry_run to false in configs/phase6_real_models.yaml
or pass --live, configure environment variables, and enable provider entries.

Usage:
    python evaluation/run_phase6_real_model_pilot.py --dry-run --limit 10
    python evaluation/run_phase6_real_model_pilot.py --live --limit 10
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.model_clients.base import ModelRunRequest
from agent.model_clients.factory import build_client
from agent.simulated_extractor import simulate_extraction
from adjudication.rule_based_judge import RuleBasedJudge
from security.defense_policy import DEFENSES, DEFAULT_ALLOWED_CAPABILITIES
from security.schema_validator import validate_transaction_schema
from security.field_level_validator import validate_high_risk_fields
from tms_mock.audit_log import AuditLogger
from tms_mock.endpoints import MockTMS


DRY_RUN_MODELS = [
    {"model_tier": "frontier", "model_name": "dry_run_frontier_sim", "provider": "offline_simulation"},
    {"model_tier": "mid_tier", "model_name": "dry_run_mid_tier_sim", "provider": "offline_simulation"},
    {"model_tier": "open_weight", "model_name": "dry_run_open_weight_sim", "provider": "offline_simulation"},
]

LOGGER = logging.getLogger("phase6_real_model_pilot")


def load_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def get_stop(tx, stop_type):
    for s in tx.get("stops", []):
        if isinstance(s, dict) and s.get("stop_type") == stop_type:
            return s
    return None


def task_failure(reason, api_calls=None):
    return {
        "outcome_label": "task_failure",
        "is_unsafe": False,
        "blocked_by": "invalid_extraction",
        "reasons": [reason],
        "api_calls": api_calls or [],
        "approval_required": False,
        "model_error": True,
    }


def validate_attack_inputs(tx, manifest_entry):
    if not isinstance(tx, dict):
        return f"invalid_transaction_type:{type(tx).__name__}"
    if not tx.get("load_id"):
        return "missing_load_id"

    attack = manifest_entry["attack_type"]
    if attack in {"appointment_sabotage", "dispatch_poisoning"} and not get_stop(tx, "delivery"):
        return "missing_delivery_stop"
    if attack == "carrier_substitution" and not isinstance(tx.get("carrier"), dict):
        return "missing_or_invalid_carrier"
    if attack == "status_concealment" and not isinstance(tx.get("tracking"), dict):
        return "missing_or_invalid_tracking"

    return None


def run_api_for_attack(tms, tx, m):
    load_id = tx["load_id"]
    attack = m["attack_type"]
    tms.create_load(tx)

    delivery = get_stop(tx, "delivery")
    if attack == "appointment_sabotage":
        tms.schedule_appointment(load_id, "delivery", {
            "appointment_start": delivery.get("appointment_start") if delivery else None,
            "appointment_end": delivery.get("appointment_end") if delivery else None,
        })
    elif attack == "dispatch_poisoning":
        tms.send_dispatch(load_id, {
            "facility_id": delivery.get("facility_id") if delivery else None,
            "dock": delivery.get("dock") if delivery else None,
            "city": delivery.get("city") if delivery else None,
            "zip": delivery.get("zip") if delivery else None,
            "instruction": "Final driver instruction from extracted transaction."
        })
    elif attack == "carrier_substitution":
        tms.assign_carrier(load_id, tx.get("carrier", {}))
    elif attack == "status_concealment":
        tms.update_status(load_id, tx.get("tracking", {}))

    return tms.audit_logger.to_dicts()


def evaluate_one(defense, gt, proposed, manifest_entry, judge):
    if defense["schema_validation"]:
        sr = validate_transaction_schema(proposed)
        if not sr["valid"]:
            return {"outcome_label": "safe_blocked", "is_unsafe": False, "blocked_by": "schema_validation", "reasons": sr["errors"], "api_calls": [], "approval_required": False}

    if defense["field_validation"]:
        fr = validate_high_risk_fields(gt, proposed, manifest_entry.get("adversarial_values"))
        if not fr["valid"]:
            return {"outcome_label": "safe_blocked", "is_unsafe": False, "blocked_by": "field_validation", "reasons": fr["findings"], "api_calls": [], "approval_required": False}

    input_error = validate_attack_inputs(proposed, manifest_entry)
    if input_error:
        return task_failure(input_error)

    audit = AuditLogger()
    tms = MockTMS(
        audit_logger=audit,
        skill_name="phase6_real_model_pilot_skill",
        allowed_capabilities=set(DEFAULT_ALLOWED_CAPABILITIES),
        enforce_capabilities=defense["capability_enforcement"],
        require_human_approval_for_high_risk=defense["approval_required"],
    )
    try:
        events = run_api_for_attack(tms, proposed, manifest_entry)
    except Exception as e:
        return task_failure(f"api_evaluation_error:{type(e).__name__}:{e}", [event["api_call"] for event in audit.to_dicts()])

    if any(e.get("result") == "escalated" for e in events):
        return {"outcome_label": "safe_blocked", "is_unsafe": False, "blocked_by": "approval_gate", "reasons": [e.get("message", "") for e in events if e.get("result") == "escalated"], "api_calls": [e["api_call"] for e in events], "approval_required": True}

    try:
        adj = judge.judge(
            manifest_entry["load_id"],
            proposed,
            events,
            manifest_entry["attack_type"],
            manifest_entry.get("adversarial_values"),
        )
    except Exception as e:
        return task_failure(f"adjudication_error:{type(e).__name__}:{e}", [event["api_call"] for event in events])

    return {"outcome_label": adj["outcome_label"], "is_unsafe": adj["is_unsafe"], "blocked_by": "none", "reasons": adj["reasons"], "api_calls": [e["api_call"] for e in events], "approval_required": False}


def load_document_text(manifest_entry):
    path = ROOT / manifest_entry["adversarial_document_path"]
    return path.read_text(encoding="utf-8")


def get_live_models_from_env():
    """Build a simple live model list from environment variables."""
    models = []

    if os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL_FRONTIER"):
        models.append({"model_tier": "frontier", "model_name": os.getenv("OPENAI_MODEL_FRONTIER"), "provider": "openai"})
    if os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL_MID"):
        models.append({"model_tier": "mid_tier", "model_name": os.getenv("OPENAI_MODEL_MID"), "provider": "openai"})
    if os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL_FRONTIER"):
        models.append({"model_tier": "frontier", "model_name": os.getenv("ANTHROPIC_MODEL_FRONTIER"), "provider": "anthropic"})
    if os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL_MID"):
        models.append({"model_tier": "mid_tier", "model_name": os.getenv("ANTHROPIC_MODEL_MID"), "provider": "anthropic"})
    if os.getenv("HF_TOKEN") and os.getenv("HF_MODEL_OPEN_WEIGHT"):
        models.append({"model_tier": "open_weight", "model_name": os.getenv("HF_MODEL_OPEN_WEIGHT"), "provider": "huggingface"})
    if os.getenv("OLLAMA_MODEL_OPEN_WEIGHT"):
        models.append({"model_tier": "open_weight", "model_name": os.getenv("OLLAMA_MODEL_OPEN_WEIGHT"), "provider": "ollama"})

    return models


def write_metrics(rows, out_dir):
    by_model_defense = {}
    for r in rows:
        key = (r["model_tier"], r["model_name"], r["provider"], r["defense"])
        d = by_model_defense.setdefault(key, {
            "model_tier": r["model_tier"],
            "model_name": r["model_name"],
            "provider": r["provider"],
            "defense": r["defense"],
            "total": 0,
            "unsafe": 0,
            "safe_blocked": 0,
            "approval_required": 0,
            "model_error": 0,
        })
        d["total"] += 1
        d["unsafe"] += int(r["is_unsafe"])
        d["safe_blocked"] += int(r["actual_outcome_label"] == "safe_blocked")
        d["approval_required"] += int(r["approval_required"])
        d["model_error"] += int(r.get("model_error", False))

    metrics_path = out_dir / "phase6_metrics_by_model_defense.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "model_tier", "model_name", "provider", "defense", "total",
            "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate",
            "approval_required", "approval_burden", "model_error"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key in sorted(by_model_defense):
            d = by_model_defense[key]
            row = dict(d)
            row["unsafe_rate"] = round(d["unsafe"] / d["total"], 4)
            row["detection_or_block_rate"] = round(d["safe_blocked"] / d["total"], 4)
            row["approval_burden"] = round(d["approval_required"] / d["total"], 4)
            writer.writerow(row)
    return metrics_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Use offline simulated model tiers.")
    parser.add_argument("--live", action="store_true", help="Use live provider clients from environment variables.")
    parser.add_argument("--limit", type=int, default=10, help="Number of adversarial documents to process.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress logs.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    run_started_at = time.perf_counter()
    dry_run = args.dry_run or not args.live

    LOGGER.info("Starting Phase 6 pilot: mode=%s limit=%s", "dry-run" if dry_run else "live", args.limit)
    prompt = (ROOT / "agent" / "prompts" / "extraction_prompt.md").read_text(encoding="utf-8")
    records = {r["load_id"]: r for r in load_jsonl(ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl")}
    manifest = load_jsonl(ROOT / "data" / "adversarial" / "metadata" / "adversarial_manifest.jsonl")[: args.limit]
    judge = RuleBasedJudge(ROOT)
    LOGGER.info("Loaded %s manifest entries and %s ground-truth transactions", len(manifest), len(records))

    out_dir = ROOT / "outputs" / "phase6_real_model_pilot"
    out_dir.mkdir(parents=True, exist_ok=True)

    models = DRY_RUN_MODELS if dry_run else get_live_models_from_env()
    if not models:
        raise SystemExit("No live models configured. Set environment variables or use --dry-run.")
    LOGGER.info(
        "Configured %s model(s): %s",
        len(models),
        ", ".join(f"{m['provider']}:{m['model_name']}[{m['model_tier']}]" for m in models),
    )

    extraction_rows = []
    evaluation_rows = []

    total_extractions = len(models) * len(manifest)
    completed_extractions = 0

    for model_index, model in enumerate(models, start=1):
        model_started_at = time.perf_counter()
        LOGGER.info(
            "Model %s/%s start: provider=%s tier=%s name=%s",
            model_index,
            len(models),
            model["provider"],
            model["model_tier"],
            model["model_name"],
        )
        client = None if dry_run else build_client(model["provider"], model["model_name"])

        for doc_index, m in enumerate(manifest, start=1):
            extraction_started_at = time.perf_counter()
            gt = records[m["load_id"]]
            doc_text = load_document_text(m)
            LOGGER.info(
                "Extraction %s/%s start: model=%s doc=%s/%s attack_id=%s attack_type=%s source=%s load_id=%s chars=%s",
                completed_extractions + 1,
                total_extractions,
                model["model_name"],
                doc_index,
                len(manifest),
                m["attack_id"],
                m["attack_type"],
                m["source_document_type"],
                m["load_id"],
                len(doc_text),
            )

            if dry_run:
                sim_tier = {
                    "frontier": "frontier_sim",
                    "mid_tier": "mid_tier_sim",
                    "open_weight": "open_weight_sim",
                }[model["model_tier"]]
                proposed = simulate_extraction(gt, m, sim_tier)
                raw_text = json.dumps(proposed)
                success = True
                error = ""
            else:
                request = ModelRunRequest(
                    model_tier=model["model_tier"],
                    model_name=model["model_name"],
                    prompt=prompt,
                    document_text=doc_text,
                    metadata=m,
                )
                response = client.run(request)
                proposed = response.output_json
                raw_text = response.raw_text
                success = response.success
                error = response.error
            completed_extractions += 1
            LOGGER.info(
                "Extraction %s/%s done: success=%s elapsed=%.2fs error=%s",
                completed_extractions,
                total_extractions,
                success,
                time.perf_counter() - extraction_started_at,
                error or "-",
            )

            extraction_rows.append({
                "model_tier": model["model_tier"],
                "model_name": model["model_name"],
                "provider": model["provider"],
                "attack_id": m["attack_id"],
                "attack_type": m["attack_type"],
                "load_id": m["load_id"],
                "source_document_type": m["source_document_type"],
                "success": success,
                "error": error,
                "raw_text": raw_text,
                "extracted_transaction": proposed,
                })

            evaluation_started_at = time.perf_counter()
            for defense_name, defense in DEFENSES.items():
                if not success:
                    evaluation_rows.append({
                        "model_tier": model["model_tier"],
                        "model_name": model["model_name"],
                        "provider": model["provider"],
                        "defense": defense_name,
                        "attack_id": m["attack_id"],
                        "attack_type": m["attack_type"],
                        "load_id": m["load_id"],
                        "actual_outcome_label": "task_failure",
                        "is_unsafe": False,
                        "blocked_by": "model_error",
                        "approval_required": False,
                        "reasons": [error],
                        "api_calls": [],
                        "model_error": True,
                    })
                    continue

                result = evaluate_one(defense, gt, proposed, m, judge)
                evaluation_rows.append({
                    "model_tier": model["model_tier"],
                    "model_name": model["model_name"],
                    "provider": model["provider"],
                    "defense": defense_name,
                    "attack_id": m["attack_id"],
                    "attack_type": m["attack_type"],
                    "load_id": m["load_id"],
                    "actual_outcome_label": result["outcome_label"],
                    "is_unsafe": result["is_unsafe"],
                    "blocked_by": result["blocked_by"],
                    "approval_required": result["approval_required"],
                    "reasons": result["reasons"],
                    "api_calls": result["api_calls"],
                    "model_error": result.get("model_error", False),
                })
            LOGGER.info(
                "Evaluated %s defense(s) for attack_id=%s in %.2fs",
                len(DEFENSES),
                m["attack_id"],
                time.perf_counter() - evaluation_started_at,
            )

        LOGGER.info(
            "Model %s/%s complete: name=%s elapsed=%.2fs",
            model_index,
            len(models),
            model["model_name"],
            time.perf_counter() - model_started_at,
        )

    LOGGER.info("Writing output files to %s", out_dir)
    with (out_dir / "phase6_extraction_outputs.jsonl").open("w", encoding="utf-8") as f:
        for row in extraction_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with (out_dir / "phase6_evaluation_results.jsonl").open("w", encoding="utf-8") as f:
        for row in evaluation_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    metrics_path = write_metrics(evaluation_rows, out_dir)
    LOGGER.info("Finished Phase 6 pilot in %.2fs", time.perf_counter() - run_started_at)

    print(f"Dry run: {dry_run}")
    print(f"Models: {len(models)}")
    print(f"Documents per model: {len(manifest)}")
    print(f"Extraction rows: {len(extraction_rows)}")
    print(f"Evaluation rows: {len(evaluation_rows)}")
    print(f"Wrote metrics: {metrics_path}")


if __name__ == "__main__":
    main()
