from copy import deepcopy
from pathlib import Path
import csv, json, sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tms_mock.audit_log import AuditLogger
from tms_mock.endpoints import MockTMS
from adjudication.rule_based_judge import RuleBasedJudge

def load_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def get_stop(tx, stop_type):
    for s in tx.get("stops", []):
        if s.get("stop_type") == stop_type:
            return s
    return None

def canonical_map():
    return {r["load_id"]: r for r in load_jsonl(ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl")}

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
        # Simulates unsafe concealment: the source has an exception, but final tracking omits it.
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

def main():
    out_dir = ROOT / "outputs" / "phase3_demo"
    out_dir.mkdir(parents=True, exist_ok=True)

    records = canonical_map()
    manifest = load_jsonl(ROOT / "data" / "adversarial" / "metadata" / "adversarial_manifest.jsonl")
    judge = RuleBasedJudge(ROOT)

    results = []
    for m in manifest:
        gt = records[m["load_id"]]
        final_tx = apply_adversarial_values(gt, m)

        audit = AuditLogger()
        tms = MockTMS(audit_logger=audit, skill_name="phase3_demo_skill", enforce_capabilities=False)
        audit_events = run_api_for_attack(tms, final_tx, m)

        adj = judge.judge(
            load_id=m["load_id"],
            final_transaction=final_tx,
            audit_events=audit_events,
            attack_type=m["attack_type"],
            adversarial_values=m.get("adversarial_values"),
        )

        results.append({
            "attack_id": m["attack_id"],
            "attack_type": m["attack_type"],
            "load_id": m["load_id"],
            "source_document_type": m["source_document_type"],
            "expected_unsafe_label": m["expected_unsafe_label"],
            "actual_outcome_label": adj["outcome_label"],
            "is_unsafe": adj["is_unsafe"],
            "reasons": adj["reasons"],
            "api_calls": [e["api_call"] for e in audit_events],
        })

    result_path = out_dir / "phase3_demo_results.jsonl"
    with result_path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = {}
    for r in results:
        key = (r["attack_type"], r["actual_outcome_label"])
        counts[key] = counts.get(key, 0) + 1

    summary_path = out_dir / "phase3_metrics_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["attack_type", "outcome_label", "count"])
        writer.writeheader()
        for (attack_type, label), count in sorted(counts.items()):
            writer.writerow({"attack_type": attack_type, "outcome_label": label, "count": count})

    print(f"Runs evaluated: {len(results)}")
    print(f"Unsafe outcomes: {sum(1 for r in results if r['is_unsafe'])}")
    print(f"Wrote: {result_path}")
    print(f"Wrote: {summary_path}")

if __name__ == "__main__":
    main()
