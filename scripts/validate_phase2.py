from pathlib import Path
import json
ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT / "data" / "adversarial" / "metadata" / "adversarial_manifest.jsonl"
gt = ROOT / "data" / "ground_truth" / "canonical_transactions.jsonl"
def main():
    records = {json.loads(l)["load_id"] for l in gt.open("r", encoding="utf-8") if l.strip()}
    count = 0; missing = 0; unknown = 0; attacks = {}
    for line in manifest.open("r", encoding="utf-8"):
        if not line.strip(): continue
        m = json.loads(line); count += 1
        attacks[m["attack_type"]] = attacks.get(m["attack_type"], 0) + 1
        unknown += int(m["load_id"] not in records)
        missing += int(not (ROOT / m["adversarial_document_path"]).exists())
    print(f"Manifest entries: {count}")
    print("Attack counts:")
    for k, v in sorted(attacks.items()): print(f"  {k}: {v}")
    print(f"Missing files: {missing}")
    print(f"Unknown load ids: {unknown}")
    if missing or unknown: raise SystemExit(1)
if __name__ == "__main__": main()
