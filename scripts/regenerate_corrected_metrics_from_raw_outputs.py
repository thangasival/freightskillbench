#!/usr/bin/env python
r"""
Regenerate corrected Phase 6 metrics from raw live output folders.

This script fixes the document-type issue by deriving source_document_type
from attack_id suffixes such as -EMAIL, -PDF_TEXT, -EDI_204, and -EDI_214.

Example CMD:

  python scripts\regenerate_corrected_metrics_from_raw_outputs.py ^
    --raw-output-dir C:\SkillChain-Logistics\freightskillbench_phase6_v06\outputs ^
    --output-dir C:\SkillChain-Logistics\freightskillbench_phase6_v06\outputs\FINAL_PHASE6_LIVE_RESULTS

The raw-output-dir should contain folders such as:
  phase6_real_model_pilot_openai_frontier_limit60
  phase6_real_model_pilot_anthropic_frontier_limit60
  phase6_real_model_pilot_open_weight_limit60
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def derive_source_document_type(attack_id: str) -> str:
    attack_id = attack_id or ""
    if attack_id.endswith("-PDF_TEXT"):
        return "pdf_text"
    if attack_id.endswith("-EDI_204"):
        return "edi_204"
    if attack_id.endswith("-EDI_210"):
        return "edi_210"
    if attack_id.endswith("-EDI_214"):
        return "edi_214"
    if attack_id.endswith("-EMAIL"):
        return "email"
    return "unknown"


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def aggregate_eval(df: pd.DataFrame, group_cols: list[str]) -> pd.DataFrame:
    g = df.groupby(group_cols, dropna=False)
    out = g.agg(
        total=("is_unsafe", "size"),
        unsafe=("is_unsafe", lambda s: int(pd.Series(s).fillna(False).sum())),
        safe_blocked=("actual_outcome_label", lambda s: int((s == "safe_blocked").sum())),
        approval_required=("approval_required", lambda s: int(pd.Series(s).fillna(False).sum())),
        model_error=("model_error", lambda s: int(pd.Series(s).fillna(False).sum())),
        task_failure=("actual_outcome_label", lambda s: int((s == "task_failure").sum())),
    ).reset_index()

    out["unsafe_rate"] = (out["unsafe"] / out["total"]).round(4)
    out["block_rate"] = (out["safe_blocked"] / out["total"]).round(4)
    out["approval_burden"] = (out["approval_required"] / out["total"]).round(4)
    out["model_error_rate"] = (out["model_error"] / out["total"]).round(4)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-output-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    raw_output_dir = Path(args.raw_output_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    eval_rows = []
    extraction_rows = []

    # Support both layouts:
    #   outputs/phase6_real_model_pilot_*_limit60/phase6_evaluation_results.jsonl
    #   outputs/FINAL_PHASE6_LIVE_RESULTS/*_limit60/phase6_evaluation_results.jsonl
    # A recursive search is safer for replication packages because raw folders may
    # be archived either at the outputs root or inside FINAL_PHASE6_LIVE_RESULTS.
    folders = sorted({p.parent for p in raw_output_dir.rglob("phase6_evaluation_results.jsonl")})

    for folder in folders:
        eval_file = folder / "phase6_evaluation_results.jsonl"
        extract_file = folder / "phase6_extraction_outputs.jsonl"

        if eval_file.exists():
            for row in load_jsonl(eval_file):
                row["folder"] = folder.name
                row["source_document_type"] = derive_source_document_type(row.get("attack_id", ""))
                eval_rows.append(row)

        if extract_file.exists():
            for row in load_jsonl(extract_file):
                row["folder"] = folder.name
                row["source_document_type"] = derive_source_document_type(row.get("attack_id", ""))
                extraction_rows.append(row)

    if not eval_rows:
        raise FileNotFoundError(
            f"No phase6_evaluation_results.jsonl files found under {raw_output_dir}"
        )

    eval_df = pd.DataFrame(eval_rows)
    extract_df = pd.DataFrame(extraction_rows)

    model_defense = aggregate_eval(
        eval_df,
        ["folder", "model_tier", "model_name", "provider", "defense"],
    )
    attack = aggregate_eval(
        eval_df,
        ["folder", "model_tier", "model_name", "provider", "defense", "attack_type"],
    )
    doctype = aggregate_eval(
        eval_df,
        ["folder", "model_tier", "model_name", "provider", "defense", "source_document_type"],
    )

    model_defense.to_csv(output_dir / "phase6_limit60_combined_model_defense_metrics.csv", index=False)
    attack.to_csv(output_dir / "phase6_limit60_corrected_model_defense_attack_metrics.csv", index=False)
    doctype.to_csv(output_dir / "phase6_limit60_corrected_model_defense_doctype_metrics.csv", index=False)

    if not extract_df.empty:
        success = extract_df.groupby(
            ["folder", "model_tier", "model_name", "provider"],
            dropna=False,
        ).agg(
            total=("success", "size"),
            successful_extractions=("success", lambda s: int(pd.Series(s).fillna(False).sum())),
            failed_extractions=("success", lambda s: int((~pd.Series(s).fillna(False).astype(bool)).sum())),
        ).reset_index()
        success["success_rate"] = (success["successful_extractions"] / success["total"]).round(4)
        success.to_csv(output_dir / "phase6_limit60_extraction_success_summary.csv", index=False)

    print(f"Wrote corrected metrics to: {output_dir}")
    print("Document-type counts from evaluation rows:")
    print(eval_df["source_document_type"].value_counts(dropna=False).to_string())


if __name__ == "__main__":
    main()
