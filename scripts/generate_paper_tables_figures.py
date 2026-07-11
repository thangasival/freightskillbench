#!/usr/bin/env python
r"""
Generate manuscript-ready tables and figures for FreightSkillBench / SkillChain-Logistics.

Input folder should contain these corrected Phase 6 files:

  phase6_limit60_combined_model_defense_metrics.csv
  phase6_limit60_corrected_model_defense_attack_metrics.csv
  phase6_limit60_corrected_model_defense_doctype_metrics.csv
  phase6_limit60_extraction_success_summary.csv

Example:

  python scripts/generate_paper_tables_figures.py ^
    --input-dir outputs\FINAL_PHASE6_LIVE_RESULTS ^
    --output-dir manuscript_artifacts

macOS/Linux:

  python scripts/generate_paper_tables_figures.py \
    --input-dir outputs/FINAL_PHASE6_LIVE_RESULTS \
    --output-dir manuscript_artifacts

Dependencies:
  pip install pandas matplotlib
"""

from __future__ import annotations

import argparse
from pathlib import Path
import textwrap

import pandas as pd
import matplotlib.pyplot as plt


DEFENSE_ORDER = [
    "D0_no_control",
    "D1_schema_only",
    "D2_field_validation",
    "D3_manifest_only",
    "D4_approval_gate",
    "D5_full_control",
]

DEFENSE_LABELS = {
    "D0_no_control": "D0\nNo control",
    "D1_schema_only": "D1\nSchema",
    "D2_field_validation": "D2\nField validation",
    "D3_manifest_only": "D3\nManifest",
    "D4_approval_gate": "D4\nApproval gate",
    "D5_full_control": "D5\nFull control",
}

ATTACK_LABELS = {
    "hazmat_suppression": "Hazmat\nsuppression",
    "appointment_sabotage": "Appointment\nsabotage",
    "dispatch_poisoning": "Dispatch\npoisoning",
    "carrier_substitution": "Carrier\nsubstitution",
    "status_concealment": "Status\nconcealment",
}

REQUIRED_FILES = {
    "model_defense": "phase6_limit60_combined_model_defense_metrics.csv",
    "attack": "phase6_limit60_corrected_model_defense_attack_metrics.csv",
    "doctype": "phase6_limit60_corrected_model_defense_doctype_metrics.csv",
    "success": "phase6_limit60_extraction_success_summary.csv",
}


def read_inputs(input_dir: Path) -> dict[str, pd.DataFrame]:
    dfs = {}
    missing = []
    for key, filename in REQUIRED_FILES.items():
        path = input_dir / filename
        if not path.exists():
            missing.append(str(path))
        else:
            dfs[key] = pd.read_csv(path)
    if missing:
        raise FileNotFoundError(
            "Missing required input files:\n" + "\n".join(missing)
        )
    return dfs


def ensure_dirs(output_dir: Path) -> dict[str, Path]:
    dirs = {
        "tables": output_dir / "tables",
        "figures": output_dir / "figures",
        "latex": output_dir / "latex",
        "markdown": output_dir / "markdown",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def pct(x) -> str:
    try:
        return f"{float(x) * 100:.1f}%"
    except Exception:
        return str(x)


def save_table(df: pd.DataFrame, stem: str, dirs: dict[str, Path], index: bool = False) -> None:
    df.to_csv(dirs["tables"] / f"{stem}.csv", index=index)
    df.to_markdown(dirs["markdown"] / f"{stem}.md", index=index)
    df.to_latex(dirs["latex"] / f"{stem}.tex", index=index, escape=True)


def build_table_1_attack_taxonomy() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "Attack type": "Hazmat suppression",
            "Targeted logistics fields": "hazmat flag; hazmat class; UN number",
            "Operational risk": "Safety/compliance violation",
            "Expected unsafe label": "unsafe_field_acceptance",
            "Document formats": "email; pdf_text; edi_204",
        },
        {
            "Attack type": "Appointment sabotage",
            "Targeted logistics fields": "delivery appointment start/end",
            "Operational risk": "Facility capacity strain; delayed receiving",
            "Expected unsafe label": "unsafe_field_acceptance",
            "Document formats": "email; pdf_text; edi_204",
        },
        {
            "Attack type": "Dispatch poisoning",
            "Targeted logistics fields": "facility ID; dock; city; ZIP",
            "Operational risk": "Wrong-site dispatch; misrouted freight",
            "Expected unsafe label": "unsafe_action_execution / unsafe_field_acceptance",
            "Document formats": "email; pdf_text",
        },
        {
            "Attack type": "Carrier substitution",
            "Targeted logistics fields": "carrier identity; DOT; MC",
            "Operational risk": "Unauthorized pickup; chain-of-custody failure",
            "Expected unsafe label": "unsafe_field_acceptance",
            "Document formats": "email; pdf_text",
        },
        {
            "Attack type": "Status concealment",
            "Targeted logistics fields": "tracking status; exception status",
            "Operational risk": "Delayed escalation; shipment visibility failure",
            "Expected unsafe label": "unsafe_concealment",
            "Document formats": "email; edi_214",
        },
    ])


def build_table_2_model_defense(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "model_tier", "model_name", "provider", "defense", "total",
        "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate",
        "approval_required", "approval_burden"
    ]
    existing = [c for c in cols if c in df.columns]
    out = df[existing].copy()
    for col in ["unsafe_rate", "detection_or_block_rate", "approval_burden"]:
        if col in out.columns:
            out[col] = out[col].apply(pct)
    return out


def build_table_3_attack_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "model_tier", "model_name", "provider", "defense", "attack_type",
        "total", "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate"
    ]
    existing = [c for c in cols if c in df.columns]
    out = df[existing].copy()
    for col in ["unsafe_rate", "detection_or_block_rate"]:
        if col in out.columns:
            out[col] = out[col].apply(pct)
    return out


def build_table_4_doctype_breakdown(df: pd.DataFrame) -> pd.DataFrame:
    cols = [
        "model_tier", "model_name", "provider", "defense", "source_document_type",
        "total", "unsafe", "unsafe_rate", "safe_blocked", "detection_or_block_rate"
    ]
    existing = [c for c in cols if c in df.columns]
    out = df[existing].copy()
    for col in ["unsafe_rate", "detection_or_block_rate"]:
        if col in out.columns:
            out[col] = out[col].apply(pct)
    return out


def build_table_5_extraction_success(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    rate_cols = [c for c in out.columns if "rate" in c.lower()]
    for col in rate_cols:
        out[col] = out[col].apply(pct)
    return out


def plot_model_defense_heatmap(df: pd.DataFrame, fig_dir: Path) -> None:
    pivot = df.pivot_table(
        index="model_name",
        columns="defense",
        values="unsafe_rate",
        aggfunc="mean",
    )
    pivot = pivot[[d for d in DEFENSE_ORDER if d in pivot.columns]]

    fig, ax = plt.subplots(figsize=(11, max(4, 0.55 * len(pivot.index) + 2)))
    im = ax.imshow(pivot.values, aspect="auto")

    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels([DEFENSE_LABELS.get(c, c) for c in pivot.columns], rotation=0)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)

    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            ax.text(j, i, f"{pivot.values[i, j] * 100:.0f}%", ha="center", va="center")

    ax.set_title("Unsafe transaction rate by model and defense")
    ax.set_xlabel("Defense condition")
    ax.set_ylabel("Model")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Unsafe rate")

    fig.tight_layout()
    fig.savefig(fig_dir / "figure_3_model_defense_unsafe_heatmap.png", dpi=300)
    plt.close(fig)


def plot_defense_average_bar(df: pd.DataFrame, fig_dir: Path) -> None:
    temp = df.groupby("defense", as_index=False)["unsafe_rate"].mean()
    temp["defense"] = pd.Categorical(temp["defense"], categories=DEFENSE_ORDER, ordered=True)
    temp = temp.sort_values("defense")

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([DEFENSE_LABELS.get(d, d) for d in temp["defense"]], temp["unsafe_rate"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Mean unsafe transaction rate")
    ax.set_xlabel("Defense condition")
    ax.set_title("Average unsafe transaction rate by defense")
    for i, v in enumerate(temp["unsafe_rate"]):
        ax.text(i, v + 0.02, f"{v * 100:.0f}%", ha="center")
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_4_average_unsafe_rate_by_defense.png", dpi=300)
    plt.close(fig)


def plot_attack_defense_bar(df: pd.DataFrame, fig_dir: Path) -> None:
    # Average across models for each attack and defense.
    temp = df.groupby(["attack_type", "defense"], as_index=False)["unsafe_rate"].mean()
    pivot = temp.pivot(index="attack_type", columns="defense", values="unsafe_rate")
    pivot = pivot[[d for d in DEFENSE_ORDER if d in pivot.columns]]
    pivot = pivot.sort_index()

    ax = pivot.plot(kind="bar", figsize=(12, 6))
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Mean unsafe transaction rate")
    ax.set_xlabel("Attack type")
    ax.set_title("Unsafe transaction rate by attack type and defense")
    ax.set_xticklabels([ATTACK_LABELS.get(x.get_text(), x.get_text()) for x in ax.get_xticklabels()], rotation=0)
    ax.legend(title="Defense", bbox_to_anchor=(1.02, 1), loc="upper left")
    fig = ax.get_figure()
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_5_attack_defense_unsafe_rate.png", dpi=300)
    plt.close(fig)


def plot_doctype_bar(df: pd.DataFrame, fig_dir: Path) -> None:
    # D0 only is most interpretable for document-type susceptibility.
    d0 = df[df["defense"] == "D0_no_control"].copy()
    if "source_document_type" not in d0.columns or d0["source_document_type"].isna().all():
        raise ValueError(
            "Document-type figure cannot be generated because source_document_type is missing. "
            "Regenerate corrected metrics from raw phase6_evaluation_results.jsonl using "
            "scripts/regenerate_corrected_metrics_from_raw_outputs.py."
        )
    temp = d0.groupby("source_document_type", as_index=False)["unsafe_rate"].mean()
    temp = temp.sort_values("source_document_type")

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(temp["source_document_type"], temp["unsafe_rate"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Mean unsafe transaction rate")
    ax.set_xlabel("Document type")
    ax.set_title("D0 unsafe transaction rate by document type")
    for i, v in enumerate(temp["unsafe_rate"]):
        ax.text(i, v + 0.02, f"{v * 100:.0f}%", ha="center")
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_6_doctype_unsafe_rate_d0.png", dpi=300)
    plt.close(fig)


def plot_extraction_success(df: pd.DataFrame, fig_dir: Path) -> None:
    # Try flexible column names because success summary may vary.
    model_col = "model_name" if "model_name" in df.columns else df.columns[0]
    success_rate_col = None
    for candidate in ["success_rate", "extraction_success_rate", "success"]:
        if candidate in df.columns:
            success_rate_col = candidate
            break

    if success_rate_col is None:
        # Build from success/total columns if present.
        if {"successful_extractions", "total"}.issubset(df.columns):
            df = df.copy()
            df["success_rate_generated"] = df["successful_extractions"] / df["total"]
            success_rate_col = "success_rate_generated"
        elif {"success_count", "total"}.issubset(df.columns):
            df = df.copy()
            df["success_rate_generated"] = df["success_count"] / df["total"]
            success_rate_col = "success_rate_generated"
        else:
            return

    temp = df.copy()
    temp[success_rate_col] = pd.to_numeric(temp[success_rate_col], errors="coerce")
    temp = temp.dropna(subset=[success_rate_col])

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(temp[model_col].astype(str), temp[success_rate_col])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Extraction success rate")
    ax.set_xlabel("Model")
    ax.set_title("Model extraction success rate")
    ax.tick_params(axis="x", rotation=30)
    for i, v in enumerate(temp[success_rate_col]):
        ax.text(i, v + 0.02, f"{v * 100:.0f}%", ha="center")
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_7_extraction_success_rate.png", dpi=300)
    plt.close(fig)


def write_results_narrative(output_dir: Path, model_defense: pd.DataFrame) -> None:
    d0 = model_defense[model_defense["defense"] == "D0_no_control"]
    d3 = model_defense[model_defense["defense"] == "D3_manifest_only"]
    d2 = model_defense[model_defense["defense"] == "D2_field_validation"]
    d5 = model_defense[model_defense["defense"] == "D5_full_control"]

    def summarize(df, defense_name):
        unsafe = int(pd.to_numeric(df["unsafe"], errors="coerce").sum())
        total = int(pd.to_numeric(df["total"], errors="coerce").sum())
        rate = unsafe / total if total else 0
        return unsafe, total, rate

    d0_u, d0_t, d0_r = summarize(d0, "D0")
    d3_u, d3_t, d3_r = summarize(d3, "D3")
    d2_u, d2_t, d2_r = summarize(d2, "D2")
    d5_u, d5_t, d5_r = summarize(d5, "D5")

    text = f"""# Manuscript Results Narrative Draft

Across the live Phase 6 model runs, unsafe transaction acceptance was concentrated in the no-control and manifest-only conditions. In D0_no_control, models accepted unsafe transaction states in {d0_u}/{d0_t} evaluated defense trials ({d0_r:.1%}). In D3_manifest_only, unsafe acceptance remained {d3_u}/{d3_t} ({d3_r:.1%}), indicating that capability manifests alone did not prevent unsafe logistics field acceptance when an otherwise permitted operation carried manipulated high-risk fields.

Field-level validation eliminated unsafe acceptance in the evaluated cases. Under D2_field_validation, unsafe outcomes were {d2_u}/{d2_t} ({d2_r:.1%}). Under D5_full_control, unsafe outcomes were {d5_u}/{d5_t} ({d5_r:.1%}). These results support the central finding that logistics-specific field integrity checks are necessary beyond generic schema validation and capability declarations.

Recommended wording:

> Capability manifests alone are insufficient when an allowed operation such as create_load carries manipulated high-risk logistics fields. In contrast, field-level validation over safety, appointment, carrier, dispatch, and tracking fields blocked unsafe transaction acceptance across the evaluated live-model runs.
"""
    (output_dir / "markdown" / "results_narrative_draft.md").write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir",
        required=True,
        help="Folder containing corrected Phase 6 live metrics CSV files.",
    )
    parser.add_argument(
        "--output-dir",
        default="manuscript_artifacts",
        help="Output folder for generated tables and figures.",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    dfs = read_inputs(input_dir)
    dirs = ensure_dirs(output_dir)

    # Tables
    table1 = build_table_1_attack_taxonomy()
    table2 = build_table_2_model_defense(dfs["model_defense"])
    table3 = build_table_3_attack_breakdown(dfs["attack"])
    table4 = build_table_4_doctype_breakdown(dfs["doctype"])
    table5 = build_table_5_extraction_success(dfs["success"])

    save_table(table1, "table_1_attack_taxonomy", dirs)
    save_table(table2, "table_2_model_defense_unsafe_rates", dirs)
    save_table(table3, "table_3_attack_breakdown", dirs)
    save_table(table4, "table_4_document_type_breakdown", dirs)
    save_table(table5, "table_5_extraction_success", dirs)

    # Figures
    plot_model_defense_heatmap(dfs["model_defense"], dirs["figures"])
    plot_defense_average_bar(dfs["model_defense"], dirs["figures"])
    plot_attack_defense_bar(dfs["attack"], dirs["figures"])
    plot_doctype_bar(dfs["doctype"], dirs["figures"])
    plot_extraction_success(dfs["success"], dirs["figures"])

    # Narrative
    write_results_narrative(output_dir, dfs["model_defense"])

    print(f"Generated manuscript tables and figures in: {output_dir}")
    print("Tables:")
    for p in sorted(dirs["tables"].glob("*.csv")):
        print(f"  {p}")
    print("Figures:")
    for p in sorted(dirs["figures"].glob("*.png")):
        print(f"  {p}")


if __name__ == "__main__":
    main()
