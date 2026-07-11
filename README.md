# FreightSkillBench Manuscript Table and Figure Generation Package

## Purpose

This package generates manuscript-ready tables, PNG figures, Markdown tables, and LaTeX tables from the corrected Phase 6 live metrics.

## Required input files

Place these files in one input folder, for example:

```text
outputs/FINAL_PHASE6_LIVE_RESULTS/
  phase6_limit60_combined_model_defense_metrics.csv
  phase6_limit60_corrected_model_defense_attack_metrics.csv
  phase6_limit60_corrected_model_defense_doctype_metrics.csv
  phase6_limit60_extraction_success_summary.csv
```

## Install dependencies

```bash
pip install pandas matplotlib tabulate
```

`tabulate` is needed for Pandas Markdown table export.

## Run on Windows CMD

From the project root:

```cmd
python scripts\generate_paper_tables_figures.py --input-dir outputs\FINAL_PHASE6_LIVE_RESULTS --output-dir manuscript_artifacts
```

## Run on macOS / Linux

```bash
python scripts/generate_paper_tables_figures.py --input-dir outputs/FINAL_PHASE6_LIVE_RESULTS --output-dir manuscript_artifacts
```

## Outputs

```text
manuscript_artifacts/
  tables/
    table_1_attack_taxonomy.csv
    table_2_model_defense_unsafe_rates.csv
    table_3_attack_breakdown.csv
    table_4_document_type_breakdown.csv
    table_5_extraction_success.csv

  markdown/
    table_1_attack_taxonomy.md
    table_2_model_defense_unsafe_rates.md
    table_3_attack_breakdown.md
    table_4_document_type_breakdown.md
    table_5_extraction_success.md
    results_narrative_draft.md

  latex/
    table_1_attack_taxonomy.tex
    table_2_model_defense_unsafe_rates.tex
    table_3_attack_breakdown.tex
    table_4_document_type_breakdown.tex
    table_5_extraction_success.tex

  figures/
    figure_3_model_defense_unsafe_heatmap.png
    figure_4_average_unsafe_rate_by_defense.png
    figure_5_attack_defense_unsafe_rate.png
    figure_6_doctype_unsafe_rate_d0.png
    figure_7_extraction_success_rate.png
```

## Mermaid figures

See:

```text
docs/mermaid_figures.md
```

This file includes Mermaid code for:

1. SkillChain-Logistics threat model
2. FreightSkillBench benchmark pipeline
3. D0-D5 defense stack
4. Attack taxonomy
5. Cyber/logical interdependency framing
6. Results interpretation logic

## Recommended paper usage

Use these as the core manuscript artifacts:

| Manuscript item | Generated source |
|---|---|
| Table 1 | `table_1_attack_taxonomy.*` |
| Table 2 | `table_2_model_defense_unsafe_rates.*` |
| Table 3 | `table_3_attack_breakdown.*` |
| Table 4 | `table_4_document_type_breakdown.*` |
| Table 5 | `table_5_extraction_success.*` |
| Figure 1 | Mermaid threat model |
| Figure 2 | Mermaid benchmark pipeline |
| Figure 3 | `figure_3_model_defense_unsafe_heatmap.png` |
| Figure 4 | `figure_4_average_unsafe_rate_by_defense.png` |
| Figure 5 | `figure_5_attack_defense_unsafe_rate.png` |
| Figure 6 | `figure_6_doctype_unsafe_rate_d0.png` |


## Fix for empty document-type figure

If `figure_6_doctype_unsafe_rate_d0.png` is blank or Table 4 has `NaN` under `source_document_type`, regenerate the corrected metrics from raw Phase 6 output folders:

```cmd
python scripts\regenerate_corrected_metrics_from_raw_outputs.py --raw-output-dir outputs --output-dir outputs\FINAL_PHASE6_LIVE_RESULTS
```

Then regenerate tables and figures:

```cmd
python scripts\generate_paper_tables_figures.py --input-dir outputs\FINAL_PHASE6_LIVE_RESULTS --output-dir manuscript_artifacts
```
