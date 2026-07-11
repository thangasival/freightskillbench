# FreightSkillBench Replication Package Validation Report

Validation status: **PASS**

## Package summary

- Files: 282
- Total size: 4,356,172 bytes
- `requirements.txt`: added
- `.env.example`: added
- `.gitignore`: added
- Missing manuscript-generation scripts from uploaded ZIP: added from the fixed generation package
- Figure 6 validation: `2400x1500, bytes=93464, non_white_ratio=0.547`

## Required files checked

- `requirements.txt`: OK
- `README.md`: OK
- `DATA_CARD.md`: OK
- `scripts/generate_paper_tables_figures.py`: OK
- `scripts/regenerate_corrected_metrics_from_raw_outputs.py`: OK
- `docs/mermaid_figures.md`: OK
- `.env.example`: OK
- `.gitignore`: OK
- `LICENSE_NOTE.md`: OK

## Validation commands

### `python scripts/validate_phase2.py`

- Exit code: `0`

Stdout excerpt:

```text
Manifest entries: 60
Attack counts:
  appointment_sabotage: 15
  carrier_substitution: 10
  dispatch_poisoning: 10
  hazmat_suppression: 15
  status_concealment: 10
Missing files: 0
Unknown load ids: 0
```
### `python evaluation/run_phase3_demo.py`

- Exit code: `0`

Stdout excerpt:

```text
Runs evaluated: 60
Unsafe outcomes: 60
Wrote: /mnt/data/freightskillbench_replication_FIXED/outputs/phase3_demo/phase3_demo_results.jsonl
Wrote: /mnt/data/freightskillbench_replication_FIXED/outputs/phase3_demo/phase3_metrics_summary.csv
```
### `python evaluation/run_phase4_controls.py`

- Exit code: `0`

Stdout excerpt:

```text
Runs evaluated: 360
D0_no_control: unsafe=60/60 block=0/60 approval=0/60
D1_schema_only: unsafe=60/60 block=0/60 approval=0/60
D2_field_validation: unsafe=0/60 block=60/60 approval=0/60
D3_manifest_only: unsafe=60/60 block=0/60 approval=0/60
D4_approval_gate: unsafe=0/60 block=60/60 approval=60/60
D5_full_control: unsafe=0/60 block=60/60 approval=0/60
```
### `python scripts/regenerate_corrected_metrics_from_raw_outputs.py --raw-output-dir outputs --output-dir outputs/FINAL_PHASE6_LIVE_RESULTS`

- Exit code: `0`

Stdout excerpt:

```text
Wrote corrected metrics to: outputs/FINAL_PHASE6_LIVE_RESULTS
Document-type counts from evaluation rows:
source_document_type
email       750
pdf_text    600
edi_204     300
edi_214     150
```
### `python scripts/generate_paper_tables_figures.py --input-dir outputs/FINAL_PHASE6_LIVE_RESULTS --output-dir manuscript_artifacts`

- Exit code: `0`

Stdout excerpt:

```text
Generated manuscript tables and figures in: manuscript_artifacts
Tables:
  manuscript_artifacts/tables/table_1_attack_taxonomy.csv
  manuscript_artifacts/tables/table_2_model_defense_unsafe_rates.csv
  manuscript_artifacts/tables/table_3_attack_breakdown.csv
  manuscript_artifacts/tables/table_4_document_type_breakdown.csv
  manuscript_artifacts/tables/table_5_extraction_success.csv
Figures:
  manuscript_artifacts/figures/figure_3_model_defense_unsafe_heatmap.png
  manuscript_artifacts/figures/figure_4_average_unsafe_rate_by_defense.png
  manuscript_artifacts/figures/figure_5_attack_defense_unsafe_rate.png
  manuscript_artifacts/figures/figure_6_doctype_unsafe_rate_d0.png
  manuscript_artifacts/figures/figure_7_extraction_success_rate.png
```

## Cleanup and security checks

- `__pycache__` / `.pyc` files in final ZIP: none
- Obvious committed live credential patterns: none found
- `.env` is ignored by `.gitignore`; only `.env.example` is included.

## Requirements added

```text
# FreightSkillBench / SkillChain-Logistics replication package
# Python 3.10+ recommended

# Table/figure generation and result summarization
pandas>=2.0.0
matplotlib>=3.7.0
tabulate>=0.9.0

# Live model-provider adapters and hosted/local model calls
requests>=2.31.0
openai>=1.0.0
anthropic>=0.34.0

# Optional, useful for notebooks/interactive inspection
jupyter>=1.0.0
```

## Notes before GitHub/Zenodo deposit

- Add a formal `LICENSE` file before public release. I included `LICENSE_NOTE.md` as a reminder because the final license choice is an author/institution decision.
- Add final repository URL and Zenodo DOI after creating the public archive.
- Keep real provider keys outside the repository. Do not commit `.env`.
