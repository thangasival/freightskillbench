# FreightSkillBench Replication Package

This repository contains the replication package for **FreightSkillBench**, the benchmark and evaluation pipeline used in the SkillChain-Logistics manuscript on agent-skill risk in AI-enabled shipping and logistics infrastructure.

## Contents

```text
data/                         Synthetic benchmark data and ground truth
schemas/                      JSON schemas for transactions and adversarial manifests
scripts/                      Data, metric, and manuscript-artifact generation scripts
agent/                        Simulated and provider-backed extraction clients
tms_mock/                     Mock TMS/API simulator with audit logging
security/                     D0-D5 defense-control implementations
adjudication/                 Rule-based unsafe-transaction adjudication
outputs/FINAL_PHASE6_LIVE_RESULTS/  Corrected Phase 6 result metrics and raw output folders
manuscript_artifacts/         Tables and figures used by the manuscript
DATA_CARD.md                  Dataset description, intended use, and limitations
requirements.txt              Python package requirements
.env.example                  Template for optional live provider credentials
```

## Setup

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Reproduce deterministic benchmark stages

These stages do not require model-provider credentials.

```bash
python scripts/generate_phase1.py
python scripts/generate_phase2.py
python scripts/validate_phase2.py
python evaluation/run_phase3_demo.py
python evaluation/run_phase4_controls.py
python evaluation/run_phase5_model_extraction.py
```

Expected Phase 4 pattern:

```text
D0_no_control: unsafe=60/60
D1_schema_only: unsafe=60/60
D2_field_validation: unsafe=0/60
D3_manifest_only: unsafe=60/60
D4_approval_gate: unsafe=0/60
D5_full_control: unsafe=0/60
```

## Optional live model run

Copy `.env.example` to `.env` or export variables in the shell. Do **not** commit real API keys.

```bash
python evaluation/run_phase6_real_model_pilot.py --live --limit 60
```

For offline pipeline validation:

```bash
python evaluation/run_phase6_real_model_pilot.py --dry-run --limit 10
```

## Regenerate corrected metrics from raw Phase 6 outputs

```bash
python scripts/regenerate_corrected_metrics_from_raw_outputs.py --raw-output-dir outputs --output-dir outputs/FINAL_PHASE6_LIVE_RESULTS
```

## Generate manuscript tables and figures

```bash
python scripts/generate_paper_tables_figures.py --input-dir outputs/FINAL_PHASE6_LIVE_RESULTS --output-dir manuscript_artifacts
```

Generated outputs include CSV, Markdown, LaTeX, and PNG artifacts under `manuscript_artifacts/`.

## Mermaid figures

See `docs/mermaid_figures.md` for the manuscript's Mermaid diagram source.

## Data and privacy

This package contains synthetic benchmark records only. It does not include proprietary logistics records, customer data, carrier operational data, or provider API keys. Synthetic account tokens and payment identifiers in the CSV files are benchmark placeholders, not real credentials.

## Citation and archival deposit

Before public release, add the final GitHub URL and, preferably, create a Zenodo archive DOI for the exact release used in the manuscript.
