# FreightSkillBench Replication Package

FreightSkillBench is a synthetic, standards-grounded benchmark and reproducibility package for evaluating **document-to-transaction integrity in AI-enabled shipping and logistics workflows**.

The repository supports the manuscript:

> **From Documents to Transactions: Evaluating Integrity Controls in AI-Enabled Shipping and Logistics Infrastructure**

The package evaluates whether manipulated or legitimately changed freight fields cross an extraction and tool-execution boundary and become accepted, blocked, or escalated transactions in a mock transportation management system (TMS). The evaluated attacks are data falsification and omission attacks, not prompt injection or skill poisoning.

## Repository contents

```text
data/                                Synthetic benchmark data and ground truth
schemas/                             Transaction and adversarial-manifest schemas
scripts/                             Data, metric, and manuscript-artifact generators
agent/                               Simulated and provider-backed extraction clients
evaluation/                          Phase 3-6 and M1 experiment runners
tms_mock/                            Mock TMS/API simulator and audit logging
security/                            Schema, field, capability, approval, and reference controls
adjudication/                        Rule-based transaction-integrity adjudication
tests/                               Validation tests for the M1 reference-aware logic
docs/                                Execution and validation documentation
outputs/FINAL_PHASE6_LIVE_RESULTS/   Corrected original live-pilot results
outputs/m1_experiments/              Completed M1 raw outputs and corrected v2 metrics
manuscript_artifacts/                Tables and figures used by the manuscript
DATA_CARD.md                         Dataset scope, inventory, limitations, and results
CHANGELOG.md                         Version history and analysis corrections
requirements.txt                     Python dependencies
.env.example                         Template for optional provider credentials
run_m1_live_minimum.cmd              Windows launcher for the full M1 live run
run_m1_reference_only.cmd            Windows launcher for offline reference sensitivity
run_m1_smoke_test.cmd                Windows launcher for M1 dry-run validation
```

## Completed benchmark inventory

The repository contains:

- 60 adversarial cases across five attack types.
- 60 matched benign or legitimate-change cases.
- Four source representations: email, linearized PDF text, EDI 204, and EDI 214.
- Five configured model endpoints across OpenAI, Anthropic, and Ollama.
- 300 archived adversarial extractions.
- 300 benign extractions.
- 150 additional repeated extractions on a stratified 15-case subset.
- **750 total extraction records**.
- **4,500 corrected policy-evaluation rows**.
- **1,200 corrected reference-sensitivity rows**.

## Setup

Python 3.10 or later is recommended.

```bash
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS/Linux
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Reproduce deterministic benchmark stages

The following stages do not require provider credentials:

```bash
python scripts/generate_phase1.py
python scripts/generate_phase2.py
python scripts/validate_phase2.py
python evaluation/run_phase3_demo.py
python evaluation/run_phase4_controls.py
python evaluation/run_phase5_model_extraction.py
```

Phase 5 uses offline simulated model tiers to validate the pipeline. Do not report Phase 5 outputs as real frontier, mid-tier, or open-weight model performance.

## Original Phase 6 live pilot

Copy `.env.example` to `.env`, or export the required environment variables. Never commit actual API keys.

Run the original live pilot:

```bash
python evaluation/run_phase6_real_model_pilot.py --live --limit 60
```

Run an offline smoke test:

```bash
python evaluation/run_phase6_real_model_pilot.py --dry-run --limit 10
```

Regenerate corrected Phase 6 metrics:

```bash
python scripts/regenerate_corrected_metrics_from_raw_outputs.py \
  --raw-output-dir outputs \
  --output-dir outputs/FINAL_PHASE6_LIVE_RESULTS
```

Generate Phase 6 manuscript tables and figures:

```bash
python scripts/generate_paper_tables_figures.py \
  --input-dir outputs/FINAL_PHASE6_LIVE_RESULTS \
  --output-dir manuscript_artifacts
```

## M1 experimental extension

The M1 extension addresses three peer-review concerns:

1. A matched benign and legitimate-change arm for utility and false-intervention measurement.
2. Degraded-reference conditions for complete, partial, missing, and stale/poisoned references.
3. Repeated model calls on a stratified subset for agreement analysis.

### Validate the M1 implementation

```bash
python tests/test_m1_reference_validator.py
```

Expected output:

```text
M1 reference-aware validator tests passed.
```

### Offline smoke test

On Windows:

```powershell
.\run_m1_smoke_test.cmd
```

Or run the Python command directly:

```bash
python evaluation/run_m1_experiments.py \
  --mode all \
  --dry-run \
  --benign-limit 10 \
  --repeat-limit 5 \
  --additional-repeats 2
```

Dry-run outputs validate the pipeline only and must not be reported as live experimental evidence.

### Configure providers

Example PowerShell environment variables:

```powershell
$env:OPENAI_API_KEY="YOUR_KEY"
$env:OPENAI_MODEL_FRONTIER="YOUR_FRONTIER_MODEL"
$env:OPENAI_MODEL_MID="YOUR_MID_MODEL"

$env:ANTHROPIC_API_KEY="YOUR_KEY"
$env:ANTHROPIC_MODEL_FRONTIER="YOUR_FRONTIER_MODEL"
$env:ANTHROPIC_MODEL_MID="YOUR_MID_MODEL"

$env:OLLAMA_BASE_URL="http://localhost:11434"
$env:OLLAMA_MODEL_OPEN_WEIGHT="qwen2.5:7b"
```

For Ollama, start the service and ensure the configured model is installed:

```powershell
ollama serve
ollama pull qwen2.5:7b
```

### Run the complete M1 experiment

On Windows:

```powershell
.\run_m1_live_minimum.cmd
```

Equivalent Python command:

```bash
python evaluation/run_m1_experiments.py \
  --mode all \
  --live \
  --benign-limit 60 \
  --repeat-limit 15 \
  --additional-repeats 2 \
  --delay-between-repeats 60 \
  --output-dir outputs/m1_experiments \
  --resume
```

With five configured model endpoints, this design makes 450 new provider calls:

```text
60 benign cases × 5 models                  = 300 calls
15 repeated adversarial cases × 5 × 2 runs = 150 calls
Total new calls                             = 450 calls
```

The original 300 adversarial extractions are imported as repeat 0.

### Run reference sensitivity without provider calls

```powershell
.\run_m1_reference_only.cmd
```

Or:

```bash
python evaluation/run_m1_experiments.py \
  --mode reference \
  --output-dir outputs/m1_experiments
```

## Corrected M1 v2 re-analysis

The completed 750-row model run does not need to be repeated. The authoritative M1 results are generated with the v2 post-processor:

```powershell
python .\evaluation\reanalyze_m1_outputs_v2.py `
  --output-dir .\outputs\m1_experiments
```

Equivalent cross-platform command:

```bash
python evaluation/reanalyze_m1_outputs_v2.py \
  --output-dir outputs/m1_experiments
```

The v2 post-processor makes no OpenAI, Anthropic, or Ollama calls.

It corrects two issues in the initial M1 analysis:

1. Validation is restricted to fields relevant to the case and represented by the source format.
2. Benign false-block and false-escalation rates are conditioned on integrity-valid incoming extractions.

The raw model extractions are unchanged. Only derived evaluation and summary files are regenerated.

## Authoritative M1 output files

Use the following files for analysis and manuscript reporting:

```text
outputs/m1_experiments/m1_extractions.jsonl
outputs/m1_experiments/m1_evaluations_v2.jsonl
outputs/m1_experiments/m1_metrics_by_arm_model_defense_v2.csv
outputs/m1_experiments/m1_mixed_traffic_metrics_v2.csv
outputs/m1_experiments/m1_reference_sensitivity_rows_v2.jsonl
outputs/m1_experiments/m1_reference_sensitivity_metrics_v2.csv
outputs/m1_experiments/m1_repeat_agreement_v2.csv
outputs/m1_experiments/M1_RESULTS_SUMMARY_v2.md
outputs/m1_experiments/M1_V2_Validation_Report.md
```

Do not use the original unversioned M1 derived summaries for manuscript reporting.

## Corrected M1 result summary

The completed package passed the following checks:

```text
Extraction rows:                  750
Successful extraction rows:       750
Malformed JSONL rows:                0
Duplicate extraction keys:           0
Corrected policy-evaluation rows: 4,500
Corrected reference rows:         1,200
```

Main corrected observations:

- Benign extractions integrity-valid on applicable fields: **280/300 (93.33%)**.
- Adversarial extractions with manifested target-field compromise: **237/300 (79.00%)**.
- D0 unsafe acceptance: **236/300 overall** and **236/237 (99.58%) conditional on manifestation**.
- D1 false-block rate among valid benign rows: **3.57%**.
- D2 false-block rate among valid benign rows: **3.57%**; conditional unsafe acceptance: **0%**.
- D3 legitimate-task obstruction: **62.14%**; conditional unsafe acceptance: **99.58%**.
- D4 false-escalation rate: **100%** among valid benign rows.
- D5 false-block rate: **3.57%**; false-escalation rate: **96.43%**; conditional unsafe acceptance: **0%**.
- Exact JSON repeat agreement: **26.67%–91.11%**, depending on model.
- Applicable target-field repeat agreement: **90.74%–100%**.

Reference sensitivity:

- Complete references detected **100%** of manifested attacks.
- Partial references detected **100%** in this synthetic set because retained anchor fields overlapped the manipulated target fields.
- Missing references produced **100% false-negative rates**.
- Stale or poisoned references produced approximately **98.67%–100% false-negative rates**.

These are descriptive results from a synthetic benchmark. They are not production attack-prevalence or false-positive estimates.

## Resume behavior

The M1 runner writes extraction records incrementally. An interrupted run can be resumed with the same command and `--resume`; existing experiment keys are skipped.

A complete extraction file contains:

```text
300 archived adversarial rows
300 benign rows
150 additional repeat rows
750 total rows
```

## Generate manuscript artifacts

Use only the corrected v2 output files when generating revised M1 tables and figures. The original Phase 6 artifact generator may require an M1-specific input mapping or an updated manuscript-artifact script.

Preserve the distinction between:

- Overall attack manifestation.
- Unsafe acceptance conditional on manifestation.
- False blocking among integrity-valid benign inputs.
- False escalation among integrity-valid benign inputs.
- Reference-quality sensitivity.
- Exact JSON versus applicable-field repeat agreement.

## Data and privacy

The package contains synthetic benchmark records only. It does not include proprietary logistics documents, customer data, carrier operational data, confidential employer information, or provider credentials.

See [`DATA_CARD.md`](DATA_CARD.md) for the complete inventory, intended-use restrictions, evaluation definitions, and limitations.

## Known limitations

- Synthetic adversarial and benign cases.
- No population-representative freight-document sample.
- Repeat testing uses a stratified 15-case subset.
- Hosted provider outputs are not immutable model snapshots.
- The open-weight tag does not record a model-file digest unless added separately.
- No prompt-injection, poisoned-skill, or autonomous-planning condition.
- Linearized PDF text only; no OCR or page-layout evaluation.
- Reference scenarios are synthetic and do not represent every production master-data failure.
- Partial-reference performance is favorable by construction in this set and should not be generalized.
- The benchmark measures transaction integrity, not downstream queueing, network delay, or cascading infrastructure loss.

## Mermaid figures

The source for repository diagrams is available in:

```text
docs/mermaid_figures.md
```

## Versioning and archival deposit

The original v1.0.0 replication package is archived on Zenodo:

> Thangavel, S. (2026). *FreightSkillBench: Replication Package for Evaluating Integrity Controls in AI-Enabled Shipping and Logistics Infrastructure* (Version 1.0.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.21304557

The M1 extension adds new benchmark cases, 450 new live model calls, corrected analysis code, and new result artifacts. Publish it as a new semantic release, recommended as **v1.1.0**, and create a new Zenodo version. After Zenodo assigns the version-specific DOI, update:

- This README.
- `DATA_CARD.md`.
- `CITATION.cff`.
- `CHANGELOG.md`.
- The manuscript data-availability statement.
- The software reference in the manuscript bibliography.

## Recommended release checklist

Before publishing v1.1.0:

- Confirm that only `_v2` M1 derived outputs are treated as authoritative.
- Remove or clearly deprecate unversioned M1 summary files.
- Confirm that `.env`, API keys, temporary logs, and smoke-test outputs are excluded.
- Include `evaluation/reanalyze_m1_outputs_v2.py`.
- Include the 750-row `m1_extractions.jsonl` evidence file.
- Include `M1_V2_Validation_Report.md` and execution instructions.
- Run the repository tests from a clean environment.
- Create and push the `v1.1.0` Git tag.
- Publish the matching Zenodo version and record its DOI.

## License

Use the repository's declared licenses. Recommended licensing is:

- Source code: MIT License.
- Synthetic benchmark data and documentation: Creative Commons Attribution 4.0 International.
