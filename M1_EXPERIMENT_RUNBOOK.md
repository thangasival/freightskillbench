# FreightSkillBench M1 Experiment Runbook

## Purpose

This extension addresses the core experimental concern in Review Comment M1 by adding evidence that is not fixed entirely by the original benchmark construction:

1. **Matched benign and legitimate-change arm** — evaluates false blocks, false escalations, utility retention, and approval precision.
2. **Degraded-reference sensitivity** — evaluates complete, partial, missing, and stale/poisoned reference conditions.
3. **Repeated model runs** — evaluates exact-output and high-risk-field agreement across three passes.

The script reuses the archived Phase 6 adversarial outputs as **repeat 0**. When the same model identifiers are used, only two additional passes are required for the repeated-run subset.

---

## 1. Files added by this patch

```text
evaluation/run_m1_experiments.py
security/reference_aware_validator.py
tests/test_m1_reference_validator.py
M1_EXPERIMENT_RUNBOOK.md
run_m1_smoke_test.cmd
run_m1_reference_only.cmd
run_m1_live_minimum.cmd
```

The original Phase 6 scripts and archived outputs are not overwritten.

---

## 2. Experimental design implemented

### 2.1 Matched benign arm

The script creates one benign case for each of the 60 adversarial cases, preserving the same load and source representation.

| Matched scenario | Benign construction |
|---|---|
| Hazmat suppression | Clean canonical compliance document |
| Appointment sabotage | Authenticated one-hour appointment reschedule |
| Dispatch poisoning | Authenticated dock reassignment at the same facility |
| Carrier substitution | Authenticated change to another approved compatible carrier |
| Status concealment | Clean status document with no concealed exception |

The case-specific authoritative transaction is updated for legitimate changes. This prevents a valid reschedule or authorized carrier change from being mislabeled as malicious merely because it differs from the original canonical record.

### 2.2 Degraded-reference scenarios

The archived adversarial extractions are re-evaluated under:

```text
complete_reference
partial_target_reference
missing_target_reference
stale_or_poisoned_target_reference
```

No model API calls are required for this analysis.

### 2.3 Repeated-run subset

The script selects a stratified 15-case subset across all five attack classes. The archived Phase 6 output is repeat 0. Two new passes produce three observations per model–case pair.

---

## 3. Prerequisites

Run all commands from the FreightSkillBench package root.

```powershell
python --version
python -m pip install -r requirements.txt
```

Recommended Python version:

```text
Python 3.10 or newer
```

For Ollama:

```powershell
ollama serve
ollama pull qwen2.5:7b
```

---

## 4. Configure model environment variables

Use the same model identifiers as the archived Phase 6 run when they remain available. Matching identifiers allow the archived run to serve as repeat 0.

### Windows PowerShell

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

Only configured providers are executed. API keys and credentials are never written to output files.

---

## 5. Validate the patch

Run the unit test:

```powershell
python tests\test_m1_reference_validator.py
```

Expected:

```text
M1 reference-aware validator tests passed.
```

Run the offline smoke test:

```powershell
python evaluation\run_m1_experiments.py `
  --mode all `
  --dry-run `
  --benign-limit 10 `
  --repeat-limit 5 `
  --additional-repeats 2 `
  --output-dir outputs\m1_smoke_test
```

This validates file generation, evaluation logic, metrics, and resume behavior. Dry-run results must not be reported as empirical model results.

---

## 6. Run degraded-reference sensitivity first

This step uses archived outputs and makes **no API calls**.

```powershell
python evaluation\run_m1_experiments.py `
  --mode reference `
  --output-dir outputs\m1_experiments
```

Expected key files:

```text
outputs/m1_experiments/m1_reference_sensitivity_rows.jsonl
outputs/m1_experiments/m1_reference_sensitivity_metrics.csv
```

For the complete archived five-model run, each reference scenario should cover 300 adversarial extraction rows. Four scenarios should produce 1,200 row-level sensitivity records.

---

## 7. Run the minimum live M1 extension

### One-command execution

```powershell
python evaluation\run_m1_experiments.py `
  --mode all `
  --live `
  --benign-limit 60 `
  --repeat-limit 15 `
  --additional-repeats 2 `
  --delay-between-repeats 60 `
  --output-dir outputs\m1_experiments `
  --resume
```

This command:

1. Imports the 300 archived adversarial extractions as repeat 0.
2. Runs the 60 matched benign cases once per configured model.
3. Runs two additional passes on a stratified 15-case adversarial subset.
4. Runs degraded-reference sensitivity.
5. Generates all summary files.

### Expected new API-call count

For `M` configured models:

```text
benign calls = 60 × M
repeat calls = 15 × M × 2
total new calls = 90 × M
```

With five models:

```text
450 new model calls
```

### When archived model identifiers are no longer available

Use three fully new passes instead of relying on archived repeat 0:

```powershell
python evaluation\run_m1_experiments.py `
  --mode repeats `
  --live `
  --repeat-limit 15 `
  --additional-repeats 3 `
  --delay-between-repeats 60 `
  --output-dir outputs\m1_experiments `
  --resume
```

The repeat-agreement script groups by exact provider and model name, so changed model identifiers are not incorrectly treated as the same configuration.

---

## 8. Run in stages

The following staged approach is safer for long provider runs.

### Stage A — benign arm

```powershell
python evaluation\run_m1_experiments.py `
  --mode benign `
  --live `
  --benign-limit 60 `
  --output-dir outputs\m1_experiments `
  --resume
```

### Stage B — two additional repeat passes

```powershell
python evaluation\run_m1_experiments.py `
  --mode repeats `
  --live `
  --repeat-limit 15 `
  --additional-repeats 2 `
  --delay-between-repeats 60 `
  --output-dir outputs\m1_experiments `
  --resume
```

### Stage C — degraded references

```powershell
python evaluation\run_m1_experiments.py `
  --mode reference `
  --output-dir outputs\m1_experiments
```

### Stage D — regenerate summaries

```powershell
python evaluation\run_m1_experiments.py `
  --mode summarize `
  --output-dir outputs\m1_experiments
```

The `--resume` option skips completed model–case–repeat combinations using their compound key. It is safe to rerun a partially completed command.

---

## 9. Restrict the run to selected providers

OpenAI only:

```powershell
python evaluation\run_m1_experiments.py --mode all --live --providers openai --resume
```

Anthropic and Ollama:

```powershell
python evaluation\run_m1_experiments.py --mode all --live --providers anthropic,ollama --resume
```

Exact model names:

```powershell
python evaluation\run_m1_experiments.py `
  --mode repeats `
  --live `
  --model-names "MODEL_A,MODEL_B" `
  --additional-repeats 2 `
  --resume
```

---

## 10. Output files

```text
outputs/m1_experiments/
  m1_extractions.jsonl
  m1_evaluations.jsonl
  m1_metrics_by_arm_model_defense.csv
  m1_mixed_traffic_metrics.csv
  m1_repeat_agreement.csv
  m1_reference_sensitivity_rows.jsonl
  m1_reference_sensitivity_metrics.csv
  M1_RESULTS_SUMMARY.md
```

### `m1_mixed_traffic_metrics.csv`

Reports, by defense:

- benign false-block rate;
- benign false-escalation rate;
- benign utility retention;
- adversarial block/escalation rate;
- adversarial unsafe-acceptance rate;
- approval precision in the balanced matched sample;
- projected approval burden at 1%, 5%, and 10% attack prevalence.

Only repeat-0 model configurations represented in both the benign and adversarial arms are included. This prevents mismatched model versions from being combined.

### `m1_reference_sensitivity_metrics.csv`

Reports validator block and false-negative rates by attack type and reference-quality scenario.

### `m1_repeat_agreement.csv`

Reports:

- exact JSON match rate across repeat pairs;
- agreement across high-risk transaction fields.

---

## 11. Full-run validation targets

With five matching model configurations, 60 benign cases, and two new repeats on 15 cases:

```text
Archived adversarial extraction rows: 300
New benign extraction rows: 300
New repeat extraction rows: 150
Total extraction rows: 750
Total six-policy evaluation rows: 4,500
Reference-sensitivity rows: 1,200
Model-case groups with at least three repeats: 75
```

Check:

```powershell
Get-Content outputs\m1_experiments\M1_RESULTS_SUMMARY.md
Import-Csv outputs\m1_experiments\m1_mixed_traffic_metrics.csv | Format-Table
Import-Csv outputs\m1_experiments\m1_repeat_agreement.csv | Format-Table
Import-Csv outputs\m1_experiments\m1_reference_sensitivity_metrics.csv | Format-Table
```

Counts will differ when fewer models are configured or when limits are reduced.

---

## 12. Interpretation rules for the manuscript

Do not state that M1 is resolved merely because the script completed. Verify the resulting CSV files first.

The revised manuscript can claim the benign-arm extension only after reporting:

1. false-block and utility-retention results for D1, D2, and D5;
2. approval precision and burden for D4/D5;
3. degraded-reference false-negative rates;
4. repeat agreement for the selected model–case subset;
5. the exact number of models, calls, failures, and completed repetitions.

Preserve these qualifications:

- The benign set remains synthetic.
- The reference degradation patterns are controlled scenarios, not measured production frequencies.
- Repeated hosted-model calls characterize the accessed configurations and dates, not immutable model families.
- Approval-burden projections depend on assumed attack prevalence.
