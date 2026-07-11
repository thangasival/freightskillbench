# FreightSkillBench M1 Patch Validation Report

Validation status: **PASS for offline and archived-data checks**

## Added capabilities

- Matched benign and legitimate-change case generation.
- Complete, partial, missing, and stale/poisoned reference scenarios.
- Archived Phase 6 import as repeat 0.
- Additional repeated-run support with resume and provider filters.
- Mixed-traffic false-block, utility, approval, and projected-burden metrics.
- Repeat exact-output and high-risk-field agreement metrics.

## Validation commands completed

```text
python -m py_compile evaluation/run_m1_experiments.py security/reference_aware_validator.py tests/test_m1_reference_validator.py
python tests/test_m1_reference_validator.py
python scripts/validate_phase2.py
python evaluation/run_phase3_demo.py
python evaluation/run_phase4_controls.py
python evaluation/run_m1_experiments.py --mode reference --output-dir outputs/m1_validation
python evaluation/run_m1_experiments.py --mode all --dry-run --benign-limit 10 --repeat-limit 5 --additional-repeats 2 --output-dir outputs/m1_validation
```

## Results

- Python compilation: PASS.
- M1 reference-aware validator unit test: PASS.
- Phase 2 manifest validation: 60 entries, 0 missing files, 0 unknown load IDs.
- Phase 3 regression check: 60 runs completed.
- Phase 4 regression check: 360 runs completed with original D0–D5 totals preserved.
- Archived degraded-reference analysis: completed without provider calls.
- M1 dry-run smoke test: completed and generated all expected JSONL, CSV, and Markdown outputs.

## Not validated in this environment

Live OpenAI, Anthropic, Hugging Face, and Ollama calls were not executed. The user must run the live commands with their configured credentials and inspect the resulting metrics before updating manuscript claims.
