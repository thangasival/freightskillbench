# M1 v2 Validation Report

## Input package

- Completed extraction rows: 750
- Successful extraction rows: 750
- Malformed JSONL rows: 0
- Duplicate extraction keys: 0
- Providers: OpenAI, Anthropic, Ollama
- Model configurations: 5
- Repeat-0 rows: 600
- Additional repeat rows: 150

## Corrected re-analysis

- Evaluation rows regenerated: 4,500
- Reference-sensitivity rows regenerated: 1,200
- Model/API calls made: 0
- Benign repeat-0 applicable-field integrity: 280/300 (93.33%)
- Adversarial repeat-0 target-field manifestation: 237/300 (79.00%)
- D0 unsafe acceptance: 236/300 overall; 236/237 conditional on manifestation

## Main control results

- D1 schema only: 3.57% false-block rate among integrity-valid benign rows; 91.14% conditional unsafe acceptance among manifested attacks.
- D2 field validation: 3.57% false-block rate among integrity-valid benign rows, caused by preceding schema validation; 0% conditional unsafe acceptance.
- D3 manifest only: 62.14% legitimate-task obstruction among integrity-valid benign rows; 99.58% conditional unsafe acceptance.
- D4 approval gate: 100% false-escalation rate among integrity-valid benign rows; projected approval burden approximately 100% at 1% attack prevalence.
- D5 full control: 3.57% false-block rate and 96.43% false-escalation rate among integrity-valid benign rows; 0% conditional unsafe acceptance.

## Reference sensitivity

- Complete references detected 100% of manifested target-field attacks.
- Partial references also detected 100% in this synthetic set because the retained anchor field was manipulated in every manifested case.
- Missing references produced 100% false-negative rates.
- Stale/poisoned references produced 98.67%–100% false-negative rates across attack classes.

## Repeatability

- Exact JSON agreement ranged from 26.67% to 91.11%.
- Applicable target-field agreement ranged from 90.74% to 100%.

## Decision

The completed extraction run is usable. The original v1 summary metrics are not suitable for manuscript reporting. The corrected v2 outputs should be treated as authoritative for the M1 revision.
