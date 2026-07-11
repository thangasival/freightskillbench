# FreightSkillBench M1 Corrected Analysis (v2)

## Integrity checks

- Extraction rows reused: 750
- Evaluation rows regenerated: 4500
- API/model calls made by this post-processor: 0
- Benign repeat-0 integrity-valid rate on case-relevant, source-supported fields: 0.9333
- Adversarial repeat-0 attack-manifestation rate in extracted target fields: 0.79

## Control trade-offs

- D0 conditional unsafe acceptance among manifested attacks: 0.9958
- D2 false-block rate among integrity-valid benign inputs: 0.0357
- D2 conditional unsafe acceptance among manifested attacks: 0.0
- D4 false-escalation rate among integrity-valid benign inputs: 1.0
- D4 projected approval burden at 1% attack prevalence: 1.0
- D5 false-block rate among integrity-valid benign inputs: 0.0357

## Reference sensitivity

Complete-reference detection among manifested attacks is reported by attack type in `m1_reference_sensitivity_metrics_v2.csv`. Missing and stale/poisoned references should be interpreted as stress tests of reference availability and integrity, not as model comparisons.

## Repeatability

Exact JSON equality is substantially lower than applicable-field agreement for most models. Use the field-level agreement column for operational conclusions and retain exact equality as a strict sensitivity measure.

## Important interpretation

The original v1 summary counted every benign block as a false block and compared against fields that some source formats did not contain. Do not cite the v1 benign utility or false-block columns. The v2 files condition false-block and false-escalation rates on integrity-valid benign extractions and separate attack manifestation from downstream unsafe acceptance.
