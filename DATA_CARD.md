# Data Card: FreightSkillBench Phase 2 v0.2

## Data Type

Synthetic logistics security benchmark data with adversarial document variants.

## Private / Sensitive Data

No private company data is included. All carrier names, facilities, shipment IDs, payment tokens, and account identifiers are synthetic.

## Intended Use

- Research on AI-agent skill security.
- Logistics document-to-transaction evaluation.
- Rule-based unsafe-transaction adjudication.
- Benchmark development for SkillChain-Logistics.
- Testing whether AI-assisted extraction preserves high-risk logistics fields.

## Attack Types Included

- Hazmat suppression.
- Appointment sabotage.
- Dispatch poisoning.
- Carrier substitution.
- Status concealment.

## Not Intended For

- Operational freight planning.
- Carrier vetting.
- Financial settlement.
- Real TMS integration without modification.

## Known Limitations

- Synthetic data only.
- No adversarial skills yet; this phase covers adversarial documents.
- No mock TMS/API yet.
- EDI renderings are simplified and benchmark-oriented, not certified EDI examples.
- Status-concealment examples use simplified exception notation for evaluation design.

## Phase 3 Additions

Phase 3 adds mock execution and deterministic rule-based adjudication. No LLM is used for primary unsafe labels.


## Phase 4 Additions

Phase 4 adds deterministic defense-control evaluation.

- D0_no_control.
- D1_schema_only.
- D2_field_validation.
- D3_manifest_only.
- D4_approval_gate.
- D5_full_control.

Phase 4 still does not call an LLM. It validates the security-control and adjudication mechanics before Phase 5 model/agent extraction.


## Phase 5 Additions

Phase 5 adds a model/agent extraction harness.

Important: the provided Phase 5 outputs use offline simulated model tiers and should not be reported as real frontier/mid/open-weight model performance. They validate the pipeline only.

Real model outputs should be generated through provider-specific clients and then evaluated with the same D0–D5 defense and rule-based adjudication logic.


## Phase 6 Additions

Phase 6 adds real-model-ready adapters and a live-pilot runner.

The included Phase 6 outputs were generated in dry-run mode and should not be reported as empirical model performance. Use `--live` with configured provider credentials to generate reportable model results.
