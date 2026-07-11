# Data Card: FreightSkillBench v1.1.0

## Dataset summary

FreightSkillBench is a synthetic, standards-grounded benchmark for evaluating document-to-transaction integrity in AI-enabled freight and logistics workflows. It combines canonical shipment records, adversarial and benign document variants, provider-backed extraction outputs, a mock transportation management system (TMS), deterministic control policies, and rule-based transaction-integrity adjudication.

The benchmark is designed to test whether manipulated or legitimately changed operational fields in freight documents are preserved, rejected, escalated, or accepted when converted into downstream transaction records.

## Data type

- Synthetic canonical freight records.
- Synthetic adversarial freight documents.
- Synthetic matched benign and legitimate-change documents.
- Email, linearized PDF text, EDI 204, and EDI 214 representations.
- Structured model extraction outputs.
- Mock-TMS execution and audit traces.
- Deterministic policy-evaluation outputs.
- Reference-quality sensitivity results.
- Repeated-run agreement metrics.

## Dataset inventory

### Core adversarial benchmark

- Canonical adversarial cases: **60**.
- Attack types: **5**.
- Document representations: **4**.
- Model configurations: **5**.
- Archived adversarial extractions: **300**.

### M1 experimental extension

- Matched benign and legitimate-change cases: **60**.
- Benign extractions: **300**.
- Stratified adversarial repeat subset: **15 cases**.
- Additional repeat passes: **2**.
- Additional repeated extractions: **150**.
- Total extraction records: **750**.
- Policy-evaluation rows: **4,500**.
- Reference-sensitivity rows: **1,200**.
- Reference conditions: complete, partial, missing, and stale/poisoned.

## Private and sensitive data

No private company or customer data are included. All carrier names, facilities, shipment identifiers, account identifiers, payment tokens, appointment records, and operational events are synthetic.

The package does not contain:

- Employer data.
- Customer or consignee information.
- Actual carrier operational records.
- Confidential freight tenders or rate confirmations.
- Production TMS credentials.
- Provider API keys.
- Personally identifiable information.

Synthetic account tokens and payment identifiers are benchmark placeholders and are not usable credentials.

## Intended uses

FreightSkillBench is intended for:

- Research on document-to-transaction integrity.
- Evaluation of AI-assisted freight-document extraction.
- Logistics cybersecurity and critical-infrastructure research.
- Testing schema, reference, capability, approval, and combined controls.
- Studying how data falsification and omission reach downstream transactions.
- Evaluating benign utility, false blocking, false escalation, and approval burden.
- Studying sensitivity to incomplete or unreliable reference data.
- Repeated-run agreement analysis for model extraction outputs.
- Reproduction and extension of the associated manuscript results.

## Not intended for

FreightSkillBench is not intended for:

- Operational freight planning or dispatch.
- Carrier qualification or regulatory vetting.
- Financial settlement or invoice approval.
- Hazardous-material compliance decisions.
- Production appointment scheduling.
- Real TMS deployment without independent security review and modification.
- Estimating the real-world prevalence of freight-document fraud.
- Ranking model families from the reported single benchmark run.

## Attack types

The adversarial arm contains five data-falsification or omission attacks:

1. **Hazmat suppression** — removal or alteration of hazardous-material indicators.
2. **Appointment sabotage** — manipulation of pickup or delivery appointment windows.
3. **Dispatch poisoning** — manipulation of facility, dock, gate, city, or ZIP information.
4. **Carrier substitution** — replacement of approved carrier identifiers.
5. **Status concealment** — omission of delay, damage, exception, or short-shipment signals.

These are data-integrity attacks. The reported experiment does not contain adversarial instructions, prompt injection, autonomous tool selection, or poisoned skill files.

## Benign and legitimate-change arm

The M1 extension adds matched benign documents corresponding to the adversarial benchmark. The arm includes unchanged valid records and legitimate operational changes, such as authorized appointment reschedules, carrier changes, and facility or dock updates.

The benign arm supports measurement of:

- Integrity-valid extraction rate.
- Utility retention.
- False-block rate.
- False-escalation rate.
- Legitimate-task obstruction.
- Projected approval burden under mixed traffic.

The benign cases remain synthetic and do not establish production false-positive rates.

## Document representations

The benchmark includes:

- Email text.
- Linearized PDF text.
- EDI 204-style load tender messages.
- EDI 214-style shipment-status messages.

The linearized PDF condition contains text only. It does not test page rendering, optical character recognition, scanned-document noise, handwriting, or layout-aware document understanding.

The EDI examples are simplified, benchmark-oriented representations and are not certified implementation-guide examples.

## Model and execution design

The completed live package contains outputs from five configured model endpoints across OpenAI, Anthropic, and Ollama adapters.

The execution scaffold uses a static extraction prompt followed by deterministic orchestration. The model does not autonomously select tools or revise an execution plan. Provider labels are experiment configuration identifiers and should not be interpreted as immutable model snapshots unless the corresponding provider or local model digest is recorded.

## Control conditions

Each extraction is evaluated under six control policies:

- **D0 — No control:** accept the extracted transaction without validation.
- **D1 — Schema only:** enforce structure and required data types.
- **D2 — Field validation:** compare applicable high-risk fields with available references.
- **D3 — Capability manifest:** enforce declared endpoint permissions without verifying field truth.
- **D4 — Approval gate:** escalate high-risk actions for human review.
- **D5 — Full control:** combine schema, field, capability, approval, and audit controls.

## Ground truth and evaluation concepts

The corrected v2 analysis uses the following concepts:

- **`input_integrity_valid`** — a benign extraction matches expected values on fields relevant to the case and represented by the source format.
- **`attack_manifested`** — an adversarial document produces an incorrect or omitted target field in the extraction.
- **`unsafe_acceptance`** — a manifested target-field error reaches an accepted TMS action.
- **`false_block_rate_valid_benign`** — block rate among benign extractions that were already integrity-valid.
- **`false_escalation_rate_valid_benign`** — escalation rate among integrity-valid benign extractions.
- **`conditional_unsafe_acceptance_rate_manifested`** — unsafe acceptance conditional on the attack appearing in the extracted target field.

## Authoritative M1 v2 results

The completed run passed the following integrity checks:

- Extraction rows: **750/750**.
- Successful extraction rows: **750/750**.
- Malformed JSONL rows: **0**.
- Duplicate extraction keys: **0**.
- Regenerated policy-evaluation rows: **4,500**.
- Regenerated reference-sensitivity rows: **1,200**.

Key corrected observations are:

- Integrity-valid benign extractions: **280/300 (93.33%)**.
- Adversarial extractions with manifested target-field compromise: **237/300 (79.00%)**.
- D0 unsafe acceptance: **236/300 overall** and **236/237 (99.58%) conditional on manifestation**.
- D1 false-block rate among integrity-valid benign rows: **3.57%**.
- D2 false-block rate among integrity-valid benign rows: **3.57%**; conditional unsafe acceptance: **0%**.
- D3 legitimate-task obstruction among integrity-valid benign rows: **62.14%**; conditional unsafe acceptance: **99.58%**.
- D4 false-escalation rate among integrity-valid benign rows: **100%**.
- D5 false-block rate: **3.57%**; false-escalation rate: **96.43%**; conditional unsafe acceptance: **0%**.
- Exact JSON repeat agreement by model: **26.67%–91.11%**.
- Applicable target-field repeat agreement by model: **90.74%–100%**.

Reference-quality sensitivity showed:

- Complete references detected **100%** of manifested target-field attacks.
- Partial references detected **100%** in this synthetic set because a retained anchor field was manipulated in every manifested case.
- Missing references produced **100% false-negative rates**.
- Stale or poisoned references produced approximately **98.67%–100% false-negative rates**, depending on attack class.

These values are descriptive results from this synthetic benchmark and should not be generalized as production rates.

## Corrected-analysis notice

The original M1 summarizer was replaced by the v2 post-processor because it:

1. Compared extractions with high-risk canonical fields that were not represented in some source formats.
2. Counted every block on a benign row as a false block, even when the incoming extraction already contained an applicable-field error.

The v2 analysis limits validation to case-relevant, source-supported fields and conditions false-block and false-escalation rates on integrity-valid benign extractions.

The raw 750 model extraction records were not modified. The correction applies to derived evaluation and summary outputs.

The following files are authoritative for M1 reporting:

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

## Development phases

### Phase 1–2: synthetic benchmark construction

Canonical shipments, document representations, adversarial mutations, schemas, and deterministic ground truth were generated and validated.

### Phase 3: mock execution

Phase 3 added the mock TMS/API simulator, audit logging, and deterministic unsafe-transaction adjudication.

### Phase 4: deterministic controls

Phase 4 added the six D0–D5 control policies and validated control-flow mechanics without live model calls.

### Phase 5: extraction harness

Phase 5 added offline simulated model tiers to validate the extraction and evaluation pipeline. Phase 5 outputs must not be reported as real provider performance.

### Phase 6: provider-backed live pilot

Phase 6 added OpenAI, Anthropic, and Ollama adapters, live extraction, raw request/response logging, and corrected live-pilot metrics.

### M1 extension

The M1 extension added the matched benign arm, degraded-reference sensitivity analysis, and repeated-run agreement testing. The v2 post-processor supplies the authoritative M1 derived metrics.

## Known limitations

- All records and documents are synthetic.
- The benign arm is synthetic and matched to the adversarial cases.
- Attack prevalence is not estimated.
- The repeatability analysis covers a stratified 15-case subset rather than all 60 cases.
- Each commercial-provider response depends on a non-immutable hosted service.
- The open-weight model tag is not a substitute for a recorded model-file digest.
- The benchmark does not test prompt injection, skill poisoning, autonomous planning, or model-selected tools.
- PDF inputs are text-only and exclude OCR and layout noise.
- Reference validation assumes the specified reference scenario; production references may be incomplete, delayed, inconsistent, or compromised.
- Partial references performed well in this synthetic set because retained anchors overlapped the manipulated fields; this should not be generalized.
- D4 and D5 approval results indicate substantial review burden in the tested design.
- The benchmark measures transaction-integrity outcomes, not downstream facility queues, network disruption, sector loss, or cascading infrastructure consequences.
- The benchmark does not provide a statistical power analysis or a population-representative freight-document sample.

## Ethical and responsible-use considerations

The benchmark is intended to improve defensive evaluation. It should not be used to generate deceptive real-world freight documents, impersonate carriers, bypass safety requirements, or interfere with logistics operations.

Researchers publishing extensions should preserve the synthetic-data boundary, disclose model and reference assumptions, archive raw outputs, and distinguish extraction errors from defense errors.

## Licensing

Use the repository license for source code and the declared data license for synthetic benchmark data and documentation. Recommended release metadata are:

- Code: MIT License.
- Synthetic data and documentation: Creative Commons Attribution 4.0 International.

## Versioning and citation

The v1.0.0 Zenodo record archives the original replication package:

> Thangavel, S. (2026). *FreightSkillBench: Replication Package for Evaluating Integrity Controls in AI-Enabled Shipping and Logistics Infrastructure* (Version 1.0.0) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.21304557

Because the M1 extension adds new data, model outputs, scripts, and corrected analyses, it should be published as a new semantic release, recommended as **v1.1.0**, with its own version-specific Zenodo DOI. Update this data card with that DOI after the new Zenodo version is published.
