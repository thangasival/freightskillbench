## Version 1.1.0

### Added

- Matched benign and legitimate-change evaluation arm.
- Degraded-reference sensitivity analysis.
- Three-observation repeatability analysis on a stratified subset.
- Reference-aware validator and associated tests.
- Corrected v2 post-processing pipeline.

### Corrected

- Restricted field-integrity evaluation to attack-relevant fields represented
  by the source document.
- Counted benign blocking as false blocking only when the incoming extraction
  was integrity-valid on applicable fields.
- Separated attack manifestation from downstream unsafe acceptance.

The original raw model outputs were not modified. The correction applies to
derived M1 evaluation and summary files.