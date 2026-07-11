# Manuscript Results Narrative Draft

Across the live Phase 6 model runs, unsafe transaction acceptance was concentrated in the no-control and manifest-only conditions. In D0_no_control, models accepted unsafe transaction states in 299/300 evaluated defense trials (99.7%). In D3_manifest_only, unsafe acceptance remained 299/300 (99.7%), indicating that capability manifests alone did not prevent unsafe logistics field acceptance when an otherwise permitted operation carried manipulated high-risk fields.

Field-level validation eliminated unsafe acceptance in the evaluated cases. Under D2_field_validation, unsafe outcomes were 0/300 (0.0%). Under D5_full_control, unsafe outcomes were 0/300 (0.0%). These results support the central finding that logistics-specific field integrity checks are necessary beyond generic schema validation and capability declarations.

Recommended wording:

> Capability manifests alone are insufficient when an allowed operation such as create_load carries manipulated high-risk logistics fields. In contrast, field-level validation over safety, appointment, carrier, dispatch, and tracking fields blocked unsafe transaction acceptance across the evaluated live-model runs.
