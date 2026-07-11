"""
Defense policy definitions for FreightSkillBench Phase 4.
"""

DEFENSES = {
    "D0_no_control": {
        "schema_validation": False,
        "field_validation": False,
        "capability_enforcement": False,
        "approval_required": False,
    },
    "D1_schema_only": {
        "schema_validation": True,
        "field_validation": False,
        "capability_enforcement": False,
        "approval_required": False,
    },
    "D2_field_validation": {
        "schema_validation": True,
        "field_validation": True,
        "capability_enforcement": False,
        "approval_required": False,
    },
    "D3_manifest_only": {
        "schema_validation": False,
        "field_validation": False,
        "capability_enforcement": True,
        "approval_required": False,
    },
    "D4_approval_gate": {
        "schema_validation": False,
        "field_validation": False,
        "capability_enforcement": True,
        "approval_required": True,
    },
    "D5_full_control": {
        "schema_validation": True,
        "field_validation": True,
        "capability_enforcement": True,
        "approval_required": True,
    },
}

DEFAULT_ALLOWED_CAPABILITIES = [
    "create_load",
    "update_status"
]
