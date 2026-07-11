"""
Basic schema validator for FreightSkillBench transaction objects.

This is intentionally lightweight. It checks the presence of required top-level
structures and common high-risk fields. It is not a replacement for JSON Schema
validation in production.
"""

REQUIRED_TOP_LEVEL = [
    "load_id", "carrier", "stops", "equipment", "cargo",
    "commercial_terms", "tracking", "dependent_sector"
]

REQUIRED_CARGO_FIELDS = [
    "commodity", "total_weight_lb", "total_pieces", "hazmat"
]

REQUIRED_STOP_FIELDS = [
    "stop_type", "sequence", "facility_id", "name", "street", "city",
    "state", "zip", "dock", "appointment_start", "appointment_end"
]

def validate_transaction_schema(transaction):
    errors = []

    if not isinstance(transaction, dict):
        return {
            "valid": False,
            "errors": [f"invalid_transaction_type:{type(transaction).__name__}"],
        }

    for field in REQUIRED_TOP_LEVEL:
        if field not in transaction:
            errors.append(f"missing_top_level:{field}")

    stops = transaction.get("stops", [])
    if not isinstance(stops, list) or len(stops) < 2:
        errors.append("stops_missing_or_insufficient")

    for i, stop in enumerate(stops if isinstance(stops, list) else []):
        if not isinstance(stop, dict):
            errors.append(f"stop_{i}_invalid_type:{type(stop).__name__}")
            continue
        for field in REQUIRED_STOP_FIELDS:
            if field not in stop:
                errors.append(f"stop_{i}_missing:{field}")

    cargo = transaction.get("cargo", {})
    if not isinstance(cargo, dict):
        errors.append(f"cargo_invalid_type:{type(cargo).__name__}")
        cargo = {}
    for field in REQUIRED_CARGO_FIELDS:
        if field not in cargo:
            errors.append(f"cargo_missing:{field}")

    carrier = transaction.get("carrier", {})
    if not isinstance(carrier, dict):
        errors.append(f"carrier_invalid_type:{type(carrier).__name__}")
        carrier = {}
    for field in ["carrier_id", "name", "dot_number", "mc_number"]:
        if field not in carrier:
            errors.append(f"carrier_missing:{field}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
    }
