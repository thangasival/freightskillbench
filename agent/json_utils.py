"""
JSON extraction and normalization utilities for provider model outputs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Tuple


def extract_json_object(text: str) -> Tuple[Dict[str, Any], str]:
    """Extract the first JSON object from a provider response."""
    if not text:
        return {}, "empty_output"

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.I).strip()
        stripped = re.sub(r"```$", "", stripped).strip()

    try:
        return json.loads(stripped), ""
    except Exception:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        candidate = stripped[start:end + 1]
        try:
            return json.loads(candidate), ""
        except Exception as e:
            return {}, f"json_parse_error:{e}"

    return {}, "no_json_object_found"


def ensure_warnings(obj: Dict[str, Any]) -> Dict[str, Any]:
    if "warnings" not in obj or obj["warnings"] is None:
        obj["warnings"] = []
    if not isinstance(obj["warnings"], list):
        obj["warnings"] = [str(obj["warnings"])]
    return obj
