"""
Model client interfaces for FreightSkillBench Phase 5.

This file intentionally avoids hard-coding provider credentials. Add provider
implementations in separate files or wire them through environment variables.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ModelRunRequest:
    model_tier: str
    model_name: str
    prompt: str
    document_text: str
    metadata: Dict[str, Any]


@dataclass
class ModelRunResponse:
    model_tier: str
    model_name: str
    output_json: Dict[str, Any]
    raw_text: str
    success: bool
    error: str = ""


class BaseModelClient:
    def run(self, request: ModelRunRequest) -> ModelRunResponse:
        raise NotImplementedError
