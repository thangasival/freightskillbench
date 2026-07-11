"""
Provider stubs for Phase 5.

These are placeholders. They document where frontier-tier, mid-tier, and
open-weight model calls should be implemented. The sandbox package uses the
offline simulated extractor so the benchmark can run without external APIs.
"""

from __future__ import annotations

from .base import BaseModelClient, ModelRunRequest, ModelRunResponse


class ProviderModelClient(BaseModelClient):
    def __init__(self, provider: str, model_name: str):
        self.provider = provider
        self.model_name = model_name

    def run(self, request: ModelRunRequest) -> ModelRunResponse:
        raise NotImplementedError(
            "Provider API calls are not implemented in this offline package. "
            "Implement this method with your chosen model provider, then pass the "
            "model output into the Phase 4 evaluator."
        )
