"""
OpenAI Responses API client for FreightSkillBench Phase 6.

Requires:
    pip install openai
    export OPENAI_API_KEY=...
    export OPENAI_MODEL_FRONTIER=...
or:
    export OPENAI_MODEL_MID=...

This client is not executed unless dry_run=false and the provider/model are enabled.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from .base import BaseModelClient, ModelRunRequest, ModelRunResponse
from agent.json_utils import extract_json_object, ensure_warnings


def supports_temperature(model: str) -> bool:
    model_name = model.lower().strip()
    return not model_name.startswith(("gpt-5", "o1", "o3", "o4"))


def is_temperature_unsupported_error(error: Exception) -> bool:
    message = str(error).lower()
    return "unsupported parameter" in message and "temperature" in message


class OpenAIResponsesClient(BaseModelClient):
    def __init__(self, model: str | None = None, api_key_env: str = "OPENAI_API_KEY"):
        self.model = model
        self.api_key_env = api_key_env

    def run(self, request: ModelRunRequest) -> ModelRunResponse:
        api_key = os.getenv(self.api_key_env)
        model = self.model or request.model_name

        if not api_key:
            return ModelRunResponse(
                model_tier=request.model_tier,
                model_name=model,
                output_json={},
                raw_text="",
                success=False,
                error=f"Missing environment variable: {self.api_key_env}",
            )

        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)

            full_input = (
                request.prompt
                + "\n\n--- LOGISTICS DOCUMENT START ---\n"
                + request.document_text
                + "\n--- LOGISTICS DOCUMENT END ---\n"
            )

            create_kwargs = {
                "model": model,
                "input": full_input,
            }
            if supports_temperature(model):
                create_kwargs["temperature"] = 0

            try:
                response = client.responses.create(**create_kwargs)
            except Exception as e:
                if "temperature" in create_kwargs and is_temperature_unsupported_error(e):
                    create_kwargs.pop("temperature")
                    response = client.responses.create(**create_kwargs)
                else:
                    raise

            raw_text = getattr(response, "output_text", "") or str(response)
            obj, err = extract_json_object(raw_text)
            if err:
                return ModelRunResponse(
                    model_tier=request.model_tier,
                    model_name=model,
                    output_json={},
                    raw_text=raw_text,
                    success=False,
                    error=err,
                )

            return ModelRunResponse(
                model_tier=request.model_tier,
                model_name=model,
                output_json=ensure_warnings(obj),
                raw_text=raw_text,
                success=True,
                error="",
            )

        except Exception as e:
            return ModelRunResponse(
                model_tier=request.model_tier,
                model_name=model,
                output_json={},
                raw_text="",
                success=False,
                error=f"openai_client_error:{e}",
            )
