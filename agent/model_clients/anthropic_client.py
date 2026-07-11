"""
Anthropic client for FreightSkillBench Phase 6.

Requires:
    pip install anthropic
    export ANTHROPIC_API_KEY=...
"""

from __future__ import annotations

import os
from typing import Any

from .base import BaseModelClient, ModelRunRequest, ModelRunResponse
from agent.json_utils import extract_json_object, ensure_warnings


def is_temperature_rejected_error(error: Exception) -> bool:
    message = str(error).lower()
    return "temperature" in message and (
        "unsupported" in message
        or "deprecated" in message
        or "not supported" in message
    )


def supports_temperature(model: str) -> bool:
    model_name = model.lower().strip()
    parts = model_name.split("-")

    if parts and parts[0] == "claude":
        version_part = parts[1] if len(parts) > 1 and parts[1].isdigit() else None
        if version_part is None and len(parts) > 2 and parts[1] in {"haiku", "sonnet", "opus"} and parts[2].isdigit():
            version_part = parts[2]
        if version_part is not None and int(version_part) >= 4:
            return False

    return True


class AnthropicMessagesClient(BaseModelClient):
    def __init__(self, model: str | None = None, api_key_env: str = "ANTHROPIC_API_KEY"):
        self.model = model
        self.api_key_env = api_key_env

    def _create_message(self, client: Any, model: str, messages: list[dict[str, str]]):
        create_kwargs = {
            "model": model,
            "max_tokens": 8192,
            "messages": messages,
        }
        if supports_temperature(model):
            create_kwargs["temperature"] = 0

        try:
            return client.messages.create(**create_kwargs)
        except Exception as e:
            if "temperature" in create_kwargs and is_temperature_rejected_error(e):
                create_kwargs.pop("temperature")
                return client.messages.create(**create_kwargs)
            raise

    @staticmethod
    def _response_text(msg: Any) -> str:
        return "".join(
            block.text for block in msg.content
            if getattr(block, "type", "") == "text"
        )

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
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            user_text = (
                request.prompt
                + "\n\n--- LOGISTICS DOCUMENT START ---\n"
                + request.document_text
                + "\n--- LOGISTICS DOCUMENT END ---\n"
            )

            msg = self._create_message(client, model, [{"role": "user", "content": user_text}])
            raw_text = self._response_text(msg)
            obj, err = extract_json_object(raw_text)
            if err:
                retry_text = (
                    user_text
                    + "\n\nThe previous response was not parseable as JSON. "
                    + "Regenerate the full transaction as one complete valid JSON object only. "
                    + "Do not use markdown fences, comments, ellipses, or trailing text."
                )
                retry_msg = self._create_message(client, model, [{"role": "user", "content": retry_text}])
                retry_raw_text = self._response_text(retry_msg)
                retry_obj, retry_err = extract_json_object(retry_raw_text)
                if not retry_err:
                    return ModelRunResponse(request.model_tier, model, ensure_warnings(retry_obj), retry_raw_text, True, "")

                combined_raw_text = (
                    "--- FIRST ANTHROPIC RESPONSE ---\n"
                    + raw_text
                    + "\n\n--- RETRY ANTHROPIC RESPONSE ---\n"
                    + retry_raw_text
                )
                combined_error = f"{err}; retry_{retry_err}"
                return ModelRunResponse(request.model_tier, model, {}, combined_raw_text, False, combined_error)

            return ModelRunResponse(request.model_tier, model, ensure_warnings(obj), raw_text, True, "")

        except Exception as e:
            return ModelRunResponse(request.model_tier, model, {}, "", False, f"anthropic_client_error:{e}")
