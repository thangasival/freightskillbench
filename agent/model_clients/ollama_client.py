"""
Ollama local client for FreightSkillBench Phase 6.

Requires:
    ollama serve
    ollama pull <model>
    export OLLAMA_MODEL_OPEN_WEIGHT=<model>
"""

from __future__ import annotations

import os
import requests

from .base import BaseModelClient, ModelRunRequest, ModelRunResponse
from agent.json_utils import extract_json_object, ensure_warnings


class OllamaClient(BaseModelClient):
    def __init__(self, model: str | None = None, base_url_env: str = "OLLAMA_BASE_URL"):
        self.model = model
        self.base_url_env = base_url_env

    def run(self, request: ModelRunRequest) -> ModelRunResponse:
        base_url = os.getenv(self.base_url_env, "http://localhost:11434").rstrip("/")
        model = self.model or request.model_name

        try:
            payload = {
                "model": model,
                "prompt": request.prompt + "\n\n--- LOGISTICS DOCUMENT START ---\n" + request.document_text + "\n--- LOGISTICS DOCUMENT END ---\n",
                "stream": False,
                "options": {
                    "temperature": 0.0,
                    "num_predict": 2048,
                },
            }
            resp = requests.post(f"{base_url}/api/generate", json=payload, timeout=600)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data.get("response", "")

            obj, err = extract_json_object(raw_text)
            if err:
                return ModelRunResponse(request.model_tier, model, {}, raw_text, False, err)

            return ModelRunResponse(request.model_tier, model, ensure_warnings(obj), raw_text, True, "")

        except Exception as e:
            return ModelRunResponse(request.model_tier, model, {}, "", False, f"ollama_client_error:{e}")
