"""
Hugging Face Inference client for FreightSkillBench Phase 6.

Requires:
    pip install requests
    export HF_TOKEN=...
    export HF_MODEL_OPEN_WEIGHT=...
"""

from __future__ import annotations

import os
import requests

from .base import BaseModelClient, ModelRunRequest, ModelRunResponse
from agent.json_utils import extract_json_object, ensure_warnings


class HuggingFaceInferenceClient(BaseModelClient):
    def __init__(self, model: str | None = None, token_env: str = "HF_TOKEN"):
        self.model = model
        self.token_env = token_env

    def run(self, request: ModelRunRequest) -> ModelRunResponse:
        token = os.getenv(self.token_env)
        model = self.model or request.model_name

        if not token:
            return ModelRunResponse(request.model_tier, model, {}, "", False, f"Missing environment variable: {self.token_env}")

        try:
            url = f"https://api-inference.huggingface.co/models/{model}"
            headers = {"Authorization": f"Bearer {token}"}
            payload = {
                "inputs": request.prompt + "\n\n--- LOGISTICS DOCUMENT START ---\n" + request.document_text + "\n--- LOGISTICS DOCUMENT END ---\n",
                "parameters": {"temperature": 0.0, "max_new_tokens": 4096, "return_full_text": False},
            }

            resp = requests.post(url, headers=headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()

            if isinstance(data, list) and data and "generated_text" in data[0]:
                raw_text = data[0]["generated_text"]
            elif isinstance(data, dict) and "generated_text" in data:
                raw_text = data["generated_text"]
            else:
                raw_text = str(data)

            obj, err = extract_json_object(raw_text)
            if err:
                return ModelRunResponse(request.model_tier, model, {}, raw_text, False, err)

            return ModelRunResponse(request.model_tier, model, ensure_warnings(obj), raw_text, True, "")

        except Exception as e:
            return ModelRunResponse(request.model_tier, model, {}, "", False, f"huggingface_client_error:{e}")
