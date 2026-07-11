"""
Provider factory for FreightSkillBench Phase 6.
"""

from __future__ import annotations

from agent.model_clients.openai_responses_client import OpenAIResponsesClient
from agent.model_clients.anthropic_client import AnthropicMessagesClient
from agent.model_clients.huggingface_client import HuggingFaceInferenceClient
from agent.model_clients.ollama_client import OllamaClient


def build_client(provider: str, model: str):
    provider = provider.lower().strip()
    if provider == "openai":
        return OpenAIResponsesClient(model=model)
    if provider == "anthropic":
        return AnthropicMessagesClient(model=model)
    if provider in {"huggingface", "hf"}:
        return HuggingFaceInferenceClient(model=model)
    if provider == "ollama":
        return OllamaClient(model=model)
    raise ValueError(f"Unsupported provider: {provider}")
