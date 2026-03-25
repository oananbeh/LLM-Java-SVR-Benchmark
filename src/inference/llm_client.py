"""
Unified LLM client for querying ChatGPT-4, Claude 3.5 Sonnet,
Gemini 2.0 Flash, and Llama 3.2 (via Ollama).

Usage:
    client = LLMClient(model="gpt-4", api_key="...")
    response = client.query(prompt, temperature=0.0)
"""

import os
import time
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    model: str
    prompt: str
    output: str
    tokens_used: int
    latency_sec: float
    error: Optional[str] = None


SUPPORTED_MODELS = {
    "gpt-4":            "openai",
    "gpt-4o":           "openai",
    "claude-3-5-sonnet-20241022": "anthropic",
    "gemini-2.0-flash": "google",
    "llama3.2":         "ollama",
}


class LLMClient:
    """
    Single interface for all four LLMs used in the study.
    Pass model name; the client resolves the correct backend.
    """

    def __init__(self, model: str, api_key: Optional[str] = None,
                 ollama_base_url: str = "http://localhost:11434",
                 max_retries: int = 3, retry_delay: float = 5.0):
        if model not in SUPPORTED_MODELS:
            raise ValueError(f"Unsupported model '{model}'. Choose from: {list(SUPPORTED_MODELS)}")
        self.model = model
        self.backend = SUPPORTED_MODELS[model]
        self.api_key = api_key
        self.ollama_base_url = ollama_base_url
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._client = self._init_client()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_client(self):
        if self.backend == "openai":
            from openai import OpenAI
            key = self.api_key or os.environ.get("OPENAI_API_KEY")
            if not key:
                raise EnvironmentError("OPENAI_API_KEY not set.")
            return OpenAI(api_key=key)

        elif self.backend == "anthropic":
            import anthropic
            key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise EnvironmentError("ANTHROPIC_API_KEY not set.")
            return anthropic.Anthropic(api_key=key)

        elif self.backend == "google":
            import google.generativeai as genai
            key = self.api_key or os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise EnvironmentError("GOOGLE_API_KEY not set.")
            genai.configure(api_key=key)
            return genai.GenerativeModel(self.model)

        elif self.backend == "ollama":
            # Ollama is a local REST server; no special client object needed.
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def query(self, prompt: str, temperature: float = 0.0,
              max_tokens: int = 2048) -> LLMResponse:
        """
        Send a prompt and return an LLMResponse.
        Retries up to self.max_retries times on transient failures.
        """
        last_error = None
        for attempt in range(1, self.max_retries + 1):
            try:
                start = time.time()
                output, tokens = self._dispatch(prompt, temperature, max_tokens)
                latency = time.time() - start
                return LLMResponse(
                    model=self.model,
                    prompt=prompt,
                    output=output,
                    tokens_used=tokens,
                    latency_sec=round(latency, 3),
                )
            except Exception as exc:
                last_error = str(exc)
                logger.warning(f"Attempt {attempt}/{self.max_retries} failed for {self.model}: {exc}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * attempt)

        return LLMResponse(
            model=self.model,
            prompt=prompt,
            output="",
            tokens_used=0,
            latency_sec=0.0,
            error=last_error,
        )

    # ------------------------------------------------------------------
    # Backend dispatchers
    # ------------------------------------------------------------------

    def _dispatch(self, prompt: str, temperature: float,
                  max_tokens: int) -> tuple[str, int]:
        if self.backend == "openai":
            return self._call_openai(prompt, temperature, max_tokens)
        elif self.backend == "anthropic":
            return self._call_anthropic(prompt, temperature, max_tokens)
        elif self.backend == "google":
            return self._call_google(prompt, temperature, max_tokens)
        elif self.backend == "ollama":
            return self._call_ollama(prompt, temperature, max_tokens)

    def _call_openai(self, prompt: str, temperature: float,
                     max_tokens: int) -> tuple[str, int]:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        text = resp.choices[0].message.content.strip()
        tokens = resp.usage.total_tokens
        return text, tokens

    def _call_anthropic(self, prompt: str, temperature: float,
                        max_tokens: int) -> tuple[str, int]:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text.strip()
        tokens = resp.usage.input_tokens + resp.usage.output_tokens
        return text, tokens

    def _call_google(self, prompt: str, temperature: float,
                     max_tokens: int) -> tuple[str, int]:
        import google.generativeai as genai
        cfg = genai.GenerationConfig(
            temperature=temperature,
            max_output_tokens=max_tokens,
        )
        resp = self._client.generate_content(prompt, generation_config=cfg)
        text = resp.text.strip()
        # Gemini does not always expose token counts in the free tier
        tokens = getattr(resp.usage_metadata, "total_token_count", 0)
        return text, tokens

    def _call_ollama(self, prompt: str, temperature: float,
                     max_tokens: int) -> tuple[str, int]:
        import requests
        payload = {
            "model": self.model,
            "prompt": prompt,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "stream": False,
        }
        resp = requests.post(
            f"{self.ollama_base_url}/api/generate",
            json=payload,
            timeout=300,
        )
        resp.raise_for_status()
        data = resp.json()
        text = data.get("response", "").strip()
        tokens = data.get("eval_count", 0)
        return text, tokens
