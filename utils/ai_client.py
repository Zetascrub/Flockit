import json

import requests

from utils.common import print_status
from utils.config import AIProviderConfig


class AIClient:
    """Provider-neutral AI client (Ollama or OpenAI), used for per-port
    analysis, plugin generation, and cross-host finding narration alike.
    Honors config.provider consistently instead of hardcoding Ollama."""

    def __init__(self, config: AIProviderConfig):
        self.config = config

    def available(self) -> bool:
        if self.config.provider == "openai":
            return bool(self.config.openai_api_key and "apikey" not in self.config.openai_api_key.lower())
        return self._check_ollama()

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        if self.config.provider == "openai":
            return self._openai_chat(system_prompt, user_prompt)
        return self._ollama_chat(system_prompt, user_prompt)

    def _check_ollama(self) -> bool:
        host = self.config.ollama_host
        for path in ("/api/status", "/api/version"):
            try:
                response = requests.get(f"http://{host}{path}", timeout=3)
                if response.status_code == 200:
                    print_status(f"[+] Ollama service is running ({path} check)", "info")
                    return True
                print_status(f"[~] {path} returned {response.status_code}", "warning")
            except requests.RequestException as e:
                print_status(f"[!] {path} unreachable: {e}", "warning")
        print_status("[-] Ollama does not appear to be running correctly.", "error")
        return False

    def _ollama_chat(self, system_prompt: str, user_prompt: str) -> str:
        host = self.config.ollama_host.replace("http://", "").replace("https://", "")
        model = self.config.ollama_model
        url = f"http://{host}/api/chat"

        payload = {
            "model": model,
            "stream": True,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            response = requests.post(url, json=payload, stream=True, timeout=30)

            content_accumulator = []
            for line in response.iter_lines(decode_unicode=True):
                if not line.strip():
                    continue
                try:
                    chunk = json.loads(line)
                    content_piece = chunk.get("message", {}).get("content", "")
                    if content_piece:
                        content_accumulator.append(content_piece)
                except json.JSONDecodeError as e:
                    print_status(f"[!] Stream chunk parse failed: {e}", "warning")

            return "".join(content_accumulator).strip()

        except requests.RequestException as e:
            print_status(f"[!] Ollama streaming request failed: {e}", "error")
            return "⚠️ Ollama Error: Failed to connect to Ollama. Please check that Ollama is downloaded, running and accessible."

    def _openai_chat(self, system_prompt: str, user_prompt: str) -> str:
        try:
            from openai import OpenAI
        except ImportError:
            print_status("openai package not installed. Install with `pip install openai`.", "error")
            return ""

        api_key = self.config.openai_api_key
        if not api_key:
            print_status("OpenAI API key not found in settings.", "error")
            return ""

        client = OpenAI(api_key=api_key)
        try:
            response = client.chat.completions.create(
                model=self.config.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.4,
            )
            return response.choices[0].message.content
        except Exception as e:
            print_status(f"[!] OpenAI error: {e}", "error")
            return ""
