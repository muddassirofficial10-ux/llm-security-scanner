"""Targets = the chatbot / LLM application being tested.

- DemoTarget:   built-in vulnerable ShopBot (no API key needed)
- HTTPTarget:   any chatbot API that accepts JSON {"<field>": prompt}
- OpenAITarget: any OpenAI-compatible chat API (OpenAI, Ollama, LM Studio, vLLM ...)
Only the Python standard library is used, so there is nothing extra to install.
"""
import json
import os
import urllib.request

from .demo_bot import CANARY, DemoBot


class Target:
    name = "target"
    canary = None

    def send(self, prompt: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class DemoTarget(Target):
    def __init__(self, hardened: bool = False):
        self.bot = DemoBot(hardened=hardened)
        self.name = "demo-shopbot (hardened)" if hardened else "demo-shopbot (vulnerable)"
        self.canary = CANARY

    def send(self, prompt: str) -> str:
        return self.bot.chat(prompt)


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


class HTTPTarget(Target):
    """Generic JSON chatbot endpoint. reply_path like 'reply' or 'data.answer'."""

    def __init__(self, url: str, prompt_field: str = "message", reply_path: str = "reply",
                 headers: dict | None = None, canary: str | None = None):
        self.url, self.prompt_field, self.reply_path = url, prompt_field, reply_path
        self.headers = headers or {}
        self.name, self.canary = url, canary

    def send(self, prompt: str) -> str:
        data = _post_json(self.url, {self.prompt_field: prompt}, self.headers)
        for key in self.reply_path.split("."):
            data = data[int(key)] if isinstance(data, list) else data.get(key, "")
        return str(data)


class OpenAITarget(Target):
    """OpenAI-compatible /v1/chat/completions. The API key is read from an environment variable."""

    def __init__(self, base_url: str, model: str, system_prompt: str = "", api_key_env: str = "OPENAI_API_KEY",
                 canary: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.model, self.system_prompt = model, system_prompt
        self.api_key = os.environ.get(api_key_env, "")
        self.name, self.canary = f"{model} @ {self.base_url}", canary

    def send(self, prompt: str) -> str:
        messages = ([{"role": "system", "content": self.system_prompt}] if self.system_prompt else []) + [
            {"role": "user", "content": prompt}
        ]
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post_json(f"{self.base_url}/chat/completions",
                          {"model": self.model, "messages": messages, "max_tokens": 800}, headers)
        return data["choices"][0]["message"]["content"]
