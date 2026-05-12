import time
from typing import Optional

import requests

try:
    from .config import (
        LLM_CTX_NUM,
        LLM_MODEL,
        LLM_OLLAMA_URL,
        LLM_RETRY,
        LLM_TEMPERATURE,
        LLM_TOP_P,
    )
    from .logger import log
except ImportError:
    from config import (  # type: ignore
        LLM_CTX_NUM,
        LLM_MODEL,
        LLM_OLLAMA_URL,
        LLM_RETRY,
        LLM_TEMPERATURE,
        LLM_TOP_P,
    )
    from logger import log  # type: ignore


class AgentBase:
    def __init__(self) -> None:
        self.default_url = LLM_OLLAMA_URL
        self.retry = LLM_RETRY 
        self.model = LLM_MODEL
        self.temperature = LLM_TEMPERATURE
        self.top_p = LLM_TOP_P
        self.ctx_num = LLM_CTX_NUM

    def run(
        self,
        prompt: str,
    ) -> Optional[str]:
        target_url = self.default_url
        if not target_url:
            log("Agent run failed: ollama_url is empty.")
            return None

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "top_p": self.top_p,
                "num_ctx": self.ctx_num,
            },
        }

        for attempt in range(self.retry):
            try:
                response = requests.post(target_url, json=payload, timeout=600)
                if response.status_code == 200:
                    result = response.json()
                    return result.get("response", "").strip()
                log(f"Error from Ollama (Attempt {attempt + 1}): {response.status_code} - {response.text}")
                time.sleep(2)
            except Exception as e:
                log(f"Exception calling Ollama (Attempt {attempt + 1}): {e}")
                time.sleep(2)

        return None
    
class ImpAgent(AgentBase):
    """应用层实现类，对外可直接实例化使用。"""

    def __init__(self) -> None:
        super().__init__()

    def run(self, prompt: str) -> Optional[str]:
        return super().run(prompt)