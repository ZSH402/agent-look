"""最小 LLM 客户端：从 .secrets/qwen_api_key 读取密钥，调用 OpenAI 兼容端点。

**密钥永不打印、永不写入结果文件。**
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYFILE = os.path.join(HERE, ".secrets", "qwen_api_key")
BASE = "https://dashscope.aliyuncs.com/compatible-mode/v1"


def _key() -> str:
    with open(KEYFILE, encoding="utf-8") as f:
        return f.read().strip()


def chat(messages, model: str = "qwen3.7-flash", temperature: float = 0.0,
         max_tokens: int = 2048, timeout: int = 120) -> dict:
    body = json.dumps({"model": model, "messages": messages,
                       "temperature": temperature, "max_tokens": max_tokens}).encode()
    req = urllib.request.Request(
        f"{BASE}/chat/completions", data=body,
        headers={"Authorization": f"Bearer {_key()}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode()[:400]}
    except Exception as e:                                    # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"}


def text(resp: dict) -> str:
    if "error" in resp:
        return f"[ERROR] {resp['error']} {resp.get('body','')}"
    try:
        return resp["choices"][0]["message"]["content"]
    except Exception:                                         # noqa: BLE001
        return f"[UNPARSED] {json.dumps(resp)[:400]}"


def usage(resp: dict) -> dict:
    return resp.get("usage", {})
