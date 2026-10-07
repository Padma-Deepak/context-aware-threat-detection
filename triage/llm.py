"""Chat-model access for the triage agent: provider switch, response cache, budget guard.

Providers (TRIAGE_PROVIDER):
    ollama    (default) local model at http://localhost:11434/v1, costs nothing
    lmstudio            local model at http://localhost:1234/v1 (MLX builds are often faster on Apple Silicon)
    openai              OpenAI API, needs OPENAI_API_KEY; every call is charged against TRIAGE_BUDGET_USD

All three speak the OpenAI chat-completions protocol, so one client covers them.

Response cache (TRIAGE_CACHE):
    readwrite (default) reuse an identical earlier call, otherwise call the model and store the result
    record              always call the model, store the result (refreshes a cassette)
    replay              never call the model; a cache miss raises CacheMiss. CI uses this with a committed
                        cassette, so LLM regression tests run without a key or a local model.
    off                 no cache

The cache key is everything that can change the response: provider, model, temperature, seed, the full
message list and the tool schemas. Re-running an analysis or fixing a grading bug never pays twice.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, messages_from_dict, messages_to_dict

ROOT = Path(__file__).resolve().parents[1]

PROVIDERS = {
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "openai": None,
}
DEFAULT_MODEL = {"ollama": "gpt-oss:20b", "lmstudio": "qwen3.6-35b-a3b", "openai": "gpt-4o-mini"}

# USD per 1M tokens (input, output). Local models are free. Check openai.com/api/pricing before a paid
# run and override with TRIAGE_PRICE_IN / TRIAGE_PRICE_OUT if these are stale.
PRICES = {
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-5.6-luna": (0.20, 1.20),
}


class CacheMiss(RuntimeError):
    """Raised in replay mode when a call is not in the cassette."""


class BudgetExceeded(RuntimeError):
    """Raised before a paid call once the spend limit is reached."""


def _message_dict(m: BaseMessage) -> dict:
    """Stable, provider-agnostic form of a message for hashing."""
    d = {"type": m.type, "content": m.content}
    if isinstance(m, AIMessage) and m.tool_calls:
        d["tool_calls"] = [{"name": c["name"], "args": c["args"], "id": c.get("id")} for c in m.tool_calls]
    if getattr(m, "tool_call_id", None):
        d["tool_call_id"] = m.tool_call_id
    return d


def cache_key(provider: str, model: str, temperature: float, seed: int | None, messages, tools) -> str:
    blob = json.dumps(
        {
            "provider": provider,
            "model": model,
            "temperature": temperature,
            "seed": seed,
            "messages": [_message_dict(m) for m in messages],
            "tools": tools or [],
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


class ResponseCache:
    def __init__(self, path: Path | str, mode: str = "readwrite"):
        if mode not in ("readwrite", "record", "replay", "off"):
            raise ValueError(f"unknown TRIAGE_CACHE mode {mode!r}")
        self.mode = mode
        self.hits = self.misses = 0
        self._lock = threading.Lock()
        if mode != "off":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(path), check_same_thread=False)
            self._db.execute("CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, message TEXT, created REAL)")

    def get(self, key: str) -> AIMessage | None:
        if self.mode in ("off", "record"):
            return None
        with self._lock:
            row = self._db.execute("SELECT message FROM responses WHERE key = ?", (key,)).fetchone()
        if row is None:
            self.misses += 1
            if self.mode == "replay":
                raise CacheMiss(f"response {key[:12]} is not in the cassette (TRIAGE_CACHE=replay)")
            return None
        self.hits += 1
        return messages_from_dict([json.loads(row[0])])[0]

    def put(self, key: str, message: AIMessage):
        if self.mode in ("off", "replay"):
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO responses VALUES (?, ?, ?)",
                (key, json.dumps(messages_to_dict([message])[0]), time.time()),
            )
            self._db.commit()


@dataclass
class Budget:
    """Running spend for paid providers. Thread-safe; shared by every agent in a run."""

    max_usd: float
    price_in: float = 0.0
    price_out: float = 0.0
    spent_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def check(self):
        if self.price_in or self.price_out:
            if self.spent_usd >= self.max_usd:
                raise BudgetExceeded(f"spent ${self.spent_usd:.4f} of ${self.max_usd:.2f} (TRIAGE_BUDGET_USD)")

    def add(self, input_tokens: int, output_tokens: int) -> float:
        cost = (input_tokens * self.price_in + output_tokens * self.price_out) / 1e6
        with self._lock:
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            self.spent_usd += cost
        return cost


class ChatClient:
    """``invoke(messages, tools) -> (AIMessage, info)``; info has tokens, cost and whether it was cached.

    ``backend`` is anything with ``bind_tools(tools).invoke(messages)``; tests pass a scripted fake.
    """

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        temperature: float = 0.0,
        seed: int | None = None,
        cache: ResponseCache | None = None,
        budget: Budget | None = None,
        backend=None,
        max_tokens: int | None = None,
    ):
        self.provider = (provider or os.getenv("TRIAGE_PROVIDER", "ollama")).lower()
        if self.provider not in PROVIDERS:
            raise ValueError(f"TRIAGE_PROVIDER must be one of {sorted(PROVIDERS)}")
        self.model = model or os.getenv("TRIAGE_MODEL") or DEFAULT_MODEL[self.provider]
        self.temperature = temperature
        self.seed = seed
        self.max_tokens = max_tokens or int(os.getenv("TRIAGE_MAX_OUTPUT_TOKENS", "4096"))
        self.cache = cache if cache is not None else default_cache()
        self.budget = budget if budget is not None else default_budget(self.provider, self.model)
        self._backend = backend
        self.parse_retries = 0

    def _get_backend(self):
        if self._backend is None:
            from langchain_openai import ChatOpenAI

            base_url = os.getenv("TRIAGE_BASE_URL") or PROVIDERS[self.provider]
            api_key = os.getenv("OPENAI_API_KEY") if self.provider == "openai" else "local"
            kwargs = {"base_url": base_url} if base_url else {}
            if self.seed is not None:
                kwargs["seed"] = self.seed
            self._backend = ChatOpenAI(
                model=self.model,
                temperature=self.temperature,
                api_key=api_key,
                max_tokens=self.max_tokens,
                timeout=float(os.getenv("TRIAGE_TIMEOUT", "600")),
                max_retries=6,
                **kwargs,
            )
        return self._backend

    def invoke(self, messages: list[BaseMessage], tools: list[dict] | None = None):
        key = cache_key(self.provider, self.model, self.temperature, self.seed, messages, tools)
        cached = self.cache.get(key)
        if cached is not None:
            usage = cached.usage_metadata or {}
            return cached, {"cached": True, "input_tokens": usage.get("input_tokens", 0),
                            "output_tokens": usage.get("output_tokens", 0), "cost_usd": 0.0, "seconds": 0.0}
        self.budget.check()
        backend = self._get_backend()
        runnable = backend.bind_tools(tools) if tools else backend
        start = time.time()
        msg = self._invoke_with_retry(runnable, messages, tools)
        seconds = time.time() - start
        usage = msg.usage_metadata or {}
        cost = self.budget.add(usage.get("input_tokens", 0), usage.get("output_tokens", 0))
        self.cache.put(key, msg)
        return msg, {"cached": False, "input_tokens": usage.get("input_tokens", 0),
                     "output_tokens": usage.get("output_tokens", 0), "cost_usd": cost, "seconds": seconds}


    PARSE_RETRIES = 3
    RETRYABLE = ("error parsing tool call", "token repeat limit")
    PARSE_HINT = ("Your last reply could not be parsed as a tool call. Reply with the tool call only: "
                  "no explanation, no text before or after it.")

    def _invoke_with_retry(self, runnable, messages, tools):
        """Local servers (Ollama with reasoning models such as gpt-oss) sometimes return HTTP 500 'error
        parsing tool call' (reasoning written into the tool-call channel) or 'token repeat limit' (a
        degenerate loop). The request is not at fault, so retry with a reminder; any other error is
        raised unchanged."""
        for attempt in range(self.PARSE_RETRIES + 1):
            try:
                return runnable.invoke(messages if attempt == 0 else messages + [HumanMessage(content=self.PARSE_HINT)])
            except Exception as exc:  # noqa: BLE001
                if not any(k in str(exc) for k in self.RETRYABLE) or attempt == self.PARSE_RETRIES:
                    raise
                self.parse_retries += 1


_DEFAULT_CACHE = None
_DEFAULT_BUDGETS: dict = {}


def default_cache() -> ResponseCache:
    global _DEFAULT_CACHE
    if _DEFAULT_CACHE is None:
        path = os.getenv("TRIAGE_CACHE_PATH", str(ROOT / ".llm_cache" / "responses.sqlite"))
        _DEFAULT_CACHE = ResponseCache(path, os.getenv("TRIAGE_CACHE", "readwrite"))
    return _DEFAULT_CACHE


def default_budget(provider: str, model: str) -> Budget:
    """One shared Budget per (provider, model) so concurrent agents draw from the same limit."""
    key = (provider, model)
    if key not in _DEFAULT_BUDGETS:
        if provider == "openai":
            price_in, price_out = PRICES.get(model, (None, None))
            price_in = float(os.getenv("TRIAGE_PRICE_IN", price_in if price_in is not None else 0))
            price_out = float(os.getenv("TRIAGE_PRICE_OUT", price_out if price_out is not None else 0))
            if not (price_in or price_out):
                raise ValueError(f"no price known for {model}; set TRIAGE_PRICE_IN and TRIAGE_PRICE_OUT (USD per 1M)")
        else:
            price_in = price_out = 0.0
        _DEFAULT_BUDGETS[key] = Budget(float(os.getenv("TRIAGE_BUDGET_USD", "5")), price_in, price_out)
    return _DEFAULT_BUDGETS[key]
