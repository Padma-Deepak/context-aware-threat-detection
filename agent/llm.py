"""Provider-agnostic chat-model factory.

Lets the same benchmark run against a second model family to check whether a
result is specific to one model.

    LLM_PROVIDER=openai     (default)  OPENAI_MODEL=gpt-4o           SUMMARIZER_MODEL=gpt-4o-mini
    LLM_PROVIDER=anthropic             ANTHROPIC_MODEL=claude-sonnet-5-5
                                       SUMMARIZER_MODEL=claude-haiku-4-5-20251001
"""

import os

DEFAULT_AGENT_MODEL = {"openai": "gpt-4o", "anthropic": "claude-sonnet-5-5"}
DEFAULT_SUMMARIZER_MODEL = {"openai": "gpt-4o-mini", "anthropic": "claude-haiku-4-5-20251001"}


def provider():
    p = os.getenv("LLM_PROVIDER", "openai").lower()
    if p not in DEFAULT_AGENT_MODEL:
        raise ValueError(f"Unknown LLM_PROVIDER {p!r}; choose openai or anthropic")
    return p


def agent_model_name():
    p = provider()
    env = "OPENAI_MODEL" if p == "openai" else "ANTHROPIC_MODEL"
    return os.getenv(env, DEFAULT_AGENT_MODEL[p])


def summarizer_model_name():
    return os.getenv("SUMMARIZER_MODEL", DEFAULT_SUMMARIZER_MODEL[provider()])


def _build(model, temperature, max_tokens=None, **kwargs):
    if provider() == "openai":
        from langchain_openai import ChatOpenAI

        extra = {"max_tokens": max_tokens} if max_tokens else {}
        # stream_usage=True: AgentExecutor streams the model, and without it OpenAI omits usage from streamed
        # responses, so real token counts would silently be 0 (found in the Sep 27 token-accounting fix).
        return ChatOpenAI(model=model, temperature=temperature, api_key=os.getenv("OPENAI_API_KEY"),
                          stream_usage=True, **extra, **kwargs)
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(
        model=model,
        temperature=temperature,
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        max_tokens=max_tokens or 4096,
        **kwargs,
    )


def make_agent_llm():
    return _build(agent_model_name(), 0, max_retries=8, timeout=120)


def make_summarizer():
    """Return a callable ``prompt -> (text, total_tokens)`` for rolling summaries."""
    llm = _build(summarizer_model_name(), 0, max_tokens=1200)  # v3 keeps one line per investigation, so it grows with the chain

    def summarize(prompt):
        msg = llm.invoke(prompt)
        usage = getattr(msg, "usage_metadata", None) or {}
        text = msg.content if isinstance(msg.content, str) else "".join(
            b.get("text", "") for b in msg.content if isinstance(b, dict)
        )
        return text.strip(), usage.get("total_tokens", 0)

    return summarize
