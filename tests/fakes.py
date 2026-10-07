"""Scripted stand-ins for a chat model, so the agent loop can be tested with no API key or local model."""

from __future__ import annotations

import itertools

from langchain_core.messages import AIMessage

_ids = itertools.count()


def call(name: str, **args) -> AIMessage:
    """An AIMessage that calls one tool."""
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{next(_ids)}"}],
                     usage_metadata={"input_tokens": 100, "output_tokens": 10, "total_tokens": 110})


def text(content: str) -> AIMessage:
    return AIMessage(content=content, usage_metadata={"input_tokens": 100, "output_tokens": 10, "total_tokens": 110})


class ScriptedChat:
    """``policy(messages, tools) -> AIMessage``; or a list of messages returned in order."""

    def __init__(self, policy):
        if isinstance(policy, list):
            seq = iter(policy)
            self.policy = lambda messages, tools: next(seq)
        else:
            self.policy = policy
        self.calls = []
        self._tools = None

    def bind_tools(self, tools):
        bound = ScriptedChat(self.policy)
        bound.calls = self.calls
        bound._tools = tools
        return bound

    def invoke(self, messages):
        self.calls.append((messages, self._tools))
        return self.policy(messages, self._tools)
