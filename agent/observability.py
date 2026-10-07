"""Token accounting and tracing callbacks for LangChain runs.

UsageCallback  - sums the *real* token usage the API reports across every LLM
                 call in a run (all agent iterations, including the injected
                 history and scratchpad that the old chars//4 estimate ignored).
TraceCallback  - appends one JSON line per LLM/tool event to TRACE_FILE. It is a
                 dependency-free stand-in for a tracing backend; to use Langfuse
                 instead, pass langfuse.callback.CallbackHandler() in the same
                 `callbacks` list (see README).
"""

import json
import os
import time

from langchain_core.callbacks import BaseCallbackHandler


class UsageCallback(BaseCallbackHandler):
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.llm_calls = 0

    @property
    def total_tokens(self):
        return self.input_tokens + self.output_tokens

    def on_llm_end(self, response, **kwargs):
        self.llm_calls += 1
        found = False
        for gens in response.generations:
            for g in gens:
                usage = getattr(getattr(g, "message", None), "usage_metadata", None)
                if usage:
                    self.input_tokens += usage.get("input_tokens", 0)
                    self.output_tokens += usage.get("output_tokens", 0)
                    found = True
        if not found:
            tu = (response.llm_output or {}).get("token_usage") or {}
            self.input_tokens += tu.get("prompt_tokens", 0)
            self.output_tokens += tu.get("completion_tokens", 0)


class TraceCallback(BaseCallbackHandler):
    def __init__(self, path=None, run_label=""):
        self.path = path or os.getenv("TRACE_FILE")
        self.run_label = run_label

    def _write(self, event, **fields):
        if not self.path:
            return
        rec = {"t": round(time.time(), 3), "label": self.run_label, "event": event, **fields}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def on_tool_start(self, serialized, input_str, **kwargs):
        self._write("tool_start", tool=(serialized or {}).get("name"), input=input_str)

    def on_tool_end(self, output, **kwargs):
        self._write("tool_end", output=str(output)[:2000])

    def on_llm_end(self, response, **kwargs):
        self._write("llm_end", generations=len(response.generations))
