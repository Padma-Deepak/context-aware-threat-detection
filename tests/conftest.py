import json
from types import SimpleNamespace

import pytest


def action(tool, **tool_input):
    """Stand-in for LangChain's AgentAction: only .tool and .tool_input are used."""
    return SimpleNamespace(tool=tool, tool_input=tool_input)


def ip_rep(ip, score, malicious=None, sources=(), first_seen="2026-01-01"):
    return json.dumps(
        {
            "ip": ip,
            "malicious": score >= 50 if malicious is None else malicious,
            "score": score,
            "sources_flagging": list(sources),
            "first_seen": first_seen,
        }
    )


def report(verdict, target="203.0.113.1"):
    return (
        f"## Investigation Report\n\n**Target:** {target}\n\n### Risk Assessment\n"
        f"**Severity:** HIGH\n**Confidence:** MEDIUM\n**ATT&CK:** T1110 Brute Force\n\nVERDICT: {verdict}\n"
    )


@pytest.fixture
def fake_summarizer():
    calls = []

    def summarize(prompt):
        calls.append(prompt)
        return f"SUMMARY#{len(calls)}", 100

    summarize.calls = calls
    return summarize
