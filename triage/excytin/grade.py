"""Grading ExCyTIn answers.

1. ``match``: deterministic. The normalised golden answer appears in the normalised submission as a whole
   token, and the submission is not a long enumeration (upstream's rule: lists of more than 10 items are
   not credited). Fast, free, reproducible; it decides most cases.
2. ``judge``: anything ``match`` rejects goes to an LLM judge using upstream's fuzzy prompt verbatim
   (format differences, timestamps within a reasonable window, "notepad" vs "notepad.exe"). Run on the
   local model it is free; pass ``judge=None`` to grade with ``match`` only.

Reported metric: answer accuracy (upstream's first-stage check). Upstream's headline "reward" also gives
partial credit for correct intermediate steps, so numbers here are comparable to their answer-correct
rate, not to that reward.
"""

from __future__ import annotations

import re

from langchain_core.messages import HumanMessage, SystemMessage

from triage.excytin.judge_prompt import EVAL_ANSWER_TEMPLATE, FUZZY_ANSWER_CHECK_PROMPT

_STRIP = re.compile(r"^(https?://)?(www\.)?")
_SEPARATORS = re.compile(r"[,;\n]|\band\b")


def normalise(text: str) -> str:
    t = (text or "").strip().lower()
    t = t.replace("`", "").replace('"', "").replace("'", "")
    t = _STRIP.sub("", t).rstrip("/").rstrip(".")
    return re.sub(r"\s+", " ", t)


def _variants(golden: str) -> set:
    g = normalise(golden)
    out = {g}
    if g.endswith(".exe"):
        out.add(g[:-4])
    if "@" in g:  # account given as UPN; the bare user name is the same account
        out.add(g.split("@")[0])
    return {v for v in out if v}


def match(golden: str, submitted: str) -> bool:
    sub = normalise(submitted)
    if not sub:
        return False
    if len([p for p in _SEPARATORS.split(sub) if p.strip()]) > 10:
        return False
    for g in _variants(golden):
        if re.search(r"(?<![\w.-])" + re.escape(g) + r"(?![\w-])", sub):
            return True
    return False


class Grader:
    def __init__(self, judge=None):
        """``judge``: a ChatClient (or anything with ``invoke(messages, tools=None)``) or None."""
        self.judge = judge

    def grade(self, question: dict, submitted: str) -> dict:
        golden = str(question["answer"])
        if match(golden, submitted):
            return {"correct": True, "method": "match"}
        if not (submitted or "").strip():
            return {"correct": False, "method": "empty"}
        if self.judge is None:
            return {"correct": False, "method": "match"}
        prompt = EVAL_ANSWER_TEMPLATE.format(
            question=f"{question.get('context', '')} {question['question']}".strip(),
            golden_answer=golden, submitted_answer=submitted)
        msg, _ = self.judge.invoke([SystemMessage(content=FUZZY_ANSWER_CHECK_PROMPT), HumanMessage(content=prompt)])
        text = msg.content if isinstance(msg.content, str) else str(msg.content)
        verdict = re.search(r"Is_Answer_Correct:\s*\**\s*\"?(True|False)", text, re.I)
        return {"correct": bool(verdict and verdict.group(1).lower() == "true"), "method": "judge",
                "judge_text": text[-400:]}
