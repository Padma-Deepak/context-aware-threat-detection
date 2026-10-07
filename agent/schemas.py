"""Typed report parsing.

The agent's report is free text with a fixed layout. Instead of trusting a
single regex, parse it into a validated Pydantic model so that malformed
reports (wrong enum value, missing fields) are detected and counted rather
than silently mis-scored.
"""

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, ValidationError

Verdict = Literal["MALICIOUS", "BENIGN", "ESCALATE"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]

# Tolerates "VERDICT: X", "**VERDICT:** X", "VERDICT: **X**".
_VERDICT_RE = re.compile(r"VERDICT:?\**\s*\**\s*(MALICIOUS|BENIGN|ESCALATE)\b")
_SEVERITY_RE = re.compile(r"\*\*Severity:?\*\*:?\s*\[?\s*(CRITICAL|HIGH|MEDIUM|LOW)\b", re.I)
_CONFIDENCE_RE = re.compile(r"\*\*Confidence:?\*\*:?\s*\[?\s*(HIGH|MEDIUM|LOW)\b", re.I)
_TARGET_RE = re.compile(r"\*\*Target:?\*\*:?\s*(.+)")
_ATTACK_LINE_RE = re.compile(r"\*\*ATT&CK:?\*\*:?\s*(.+)")
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class InvestigationReport(BaseModel):
    verdict: Verdict
    target: Optional[str] = None
    severity: Optional[Severity] = None
    confidence: Optional[Confidence] = None
    attack_techniques: List[str] = Field(default_factory=list)


def extract_verdict(report: str) -> str:
    """Return the LAST verdict in the report, or UNKNOWN.

    Last, not first: a report that quotes the format ("VERDICT: [MALICIOUS /
    BENIGN / ESCALATE]") before concluding must be scored on its conclusion.
    """
    matches = _VERDICT_RE.findall(report or "")
    return matches[-1] if matches else "UNKNOWN"


def parse_report(report: str) -> Optional[InvestigationReport]:
    """Parse a report into a validated model, or None if it has no valid verdict."""
    verdict = extract_verdict(report)
    if verdict == "UNKNOWN":
        return None

    def first(rx):
        m = rx.search(report)
        return m.group(1).strip().upper() if m else None

    target = _TARGET_RE.search(report)
    attack = _ATTACK_LINE_RE.search(report)
    try:
        return InvestigationReport(
            verdict=verdict,
            target=target.group(1).strip() if target else None,
            severity=first(_SEVERITY_RE),
            confidence=first(_CONFIDENCE_RE),
            attack_techniques=sorted(set(_TECHNIQUE_RE.findall(attack.group(1)))) if attack else [],
        )
    except ValidationError:
        return None
