"""Pick a local model: run the same small question set on each and compare accuracy, tool-call reliability
and speed.

    python -m triage.excytin.bakeoff --models "batiai/qwen3.6-35b:iq3,gpt-oss:20b" --per-incident 3

24 questions (3 from each incident) per model with no memory. Writes results/excytin/bakeoff_<model>.jsonl
and prints a table. Free on a local model; a few minutes per model.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from triage.excytin import run
from triage.excytin.analyze import load


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", required=True, help="comma-separated model names as your server knows them")
    ap.add_argument("--per-incident", type=int, default=3)
    ap.add_argument("--max-steps", type=int, default=15)
    ap.add_argument("--outdir", type=Path, default=Path("results/excytin"))
    args = ap.parse_args(argv)
    rows = []
    for model in [m.strip() for m in args.models.split(",") if m.strip()]:
        os.environ["TRIAGE_MODEL"] = model
        out = args.outdir / f"bakeoff_{re.sub(r'[^A-Za-z0-9.]+', '_', model)}.jsonl"
        run.main(["--memory", "none", "--per-incident", str(args.per_incident), "--max-steps", str(args.max_steps),
                  "--out", str(out)])
        recs = load(out)
        n = len(recs) or 1
        rows.append((model, sum(r["correct"] for r in recs) / n,
                     sum(r["fallback"] is not None for r in recs) / n,
                     sum(bool(r["error"]) for r in recs) / n,
                     sum(r["wall_seconds"] for r in recs) / n,
                     sum(r["steps"] for r in recs) / n, len(recs)))
    print("\n| Model | n | Accuracy | Never called submit | Errors | Sec/question | Tool calls |")
    print("|---|---|---|---|---|---|---|")
    for m, acc, nosub, err, sec, steps, n in rows:
        print(f"| {m} | {n} | {acc:.0%} | {nosub:.0%} | {err:.0%} | {sec:.0f} | {steps:.1f} |")


if __name__ == "__main__":
    main()
