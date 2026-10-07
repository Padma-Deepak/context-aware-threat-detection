"""SOC triage command line.

    python -m triage.cli rules                         which Sigma rules compile
    python -m triage.cli ingest                        load Defender alerts + Sigma hits from all incidents
    python -m triage.cli investigate --limit 20        triage the next 20 new alerts
    python -m triage.cli review 12 BENIGN --note "IT admin script"
    python -m triage.cli calibrate --alpha 0.1         fit the auto-decision threshold from labelled cases
    python -m triage.cli metrics                       recall, false positives, escalation, cost, citations
    python -m triage.cli export-feedback out.jsonl     reviewed cases as an evaluation set
    streamlit run triage/ui/app.py                     the analyst UI
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor

from triage.cases import CaseStore
from triage.conformal import calibrate, evaluate
from triage.triage_agent import CALIBRATION_FILE


def _pct(x):
    return f"{x:.1%}" if x is not None else "n/a"


def labelled_pairs(store: CaseStore):
    """(investigation, alert, truth) for every investigated alert with a known truth."""
    out = []
    for inv in store.investigations():
        alert = store.alert(inv["alert_id"])
        truth = store.truth(alert)
        if truth:
            out.append((inv, alert, truth))
    return out


def metrics(store: CaseStore) -> dict:
    invs = store.investigations()
    pairs = labelled_pairs(store)
    mal = [(i, t) for i, _, t in pairs if t == "MALICIOUS"]
    ben = [(i, t) for i, _, t in pairs if t == "BENIGN"]
    auto = [(i, t) for i, _, t in pairs if i["decision"] == "auto"]
    n = len(invs)
    m = {
        "investigated": n,
        "labelled": len(pairs),
        "malicious_recall": sum(i["verdict"] == "MALICIOUS" for i, _ in mal) / len(mal) if mal else None,
        "malicious_missed_as_benign": sum(i["verdict"] == "BENIGN" for i, _ in mal) / len(mal) if mal else None,
        "false_positive_rate": sum(i["verdict"] == "MALICIOUS" for i, _ in ben) / len(ben) if ben else None,
        "escalation_rate": sum(i["decision"] == "escalated" for i in invs) / n if n else None,
        "auto_decision_error": sum(i["verdict"] != t for i, t in auto) / len(auto) if auto else None,
        "citation_valid_rate": sum(bool(i["citations_valid"]) for i in invs) / n if n else None,
        "avg_cost_usd": sum(i["cost_usd"] or 0 for i in invs) / n if n else None,
        "avg_seconds": sum(i["seconds"] or 0 for i in invs) / n if n else None,
        "avg_steps": sum(i["steps"] or 0 for i in invs) / n if n else None,
        "errors": sum(bool(i["error"]) for i in invs),
    }
    inj = [i for i in invs if i.get("injected")]
    m["injection_attempts"] = len(inj)
    m["injection_success_rate"] = sum(i["injection_success"] for i in inj) / len(inj) if inj else None
    m["benign_labels"] = len(ben)
    return m


def format_metrics(m: dict) -> str:
    rows = [
        ("Alerts investigated", m["investigated"]), ("With a known truth label", m["labelled"]),
        ("Malicious recall", _pct(m["malicious_recall"])),
        ("Malicious alerts called BENIGN (missed)", _pct(m["malicious_missed_as_benign"])),
        ("False-positive rate (on reviewer-labelled benign)", _pct(m["false_positive_rate"]) +
         ("" if m["benign_labels"] else "  (no benign labels yet: review some alerts)")),
        ("Escalation rate", _pct(m["escalation_rate"])),
        ("Error rate of automatic decisions", _pct(m["auto_decision_error"])),
        ("Reports with valid evidence citations", _pct(m["citation_valid_rate"])),
        ("Prompt-injection success", _pct(m["injection_success_rate"]) + f"  ({m['injection_attempts']} attempts)"),
        ("Average cost per alert", f"${m['avg_cost_usd']:.4f}" if m["avg_cost_usd"] is not None else "n/a"),
        ("Average time per alert", f"{m['avg_seconds']:.0f}s" if m["avg_seconds"] is not None else "n/a"),
        ("Average tool calls per alert", f"{m['avg_steps']:.1f}" if m["avg_steps"] is not None else "n/a"),
        ("Investigations that errored", m["errors"]),
    ]
    return "| Metric | Value |\n|---|---|\n" + "\n".join(f"| {k} | {v} |" for k, v in rows)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="triage", description="SOC alert triage agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("rules")
    p = sub.add_parser("ingest")
    p.add_argument("--incidents", default="")
    p.add_argument("--sources", default="sentinel,sigma")
    p = sub.add_parser("investigate")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--alert", type=int, action="append", help="investigate these alert ids")
    p.add_argument("--source", choices=["sentinel", "sigma"])
    p.add_argument("--inject", action="store_true", help="plant a prompt-injection row (robustness test)")
    p.add_argument("--concurrency", type=int, default=1)
    p.add_argument("--max-steps", type=int, default=12)
    p = sub.add_parser("review")
    p.add_argument("alert", type=int)
    p.add_argument("verdict", choices=["MALICIOUS", "BENIGN"])
    p.add_argument("--note", default="")
    p.add_argument("--reviewer", default="analyst")
    p = sub.add_parser("calibrate")
    p.add_argument("--alpha", type=float, default=0.1, help="target error rate of automatic decisions")
    p.add_argument("--delta", type=float, default=0.1, help="allowed probability the guarantee fails")
    p.add_argument("--from-benchmark", help="calibrate from an ExCyTIn results .jsonl instead of the case store")
    sub.add_parser("metrics")
    p = sub.add_parser("export-feedback")
    p.add_argument("out")
    args = ap.parse_args(argv)
    store = CaseStore()

    if args.cmd == "rules":
        from triage.alerts import rules_report

        print(rules_report())
    elif args.cmd == "ingest":
        from triage.alerts import ingest
        from triage.excytin.setup_db import INCIDENTS

        incidents = [int(x) for x in args.incidents.split(",") if x] or INCIDENTS
        print(json.dumps(ingest(store, incidents, tuple(args.sources.split(","))), indent=1))
        print(store.counts())
    elif args.cmd == "investigate":
        from triage.triage_agent import Triage

        ids = args.alert or [a["id"] for a in store.alerts(status="new", source=args.source, limit=args.limit)]
        triage = Triage(store, max_steps=args.max_steps, inject=args.inject)

        def one(alert_id):
            out = triage.investigate(alert_id)
            print(f"alert {alert_id}: {out['verdict']} ({out['confidence']}) -> {out['status']}"
                  + (f"  ERROR {out['error']}" if out["error"] else ""), flush=True)
            return out

        # Cases share one memory, so concurrency trades cross-case recall for speed. Default sequential.
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            list(pool.map(one, ids))
    elif args.cmd == "review":
        store.add_review(args.alert, args.verdict, args.reviewer, args.note)
        print(f"alert {args.alert} reviewed as {args.verdict}")
    elif args.cmd == "calibrate":
        if args.from_benchmark:
            from triage.excytin.analyze import load

            recs = [r for r in load(args.from_benchmark) if r.get("confidence") is not None and not r.get("error")]
            scores, correct = [r["confidence"] / 100 for r in recs], [r["correct"] for r in recs]
        else:
            pairs = [(i, t) for i, _, t in labelled_pairs(store) if i["verdict"] != "ESCALATE" and i["confidence"] is not None]
            scores, correct = [i["confidence"] / 100 for i, _ in pairs], [i["verdict"] == t for i, t in pairs]
        if len(scores) < 20:
            raise SystemExit(f"need at least 20 labelled decisions to calibrate, have {len(scores)}")
        th = calibrate(scores, correct, args.alpha, args.delta)
        ev = evaluate(th, scores, correct)
        CALIBRATION_FILE.parent.mkdir(parents=True, exist_ok=True)
        CALIBRATION_FILE.write_text(json.dumps({"threshold": th.threshold, "alpha": args.alpha, "delta": args.delta,
                                                "n": len(scores), "calibration_coverage": ev["coverage"]}, indent=1))
        print(f"threshold {th.threshold} -> automatic on {ev['coverage']:.0%} of calibration cases "
              f"(error there {ev['selective_error']:.1%}); written to {CALIBRATION_FILE}")
    elif args.cmd == "metrics":
        print(format_metrics(metrics(store)))
    elif args.cmd == "export-feedback":
        with open(args.out, "w") as f:
            for rv in store.reviews():
                alert = store.alert(rv["alert_id"])
                inv = store.latest_investigation(rv["alert_id"])
                f.write(json.dumps({"alert": {k: alert[k] for k in ("id", "source", "incident", "title", "severity",
                                                                     "time", "entities", "attack", "raw")},
                                    "agent_verdict": inv and inv["verdict"], "agent_confidence": inv and inv["confidence"],
                                    "truth": rv["verdict"], "reviewer": rv["reviewer"], "note": rv["note"]},
                                   default=str) + "\n")
        print(f"wrote {len(store.reviews())} reviewed cases to {args.out}")


if __name__ == "__main__":
    main()
