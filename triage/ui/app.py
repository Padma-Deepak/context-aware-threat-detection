"""Analyst UI: alert queue, case view (verdict, cited claims, investigation timeline, entity graph),
review queue, metrics and benchmark results.

    streamlit run triage/ui/app.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from triage.cases import DEFAULT_DIR, CaseStore  # noqa: E402
from triage.cli import format_metrics, metrics  # noqa: E402
from triage.memory import GraphMemory  # noqa: E402

st.set_page_config(page_title="SOC Triage", layout="wide")

VERDICT_COLOR = {"MALICIOUS": "red", "BENIGN": "green", "ESCALATE": "orange"}
STATUS_LABEL = {"new": "New", "escalated": "Needs review", "auto_closed": "Auto-closed (benign)",
                "auto_confirmed": "Auto-confirmed (malicious)", "reviewed": "Reviewed"}
TYPE_COLOR = {"host": "#4C78A8", "account": "#F58518", "email": "#F58518", "ip": "#E45756", "domain": "#72B7B2",
              "url": "#72B7B2", "file": "#54A24B", "sha256": "#B279A2", "sha1": "#B279A2", "md5": "#B279A2",
              "process_id": "#9D755D", "command_line": "#9D755D", "alert": "#EECA3B", "sid": "#FF9DA6"}


@st.cache_resource
def store() -> CaseStore:
    return CaseStore()


@st.cache_resource
def memory() -> GraphMemory | None:
    path = DEFAULT_DIR / "memory.sqlite"
    return GraphMemory(str(path)) if path.exists() else None


def entity_graph_dot(values: list[str]) -> str | None:
    g = memory()
    if g is None or not values:
        return None
    nodes, edges = g.subgraph(values, hops=1, limit=45)
    if not nodes:
        return None
    focus = {v.lower() for v in values}

    def esc(text: str) -> str:  # inside a DOT string literal
        return text.replace("\\", "\\\\").replace('"', '\\"')

    def q(text: str) -> str:
        return f'"{esc(text)}"'

    lines = ['graph G {', 'graph [layout=neato, overlap=false, sep="+12", bgcolor="transparent"];',
             'node [style=filled, fontname="Helvetica", fontsize=10, fontcolor="white"];']
    for key, etype, value in nodes:
        label = (value[:28] + "...") if len(value) > 29 else value
        pen = ', penwidth=3, color="black"' if key in focus else ""
        lines.append(f'{q(key)} [label="{esc(label)}\\n({etype})", '
                     f'fillcolor="{TYPE_COLOR.get(etype, "#888888")}"{pen}];')
    for a, b in list(edges)[:120]:
        lines.append(f'{q(a)} -- {q(b)} [color="#999999"];')
    lines.append("}")
    return "\n".join(lines)


def queue_page():
    s = store()
    st.header("Alert queue")
    counts = s.counts()
    cols = st.columns(len(STATUS_LABEL))
    for c, (k, label) in zip(cols, STATUS_LABEL.items()):
        c.metric(label, counts.get(k, 0))
    f1, f2 = st.columns(2)
    status = f1.selectbox("Status", ["all"] + list(STATUS_LABEL), format_func=lambda k: STATUS_LABEL.get(k, "All"))
    source = f2.selectbox("Source", ["all", "sentinel", "sigma"])
    rows = s.alerts(status=None if status == "all" else status, source=None if source == "all" else source, limit=2000)
    table = []
    for a in rows:
        inv = s.latest_investigation(a["id"])
        table.append({"id": a["id"], "time": a["time"][:19], "source": a["source"], "title": a["title"],
                      "severity": a["severity"], "status": STATUS_LABEL.get(a["status"], a["status"]),
                      "verdict": inv["verdict"] if inv else "", "confidence": inv["confidence"] if inv else None,
                      "incident": a["incident"]})
    st.dataframe(table, width="stretch", hide_index=True)
    st.caption("Open a case from the sidebar by id.")


def case_page(alert_id: int):
    s = store()
    a = s.alert(alert_id)
    if not a:
        st.warning("No such alert.")
        return
    inv = s.latest_investigation(alert_id)
    st.header(f"Alert #{a['id']}: {a['title']}")
    st.markdown(f"**Severity** {a['severity']}  ·  **Source** {a['source']}  ·  **Status** "
                f"{STATUS_LABEL.get(a['status'], a['status'])}  ·  **Dataset label** {a['label'] or 'unlabelled'}  ·  "
                f"**Incident DB** {a['incident']}")
    st.caption(f"{a['time']}  ·  ATT&CK: {', '.join(a['attack']) or 'none'}")

    if not inv:
        st.info("Not investigated yet:  `python -m triage.cli investigate --alert %d`" % alert_id)
    else:
        color = VERDICT_COLOR.get(inv["verdict"], "gray")
        st.subheader(f":{color}[{inv['verdict']}]  ·  confidence {inv['confidence']}  ·  decision: {inv['decision']}")
        st.write(inv["summary"])
        meta = (f"{inv['steps']} tool calls · {inv['seconds']:.0f}s · {inv['input_tokens']}+{inv['output_tokens']} "
                f"tokens · ${inv['cost_usd']:.4f} · model {inv['model']} · citations "
                f"{'valid' if inv['citations_valid'] else 'MISSING/INVALID'}")
        st.caption(meta)
        if inv["error"]:
            st.error(inv["error"])
        evidence = {c["obs_id"]: c for c in inv["tool_calls"]}
        if inv["claims"]:
            st.markdown("**Findings** (each links to the tool result that supports it)")
            for claim in inv["claims"]:
                refs = claim.get("evidence", [])
                ok = all(r in evidence for r in refs) and refs
                st.markdown(f"- {claim['text']}  " + " ".join(f"`{r}`" for r in refs) + ("" if ok else "  ⚠️ uncited"))
        if inv["attack"]:
            st.markdown("**ATT&CK:** " + ", ".join(f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')})"
                                                  for t in inv["attack"]))
        if inv["actions"]:
            st.markdown("**Recommended actions**\n" + "\n".join(f"{i + 1}. {x}" for i, x in enumerate(inv["actions"])))

        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Investigation timeline**")
            for call in inv["tool_calls"]:
                cited = " ⭐ cited" if call["obs_id"] in inv["evidence"] else ""
                with st.expander(f"{call['obs_id']} · {call['tool']}{cited}"):
                    st.code(json.dumps(call["args"], indent=1), language="json")
                    st.text(call["output"][:3000])
        with right:
            st.markdown("**Entity graph** (case memory, 1 hop)")
            values = [v for t, v in a["entities"] if t in ("host", "account", "ip", "file", "domain", "email")][:6]
            dot = entity_graph_dot(values)
            if dot:
                st.graphviz_chart(dot, width="stretch")
            else:
                st.caption("No memory yet.")

    st.divider()
    st.markdown("**Analyst review**")
    with st.form(f"review{alert_id}"):
        verdict = st.radio("Your verdict", ["MALICIOUS", "BENIGN"], horizontal=True)
        note = st.text_input("Note")
        reviewer = st.text_input("Reviewer", value="analyst")
        if st.form_submit_button("Save review"):
            s.add_review(alert_id, verdict, reviewer, note)
            st.success("Saved. Reviews become labels for metrics and calibration.")
    with st.expander("Raw alert"):
        st.json(a["raw"])
    if inv and inv["trace"]:
        with st.expander("Full model transcript"):
            for m in inv["trace"]:
                st.markdown(f"**{m['role']}**")
                st.text((m.get("content") or "")[:4000] + ("\n" + json.dumps(m["tool_calls"]) if m.get("tool_calls") else ""))


def review_page():
    s = store()
    st.header("Review queue")
    pending = s.alerts(status="escalated")
    st.write(f"{len(pending)} alerts were escalated by the agent and wait for a human decision.")
    for a in pending[:200]:
        inv = s.latest_investigation(a["id"])
        st.markdown(f"**#{a['id']}** {a['title']} — agent: {inv['verdict'] if inv else '?'} "
                    f"({inv['confidence'] if inv else '?'})")


def metrics_page():
    st.header("Triage metrics")
    st.markdown(format_metrics(metrics(store())))
    st.caption("Malicious labels come from ExCyTIn incidents; benign labels only from analyst reviews.")


def benchmark_page():
    st.header("ExCyTIn memory benchmark")
    reports = sorted(Path("results/excytin").glob("*.md")) if Path("results/excytin").exists() else []
    if not reports:
        st.info("No benchmark report yet. Run `python -m triage.excytin.run ...` then "
                "`python -m triage.excytin.analyze ... --md results/excytin/report.md`.")
    for p in reports:
        st.subheader(p.stem)
        st.markdown(p.read_text())


page = st.sidebar.radio("Page", ["Queue", "Case", "Review queue", "Metrics", "Benchmark"])
if page == "Queue":
    queue_page()
elif page == "Case":
    ids = [a["id"] for a in store().alerts(limit=5000)]
    if ids:
        case_page(st.sidebar.selectbox("Alert id", ids))
    else:
        st.info("No alerts. Run `python -m triage.cli ingest`.")
elif page == "Review queue":
    review_page()
elif page == "Metrics":
    metrics_page()
else:
    benchmark_page()
