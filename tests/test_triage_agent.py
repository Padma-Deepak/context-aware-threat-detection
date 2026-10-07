from fakes import call, text
from langchain_core.messages import ToolMessage
from triage_fixtures import incident_db, offline_client

from triage.excytin.task import build_investigator
from triage.llm import Budget
from triage.memory import make_memory


def _tool_msgs(messages):
    return [m for m in messages if isinstance(m, ToolMessage)]


def _evidence_id(tool_message):
    return tool_message.content.split("]")[0].replace("[evidence ", "")


def test_query_then_cited_submission():
    def policy(messages, tools):
        tm = _tool_msgs(messages)
        if not tm:
            return call("run_sql", query="SELECT AlertName, Entities FROM SecurityAlert LIMIT 1")
        return call("submit_answer", answer="198.43.121.209", confidence=85, evidence=[_evidence_id(tm[0])])

    mem = make_memory("graph")
    agent = build_investigator(incident_db(), mem, offline_client(policy))
    r = agent.investigate("i5-q0", "Which IP?")
    assert r.final == {"answer": "198.43.121.209", "confidence": 85, "evidence": ["i5-q0:1"]}
    assert r.citations_valid and r.steps == 1 and r.fallback is None
    assert mem.graph.knows("198.43.121.209") and mem.graph.knows("vnevado-win10r")
    assert mem.graph.answers()[0][2] == "198.43.121.209"


def test_graph_mode_offers_memory_tools_and_other_modes_do_not():
    seen = {}

    def policy(messages, tools):
        seen["names"] = [t["function"]["name"] for t in tools]
        return call("submit_answer", answer="x", confidence=1)

    build_investigator(incident_db(), make_memory("graph"), offline_client(policy)).investigate("a", "q")
    assert {"recall", "search_memory", "run_sql", "submit_answer"} <= set(seen["names"])
    build_investigator(incident_db(), make_memory("none"), offline_client(policy)).investigate("a", "q")
    assert "recall" not in seen["names"]


def test_invented_citation_is_flagged():
    agent = build_investigator(incident_db(), make_memory("none"), offline_client(
        [call("submit_answer", answer="x", confidence=50, evidence=["made-up:9"])]))
    assert agent.investigate("q", "task").citations_valid is False


def test_prose_answer_after_two_nudges_is_parsed_as_fallback():
    agent = build_investigator(incident_db(), make_memory("none"), offline_client(
        [text("thinking"), text("still thinking"), text("Final answer: vnevado-win10r")]))
    r = agent.investigate("q", "task")
    assert r.final["answer"] == "vnevado-win10r" and r.fallback == "parsed_text" and r.final["confidence"] == 0


def test_step_limit_forces_submit_only_tools():
    offered = []

    def policy(messages, tools):
        offered.append([t["function"]["name"] for t in tools])
        if len(offered[-1]) == 1:
            return call("submit_answer", answer="best guess", confidence=10)
        return call("run_sql", query="SELECT 1")

    r = build_investigator(incident_db(), make_memory("none"), offline_client(policy), max_steps=3).investigate("q", "t")
    assert r.steps == 3 and r.final["answer"] == "best guess" and offered[-1] == ["submit_answer"]


def test_invalid_submission_gets_a_retry_then_bounded():
    r = build_investigator(incident_db(), make_memory("none"), offline_client(
        [call("submit_answer", answer="x", confidence=500),
         call("submit_answer", answer="x", confidence=50)])).investigate("q", "t")
    assert r.final["confidence"] == 50

    r = build_investigator(incident_db(), make_memory("none"), offline_client(
        lambda m, t: call("submit_answer", answer="x", confidence=999))).investigate("q", "t")
    assert r.final is None or r.fallback  # gave up instead of looping forever


def test_unknown_tool_and_bad_arguments_are_reported_to_the_model():
    def policy(messages, tools):
        tm = _tool_msgs(messages)
        if len(tm) == 0:
            return call("delete_everything")
        if len(tm) == 1:
            return call("run_sql", wrong="x")
        return call("submit_answer", answer=tm[0].content[:40] + "|" + tm[1].content[:60], confidence=1)

    r = build_investigator(incident_db(), make_memory("none"), offline_client(policy)).investigate("q", "t")
    assert "Unknown tool" in r.final["answer"] and "Bad arguments" in r.final["answer"]


def test_budget_exhaustion_is_recorded_not_raised():
    budget = Budget(0.0, price_in=1, price_out=1)
    budget.spent_usd = 1.0
    r = build_investigator(incident_db(), make_memory("none"),
                           offline_client(lambda m, t: text("x"), budget=budget)).investigate("q", "t")
    assert r.error and "BudgetExceeded" in r.error and r.final is None


def test_json_submission_written_as_prose_is_recovered():
    agent = build_investigator(incident_db(), make_memory("none"), offline_client(
        [text("thinking"), text("still"), text('I will submit {"answer": "fk8mq", "confidence": 90, "evidence": []}')]))
    r = agent.investigate("q", "task")
    assert r.final["answer"] == "fk8mq" and r.final["confidence"] == 90 and r.fallback == "parsed_text"
