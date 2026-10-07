import random

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from triage_fixtures import ENTITIES

from triage.memory import FullHistoryMemory, GraphMemory, extract_entities, make_memory


def test_extracts_shaped_values_column_hints_and_json_with_lone_backslashes():
    row = {"TimeGenerated": "2024-06-20", "AlertName": "Manatee Tempest activity group", "Entities": ENTITIES,
           "DeviceName": "vnevado-win11u", "ProcessCommandLine": "curl http://vectorsandarrows.com",
           "InitiatingProcessId": "1332"}
    ents = extract_entities(row)
    assert ("ip", "198.43.121.209") in ents
    assert ("sid", "S-1-5-21-1840191660-8534830288-125585561-1522") in ents
    assert ("host", "vnevado-win11u") in ents  # column hint
    assert ("host", "vnevado-win10r") in ents  # inside JSON that only parses after backslash repair
    assert ("account", "dp5hn@vnevado.alpineskihouse.co") in ents
    assert ("process_id", "1332") in ents
    assert ("alert", "Manatee Tempest activity group") in ents


def test_anonymised_s2_sids_and_noise_values():
    ents = extract_entities({"AccountSid": "S-2-5-21-571436798-3864380397-1837441745-3206", "DeviceName": "-",
                             "RemoteIP": "127.0.0.1"})
    assert ("sid", "S-2-5-21-571436798-3864380397-1837441745-3206") in ents
    assert not any(v in ("-", "127.0.0.1") for _, v in ents)


def test_recall_guarantee_every_extracted_entity_is_recallable_verbatim():
    """The property the design rests on: nothing seen is ever lost."""
    rng = random.Random(7)
    g = GraphMemory()
    all_rows = []
    for step in range(30):
        rows = [{"DeviceName": f"host-{rng.randint(1, 40)}",
                 "RemoteIP": f"10.{rng.randint(0, 9)}.{rng.randint(0, 9)}.{rng.randint(1, 250)}",
                 "AccountUpn": f"user{rng.randint(1, 30)}@corp.example",
                 "SHA256": "".join(rng.choice("0123456789abcdef") for _ in range(64)),
                 "Long": "x" * 5000 + " hidden 203.0.113.77 " + "y" * 100}  # beyond any display cut
                for _ in range(rng.randint(1, 6))]
        all_rows += rows
        g.add_observation(f"q{step % 5}", step, "run_sql", {"query": "..."}, "(display text)", rows)
    for row in all_rows:
        for _, value in extract_entities(row):
            assert g.knows(value), value
            text = g.recall(value)
            assert value.lower() in text.lower()
    assert g.knows("203.0.113.77")


def test_recall_reports_provenance_neighbours_and_answers():
    g = GraphMemory()
    rows = [{"DeviceName": "vnevado-win10r", "RemoteIP": "198.43.121.209", "TimeGenerated": "2024-06-20T09:00"}]
    obs = g.add_observation("i5-q1", 2, "run_sql", {"query": "q"}, "text", rows)
    g.add_answer("i5-q1", "Which IP?", "198.43.121.209")
    out = g.recall("198.43.121.209")
    assert obs == "i5-q1:2" and "i5-q1:2" in out
    assert "vnevado-win10r" in out and "2024-06-20T09:00" in out
    assert "given as an answer in task(s): i5-q1" in out
    assert "Nothing in memory" in g.recall("10.9.9.9")
    assert g.search("win10") == ["vnevado-win10r"]
    assert g.observation("i5-q1:2").tool == "run_sql"


def test_context_block_carries_prior_answers_and_auto_recalls_named_entities():
    g = GraphMemory()
    g.add_observation("q0", 1, "run_sql", {}, "t", [{"DeviceName": "vnevado-win10r", "RemoteIP": "198.43.121.209"}])
    g.add_answer("q0", "What host ran curl?", "vnevado-win10r")
    block = g.context_block("The host `vnevado-win10r` contacted 198.43.121.209. Which account?")
    assert "What host ran curl? -> vnevado-win10r" in block
    assert "Memory recall for 198.43.121.209" in block


def test_full_history_replays_real_tool_messages_and_drops_oldest_beyond_budget():
    m = FullHistoryMemory(max_chars=600)
    for i in range(5):
        transcript = [HumanMessage(content=f"task {i}"),
                      AIMessage(content="", tool_calls=[{"name": "run_sql", "args": {"query": "q"}, "id": f"c{i}"}]),
                      ToolMessage(content="r" * 100, tool_call_id=f"c{i}"),
                      AIMessage(content="", tool_calls=[{"name": "submit_answer", "args": {"answer": f"answer {i}"},
                                                         "id": f"s{i}"}]),
                      ToolMessage(content="Submitted.", tool_call_id=f"s{i}")]
        m.record_answer(f"q{i}", f"task {i}", f"answer {i}", transcript)
    msgs = m.prefix_messages("new")
    assert any(isinstance(x, AIMessage) and x.tool_calls for x in msgs)  # real tool calls, not text imitations
    assert not any("[called]" in str(x.content) for x in msgs)
    blob = " ".join(str(x.content) + str(getattr(x, "tool_calls", "")) for x in msgs)
    assert "answer 4" in blob and "answer 0" not in blob and m.dropped >= 1
    for i, x in enumerate(msgs):  # every tool message is preceded by the call it answers
        if isinstance(x, ToolMessage):
            assert any(c["id"] == x.tool_call_id for p in msgs[:i] if isinstance(p, AIMessage) for c in p.tool_calls)


@pytest.mark.parametrize("mode,tools", [("none", False), ("qa_notes", False), ("full", False), ("graph", True)])
def test_make_memory(mode, tools):
    m = make_memory(mode)
    assert m.mode == mode and m.tools_enabled is tools


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        make_memory("summary")
