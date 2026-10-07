import pytest
from fakes import ScriptedChat, text
from langchain_core.messages import HumanMessage
from triage_fixtures import incident_db

from triage.excytin.db import check_query
from triage.llm import Budget, BudgetExceeded, CacheMiss, ChatClient, ResponseCache, cache_key, default_budget


@pytest.mark.parametrize("q", ["SELECT 1", "  select * from t limit 1;", "SHOW TABLES", "DESCRIBE t",
                               "WITH x AS (SELECT 1) SELECT * FROM x", "-- note\nSELECT 1"])
def test_allowed_queries(q):
    assert check_query(q) is None


@pytest.mark.parametrize("q", ["DROP TABLE t", "SELECT 1; DROP TABLE t", "UPDATE t SET a=1", "",
                               "SELECT * INTO OUTFILE '/tmp/x' FROM t", "SELECT LOAD_FILE('/etc/passwd')",
                               "SELECT SLEEP(100)", "/* hi */ DELETE FROM t"])
def test_rejected_queries(q):
    assert check_query(q) is not None


def test_run_caps_rows_keeps_full_cells_for_memory_and_reports_errors():
    db = incident_db()
    db.max_rows = 1
    res = db.run("SELECT AlertName, Entities FROM SecurityAlert")
    assert res.truncated and len(res.rows) == 1
    assert "of more than 1 rows" in res.render()
    long = db.run("SELECT '" + "z" * 3000 + "' AS big")
    assert len(long.full_rows[0]["big"]) == 3000 and len(long.rows[0]["big"]) < 3000
    assert db.run("SELECT nope FROM missing").error
    assert db.run("DROP TABLE SecurityAlert").error.startswith("only SELECT")
    assert "SecurityAlert" in db.tables() and "AlertName" in db.describe("SecurityAlert")
    assert "Unknown table" in db.describe("Nope") and db.placeholder == "?"


def test_cache_key_depends_on_everything_that_changes_the_answer():
    m = [HumanMessage(content="hi")]
    base = cache_key("ollama", "m", 0, None, m, [])
    assert base == cache_key("ollama", "m", 0, None, [HumanMessage(content="hi")], [])
    assert base != cache_key("ollama", "m", 0.7, None, m, [])
    assert base != cache_key("ollama", "m", 0, 1, m, [])
    assert base != cache_key("ollama", "m2", 0, None, m, [])
    assert base != cache_key("ollama", "m", 0, None, m, [{"type": "function"}])


def test_cache_readwrite_then_replay_and_replay_miss(tmp_path):
    path = tmp_path / "c.sqlite"
    backend = ScriptedChat(lambda msgs, tools: text("hello"))
    c = ChatClient(provider="ollama", model="m", cache=ResponseCache(path, "readwrite"), budget=Budget(1),
                   backend=backend)
    msg, info = c.invoke([HumanMessage(content="q")])
    msg2, info2 = c.invoke([HumanMessage(content="q")])
    assert msg.content == msg2.content == "hello" and not info["cached"] and info2["cached"]
    assert len(backend.calls) == 1

    def boom(msgs, tools):
        raise AssertionError("replay must not call the model")

    r = ChatClient(provider="ollama", model="m", cache=ResponseCache(path, "replay"), budget=Budget(1),
                   backend=ScriptedChat(boom))
    assert r.invoke([HumanMessage(content="q")])[0].content == "hello"
    with pytest.raises(CacheMiss):
        r.invoke([HumanMessage(content="never recorded")])


def test_budget_stops_paid_calls_but_not_free_ones():
    paid = Budget(0.001, price_in=1000, price_out=1000)
    c = ChatClient(provider="openai", model="m", cache=ResponseCache(":memory:", "off"), budget=paid,
                   backend=ScriptedChat(lambda m, t: text("x")))
    c.invoke([HumanMessage(content="a")])  # 110 tokens * $1000/M = $0.11 > limit
    assert paid.spent_usd > 0.001
    with pytest.raises(BudgetExceeded):
        c.invoke([HumanMessage(content="b")])
    free = Budget(0.0)
    f = ChatClient(provider="ollama", model="m", cache=ResponseCache(":memory:", "off"), budget=free,
                   backend=ScriptedChat(lambda m, t: text("x")))
    f.invoke([HumanMessage(content="a")])
    f.invoke([HumanMessage(content="b")])


def test_openai_needs_a_known_or_explicit_price(monkeypatch):
    monkeypatch.delenv("TRIAGE_PRICE_IN", raising=False)
    monkeypatch.delenv("TRIAGE_PRICE_OUT", raising=False)
    with pytest.raises(ValueError):
        default_budget("openai", "some-unpriced-model")
    assert default_budget("openai", "gpt-4o-mini").price_in == 0.15
