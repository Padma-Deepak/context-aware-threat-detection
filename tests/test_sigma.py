from pathlib import Path

import pytest
import yaml
from triage_fixtures import incident_db

from triage.sigma.compiler import Compiler, Unsupported, load_rules

RULE = """
title: Shadow copy deletion
id: test-1
level: high
tags: [attack.impact, attack.t1490]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    - Image|endswith: '\\\\vssadmin.exe'
    - OriginalFileName: 'VSSADMIN.EXE'
  selection_cli:
    CommandLine|contains|all: ['delete', 'shadows']
  filter:
    User: 'SYSTEM'
  condition: all of selection_* and not filter
"""


def compile_rule(text, placeholder="?"):
    return Compiler(placeholder=placeholder).compile(yaml.safe_load(text))


def test_compiles_to_parameterised_sql_and_matches_backslash_stripped_paths():
    rule = compile_rule(RULE)
    assert rule.table == "DeviceProcessEvents" and rule.attack_ids == ["T1490"]
    assert "NOT" in rule.where and "%delete%" in rule.params and "%vssadmin.exe" in rule.params
    db = incident_db()
    res = db.run(rule.sql(), rule.params)
    assert res.error is None, res.error
    assert [r["FileName"] for r in res.rows] == ["vssadmin.exe"]


def test_like_metacharacters_in_values_are_literal():
    rule = compile_rule("""
title: t
logsource: {category: process_creation}
detection:
  sel: {CommandLine|contains: '100%_done'}
  condition: sel
""")
    assert rule.params == ["%100!%!_done%"]


@pytest.mark.parametrize("cond", ["sel1 or sel2", "1 of sel*", "(sel1 or sel2) and not sel3", "1 of them"])
def test_conditions(cond):
    doc = {"title": "t", "logsource": {"category": "process_creation"},
           "detection": {"sel1": {"Image|endswith": "\\notepad.exe"}, "sel2": {"CommandLine|startswith": "vssadmin"},
                         "sel3": {"User": "nobody"}, "condition": cond}}
    rule = Compiler(placeholder="?").compile(doc)
    res = incident_db().run(rule.sql(), rule.params)
    assert res.error is None and len(res.rows) == 2


@pytest.mark.parametrize("detection,reason", [
    ({"keywords": ["mimikatz"], "condition": "keywords"}, "keyword"),
    ({"sel": {"Image": "x"}, "condition": "sel | count() > 5"}, "aggregation"),
    ({"sel": {"Image|base64offset": "x"}, "condition": "sel"}, "modifier"),
    ({"sel": {"NoSuchField": "x"}, "condition": "sel"}, "field"),
])
def test_unsupported_features_are_refused_not_mistranslated(detection, reason):
    with pytest.raises(Unsupported, match=reason):
        Compiler().compile({"title": "t", "logsource": {"category": "process_creation"}, "detection": detection})


def test_unsupported_logsource():
    with pytest.raises(Unsupported):
        Compiler().compile({"logsource": {"category": "ps_script"}, "detection": {"s": {"a": 1}, "condition": "s"}})


def test_every_vendored_sigmahq_rule_compiles():
    rules, skipped = load_rules(Path(__file__).resolve().parents[1] / "triage" / "sigma" / "rules")
    assert len(rules) >= 20 and skipped == []
