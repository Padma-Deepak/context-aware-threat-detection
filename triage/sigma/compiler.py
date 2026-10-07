"""A small Sigma-to-SQL compiler for Defender XDR tables (the subset real rules use most).

Sigma (https://sigmahq.io) is the open, vendor-neutral format for detection rules. Rules are written
against Sysmon-style field names (Image, CommandLine, ParentImage...), so a backend maps the logsource
category to a table and each field to a column. This one targets Microsoft Defender XDR "Device*" tables
as stored in ExCyTIn's MySQL database, and compiles the whole rule into one parameterised WHERE clause so
matching runs inside the database (incident 55 has 1.8 M rows).

Supported: field maps and lists of maps; value lists (OR); modifiers contains, startswith, endswith, all,
re, cased (ignored: MySQL's default collation is case-insensitive, as Sigma is), windash; '*' and '?'
wildcards; null; conditions with and / or / not / parentheses / "1 of x*" / "all of x*" / "1 of them".
Anything else (keywords-only rules, aggregations like "| count() > 5", unknown modifiers or unmapped
fields) raises Unsupported with the reason, so a SigmaHQ rule is either compiled faithfully or skipped.

ExCyTIn quirk: its CSV loader treated backslash as an escape character, so stored paths have no
backslashes ("C:WindowsSystem32cmd.exe"). With strip_backslashes=True (the default) backslashes are
removed from rule values too. An endswith '\\cmd.exe' therefore also matches 'xcmd.exe'; documented, rare.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

CATEGORY_TABLES = {
    "process_creation": "DeviceProcessEvents",
    "network_connection": "DeviceNetworkEvents",
    "file_event": "DeviceFileEvents",
    "file_delete": "DeviceFileEvents",
    "registry_set": "DeviceRegistryEvents",
    "registry_add": "DeviceRegistryEvents",
    "registry_event": "DeviceRegistryEvents",
    "image_load": "DeviceImageLoadEvents",
    "dns_query": "DeviceNetworkEvents",
}

_COMMON = {
    "User": "AccountName",
    "ParentImage": "InitiatingProcessFolderPath",
    "ParentCommandLine": "InitiatingProcessCommandLine",
    "ParentProcessId": "InitiatingProcessId",
    "Computer": "DeviceName",
}
FIELD_MAP = {
    "DeviceProcessEvents": {**_COMMON, "Image": "FolderPath", "CommandLine": "ProcessCommandLine",
                            "OriginalFileName": "ProcessVersionInfoOriginalFileName", "ProcessId": "ProcessId",
                            "Product": "ProcessVersionInfoProductName", "Company": "ProcessVersionInfoCompanyName",
                            "Description": "ProcessVersionInfoFileDescription", "IntegrityLevel": "ProcessIntegrityLevel",
                            "CurrentDirectory": "FolderPath", "Hashes": "SHA256", "sha256": "SHA256", "md5": "MD5",
                            "sha1": "SHA1"},
    "DeviceNetworkEvents": {**_COMMON, "Image": "InitiatingProcessFolderPath",
                            "CommandLine": "InitiatingProcessCommandLine", "DestinationIp": "RemoteIP",
                            "DestinationPort": "RemotePort", "DestinationHostname": "RemoteUrl",
                            "SourceIp": "LocalIP", "SourcePort": "LocalPort", "QueryName": "RemoteUrl",
                            "Initiated": "ActionType"},
    "DeviceFileEvents": {**_COMMON, "Image": "InitiatingProcessFolderPath", "TargetFilename": "FolderPath",
                         "CommandLine": "InitiatingProcessCommandLine"},
    "DeviceRegistryEvents": {**_COMMON, "Image": "InitiatingProcessFolderPath", "TargetObject": "RegistryKey",
                             "Details": "RegistryValueData", "EventType": "ActionType"},
    "DeviceImageLoadEvents": {**_COMMON, "Image": "InitiatingProcessFolderPath", "ImageLoaded": "FolderPath"},
}
# Columns returned with every hit, so the alert has its entities (host, account, process, time).
SELECT_COLUMNS = {
    "DeviceProcessEvents": ["Timestamp", "DeviceName", "AccountName", "AccountSid", "FileName", "FolderPath",
                            "ProcessId", "ProcessCommandLine", "InitiatingProcessFileName",
                            "InitiatingProcessCommandLine", "SHA256"],
    "DeviceNetworkEvents": ["Timestamp", "DeviceName", "InitiatingProcessAccountName", "InitiatingProcessFileName",
                            "InitiatingProcessCommandLine", "RemoteIP", "RemotePort", "RemoteUrl", "ActionType"],
    "DeviceFileEvents": ["Timestamp", "DeviceName", "InitiatingProcessAccountName", "FileName", "FolderPath",
                         "InitiatingProcessFileName", "InitiatingProcessCommandLine", "ActionType", "SHA256"],
    "DeviceRegistryEvents": ["Timestamp", "DeviceName", "InitiatingProcessAccountName", "RegistryKey",
                             "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName", "ActionType"],
    "DeviceImageLoadEvents": ["Timestamp", "DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName",
                              "InitiatingProcessCommandLine"],
}
_KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cased", "windash"}
_LIKE_ESCAPE = "!"


class Unsupported(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    level: str
    table: str
    where: str
    params: list
    tags: list = field(default_factory=list)
    description: str = ""
    path: str = ""

    @property
    def attack_ids(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags
                       if t.lower().startswith("attack.t") and re.match(r"attack\.t\d{4}", t.lower())})

    def sql(self, limit: int = 500) -> str:
        cols = ", ".join(f"`{c}`" for c in SELECT_COLUMNS[self.table])
        return f"SELECT {cols} FROM `{self.table}` WHERE {self.where} LIMIT {limit}"


def _like_escape(text: str) -> str:
    return text.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2).replace("%", _LIKE_ESCAPE + "%").replace("_", _LIKE_ESCAPE + "_")


def _value_pattern(value: str, strip_backslashes: bool) -> str:
    """Sigma value -> LIKE pattern body (wildcards translated, literals escaped)."""
    v = str(value)
    if strip_backslashes:
        v = v.replace("\\", "")
    out = []
    i = 0
    while i < len(v):
        ch = v[i]
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        else:
            out.append(_like_escape(ch))
        i += 1
    return "".join(out)


class Compiler:
    def __init__(self, strip_backslashes: bool = True, placeholder: str = "%s"):
        self.strip_backslashes = strip_backslashes
        self.ph = placeholder

    def _field_expr(self, table, key, values, params):
        name, *mods = key.split("|")
        unknown = set(mods) - _KNOWN_MODIFIERS
        if unknown:
            raise Unsupported(f"modifier {sorted(unknown)} on {name}")
        column = FIELD_MAP[table].get(name)
        if column is None:
            raise Unsupported(f"field {name!r} has no mapping for {table}")
        col = f"`{column}`"
        if not isinstance(values, list):
            values = [values]
        if "windash" in mods:  # -flag also written /flag or with unicode dashes
            values = sorted({alt for v in values for alt in (str(v), str(v).replace("-", "/", 1))})
        parts = []
        for v in values:
            if v is None:
                parts.append(f"({col} IS NULL OR {col} = '')")
                continue
            if "re" in mods:
                parts.append(f"{col} REGEXP {self.ph}")
                params.append(str(v))
                continue
            body = _value_pattern(v, self.strip_backslashes)
            if "contains" in mods:
                pat = f"%{body}%"
            elif "startswith" in mods:
                pat = f"{body}%"
            elif "endswith" in mods:
                pat = f"%{body}"
            else:
                pat = body
            parts.append(f"{col} LIKE {self.ph} ESCAPE '{_LIKE_ESCAPE}'")
            params.append(pat)
        joiner = " AND " if "all" in mods else " OR "
        return "(" + joiner.join(parts) + ")" if parts else "(1=0)"

    def _selection(self, table, sel, params):
        if isinstance(sel, list):  # list of maps = OR of maps
            if not all(isinstance(s, dict) for s in sel):
                raise Unsupported("keyword (full-text) selections are not supported")
            return "(" + " OR ".join(self._selection(table, s, params) for s in sel) + ")"
        if not isinstance(sel, dict):
            raise Unsupported("keyword (full-text) selections are not supported")
        return "(" + " AND ".join(self._field_expr(table, k, v, params) for k, v in sel.items()) + ")"

    def compile_condition(self, condition: str, selections: dict) -> tuple[str, list]:
        """Translate the condition string, compiling each selection in the order it is referenced."""
        if "|" in condition:
            raise Unsupported("aggregation conditions (| count ...) are not supported")
        tokens = re.findall(r"\(|\)|[\w*]+", condition)
        out, params, i = [], [], 0
        table = self._table

        def names(pattern):
            if pattern == "them":
                return [n for n in selections]
            rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            found = [n for n in selections if rx.match(n)]
            if not found:
                raise Unsupported(f"no selection matches {pattern!r}")
            return found

        while i < len(tokens):
            t = tokens[i]
            low = t.lower()
            if low in ("and", "or", "not"):
                out.append(low.upper())
            elif t in "()":
                out.append(t)
            elif low in ("1", "all") and i + 2 < len(tokens) and tokens[i + 1].lower() == "of":
                group = [self._selection(table, selections[n], params) for n in names(tokens[i + 2])]
                out.append("(" + (" OR " if low == "1" else " AND ").join(group) + ")")
                i += 2
            elif t in selections:
                out.append(self._selection(table, selections[t], params))
            else:
                raise Unsupported(f"unknown token {t!r} in condition")
            i += 1
        return " ".join(out), params

    def compile(self, doc: dict, path: str = "") -> Rule:
        logsource = doc.get("logsource", {})
        if logsource.get("product") not in (None, "windows"):
            raise Unsupported(f"product {logsource.get('product')}")
        table = CATEGORY_TABLES.get(logsource.get("category"))
        if table is None:
            raise Unsupported(f"logsource category {logsource.get('category')!r}")
        self._table = table
        detection = dict(doc["detection"])
        condition = detection.pop("condition")
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        detection.pop("timeframe", None)
        where, params = self.compile_condition(condition, detection)
        return Rule(id=str(doc.get("id", Path(path).stem)), title=doc.get("title", Path(path).stem),
                    level=doc.get("level", "medium"), table=table, where=where, params=params,
                    tags=doc.get("tags", []), description=doc.get("description", ""), path=path)


def load_rules(directory: Path | str, compiler: Compiler | None = None):
    """Compile every .yml rule in ``directory``; returns (rules, skipped[(path, reason)])."""
    compiler = compiler or Compiler()
    rules, skipped = [], []
    for path in sorted(Path(directory).rglob("*.yml")):
        try:
            for doc in yaml.safe_load_all(path.read_text()):
                if doc and "detection" in doc:
                    rules.append(compiler.compile(doc, str(path)))
        except (Unsupported, KeyError, yaml.YAMLError) as exc:
            skipped.append((str(path), f"{exc.__class__.__name__}: {exc}"))
    return rules, skipped
