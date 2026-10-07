"""Shared helpers for the triage tests: a tiny SQLite incident database and an offline chat client."""

from __future__ import annotations

import json
import sqlite3

from fakes import ScriptedChat

from triage.excytin.db import IncidentDB
from triage.llm import Budget, ChatClient, ResponseCache

ENTITIES = json.dumps([
    {"$id": "2", "Name": "dp5hn", "Sid": "S-1-5-21-1840191660-8534830288-125585561-1522",
     "UserPrincipalName": "dp5hn@vnevado.alpineskihouse.co", "Type": "account"},
    {"$id": "3", "Url": "vectorsandarrows.com", "Type": "url"},
    {"$id": "4", "Address": "198.43.121.209", "Type": "ip"},
    {"$id": "5", "HostName": "vnevado-win10r", "Type": "host"},
]).replace('"Type": "host"', '"Type": "host", "Directory": "C:\\Windows\\System32"').replace("\\\\", "\\")
# ^ a lone backslash, as MySQL's LOAD DATA leaves Windows paths: not valid JSON until repaired.


def incident_db(rows_process=None) -> IncidentDB:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.executescript("""
        CREATE TABLE SecurityAlert (SystemAlertId TEXT, AlertName TEXT, AlertSeverity TEXT, TimeGenerated TEXT,
            Description TEXT, Entities TEXT, Tactics TEXT, Techniques TEXT, ProviderName TEXT);
        CREATE TABLE SecurityIncident (IncidentNumber TEXT, Title TEXT, AlertIds TEXT);
        CREATE TABLE DeviceProcessEvents (Timestamp TEXT, DeviceName TEXT, AccountName TEXT, AccountSid TEXT,
            FileName TEXT, FolderPath TEXT, ProcessId TEXT, ProcessCommandLine TEXT, InitiatingProcessFileName TEXT,
            InitiatingProcessCommandLine TEXT, InitiatingProcessFolderPath TEXT, SHA256 TEXT,
            ProcessVersionInfoOriginalFileName TEXT);
    """)
    conn.executemany("INSERT INTO SecurityAlert VALUES (?,?,?,?,?,?,?,?,?)", [
        ("AAA-1", "Manatee Tempest activity group", "High", "2024-06-20 09:19:23", "C2 group", ENTITIES,
         "CommandAndControl", '["T1071"]', "MDATP"),
        ("BBB-2", "Suspicious LDAP query", "Medium", "2024-06-20 09:30:00", "LDAP recon", "[]", "Discovery",
         "[]", "MDATP"),
    ])
    conn.execute("INSERT INTO SecurityIncident VALUES ('20', 'C2 incident', '[\"aaa-1\"]')")
    rows = rows_process or [
        ("2024-06-20 09:10:00", "vnevado-win10r", "dp5hn", "S-1-5-21-1", "vssadmin.exe",
         "C:WindowsSystem32vssadmin.exe", "4312", "vssadmin.exe delete shadows /all /quiet", "cmd.exe",
         "cmd /c x", "C:WindowsSystem32cmd.exe", "a" * 64, "VSSADMIN.EXE"),
        ("2024-06-20 09:11:00", "vnevado-win10r", "dp5hn", "S-1-5-21-1", "notepad.exe",
         "C:WindowsSystem32notepad.exe", "100", "notepad.exe report.txt", "explorer.exe", "explorer.exe",
         "C:Windowsexplorer.exe", "b" * 64, "NOTEPAD.EXE"),
    ]
    conn.executemany("INSERT INTO DeviceProcessEvents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit()
    return IncidentDB(5, connect=lambda: conn, max_rows=15)


def offline_client(policy, budget: Budget | None = None, cache: ResponseCache | None = None) -> ChatClient:
    return ChatClient(provider="ollama", model="scripted", cache=cache or ResponseCache(":memory:", "off"),
                      budget=budget or Budget(1.0), backend=ScriptedChat(policy))
