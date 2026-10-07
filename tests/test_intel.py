import json

import pytest

import triage.intel.http as http
import triage.intel.lookup as lookup
from triage.intel.http import HttpCache, IntelCacheMiss

KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
                            "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
                            "knownRansomwareCampaignUse": "Known", "requiredAction": "Patch"}]}
NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "published": "2021-12-10T10:15:09",
                                    "descriptions": [{"lang": "en", "value": "JNDI lookup RCE"}],
                                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0,
                                                                                "baseSeverity": "CRITICAL"}}]},
                                    "weaknesses": [{"description": [{"value": "CWE-502"}]}]}}]}


@pytest.fixture
def replay_cache(tmp_path, monkeypatch):
    """A recorded cache in replay mode: no network is ever touched."""
    rec = HttpCache(tmp_path / "http.sqlite", "readwrite")
    for url, body in [(lookup.KEV_URL, KEV), (lookup.NVD_URL + "?cveId=CVE-2021-44228", NVD)]:
        rec.db.execute("INSERT INTO http VALUES (?,?,?,?)", (HttpCache.key("GET", url, None), 200, json.dumps(body), 0))
    rec.db.commit()
    cache = HttpCache(tmp_path / "http.sqlite", "replay")
    monkeypatch.setattr(http, "_CACHE", cache)
    monkeypatch.setattr(lookup, "_kev", None)
    return cache


def test_cve_lookup_combines_nvd_and_kev_from_the_recording(replay_cache):
    nvd, kev = lookup.lookup_indicator("cve-2021-44228")
    assert nvd["found"] and nvd["cvss"] == 10.0 and nvd["severity"] == "CRITICAL" and nvd["cwe"] == ["CWE-502"]
    assert kev["known_exploited"] and kev["ransomware_use"] == "Known"
    with pytest.raises(IntelCacheMiss):
        lookup.lookup_nvd("CVE-2099-0001")


def test_attack_lookup_uses_the_saved_index(tmp_path, monkeypatch):
    index = tmp_path / "attack.json"
    index.write_text(json.dumps({"T1003.001": {"name": "LSASS Memory", "url": "u", "tactics": ["credential-access"],
                                               "description": "d"}}))
    monkeypatch.setenv("TRIAGE_ATTACK_INDEX", str(index))
    monkeypatch.setattr(lookup, "_attack", None)
    assert lookup.lookup_attack("t1003.001")["name"] == "LSASS Memory"
    assert lookup.lookup_attack("T9999")["found"] is False
    assert lookup.attack_by_name("lsass") == ["T1003.001"]


def test_private_ips_never_leave_and_keyed_sources_skip_without_keys(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.setattr(http, "_CACHE", None)  # any network attempt would need a cache; none should happen
    assert lookup.lookup_indicator("10.1.2.3")[0]["note"].startswith("private")
    out = lookup.lookup_indicator("8.8.8.8")
    assert all(r["found"] is False and "skipped" in r for r in out)


@pytest.mark.parametrize("value,kind", [("CVE-2024-1234", "cve"), ("T1059.001", "technique"), ("8.8.8.8", "ip"),
                                        ("a" * 64, "hash"), ("evil.example", "domain"), ("hello world", "unknown")])
def test_classify(value, kind):
    assert lookup.classify(value) == kind
