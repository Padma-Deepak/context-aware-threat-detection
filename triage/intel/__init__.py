"""Real threat-intelligence lookups with a record/replay cache.

Free, no key:      CISA Known Exploited Vulnerabilities, NVD CVE API 2.0, MITRE ATT&CK (STIX)
Free, needs a key: AbuseIPDB (ABUSEIPDB_API_KEY), abuse.ch ThreatFox (ABUSECH_AUTH_KEY)

Every HTTP response is cached in SQLite (TRIAGE_INTEL_CACHE = readwrite | replay | off), so a benchmark
or a CI run sees exactly the same intel every time and works offline once recorded.

Privacy: private, loopback and reserved IPs are never sent to an external service.
"""

from triage.intel.lookup import enrich, lookup_indicator  # noqa: F401
