# Sigma rules

These rules are copied unmodified from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
(`rules/windows/process_creation/`), under the Detection Rule License 1.1 in `LICENSE-SigmaHQ-DRL.md`.
Each file keeps its original `author`, `id` and `references` fields, which is the attribution the licence asks for.

They were chosen because they cover techniques that appear in the ExCyTIn incidents: shadow-copy deletion
and boot tampering (ransomware), credential-dumping tools, Kerberos abuse, remote execution and recon.

Add more by dropping any SigmaHQ rule in this folder. `python -m triage.alerts rules` lists which rules
compile and why the others are skipped.
