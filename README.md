# Mini-SIEM

A lightweight detection tool written in Go. It reads Linux and Windows logs, runs Sigma detection rules, and reports suspicious activity mapped to MITRE ATT&CK.

## Status
Work in progress. Version 1.0 planned for February 2027.

## Planned features
- Parse Linux auth.log and Windows/Sysmon logs
- Run Sigma rules
- Map alerts to MITRE ATT&CK
- Tested against real attack samples (EVTX-ATTACK-SAMPLES)
- Optional AI summary of alerts
