# KQL Queries

This folder contains threat hunting and detection queries written in Kusto Query Language (KQL) for Microsoft security platforms.

These queries are intended for use in environments such as:

- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)
- Microsoft Defender XDR

The queries focus on identifying suspicious behaviors associated with common attacker techniques, including:

- Suspicious process execution
- PowerShell abuse
- Credential access activity
- Persistence mechanisms
- Lateral movement behavior

Many of the queries are derived from Sigma rules or threat hunting investigations documented within this repository.

Where possible, detections are mapped to MITRE ATT&CK techniques and include notes on tuning and investigative context.
