# Threat Hunting & Detection Engineering Portfolio

![Last Updated](https://img.shields.io/badge/Last_Updated-2026--10--01-blue)
![GitHub Repo Size](https://img.shields.io/github/repo-size/dcrowder252/threat-hunting-detections)

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Hunt Coverage](#hunt-coverage)
- [Methodology](#methodology)
- [Purpose](#purpose)
- [Contact](#contact)

---

## Overview

This repository serves as my professional portfolio for threat hunting, detection engineering, and adversary tradecraft analysis.

It contains:

- Vendor-agnostic detection rules (Sigma)
- Platform-specific detection queries (Splunk, KQL, CrowdStrike)
- Documented threat hunting investigations
- Intel-driven hunts based on real-world threat reporting
- Technical research and detection methodology

The goal of this project is to translate real-world attacker behavior into actionable detection logic across enterprise security platforms.

---

## Repository Structure

The repository is organized by platform and domain to make content easy to navigate regardless of your environment.

```
threat-hunting-detections/
├── windows/
│   ├── powershell-abuse/
│   ├── log-clearing/
│   ├── scheduled-task-abuse/
│   ├── lolbins-certutil-mshta-regsvr32/
│   ├── lolbins-rundll32-wscript-bitsadmin/
│   └── lolbins-msiexec-wmic-msbuild/
├── linux/
│   ├── log-clearing/
│   └── scheduled-task-abuse/
├── cloud/
│   ├── azure-entra-identity/
│   └── aws-identity/
├── rmm/
│   └── rmm-abuse/
└── intel-hunts/
    └── bumblebee-adaptixc2-akira/
```

Each topic folder contains:
- A research paper covering the threat landscape and attacker tradecraft
- A hunt document with hypotheses and detection guidance
- Platform-specific queries (Splunk, CrowdStrike, KQL where applicable)
- Sigma rules for vendor-agnostic detection coverage

> **Note:** This repository was restructured in September 2026 to improve navigation. If you previously bookmarked direct links to specific files those links may need to be updated.

---

## Hunt Coverage

### Windows

| Topic | Research | Hunt Doc | CrowdStrike | Splunk | KQL | Sigma |
|---|---|---|---|---|---|---|
| PowerShell Abuse | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Log Clearing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scheduled Task Abuse | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| LOLBins — Certutil, Mshta, Regsvr32 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| LOLBins — Rundll32, Wscript, Cscript, Bitsadmin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| LOLBins — Msiexec, Wmic, Msbuild | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Linux

| Topic | Research | Hunt Doc | CrowdStrike | Splunk | KQL | Sigma |
|---|---|---|---|---|---|---|
| Log Clearing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Scheduled Task Abuse | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Cloud

| Topic | Research | Hunt Doc | CrowdStrike | Splunk | KQL | Sigma |
|---|---|---|---|---|---|---|
| Azure & Entra ID Identity | ✅ | ✅ | ➖ | ✅ | ✅ | ✅ |
| AWS Identity | ✅ | ✅ | ➖ | ✅ | ➖ | ✅ |

> ➖ Not applicable — see hunt document for explanation

### RMM

| Topic | Research | Hunt Doc | CrowdStrike | Splunk | KQL | Sigma |
|---|---|---|---|---|---|---|
| RMM Tool Abuse | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Intel Hunts

| Topic | Research | Hunt Doc | CrowdStrike | Splunk | KQL | Sigma |
|---|---|---|---|---|---|---|
| BumbleBee / AdaptixC2 / Akira | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Methodology

My workflow typically follows this progression:

**Standard Hunts:**
Research → Hunt Document → CrowdStrike → Splunk → KQL → Sigma

**Intel Hunts:**
Threat Intelligence Report → Hunt Document → CrowdStrike → Splunk → KQL → Sigma

Where possible, detections are:

- Mapped to MITRE ATT&CK techniques
- Tested against real telemetry
- Converted across multiple platforms

---

## Purpose

This repository demonstrates practical capability in:

- Writing detection logic across multiple SIEM and EDR platforms
- Investigating suspicious telemetry and building hunt hypotheses
- Translating threat reports into actionable detections
- Building platform-specific security content at scale

It serves as both a technical portfolio and a foundation for future professional consulting or product development.

---

## Contact

Daniel Crowder - datello676@gmail.com  
Huntsville, Alabama  
Threat Hunting | Detection Engineering  
LinkedIn: https://www.linkedin.com/in/dcrowder252  
X: https://x.com/dcrowder252  
