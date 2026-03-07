# Threat Hunting & Detection Engineering Portfolio

## Overview

This repository serves as my professional portfolio for threat hunting, detection engineering, and adversary tradecraft analysis.

It contains:

- Vendor-agnostic detection rules (Sigma)
- Platform-specific detection queries (Splunk, KQL, CrowdStrike)
- Documented threat hunting investigations
- Technical research and detection methodology

The goal of this project is to translate real-world attacker behavior into actionable detection logic across enterprise security platforms.

---

## Technical Focus Areas

- MITRE ATT&CK–based detection engineering
- Living-off-the-land (LOLBin) abuse detection
- Credential access monitoring
- Persistence detection
- Lateral movement analysis
- Command & Control (C2) behavior detection
- Threat intelligence to detection conversion

---

## Repository Structure


threat-hunting-detections/
│
├── sigma/ # Vendor-agnostic detection rules
├── hunts/ # Documented threat hunting investigations
├── research/ # Technical research & deep-dive analysis
├── splunk/ # Splunk detection queries
├── kql/ # Microsoft (Sentinel / Defender) queries
├── crowdstrike/ # CrowdStrike LogScale queries
└── README.md # This document


Each folder contains documentation and artifacts aligned to detection engineering workflows.

---

## Methodology

My workflow typically follows this progression:

Research → Hypothesis → Hunt → Detection → Platform Implementation → Validation

Where possible, detections are:

- Mapped to MITRE ATT&CK techniques
- Tested in lab environments
- Converted across multiple platforms

---

## Purpose

This repository demonstrates practical capability in:

- Writing detection logic
- Investigating suspicious telemetry
- Translating threat reports into actionable detections
- Building platform-specific security content

It serves as both a technical portfolio and a foundation for future professional consulting or product development.

---

## Contact

Daniel Crowder 
Huntsville, Alabama  
Threat Hunting | Detection Engineering | Offensive Security
