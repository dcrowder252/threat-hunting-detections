# Threat Hunting & Detection Engineering Portfolio

![Last Updated](https://img.shields.io/badge/Last_Updated-2026--03--06-blue)
![GitHub Repo Size](https://img.shields.io/github/repo-size/dcrowder252/threat-hunting-detections)

## Table of Contents

- [Threat Hunting \& Detection Engineering Portfolio](#threat-hunting--detection-engineering-portfolio)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Technical Focus Areas](#technical-focus-areas)
  - [Repository Structure](#repository-structure)
  - [Methodology](#methodology)
  - [Purpose](#purpose)
  - [Contact](#contact)

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

The project is organized into modular detection engineering domains:

- `sigma/` — Vendor-agnostic detection rules
- `hunts/` — Documented threat hunting investigations
- `research/` — Technical analysis and threat research
  - Threat research and behavioral analysis that informs hunting hypotheses and detection development.
    - [Remote Management Tool Abuse in Enterprise Environments][def]
- `splunk/` — Splunk-specific detection queries
- `kql/` — Microsoft Sentinel / Defender queries
- `crowdstrike/` — CrowdStrike LogScale queries


Each folder contains documentation and artifacts aligned to detection engineering workflows.

---

## Methodology

My workflow typically follows this progression:

Research → Hunt → Sigma Detection → (Splunk → Crowdstrike → KQL  )

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

Daniel Crowder - datello676@gmail.com
Huntsville, Alabama  
Threat Hunting | Detection Engineering 


[def]: research/rmm_abuse_in_enterprise.md