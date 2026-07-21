# Threat Hunt: Cloud Identity Attacks in Azure and Entra ID

## Overview

Microsoft Azure and Entra ID are central to identity and access management across modern enterprise environments. Because cloud identity attacks do not require malware or traditional exploitation techniques, they can be difficult to detect using conventional security controls. Attackers who compromise a cloud identity can access sensitive data, establish persistent access through applications and service principals, and exfiltrate large volumes of data — all through legitimate authentication mechanisms.

This hunt focuses on identifying behavioral indicators associated with cloud identity attacks across the full attack chain — from initial access through persistence, privilege escalation, and data exfiltration. Detections in this document are designed to complement existing alerts from Microsoft Defender for Cloud and Entra ID Protection rather than duplicate them, with an emphasis on chaining multiple signals together to build a more complete picture of potential intrusions.

---

## Hunt Hypothesis

If a threat actor has compromised cloud identities within our environment, evidence of that activity should be observable across Entra ID sign-in logs, audit logs, and Microsoft 365 unified audit logs.

Potential indicators may include:

- Repeated MFA failures followed by successful authentication suggesting push fatigue
- OAuth consent grants to applications outside of approved IT workflows
- New credentials added to existing applications or service principals
- Privileged role assignments made outside of normal administrative processes
- New device registrations associated with suspicious account activity
- Bulk data access or download from SharePoint, OneDrive, or Azure Storage

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

- Entra ID Sign-in Logs
- Entra ID Audit Logs
- Microsoft 365 Unified Audit Log
- Microsoft Defender for Cloud Apps
- Azure Activity Logs
- Azure Storage Diagnostic Logs

**A Note on Licensing**

Not all of these log sources are available by default. Full visibility into Entra ID sign-in logs and advanced identity risk detections requires Entra ID P1 or P2 licensing. The Microsoft 365 Unified Audit Log with extended retention and full event coverage requires Microsoft 365 E3 or E5. Microsoft Defender for Cloud Apps requires its own license for full OAuth app visibility and anomalous download detection. Organizations should assess which log sources are available in their environment before executing these hunt techniques, as gaps in log coverage may limit visibility into certain attack techniques documented in this hunt.

---

## Important Note on Chaining

Cloud identity attacks rarely generate a single high confidence alert. Attackers operating in cloud environments are often aware of built in detection capabilities and attempt to operate below the threshold of automated alerting. The hunt techniques in this document are designed to be correlated with each other and with existing Defender for Cloud and Entra ID Protection alerts to build a complete picture of potential intrusion activity.

A suspicious sign-in alert from Defender for Cloud combined with a new service principal credential addition and a bulk data download occurring within the same timeframe tells a very different story than any one of those signals in isolation. Analysts should approach cloud identity hunting with this correlation mindset.

---

## Hunt Technique 1: MFA Fatigue and Push Bombing

Repeated MFA push notifications sent to a user in a short timeframe, followed by a successful authentication, may indicate a push bombing attack where the user approved a request out of frustration or confusion. This technique is commonly associated with threat actor groups targeting enterprise cloud environments.

Hunt for sign-in events showing repeated MFA failures followed by a successful authentication for the same user account.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious MFA activity
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Atypical travel
- Microsoft Defender for Cloud Apps — Suspicious authentication activity

---

## Hunt Technique 2: Illicit Consent Grant Activity

OAuth consent grant attacks involve tricking users or administrators into granting a malicious application access to their account or tenant. Once consent is granted the application retains persistent access through OAuth tokens that are independent of the user's password or MFA settings and can survive password resets.

Hunt for OAuth permission grants made by non-administrative users or grants requesting access to sensitive resources such as mail, files, or directory data outside of approved IT workflows.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — OAuth app with suspicious attributes
- Microsoft Defender for Cloud Apps — Misleading OAuth app name
- Entra ID Protection — Suspicious application consent

---

## Hunt Technique 3: Service Principal and Application Credential Additions

Attackers who gain sufficient privileges frequently add new secrets or certificates to existing trusted applications and service principals, creating persistent backdoors that survive password resets and account remediation. Unlike user sessions which expire, application credentials remain valid until explicitly revoked.

Hunt for new credential additions to applications and service principals, particularly those occurring outside of normal change management windows or associated with high privilege applications.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Suspicious credential addition to an OAuth app
- Entra ID Protection — Suspicious service principal activity

---

## Hunt Technique 4: Privileged Role Assignments

Attackers with sufficient access frequently assign highly privileged roles to accounts they control to establish persistent administrative access to the tenant. New assignments of sensitive roles made outside of normal administrative workflows or to accounts with no prior administrative history should be treated as suspicious.

Hunt for new assignments of highly privileged roles including Global Administrator, Application Administrator, and Privileged Role Administrator.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Suspicious privileged role assignment
- Microsoft Defender for Cloud Apps — Unusual administrative activity

---

## Hunt Technique 5: Suspicious Device Registration

Attackers have been observed registering attacker-controlled devices to compromised accounts to satisfy conditional access requirements and obtain persistent trusted device tokens. In many cases, failed device registration attempts may be observed before a successful registration occurs — indicating an attacker working through conditional access controls or other enrollment restrictions before eventually succeeding.

Hunt for accounts with failed device registration attempts as an early indicator of suspicious activity. Additionally, hunt for accounts that experienced multiple failed device registration attempts followed by a successful registration — the combination of repeated failures and an eventual success is a high confidence indicator of malicious device enrollment activity.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Entra ID Protection — Anomalous device registration
- Entra ID Protection — Unfamiliar sign-in properties
- Entra ID Protection — Impossible travel

---

## Hunt Technique 6: Bulk Data Access and Smash and Grab Exfiltration

Rather than deploying ransomware, threat actors sometimes choose to focus on exfiltrating large volumes of sensitive data for use as extortion material. In Azure environments this commonly involves bulk downloads from SharePoint, OneDrive, or Azure Blob Storage, often performed rapidly after initial access is established.

Hunt for large volume file access or download activity from SharePoint, OneDrive, or Azure Storage performed by accounts or service principals not normally associated with data management activity.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your Microsoft licensing tier:

- Microsoft Defender for Cloud Apps — Unusual file download activity
- Microsoft Defender for Cloud Apps — Mass download by a single user
- Microsoft Defender for Cloud Apps — Suspicious data access following inactivity

---

## Investigation Considerations

If suspicious cloud identity activity is identified, investigators should consider the following:

- Is the activity associated with a known administrative change or approved workflow?
- Does the affected account have a history of similar activity or does this represent a departure from normal behavior?
- Are multiple indicators present in close temporal proximity — such as a suspicious sign-in followed by credential additions or role assignments?
- Has the affected account or application been used to access sensitive resources following the suspicious activity?
- Is there evidence of lateral movement to other accounts, applications, or cloud services?
- If a federated identity provider is in use, has the upstream identity provider been checked for corresponding suspicious activity?

---

## Conclusion

Cloud identity attacks represent one of the most significant and rapidly evolving threats facing enterprise environments today. By hunting for MFA fatigue patterns, illicit consent grants, application credential additions, privileged role assignments, suspicious device registrations, and bulk data exfiltration activity, defenders can identify intrusions that may not generate automated alerts on their own. Correlating these signals with existing Defender for Cloud and Entra ID Protection alerts is essential to building a complete picture of potential intrusion activity across the environment.

**A Note on CrowdStrike LogScale**

CrowdStrike LogScale queries are not included for this hunt. Azure and Entra ID telemetry is not native CrowdStrike data and is not collected by the Falcon sensor. Organizations that ingest Azure and Entra ID logs into LogScale or NextGen SIEM can adapt the Splunk queries included in this repository using LogScale syntax.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Cloud Identity Attacks in Azure and Entra ID Environments](../research/azure_entra_identity.md)
