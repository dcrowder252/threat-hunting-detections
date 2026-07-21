# Cloud Identity Attacks in Azure and Entra ID Environments

## Overview

Microsoft Azure and Entra ID have become foundational components of enterprise identity and access management across organizations of all sizes. Entra ID serves as the primary identity provider for millions of organizations, managing authentication for cloud applications, Microsoft 365 services, and hybrid on-premises environments. Its deep integration across the Microsoft ecosystem makes it both an essential business platform and one of the most attractive targets for modern threat actors.

Unlike traditional endpoint-focused intrusions, cloud identity attacks do not require malware, exploits, or even a foothold on a corporate device. An attacker who successfully compromises a cloud identity can access sensitive data, establish persistent access, move laterally across cloud services, and exfiltrate large volumes of data — all through legitimate authentication mechanisms that are difficult to distinguish from normal user behavior. This reality has fundamentally shifted the threat landscape, and defenders who rely solely on endpoint detection capabilities are increasingly blind to how modern intrusions actually unfold.

Understanding how attackers abuse cloud identity, what artifacts their activity produces, and how to detect and correlate those signals is one of the most important capabilities a modern security team can develop.

---

## Why Attackers Target Cloud Identity

Cloud identity is attractive to attackers for several reasons that make it fundamentally different from traditional intrusion targets. A compromised cloud identity requires no malware deployment, no exploit development, and no lateral movement through network segments. Once an attacker has valid credentials or a trusted authentication token, they are operating as a legitimate user from the perspective of most security controls.

The scale of access available through a single compromised identity is enormous. A user with access to Microsoft 365 may have visibility into email, SharePoint, OneDrive, Teams, and a wide range of connected applications — all accessible through a single set of credentials. Privileged identities such as Global Administrators or Application Administrators carry even broader access, often including the ability to modify security configurations, add credentials to applications, and assign roles to other accounts.

Threat actor groups such as Scattered Spider and ShinyHunters have demonstrated repeatedly that cloud identity compromise is both highly effective and extremely profitable. These groups sometimes choose not to deploy traditional malware or ransomware — instead focusing on gaining access to cloud environments, exfiltrating sensitive data, and leveraging that data as extortion material. This smash and grab approach is faster, more scalable, and harder to detect than traditional ransomware operations, and it has become the dominant model for financially motivated cloud intrusions.

---

## The Federated Identity Challenge

Many enterprise environments do not use Entra ID as their sole identity provider. Organizations frequently integrate third party identity providers such as Okta, Ping Identity, or on-premises Active Directory Federation Services into their Azure environments through federation. In these configurations, authentication may originate from an entirely different identity system before being passed to Entra ID as a trusted assertion.

This creates a significant detection challenge. When an attacker compromises an account through a federated identity provider, the initial access may generate no meaningful alerts in Entra ID itself. The suspicious activity visible in Entra ID may begin only after the attacker has already established a foothold — such as when they begin modifying application permissions, registering devices, or accessing cloud resources. Defenders must understand the full authentication chain in their environment to avoid blind spots created by federated identity configurations.

---

## Common Attack Techniques

The following are examples of common methods used by threat actors to compromise and abuse cloud identity in Azure and Entra ID environments. This is not an exhaustive list, as attacker tradecraft continues to evolve rapidly.

**MFA Fatigue and Push Bombing**

Multi-factor authentication is one of the most effective controls against credential-based attacks, but it is not impenetrable. Attackers who have obtained valid credentials frequently attempt to overwhelm users with repeated MFA push notifications until the user approves one out of frustration or confusion. This technique, commonly associated with Scattered Spider, has been used to bypass MFA at numerous high-profile organizations.

**Illicit Consent Grant Attacks**

OAuth consent grant attacks involve tricking users or administrators into granting a malicious application access to their account or tenant. Once consent is granted the malicious application retains persistent access through OAuth tokens that are independent of the user's password or MFA settings. This technique is particularly dangerous because the access persists even after a password reset and can be difficult to identify without reviewing application consent grants in the tenant.

**Service Principal and Application Credential Abuse**

Applications and service principals in Entra ID can be assigned credentials in the form of secrets or certificates that allow them to authenticate independently of any user account. Attackers who gain sufficient privileges frequently add new credentials to existing trusted applications, creating a persistent backdoor that survives password resets, account disabling, and even conditional access policy changes. Unlike user sessions which expire, application credentials remain valid until explicitly revoked.

**Privileged Role Assignment**

Attackers with sufficient access frequently assign highly privileged roles such as Global Administrator, Application Administrator, or Privileged Role Administrator to accounts they control. This provides persistent administrative access to the tenant and the ability to make further configuration changes to maintain and expand their foothold.

**Device Registration Abuse**

Conditional access policies frequently require devices to be compliant or Entra ID joined before granting access to sensitive resources. Attackers — particularly Scattered Spider — have been observed registering attacker-controlled devices to compromised accounts to satisfy these conditional access requirements and obtain persistent trusted device tokens. This effectively allows them to bypass device-based conditional access controls with their own hardware.

**Smash and Grab Data Exfiltration**

Rather than deploying ransomware, modern threat actors frequently focus on exfiltrating large volumes of sensitive data and using it as leverage for extortion. In Azure environments this commonly involves bulk downloads from SharePoint and OneDrive, access to Azure Blob Storage, and abuse of the Microsoft Graph API to enumerate and download data at scale. This approach is faster than ransomware deployment, requires no malware, and can be completed within hours of initial access.

---

## The Operational Problem

Cloud identity detection is fundamentally different from endpoint detection in ways that require defenders to adapt both their mindset and their tooling. Endpoint detections typically focus on specific process executions, file writes, or registry changes that have clear malicious signatures. Cloud identity attacks, by contrast, often involve legitimate actions performed by legitimate identities — the malicious intent is revealed only through context, timing, and the correlation of multiple signals.

A single sign-in from an unusual location may be a traveling employee or an attacker. A new application credential may be legitimate IT administration or an attacker establishing persistence. A bulk file download may be an authorized data migration or exfiltration. No single event tells the full story — defenders must learn to think in terms of attack chains, correlating multiple individually explainable signals into a coherent picture of malicious activity.

Microsoft Defender for Cloud and Entra ID Protection generate a wide range of identity-based alerts that serve as valuable starting points for investigation. However, these built-in detections do not catch everything — and attackers who understand the platform are increasingly aware of how to operate below the threshold of automated alerting. The hunt techniques documented in this repository are designed to complement built-in detections by surfacing activity that may not generate alerts on its own, while also providing context for chaining those signals together with existing alerts to build a more complete picture of an intrusion.

---

## Detection Opportunities

Effective detection of cloud identity attacks requires visibility into Entra ID sign-in logs, audit logs, and Microsoft 365 unified audit logs. The following represents a sampling of practical starting points for hunting activity associated with modern cloud identity intrusions — this is not an exhaustive list.

**Monitor for MFA anomalies and push fatigue patterns**
Repeated MFA failures followed by a successful authentication, particularly in a short timeframe, may indicate a push bombing attack. Monitoring for this pattern across the sign-in logs can surface MFA fatigue attempts before they succeed or shortly after.

**Hunt for illicit consent grant activity**
Monitoring Entra ID audit logs for OAuth permission grants — particularly grants made by non-administrative users or grants requesting access to sensitive resources such as mail, files, or directory data — can surface illicit consent grant attacks. Any application granted consent outside of approved IT workflows should be reviewed.

**Detect new application and service principal credential additions**
Monitoring Entra ID audit logs for new secrets or certificates added to existing applications and service principals can surface attacker persistence mechanisms. Particular attention should be paid to credentials added to high-privilege applications or outside of normal change management windows.

**Identify privileged role assignments**
New assignments of highly privileged roles — especially Global Administrator, Application Administrator, and Privileged Role Administrator — should be reviewed carefully. Assignments made outside of normal administrative workflows or to accounts with no prior administrative history are particularly suspicious.

**Monitor for suspicious device registrations**
Rather than monitoring all device registrations which would generate significant noise in most enterprise environments, a more targeted approach focuses on failed device registration attempts and the pattern of failures followed by eventual success. Failed device registration attempts may indicate an attacker working through conditional access controls or enrollment restrictions. A burst of failed attempts followed by a successful registration is a high confidence indicator of malicious device enrollment activity, as legitimate users typically complete enrollment without significant failure volume. Correlating device registration activity with other suspicious signals such as MFA fatigue events for the same account significantly increases detection confidence.

**Hunt for bulk data access and download activity**
Large volume file access or download activity from SharePoint, OneDrive, or Azure Blob Storage — particularly when performed by accounts or service principals not normally associated with data management — may indicate smash and grab exfiltration activity.

**Correlate signals into attack chains**
Individual signals may have innocent explanations. The combination of a suspicious sign-in, followed by a new device registration, followed by a privileged role assignment, followed by bulk data download is a high confidence indicator of an active intrusion. Training analysts to think in terms of these chains rather than individual alerts is essential for effective cloud identity detection.

---

## MITRE ATT&CK Mapping

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1621** — Multi-Factor Authentication Request Generation
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1530** — Data from Cloud Storage

---

## Sources

- https://attack.mitre.org/groups/G1015/
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- https://redcanary.com/threat-detection-report/techniques/
- https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection
- https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/
