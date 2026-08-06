# Threat Hunt: Cloud Identity Attacks in AWS Environments

## Overview

Amazon Web Services Identity and Access Management is the foundational identity layer of the AWS ecosystem, controlling access to virtually every resource in an AWS environment. Because IAM governs who can do what across the entire cloud account, it is one of the most attractive targets for attackers who have established an initial foothold. Cloud identity attacks in AWS do not require malware or traditional exploitation — an attacker with valid credentials can interact with cloud resources directly through the AWS API, appearing as a legitimate authenticated user.

This hunt focuses on identifying behavioral indicators associated with AWS identity attacks across the full attack chain — from initial access and persistence through privilege escalation and data exfiltration. The primary data source for this hunt is AWS CloudTrail, which records every API call made within an account and provides the core visibility needed to detect identity based attacks.

---

## Hunt Hypothesis

If a threat actor has compromised AWS identities within our environment, evidence of that activity should be observable in CloudTrail logs as anomalous API calls inconsistent with normal administrative activity.

Potential indicators may include:

- Root account activity outside of approved administrative scenarios
- New IAM access keys created outside of approved provisioning workflows
- IAM policy changes that expand permissions beyond what is expected
- Unusual AssumeRole activity from unexpected source identities or into privileged roles
- High volume S3 API calls indicative of enumeration or bulk data access

---

## Data Sources

This hunt requires visibility into the following telemetry sources:

- AWS CloudTrail — Management Events
- AWS CloudTrail — Data Events (required for S3 object level activity — must be explicitly enabled)
- Amazon CloudWatch — supplementary source for VPC Flow Logs and application level context

**A Note on CloudTrail Data Events**

S3 data events — which capture individual object level reads and writes — are not enabled by default in AWS CloudTrail. Organizations that have not explicitly enabled data event logging will have limited visibility into S3 based exfiltration activity. Enabling S3 data event logging should be treated as a priority for any environment where sensitive data is stored in S3.

---

## Important Note on Platform Coverage

Splunk queries are provided for this hunt as CloudTrail logs are most commonly ingested into enterprise SIEMs. KQL and CrowdStrike LogScale queries are not included as AWS CloudTrail telemetry is not native to those platforms. Organizations ingesting CloudTrail into those environments can adapt the Splunk queries using the appropriate platform syntax.

---

## Hunt Technique 1: Root Account Usage

Every AWS account has a root user with unrestricted access to all AWS services and resources. The root account cannot be restricted by IAM policies and should not be used for day to day operations. Any use of the root account outside of the very limited scenarios where it is genuinely required should be treated as a high priority alert.

Hunt for CloudTrail events where the user identity type indicates root account usage. In well managed environments root account activity is rare enough that every instance warrants investigation regardless of what action was performed.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- AWS Security Hub — Root account usage findings
- Amazon GuardDuty — Policy:IAMUser/RootCredentialUsage

---

## Hunt Technique 2: IAM Access Key Creation

IAM access keys provide programmatic access to AWS services and are a common attacker persistence mechanism. Attackers who gain sufficient privileges frequently create new access keys to establish persistent API access that survives password resets and console access revocation. Unlike console passwords which can be protected by MFA, access keys can be used directly through the API without additional authentication.

Hunt for CloudTrail `CreateAccessKey` events — particularly those occurring outside of approved provisioning processes, performed by identities that do not normally manage IAM, or occurring in close proximity to other suspicious activity such as unusual console logins.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — IAMUser/AnomalousBehavior
- AWS Security Hub — IAM access key creation findings

---

## Hunt Technique 3: Privilege Escalation via IAM Policy Changes

IAM policies define what actions an identity is permitted to perform within AWS. Attackers with the ability to modify IAM policies can escalate their own privileges or the privileges of other identities by attaching more permissive policies or creating new policies with elevated permissions. This technique can allow an attacker to elevate from a low-privilege foothold to full administrative access within the account.

Hunt for CloudTrail events associated with IAM policy modifications including `PutUserPolicy`, `AttachUserPolicy`, `PutRolePolicy`, `AttachRolePolicy`, and `CreatePolicy`. Pay particular attention to policy changes that grant broad permissions such as `AdministratorAccess` or wildcard actions performed outside of approved change management processes.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — PrivilegeEscalation:IAMUser/AdministrativePermissions
- AWS Security Hub — IAM policy modification findings

---

## Hunt Technique 4: Assumed Role Abuse

AWS IAM roles allow identities to temporarily assume the permissions of another identity through the Security Token Service. Attackers who understand the role trust relationships within an AWS environment can abuse the `AssumeRole` API to pivot to more privileged identities, access resources in other AWS accounts, or establish persistence through cross-account role assumptions.

Hunt for CloudTrail `AssumeRole` events showing unusual patterns such as role assumptions from unexpected source identities, cross-account assumptions not associated with known integrations, or role assumptions immediately followed by sensitive API calls. Establishing a baseline of normal role assumption activity is essential for this technique given how frequently `AssumeRole` is used in legitimate automation.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — IAMUser/AnomalousBehavior
- Amazon GuardDuty — UnauthorizedAccess:IAMUser/TorIPCaller

---

## Hunt Technique 5: S3 Data Enumeration and Exfiltration

Amazon S3 is one of the most commonly targeted services for data exfiltration in AWS environments. Attackers who obtain AWS credentials frequently enumerate accessible S3 buckets and download sensitive content as part of smash and grab operations. S3 exfiltration requires no special tooling and large volumes of data can be transferred quickly using standard AWS API calls.

Hunt for CloudTrail events indicating S3 enumeration activity such as `ListBuckets` and `GetBucketPolicy`, as well as high volumes of `GetObject` calls against sensitive buckets from identities or IP addresses not normally associated with that data. Note that `GetObject` events require S3 data event logging to be enabled in CloudTrail.

Related detections that may be observed in conjunction with this activity — not all may be available depending on your AWS security tooling and licensing tier:

- Amazon GuardDuty — Exfiltration:S3/AnomalousBehavior
- Amazon GuardDuty — Discovery:S3/AnomalousBehavior
- AWS Security Hub — S3 bucket security findings

---

## Investigation Considerations

If suspicious AWS identity activity is identified, investigators should consider the following:

- Is the activity associated with a known administrative change or approved workflow?
- Does the affected identity have a history of similar activity or does this represent a departure from normal behavior?
- Are multiple indicators present in close temporal proximity — such as access key creation followed immediately by S3 enumeration?
- What is the source IP address of the activity and is it consistent with expected administrative locations?
- Has the affected identity or newly created access key been used to access sensitive resources following the suspicious activity?
- Are there signs of lateral movement to other AWS accounts or services following the initial suspicious event?

---

## Conclusion

AWS identity attacks represent a significant and growing threat to organizations operating cloud workloads. By hunting for root account usage, IAM access key creation, privilege escalation via policy changes, assumed role abuse, and S3 enumeration and exfiltration activity, defenders can identify intrusions that may not generate automated alerts on their own. CloudTrail is the foundational data source for this hunt and organizations that have not enabled S3 data event logging should prioritize doing so to ensure full visibility into potential exfiltration activity.

---

## Related Research

This threat hunt builds upon the research documented in:
- [Cloud Identity Attacks in AWS Environments](../research/aws_identity_research.md)
