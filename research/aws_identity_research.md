# Cloud Identity Attacks in AWS Environments

## Overview

Amazon Web Services is one of the most widely adopted cloud platforms in the world, providing organizations with compute, storage, networking, and application services at enterprise scale. At the center of AWS security is the Identity and Access Management service — commonly referred to as IAM — which controls who can access AWS resources and what actions they are permitted to perform. IAM is the foundational identity layer of the entire AWS ecosystem, governing everything from human user access to machine-to-machine authentication between services.

Because IAM controls access to virtually every resource in an AWS environment, it is one of the most attractive targets for attackers who have gained an initial foothold. A threat actor who successfully compromises AWS identity can enumerate sensitive data, escalate privileges, establish persistent backdoors, and exfiltrate large volumes of information — all through legitimate AWS API calls that may be difficult to distinguish from normal administrative activity. Understanding how attackers abuse AWS identity mechanisms and what observable artifacts their activity produces is essential for any organization operating workloads in AWS.

---

## Why Attackers Target AWS Identity

AWS identity attacks are attractive to threat actors for many of the same reasons that cloud identity attacks are appealing in any environment — they do not require malware, exploits, or a foothold on a corporate endpoint. An attacker who obtains valid AWS credentials can interact with cloud resources directly through the AWS API, the command line interface, or the management console, appearing to AWS as a legitimate authenticated user.

The scale of potential impact from a single compromised AWS identity is significant. Depending on the permissions attached to the compromised identity, an attacker may be able to access sensitive data stored in S3 buckets, create new IAM users or access keys for persistent access, modify or delete infrastructure, or pivot to other cloud services within the same account. In environments where IAM permissions are overly permissive — a common finding in cloud security assessments — a single compromised identity may provide access to far more resources than intended.

AWS access keys, which consist of an access key ID and a secret access key, are a particularly common target. These long-lived credentials are frequently leaked through public code repositories, misconfigured storage buckets, or compromised developer workstations. Unlike passwords which are typically protected by MFA, access keys can often be used directly without any additional authentication factor, making them highly valuable to attackers.

---

## Common Attack Techniques

The following are examples of common methods used by threat actors to compromise and abuse identity in AWS environments. This is not an exhaustive list, as attacker tradecraft continues to evolve rapidly.

**Root Account Abuse**

Every AWS account has a root user — the original account owner identity with unrestricted access to all AWS services and resources. The root account cannot be restricted by IAM policies and has capabilities that no other identity in the account possesses, including the ability to close the account, change billing information, and modify support plan settings. AWS best practices strongly recommend that the root account not be used for day to day operations and that MFA be enforced on it. When root account activity is observed outside of the very limited scenarios where it is genuinely required, it should be treated as a high priority alert.

**IAM Access Key Creation**

IAM access keys provide programmatic access to AWS services and are commonly used by applications, automation tools, and developers. Attackers who gain sufficient privileges frequently create new IAM access keys — either for existing users or for newly created IAM users — to establish persistent programmatic access to the AWS environment. Unlike console passwords which require MFA, access keys can be used directly through the API without additional authentication, making them a reliable persistence mechanism that survives password resets and console access revocation.

**Privilege Escalation via IAM Policy Changes**

IAM policies define what actions an identity is permitted to perform within AWS. Attackers with the ability to modify IAM policies can escalate their own privileges or the privileges of other identities by attaching more permissive policies, creating new policies with elevated permissions, or modifying existing policies to expand their scope. This technique is particularly dangerous because it can allow an attacker to elevate from a low-privilege foothold to full administrative access within the account.

**Assumed Role Abuse**

AWS IAM roles allow one identity to temporarily assume the permissions of another identity through the AWS Security Token Service. Roles are commonly used to allow services, applications, and users to perform actions that their primary identity does not have direct permission to perform. Attackers who understand the role trust relationships within an AWS environment can abuse the AssumeRole API to pivot to more privileged identities, access resources in other AWS accounts, or establish persistence through cross-account role assumptions that may be difficult to detect.

**S3 Data Enumeration and Exfiltration**

Amazon S3 is one of the most commonly used AWS services for storing sensitive data including backups, application data, logs, and business documents. Attackers who obtain AWS credentials frequently enumerate accessible S3 buckets and download sensitive content as part of smash and grab data exfiltration operations. S3 exfiltration is attractive because it requires no special tooling — standard AWS API calls or the AWS CLI are sufficient — and large volumes of data can be transferred quickly without triggering traditional network-based data loss prevention controls.

---

## The Operational Problem

One of the primary challenges defenders face with AWS identity attacks is the volume and diversity of legitimate API activity in most cloud environments. AWS CloudTrail logs every API call made within an account, providing a comprehensive audit trail of all activity — but in active environments this can generate millions of events per day. Distinguishing malicious activity from the constant background of legitimate API calls requires a clear understanding of what normal looks like in the environment and the ability to identify deviations from that baseline.

IAM permission sprawl is another significant challenge. In many organizations, IAM permissions have grown organically over time with users, roles, and policies accumulating permissions far beyond what they actually need. This over-permissioning means that a single compromised identity may have access to far more resources than intended, and defenders may not immediately understand the full scope of what an attacker could access with a given set of credentials.

CloudTrail itself, while invaluable, has limitations that defenders should understand. Management events — which include API calls related to IAM, S3 bucket operations, and other control plane actions — are logged by default, but data events such as individual S3 object level reads and writes require explicit configuration and may not be enabled in all environments. Organizations without data event logging enabled have significantly reduced visibility into S3 based exfiltration activity.

Amazon CloudWatch provides a complementary source of visibility that defenders should also consider. While CloudTrail focuses on API activity and account actions, CloudWatch captures metrics, application logs, Lambda function execution logs, and VPC Flow Logs. Correlating CloudWatch data with CloudTrail activity can provide additional context during investigations — for example, pairing unusual API calls from CloudTrail with corresponding network connections from VPC Flow Logs can help build a more complete picture of attacker activity within the environment.

---

## Detection Opportunities

Effective detection of AWS identity attacks relies primarily on CloudTrail logs and a solid understanding of expected API activity within the environment. The following represents a sampling of practical starting points for hunting activity associated with common AWS identity intrusions — this is not an exhaustive list.

**Monitor for root account activity**

Any use of the AWS root account outside of the very limited scenarios where it is genuinely required should be treated as a high priority alert. CloudTrail records root account activity and the username field will contain the value `root` for these events. Root account usage is rare enough in well-managed environments that every instance warrants investigation.

**Hunt for IAM access key creation**

Monitoring CloudTrail for `CreateAccessKey` API calls can surface both legitimate and malicious key creation activity. Particular attention should be paid to access keys created for existing users outside of approved provisioning processes, access keys created by identities that do not normally perform administrative IAM actions, and access keys created immediately following other suspicious activity such as console logins from unusual locations.

**Detect IAM policy modifications**

CloudTrail events such as `PutUserPolicy`, `AttachUserPolicy`, `PutRolePolicy`, `AttachRolePolicy`, and `CreatePolicy` indicate changes to IAM permissions that may represent privilege escalation attempts. These events should be reviewed for changes that grant broad permissions such as `AdministratorAccess` or wildcard actions, particularly when performed outside of approved change management processes.

**Monitor for unusual AssumeRole activity**

The `AssumeRole` API call is frequently used in legitimate automation and service-to-service authentication, but unusual patterns such as role assumptions from unexpected source identities, cross-account role assumptions not associated with known integrations, or role assumptions followed immediately by sensitive API calls warrant investigation.

**Hunt for S3 enumeration and bulk access**

CloudTrail management events capture S3 bucket level operations such as `ListBuckets` and `GetBucketPolicy` which may indicate enumeration activity. For data level exfiltration visibility, S3 data event logging must be enabled. High volumes of `GetObject` calls against sensitive buckets — particularly from identities or IP addresses not normally associated with that data — may indicate exfiltration activity.

---

## MITRE ATT&CK Mapping

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1548.005** — Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access
- **T1530** — Data from Cloud Storage
- **T1087.004** — Account Discovery: Cloud Account

---

## Sources

- https://attack.mitre.org/techniques/T1078/004/
- https://attack.mitre.org/techniques/T1098/001/
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
- https://redcanary.com/threat-detection-report/techniques/
