# Threat Hunt: Unauthorized RMM Activity

## Overview

Remote Monitoring and Management (RMM) tools are commonly used by IT teams to remotely manage systems across an enterprise environment. These tools allow administrators to troubleshoot systems, deploy software, and perform maintenance without physical access to endpoints.

Because of these capabilities, RMM tools are also attractive to attackers and malicious insiders. When deployed without authorization, these tools can provide persistent remote access while blending in with legitimate administrative activity. This hunt focuses on identifying potential unauthorized usage of remote management tools within the environment.

---

## Hunt Hypothesis

If attackers deploy unauthorized RMM tools to maintain remote access within an environment, evidence of these tools should appear in network communications or system service installations.

Potential indicators may include:

•	Endpoints communicating with domains associated with RMM platforms
•	Newly installed services related to remote administration software

---

## Data Sources

This hunt may require visibility into the following telemetry sources:

* Endpoint process creation logs
* Windows event logs
* Network connection telemetry
* DNS query logs
* Endpoint service creation events

---

## Hunt Technique 1: RMM Domain Communication

Many RMM tools rely on vendor-controlled infrastructure to facilitate remote connections. Systems using these tools will typically communicate with domains owned by the RMM provider.

Review DNS queries or network telemetry for connections to domains associated with remote management platforms.

Examples may include:


* `*.anydesk.com`
* `*.teamviewer.com`
* `*.screenconnect.com`
* `*.atera.com`
* `*.splashtop.com`

Endpoints communicating with these domains should be validated to determine whether the activity is expected and associated with approved administrative tools.

NOTE: This list is not all inclusive, this is just a small sample. Add other domains as needed.

---

## Hunt Technique 2: Newly Installed RMM Services

Many RMM tools install services to maintain persistent remote access. Monitoring newly installed services can help identify when remote administration software is introduced into an environment.

Windows Event ID 7045 records service installations and can provide visibility into software deployed on endpoints.

Example service names associated with common RMM tools include:

* `AnyDesk Service`
* `TeamViewer`
* `ScreenConnect Client`
* `Atera Agent`
* `SplashtopRemoteService`

Newly installed services should be reviewed to determine whether the software is authorized within the organization.

---

## Investigation Considerations

If suspicious RMM activity is identified, investigators should consider the following questions:

* Is the RMM tool approved for use within the organization?
* Was the software installed through an official deployment process?
* Which user or process initiated the installation?
* Are there signs of additional suspicious activity on the affected host?

Answers to these questions can help determine whether the activity represents legitimate administrative use or potential malicious activity.

---

## Conclusion

RMM tools are valuable administrative utilities, but they can also provide attackers with a convenient method for maintaining remote access within a compromised environment. By monitoring network activity and service installations related to remote management software, defenders can improve their ability to detect unauthorized usage and respond to potential intrusions.
