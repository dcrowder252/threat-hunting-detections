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

Many RMM platforms communicate with vendor-controlled domains or cloud infrastructure in order to establish remote sessions. Monitoring outbound connections or DNS queries to known RMM domains may help identify systems interacting with remote management platforms that are not approved within the organization.

Example investigation steps:

* Review DNS queries for domains associated with common RMM platforms
* Identify endpoints communicating with those domains
* Determine whether the corresponding software is approved within the environment

Example domains to investigate may include:

* `*.anydesk.com`
* `*.teamviewer.com`
* `*.screenconnect.com`
* `*.atera.com`
* `*.splashtop.com`

Endpoints communicating with these domains should be validated to determine whether the activity is expected.

---

## Hunt Technique 2: Newly Installed RMM Services

Many RMM tools install background services in order to maintain persistent remote access to systems. Monitoring newly installed services can help identify when remote administration tools are deployed within an environment.

Windows Event ID **7045** records new service installations and can provide valuable visibility into software being deployed on endpoints.

Example service names that may be associated with RMM tools include:

* `AnyDesk Service`
* `TeamViewer`
* `ScreenConnect Client`
* `SplashtopRemoteService`

Security teams should review newly installed services and determine whether the corresponding software is authorized for use within the organization.

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
