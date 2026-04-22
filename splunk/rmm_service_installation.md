# RMM Service Installation — Splunk SPL

**Author:** dcrowder252
**Date:** 2026/04/21
**MITRE ATT&CK:** T1219.002
**Reference:** https://attack.mitre.org/techniques/T1219/002/

---

## Query

```spl
index=<your_index> sourcetype="WinEventLog:System"
EventCode=7045
(
    ServiceName="*AnyDesk*" OR
    ServiceName="*TeamViewer*" OR
    ServiceName="*ScreenConnect*" OR
    ServiceName="*Atera Agent*" OR
    ServiceName="*SplashtopRemoteService*"
)
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceType, ServiceStartType
| sort -_time
```

---

## Notes

- Adjust index value to match your environment
- EventCode 7045 logs newly installed services on Windows systems
- Replace field names as necessary to conform to your environment
- This list is not exhaustive — add additional RMM service names as needed
- Review results against your approved RMM tool baseline before alerting
