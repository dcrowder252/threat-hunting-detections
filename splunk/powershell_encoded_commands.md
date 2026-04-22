| SPL Conversion of Sigma Rule: PowerShell Encoded Command Execution
| Author: dcrowder252
| Date: 2026/04/21
| MITRE ATT&CK: T1059.001, T1027
| Reference: https://attack.mitre.org/techniques/T1059/001/

index=windows sourcetype="WinEventLog:Security" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=4688 OR EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(
    CommandLine="* -EncodedCommand *" OR
    CommandLine="* -EncodedC *" OR
    CommandLine="* -EncodC *" OR
    CommandLine="* -enc *" OR
    CommandLine="* -ec *"
)
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time

| ===============================================================
| NOTES:
| - Adjust index and sourcetype values to match your environment
| - EventCode 4688 requires command line auditing to be enabled
| - EventCode 1 is Sysmon process creation (recommended for better coverage)
| - Field names may vary depending on your Splunk configuration and data inputs
| - Review results against known administrative baselines before alerting
| ===============================================================