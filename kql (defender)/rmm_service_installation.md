**DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceName has_any ("AnyDesk", "TeamViewer", "ScreenConnect", "Atera Agent", "SplashtopRemoteService")**

NOTE: Replace any field name as neccessary to conform to your environment. Add in other domain names for other RMM tools as you see fit.



**DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceName has_any ("AnyDesk", "TeamViewer", "ScreenConnect", "Atera Agent", "SplashtopRemoteService")
or InitiatingProcessCommandLine has_any ("AnyDesk", "TeamViewer", "ScreenConnect", "Atera", "Splashtop")**

NOTE: ServiceName is the typical field for the service name in Microsoft telemetry, though InitiatingProcessCommandLine may also be worth searching if actors rename the display name to something benign.

NOTE: The terms are slightly looser than the ServiceName — for example Atera instead of Atera Agent — because image paths typically reference folder or binary names rather than the friendly service display name, so a broader match is more likely to catch variants

NOTE: If you find the InitiatingProcessCommandLine match is too noisy in your environment, you can always tighten it up with more specific path strings once you've had a chance to baseline what legitimate hits look like