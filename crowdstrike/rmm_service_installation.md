**#event_simpleName=ServiceInstalled
| ServiceDisplayName = /AnyDesk|TeamViewer|ScreenConnect|Atera Agent|SplashtopRemoteService/i**

NOTE: Field names vary in tenants. Adjust fields as neccessary. As always, add other RMM tools as you see fit.



**#event_simpleName=ServiceInstalled
| ServiceDisplayName = /AnyDesk|TeamViewer|ScreenConnect|Atera Agent|SplashtopRemoteService/i
OR ServiceImagePath = /AnyDesk|TeamViewer|ScreenConnect|Atera|Splashtop/i**

NOTE: ServiceDisplayName is the typical field for the service name in CrowdStrike telemetry, though ServiceImagePath may also be worth searching if actors rename the display name to something benign.

NOTE: The terms are slightly looser than ServiceDisplayName — for example Atera instead of Atera Agent — because image paths typically reference folder or binary names rather than the friendly service display name, so a broader match is more likely to catch variants.

NOTE: If you find the ServiceImagePath match is too noisy in your environment, you can always tighten it up with more specific path strings once you've had a chance to baseline what legitimate hits look like.