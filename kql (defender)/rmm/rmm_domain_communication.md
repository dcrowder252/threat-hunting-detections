**DeviceNetworkEvents
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend RemoteUrl = tolower(tostring(json.query))
| where RemoteUrl has_any ('.anydesk.com', '.teamviewer.com', '.screenconnect.com', '.atera.com', '.splashtop.com', '.splashtop.eu')**

NOTE: Add in other domain names for other RMM tools as you see fit.