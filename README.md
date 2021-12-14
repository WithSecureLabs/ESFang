# ESFang

This is a tool devised for modular consumption of EndpointSecurity Framework (ESF) events from the MacOs environment. This is my attempt to overcome a number of issues encountered with existing tools including things such as silent data dropping, strict event type consumption, lack of support for alternative data event types and file access handler overload.

This tool heavily leans on the excellent work done by Chris Ross, Omark-Ikram and the team at Objective-See for their tools ProcessMonitor, Appmon and EndpointSecurityDemo. My core understanding and applicability of ESF data ingestion was greatly enahcned and kick-started by examining their works which did much of the heavy lifting in order to make this development possible. This tool has attempted to extrapolate the best elements of these tools and expand on them in order to allow for a case-by-case ESF consumption action based on investigators needs.

The existing tools, including more refined tools such as Crescendo by FireEye, fall foul of a number of issues associated with ESF itself which in testing seems related to the way in which the ESF client ingests the data from the sub-system. The primary issue encountered was the silent loss of data. In testing, when numerous event types were ingested the results when compared to ingestion of a single event type showed that there was disparity in the data accumulated. In testing, critical events related to malicious activity were not in the acquired data set that was present in the singular event type ingestion. 

This tools primary purpose was 3 fold:
- Create a tool which avoided the silent data drop issue
- Allowed for case-by-case event collection specification
- Be expandable and integratable into monitoring systems

To this end, the tool allows the user to specify which event types they want to collect during operations from the 51 available NOTIFY event types (AUTH event types were omitted for this tool). This means researchers can target specific event types related to specific operations they wish to monitor as well as helping reduce the associated silent data loss by reducing the overall event types collected by the client. 

Data output is distributed into individual event type log files which in turn are grouped under event genre files such as process, file, sockets etc. All logs are written in JSON for easy ingestion and can be expanded to by users by altering the source code to collect additional fields outlined in the event_type documentation provided by Apple.

FUTURE NOTES - 

In order to prevent the silent data loss a potential solution would be to multi-thread the tool in order to allow for multiple ESF clients to run simultaneously with each collecting a subset of the event types. This could potentially overcome the internal threshold being reached causing the data loss being observed. I simply did not have time to employ the additional controls for this. 

*HOW TO USE*

**Requires SIP to be disabled!**

- Unfortunately, as this is a development POC code you will not be able to use this with SIP enabled as access to the ESF sub-system is restricted to signed binaries. As this is unsigned, SIP must be disabled for use. As such, only use this on non-production machines. 

- There are three types of execution, either you can specify the ID of an event_id from the configuration file, specify a group_id from the configuration file, or you can reference the configuration file with the lines of the event type ID's or groups uncommented. 

- Example 1 = Collect ES_EVENT_TYPE_NOTIFY_EXEC events only: ./ESFang -id 2 

- Example 2 = Collect File genre events: ./ESFang -group 2

- Example 3 = Collect event types or groups specified by config file: ./ESFang -config ./ESF_config.txt

**NOTE ON HARD CODED FILTER**

Within the source code is a hard coded process filter which is found at line 460 - 469. This filter can be manipulated to either capture on specific PID, PPID or process name. This was added as a "hacky" workaround for specific filtering purposes. Attempts to make this dynamic at command line to feed into Inspector all errored out. So left as hard coded. 

**NOTE ON HARD CODED PROCESS MUTER**

Within the source code is a hard coded process muting capacity found at line 471 - 491. This filter can be used to mute the capture of specific events based on process or parent process path respectively. This should be used with caution as all processes matching the name specified will be muted if either the process or parent of any activity. This was in beta-testing when released.     
