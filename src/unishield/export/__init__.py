"""
Exports and notifications for the analyst side: JSON lines, CEF and STIX 2.1
files, syslog forwarding and email/webhook notifications.

Only ``export.transport`` opens network connections, and only to
destinations allowed by ``export.policy`` (allow-listed, outside the
monitored network). Everything else in this package is local computation
and file output.
"""
