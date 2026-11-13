"""Built-in synthetic sample events, one per vendor log source.

Everything here is made up. Every event carries the MARKER text so it can be found in NG-SIEM,
and uses reserved addresses (example.com, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
Timestamps are tokens, filled with the current time whenever a sample is loaded.

`accuracy` says how far to trust the event's shape:
  documented  - field names come from the vendor's own reference or example.
  partial     - some field names are documented; the rest follow a third-party example or the
                commonly seen format.
  approximate - no usable reference could be read, so check it against a real log.
"""
import json
from datetime import datetime, timezone

MARKER = "NGSIEM-LogTester-TEST"

DOCUMENTED = "documented"
PARTIAL = "partial"
APPROXIMATE = "approximate"

SAMPLES = [
    {
        "id": "proofpoint-tap",
        "label": "Proofpoint TAP log",
        "accuracy": DOCUMENTED,
        "parser": "proofpoint-tap",
        "note": "One delivered message, as CrowdStrike's proofpoint-tap parser reads it: one message per event, with eventType naming the SIEM API category (messagesDelivered).",
        "source": "https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API",
        "event": {
            "eventType": "messagesDelivered",
            "GUID": f"{MARKER}-GUID-0001",
            "QID": f"{MARKER}-QID",
            "ccAddresses": [],
            "clusterId": "example_hosted",
            "completelyRewritten": "true",
            "fromAddress": ["sender@example.com"],
            "headerFrom": "Test Sender <sender@example.com>",
            "headerReplyTo": None,
            "impostorScore": 0,
            "malwareScore": 0,
            "messageID": f"<{MARKER}@example.com>",
            "messageParts": [
                {
                    "contentType": "text/plain",
                    "disposition": "inline",
                    "filename": "text.txt",
                    "md5": "00000000000000000000000000000000",
                    "oContentType": "text/plain",
                    "sandboxStatus": "unsupported",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                }
            ],
            "messageSize": 2048,
            "messageTime": "{{ISO_MS}}",
            "modulesRun": ["spam", "urldefense"],
            "phishScore": 0,
            "policyRoutes": ["default_inbound"],
            "quarantineFolder": None,
            "quarantineRule": None,
            "recipient": ["recipient@example.com"],
            "replyToAddress": [],
            "sender": "sender@example.com",
            "senderIP": "192.0.2.10",
            "spamScore": 0,
            "subject": f"{MARKER} synthetic event, not real mail",
            "threatsInfoMap": [],
            "toAddresses": ["recipient@example.com"],
            "xmailer": None,
        },
    },
    {
        "id": "proofpoint-tap-click",
        "label": "Proofpoint TAP click log",
        "accuracy": DOCUMENTED,
        "parser": "proofpoint-tap",
        "note": "One permitted click on a URL in a delivered message, as the SIEM API's clicksPermitted records it, with eventType naming the category.",
        "source": "https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API",
        "event": {
            "eventType": "clicksPermitted",
            "campaignId": f"{MARKER}-CAMPAIGN",
            "classification": "phish",
            "clickIP": "192.0.2.25",
            "clickTime": "{{ISO_MS}}",
            "GUID": f"{MARKER}-GUID-0002",
            "id": f"{MARKER}-CLICK-0001",
            "messageID": f"<{MARKER}@example.com>",
            "recipient": "recipient@example.com",
            "sender": "sender@example.com",
            "senderIP": "192.0.2.10",
            "threatID": f"{MARKER}-THREAT-0001",
            "threatTime": "{{ISO_MS}}",
            "threatURL": "https://threatinsight.proofpoint.com/example/threat/email/NGSIEM-LogTester-TEST",
            "threatStatus": "active",
            "url": "https://www.example.com/NGSIEM-LogTester-TEST",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NGSIEM-LogTester",
        },
    },
    {
        "id": "windows-system",
        "label": "Microsoft Windows system event log",
        "accuracy": DOCUMENTED,
        "parser": "microsoft-windows",
        "note": "Service Control Manager event 7036 as native Windows event XML, which is what CrowdStrike's microsoft-windows parser reads, so it uses Raw mode. The parser also accepts WinCollect and NXLog syslog.",
        "source": "https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema",
        "text": (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>"
            "<EventID Qualifiers='16384'>7036</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode>"
            "<Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime='{{ISO_MS}}'/><EventRecordID>1190</EventRecordID>"
            "<Correlation/><Execution ProcessID='500' ThreadID='1848'/><Channel>System</Channel>"
            "<Computer>WIN-TEST-01.example.com</Computer><Security/></System><EventData>"
            f"<Data Name='param1'>{MARKER} Service</Data><Data Name='param2'>running</Data></EventData></Event>"
        ),
    },
    {
        "id": "microsoft-entra",
        "label": "Microsoft Entra log",
        "accuracy": PARTIAL,
        "parser": "microsoft-entra-id",
        "note": "A sign-in record as exported through Azure Monitor. Field names are documented, but Microsoft publishes no complete record, so the nesting of the details is from the common format.",
        "source": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema",
        "event": {
            "time": "{{ISO_MS}}",
            "resourceId": "/tenants/00000000-0000-0000-0000-000000000000/providers/Microsoft.aadiam",
            "operationName": "Sign-in activity",
            "operationVersion": "1.0",
            "category": "SignInLogs",
            "tenantId": "00000000-0000-0000-0000-000000000000",
            "resultType": "0",
            "resultSignature": "None",
            "resultDescription": "",
            "durationMs": 0,
            "callerIpAddress": "203.0.113.20",
            "correlationId": "00000000-0000-0000-0000-000000000001",
            "identity": f"{MARKER} User",
            "Level": 4,
            "location": "US",
            "properties": {
                "id": "00000000-0000-0000-0000-000000000002",
                "createdDateTime": "{{ISO}}",
                "userDisplayName": f"{MARKER} User",
                "userPrincipalName": "test.user@example.com",
                "userId": "00000000-0000-0000-0000-000000000003",
                "appId": "00000000-0000-0000-0000-000000000004",
                "appDisplayName": "NGSIEM LogTester Sample App",
                "ipAddress": "203.0.113.20",
                "clientAppUsed": "Browser",
                "correlationId": "00000000-0000-0000-0000-000000000001",
                "conditionalAccessStatus": "notApplied",
                "isInteractive": True,
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "riskEventTypes_v2": [],
                "resourceDisplayName": "Microsoft Graph",
                "resourceId": "00000003-0000-0000-c000-000000000000",
                "status": {"errorCode": 0},
                "deviceDetail": {"operatingSystem": "Windows 10", "browser": "Edge"},
                "location": {"city": "Testville", "state": "Testing", "countryOrRegion": "US"},
                "userType": "Member",
                "authenticationProtocol": "none",
                "tokenIssuerType": "AzureAD",
            },
        },
    },
    {
        "id": "cisco-ucs",
        "label": "Cisco UCS log",
        "accuracy": APPROXIMATE,
        "parser": None,
        "note": "No CrowdStrike parser is available for Cisco UCS, so nothing in NG-SIEM will parse this. It's a plain-text syslog line, as UCS Manager sends it, so it uses Raw mode. The %UCSM marker and fault F0209 are documented, but the layout is a best estimate.",
        "source": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/ts/faults/reference/ErrMess/UCS_SEMs.html",
        "text": (
            f"{{{{SYSLOG}}}} {MARKER}-fi-a %UCSM-3-LINK_DOWN: [F0209][major][link-down]"
            "[sys/chassis-1/blade-1/adaptor-1/ext-eth-1/fault-F0209] "
            "Adapter uplink interface 1/1/1 link state: down"
        ),
    },
    {
        "id": "cisco-firepower",
        "label": "Cisco Firepower log",
        "accuracy": PARTIAL,
        "parser": "cisco-firepower",
        "note": "Connection event 430003 as a plain-text syslog line, so it uses Raw mode. The layout follows a published third-party example.",
        "source": "https://docs.rapid7.com/insightidr/cisco-firepower-threat-defense/",
        "text": (
            f"<118>{{{{ISO}}}} %FTD-6-430003: DeviceUUID: 00000000-0000-0000-0000-000000000005, "
            "AccessControlRuleAction: Allow, SrcIP: 192.0.2.30, DstIP: 198.51.100.30, SrcPort: 49152, "
            "DstPort: 443, Protocol: tcp, IngressInterface: inside, EgressInterface: outside, "
            f"IngressZone: Inside, EgressZone: Outside, ACPolicy: {MARKER}, "
            "AccessControlRuleName: Allow_Test_Outbound, Prefilter Policy: Default Prefilter Policy, "
            "User: No Authentication Required, ConnectionDuration: 60, InitiatorPackets: 10, "
            "ResponderPackets: 8, InitiatorBytes: 1200, ResponderBytes: 3400, "
            "NAPPolicy: Balanced Security and Connectivity"
        ),
    },
    {
        "id": "vmware-vsphere",
        "label": "VMware vSphere log",
        "accuracy": PARTIAL,
        "parser": "vmware-vcenter",
        "note": "A vCenter user login event as the RFC 5424 syslog line from the vpxd service, in the bracketed Event format CrowdStrike's vmware-vcenter parser reads, so it uses Raw mode.",
        "source": "https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/UserLoginSessionEvent",
        "text": (
            f"<14>1 {{{{ISO_MS}}}} {MARKER}-vcenter vpxd 4321 - - Event [1001] [1-1] [{{{{ISO_MS}}}}] "
            "[vim.event.UserLoginSessionEvent] [info] [EXAMPLE.COM\\test.user] [] [1001] "
            f"[User EXAMPLE.COM\\test.user@192.0.2.40 logged in as {MARKER}]"
        ),
    },
    {
        "id": "aws-cloudtrail",
        "label": "AWS CloudTrail log",
        "accuracy": DOCUMENTED,
        "parser": "aws-cloudtrail",
        "note": "A ConsoleLogin record following AWS's published example. CloudTrail delivers files holding a Records array of these.",
        "source": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html",
        "event": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLETESTUSER",
                "arn": f"arn:aws:iam::123456789012:user/{MARKER}",
                "accountId": "123456789012",
                "userName": MARKER,
            },
            "eventTime": "{{ISO}}",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.0.2.50",
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NGSIEM-LogTester",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home",
                "MobileVersion": "No",
                "MFAUsed": "Yes",
                "MFAIdentifier": "arn:aws:iam::123456789012:mfa/test-device",
            },
            "eventID": "00000000-0000-0000-0000-000000000007",
            "readOnly": False,
            "eventType": "AwsConsoleSignIn",
            "managementEvent": True,
            "recipientAccountId": "123456789012",
            "eventCategory": "Management",
            "tlsDetails": {
                "tlsVersion": "TLSv1.3",
                "cipherSuite": "TLS_AES_128_GCM_SHA256",
                "clientProvidedHostHeader": "us-east-1.signin.aws.amazon.com",
            },
        },
    },
    {
        "id": "aws-securityhub",
        "label": "AWS SecurityHub log",
        "accuracy": DOCUMENTED,
        "parser": "aws-security-hub",
        "note": "One finding in AWS Security Finding Format, with all required attributes. The detail-type wrapper EventBridge adds isn't included.",
        "source": "https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html",
        "event": {
            "SchemaVersion": "2018-10-08",
            "Id": f"arn:aws:securityhub:us-east-1:123456789012:security-control/Config.1/finding/{MARKER}",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "GeneratorId": "security-control/Config.1",
            "AwsAccountId": "123456789012",
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": "{{ISO_MS}}",
            "UpdatedAt": "{{ISO_MS}}",
            "Severity": {"Label": "MEDIUM", "Normalized": 40, "Original": "MEDIUM"},
            "Title": f"{MARKER} AWS Config should be enabled",
            "Description": "Synthetic finding. This control checks whether AWS Config is enabled in the current account and Region.",
            "ProductName": "Security Hub",
            "CompanyName": "AWS",
            "Region": "us-east-1",
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": "AWS::::Account:123456789012",
                    "Partition": "aws",
                    "Region": "us-east-1",
                }
            ],
            "Compliance": {"Status": "FAILED"},
            "RecordState": "ACTIVE",
            "Workflow": {"Status": "NEW"},
        },
    },
    {
        "id": "abnormal-security",
        "label": "Abnormal Security email log",
        "accuracy": PARTIAL,
        "parser": "abnormal-emailsecurity",
        "note": "A threat message as returned by the threats API, following the sample in Netskope's integration docs. Abnormal's own API reference requires a customer login.",
        "source": "https://docs.netskope.com/en/abnormal-security-plugin-for-threat-exchange/",
        "event": {
            "threatId": "00000000-0000-0000-0000-000000000008",
            "abxMessageIdStr": "1000000000000000001",
            "abxPortalUrl": "https://portal.example.com/threats/00000000-0000-0000-0000-000000000008",
            "subject": f"{MARKER} synthetic event, not real mail",
            "fromAddress": "sender@example.com",
            "fromName": "Test Sender",
            "senderDomain": "example.com",
            "toAddresses": "recipient@example.com",
            "recipientAddress": "recipient@example.com",
            "receivedTime": "{{ISO}}",
            "sentTime": "{{ISO}}",
            "internetMessageId": f"<{MARKER}@example.com>",
            "remediationStatus": "Auto Remediated",
            "attackType": "Extortion",
            "attackStrategy": "Name Impersonation",
            "returnPath": "sender@example.com",
            "replyToEmails": [],
            "ccEmails": [],
            "senderIpAddress": "192.0.2.60",
            "impersonatedParty": "None / Others",
            "attackVector": "Text",
            "attachmentNames": [],
            "attachmentCount": 0,
            "urls": [],
            "urlCount": 0,
            "summaryInsights": ["Bitcoin Topics"],
            "remediationTimestamp": "{{ISO}}",
            "isRead": True,
            "attackedParty": "VIP",
            "autoRemediated": "True",
            "postRemediated": "False",
        },
    },
    {
        "id": "checkpoint-ngfw",
        "label": "Checkpoint NGFW log",
        "accuracy": APPROXIMATE,
        "parser": "checkpoint-ngfw",
        "note": "A firewall accept in Log Exporter's JSON format. Check Point documents the JSON option, but its sample pages couldn't be read, so these field names are from the commonly seen format.",
        "source": "https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/Topics-SECMG/CLI/cp_log_export.htm",
        "event": {
            "time": "{{EPOCH}}",
            "hostname": f"{MARKER}-gw",
            "severity": "5",
            "product": "VPN-1 & FireWall-1",
            "action": "Accept",
            "ifdir": "outbound",
            "ifname": "eth1",
            "logid": "0",
            "loguid": "{0x00000000,0x00000000,0x00000000,0x00000001}",
            "origin": "192.0.2.70",
            "originsicname": f"CN={MARKER}-gw,O=example.com",
            "sequencenum": "1",
            "version": "5",
            "dst": "198.51.100.70",
            "inzone": "Internal",
            "outzone": "External",
            "layer_name": "Network",
            "match_id": "1",
            "rule_action": "Accept",
            "rule_name": f"{MARKER}-rule",
            "proto": "6",
            "s_port": "49152",
            "service": "443",
            "service_id": "https",
            "src": "192.0.2.71",
        },
    },
    {
        "id": "claroty-xdome",
        "label": "Claroty xDome log",
        "accuracy": PARTIAL,
        "parser": "claroty-xdome",
        "note": "An alert event with the alert, event, device and connection fields CrowdStrike's claroty-xdome parser reads, such as alert_id, event_id, src_ip and device_name.",
        "source": "https://docs.hunters.ai/docs/claroty-xdome",
        "event": {
            "msg_category": "alert",
            "alert_id": 1000001,
            "alert_name": f"{MARKER} Device Changed Network from Guest to Corporate",
            "alert_type_name": "Network Change",
            "alert_class": "Device Changes Alerts",
            "alert_info": {"signature_severity": "High"},
            "event_id": 138,
            "event_description": f"{MARKER} device moved from the guest network to the corporate network",
            "detected_time": "{{ISO_US}}",
            "src_ip": "192.0.2.150",
            "src_port": 56855,
            "dst_ip": "198.51.100.150",
            "dst_port": 102,
            "protocol": "TCP",
            "device_name": "TEST-PLC-01",
            "device_uid": "00000000-0000-0000-0000-00000000000b",
            "device_type": "PLC",
            "device_site_name": "Test Site",
            "username": "test.user",
        },
    },
    {
        "id": "cloudflare",
        "label": "Cloudflare log",
        "accuracy": DOCUMENTED,
        "parser": "cloudflare-waf",
        "note": "One record from the Logpush firewall events dataset, which is what CrowdStrike's cloudflare-waf parser reads: it takes the time from Datetime and the action from Action.",
        "source": "https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/",
        "event": {
            "Action": "block",
            "ClientASN": 64496,
            "ClientASNDescription": "EXAMPLE-AS",
            "ClientCountry": "us",
            "ClientIP": "203.0.113.80",
            "ClientIPClass": "noRecord",
            "ClientRefererHost": "",
            "ClientRefererPath": "",
            "ClientRefererQuery": "",
            "ClientRequestHost": "www.example.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": f"/{MARKER}",
            "ClientRequestProtocol": "HTTP/2",
            "ClientRequestQuery": "?source=synthetic",
            "ClientRequestScheme": "https",
            "ClientRequestUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NGSIEM-LogTester",
            "Datetime": "{{ISO}}",
            "Description": f"{MARKER} synthetic WAF rule match",
            "EdgeColoCode": "IAD",
            "EdgeResponseStatus": 403,
            "Kind": "firewall",
            "MatchIndex": 0,
            "OriginResponseStatus": 0,
            "RayID": "0000000000000001",
            "RuleID": "00000000000000000000000000000001",
            "Source": "firewallManaged",
        },
    },
    {
        "id": "epic-ehr",
        "label": "Epic Systems EHR log",
        "accuracy": PARTIAL,
        "parser": "epic-ehr",
        "note": "An Epic login audit event as RFC 5424 syslog carrying Epic's XML, with an EventLog element and Mnemonic name/value pairs, which is what CrowdStrike's epic-ehr parser reads. It uses Raw mode and contains no patient data.",
        "source": "https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/epic",
        "text": (
            f"<14>1 {{{{ISO_US_OFFSET}}}} {MARKER}-epic EpicSIEM 12345 - [meta sequenceId=\"1\"] "
            "<EventLog><EMPid>TESTUSER01</EMPid><E1Mid>LOGIN</E1Mid><Time>{{ISO_US_OFFSET}}</Time>"
            "<Mnemonics><Mnemonic Name=\"IP\"><Value>192.0.2.90</Value></Mnemonic>"
            "<Mnemonic Name=\"CLIENTNAME\"><Value>TEST-WORKSTATION-01</Value></Mnemonic>"
            "<Mnemonic Name=\"SUCCESS\"><Value>Yes</Value></Mnemonic>"
            "<Mnemonic Name=\"ROLE\"><Value>TESTROLE</Value></Mnemonic>"
            f"<Mnemonic Name=\"LOGIN_CONTEXT\"><Value>{MARKER}</Value></Mnemonic></Mnemonics></EventLog>"
        ),
    },
    {
        "id": "fortinet-firewall",
        "label": "Fortinet firewall log",
        "accuracy": DOCUMENTED,
        "parser": "fortinet-fortigate",
        "note": "A forward traffic log as FortiGate's key=value syslog, the format CrowdStrike's fortinet-fortigate parser reads (it has no JSON input), so it uses Raw mode.",
        "source": "https://docs.fortinet.com/document/fortigate/7.2.4/fortios-log-message-reference/949981",
        "text": (
            f"<189>date={{{{DATE}}}} time={{{{TIME}}}} devname=\"{MARKER}-FGT\" devid=\"FGT00TEST0000001\" "
            "eventtime={{EPOCH}} tz=\"+0000\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" "
            "vd=\"root\" srcip=192.0.2.100 srcport=49152 srcintf=\"port2\" srcintfrole=\"lan\" dstip=198.51.100.100 "
            "dstport=443 dstintf=\"port1\" dstintfrole=\"wan\" sessionid=1000001 proto=6 action=\"accept\" policyid=1 "
            "policytype=\"policy\" service=\"HTTPS\" dstcountry=\"Reserved\" srccountry=\"Reserved\" trandisp=\"snat\" "
            "transip=203.0.113.100 transport=49152 duration=60 sentbyte=1200 rcvdbyte=3400 sentpkt=10 rcvdpkt=8 "
            "appcat=\"unscanned\""
        ),
    },
    {
        "id": "google-workspace",
        "label": "Google Workspace log",
        "accuracy": DOCUMENTED,
        "parser": "google-workspace",
        "note": "A login_success activity from the Admin Reports API. Structure and parameters are documented, but Google publishes no complete login record. The reference is unclear on id.time, so this uses an ISO timestamp.",
        "source": "https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list",
        "event": {
            "kind": "audit#activity",
            "id": {
                "time": "{{ISO_MS}}",
                "uniqueQualifier": "1000000000000000001",
                "applicationName": "login",
                "customerId": "C00000000",
            },
            "etag": f"\"{MARKER}\"",
            "actor": {
                "callerType": "USER",
                "email": "test.user@example.com",
                "profileId": "100000000000000000001",
            },
            "ownerDomain": "example.com",
            "ipAddress": "203.0.113.110",
            "events": [
                {
                    "type": "login",
                    "name": "login_success",
                    "parameters": [
                        {"name": "login_type", "value": "google_password"},
                        {"name": "login_challenge_method", "multiValue": ["password"]},
                        {"name": "is_suspicious", "boolValue": False},
                    ],
                }
            ],
        },
    },
    {
        "id": "netskope",
        "label": "Netskope log",
        "accuracy": APPROXIMATE,
        "parser": "netskope-sse",
        "note": "An application event from the REST API v2. Netskope's pages confirmed the event types and _id, but not the other fields, so those are from the commonly seen format.",
        "source": "https://docs.netskope.com/en/using-the-rest-ap-v2-datasearch-endpoint",
        "event": {
            "_id": f"{MARKER}-0001",
            "timestamp": "{{EPOCH}}",
            "type": "nspolicy",
            "access_method": "Client",
            "action": "allow",
            "activity": "Login Successful",
            "alert": "no",
            "app": "NGSIEM LogTester Sample App",
            "appcategory": "Cloud Storage",
            "category": "Cloud Storage",
            "ccl": "high",
            "count": 1,
            "device": "Windows Device",
            "domain": "www.example.com",
            "dst_country": "US",
            "dstip": "198.51.100.120",
            "from_user": "test.user@example.com",
            "hostname": "TEST-WORKSTATION-01",
            "os": "Windows 10",
            "site": "NGSIEM LogTester Sample App",
            "src_country": "US",
            "srcip": "203.0.113.120",
            "traffic_type": "CloudApp",
            "url": f"www.example.com/{MARKER}",
            "user": "test.user@example.com",
        },
    },
    {
        "id": "okta",
        "label": "Okta log",
        "accuracy": PARTIAL,
        "parser": "okta-sso",
        "note": "A user.session.start LogEvent. Top-level fields are documented, but Okta's page hides the nested fields, so those are from the commonly seen format.",
        "source": "https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog/other/listlogevents",
        "event": {
            "actor": {
                "id": "00u000000000000TEST",
                "type": "User",
                "alternateId": "test.user@example.com",
                "displayName": f"{MARKER} User",
                "detailEntry": None,
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NGSIEM-LogTester",
                    "os": "Windows 10",
                    "browser": "CHROME",
                },
                "zone": "null",
                "device": "Computer",
                "id": None,
                "ipAddress": "203.0.113.130",
                "geographicalContext": {
                    "city": "Testville",
                    "state": "Testing",
                    "country": "United States",
                    "postalCode": "00000",
                    "geolocation": {"lat": 0.0, "lon": 0.0},
                },
            },
            "authenticationContext": {
                "authenticationProvider": None,
                "credentialProvider": None,
                "credentialType": None,
                "issuer": None,
                "interface": None,
                "authenticationStep": 0,
                "externalSessionId": f"{MARKER}-session",
            },
            "displayMessage": "User login to Okta",
            "eventType": "user.session.start",
            "outcome": {"result": "SUCCESS", "reason": None},
            "published": "{{ISO_MS}}",
            "securityContext": {
                "asNumber": 64496,
                "asOrg": "Example Org",
                "isp": "Example ISP",
                "domain": "example.com",
                "isProxy": False,
            },
            "severity": "INFO",
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
            "legacyEventType": "core.user_auth.login_success",
            "transaction": {"type": "WEB", "id": f"{MARKER}-txn", "detail": {}},
            "uuid": "00000000-0000-0000-0000-000000000009",
            "version": "0",
            "request": {"ipChain": [{"ip": "203.0.113.130", "version": "V4", "source": None}]},
            "target": [],
        },
    },
    {
        "id": "paloalto-ngfw",
        "label": "Palo Alto NGFW log",
        "accuracy": DOCUMENTED,
        "parser": "paloalto-ngfw",
        "note": "A traffic log in PAN-OS's positional CSV syslog format, with columns in the order CrowdStrike's paloalto-ngfw parser reads them, so it uses Raw mode.",
        "source": "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields",
        "text": (
            "1,{{PANOS}},000000000001,TRAFFIC,end,2561,{{PANOS}},192.0.2.140,198.51.100.140,203.0.113.140,198.51.100.140,"
            f"{MARKER}-rule,example\\test.user,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,default,{{{{PANOS}}}},"
            "1000001,1,49152,443,49152,443,0x400000,tcp,allow,4600,1200,3400,18,{{PANOS}},60,business-systems,0,"
            f"1000001,0x0,United States,United States,0,10,8,tcp-fin,0,0,0,0,,{MARKER}-fw"
        ),
    },
    {
        "id": "paloalto-prisma",
        "label": "Palo Alto Prisma log",
        "accuracy": PARTIAL,
        "parser": "paloalto-prisma-access",
        "note": "A Prisma Access GlobalProtect log using the field names CrowdStrike's paloalto-prisma-access parser reads, such as LogType, EventName, SourceUser and SourceAddress. This covers Prisma Access, not Prisma Cloud.",
        "source": "https://docs.paloaltonetworks.com/cortex/cortex-data-lake/log-forwarding-schema-reference/network-logs/network-globalprotect-log/network-globalprotect-https-fields",
        "event": {
            "TimeGenerated": "{{ISO}}",
            "TimeReceived": "{{ISO}}",
            "LogType": "GLOBALPROTECT",
            "Subtype": "globalprotect",
            "VendorName": "Palo Alto Networks",
            "LogSource": "firewall",
            "DeviceName": f"{MARKER}-prisma",
            "DeviceSN": "000000000002",
            "CortexDataLakeTenantID": "000000000000000000000000000000",
            "IsPrismaUsers": True,
            "IsPrismaNetworks": False,
            "EventName": "gateway-connected",
            "EventStatus": "success",
            "Stage": "tunnel",
            "AuthMethod": "SAML",
            "ConnectionMethod": "user-logon",
            "TunnelType": "IPSec",
            "Gateway": "test-gateway",
            "Portal": "test-portal",
            "SourceUser": "test.user@example.com",
            "SourceRegion": "US",
            "SourceAddress": "203.0.113.150",
            "PrivateIPv4": "10.0.0.150",
            "EndpointDeviceName": "TEST-WORKSTATION-01",
            "EndpointOSType": "Windows",
            "EndpointOSVersion": "Microsoft Windows 10 Pro",
            "EndpointSN": "TESTSERIAL0001",
            "HostID": "00000000-0000-0000-0000-00000000000a",
            "LoginDuration": 60,
            "RepeatCount": 1,
            "SequenceNo": 1000001,
            "Description": f"{MARKER} GlobalProtect gateway connected",
        },
    },
    {
        "id": "snowflake",
        "label": "Snowflake log",
        "accuracy": DOCUMENTED,
        "parser": "snowflake-audit",
        "note": "One row from the ACCOUNT_USAGE LOGIN_HISTORY view as JSON. Column names are documented, but Snowflake has no native log export, so the exact JSON depends on your export job.",
        "source": "https://docs.snowflake.com/en/sql-reference/account-usage/login_history",
        "event": {
            "EVENT_ID": 1000000000001,
            "EVENT_TIMESTAMP": "{{ISO_MS}}",
            "EVENT_TYPE": "LOGIN",
            "USER_NAME": MARKER,
            "CLIENT_IP": "203.0.113.160",
            "REPORTED_CLIENT_TYPE": "JDBC_DRIVER",
            "REPORTED_CLIENT_VERSION": "3.14.0",
            "FIRST_AUTHENTICATION_FACTOR": "PASSWORD",
            "SECOND_AUTHENTICATION_FACTOR": None,
            "IS_SUCCESS": "YES",
            "ERROR_CODE": None,
            "ERROR_MESSAGE": None,
            "RELATED_EVENT_ID": 0,
            "CONNECTION": None,
        },
    },
]

SAMPLE_IDS = {sample["id"] for sample in SAMPLES}


def _tokens(now):
    return {
        "{{ISO_US_OFFSET}}": now.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "{{ISO_US}}": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "{{ISO_MS}}": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "{{ISO}}": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "{{DATE}}": now.strftime("%Y-%m-%d"),
        "{{TIME}}": now.strftime("%H:%M:%S"),
        "{{SYSLOG}}": now.strftime("%b %d %H:%M:%S"),
        "{{PANOS}}": now.strftime("%Y/%m/%d %H:%M:%S"),
        "{{EPOCH}}": str(int(now.timestamp())),
    }


def _fill(value, tokens):
    if isinstance(value, dict):
        return {key: _fill(item, tokens) for key, item in value.items()}
    if isinstance(value, list):
        return [_fill(item, tokens) for item in value]
    if isinstance(value, str):
        for token, replacement in tokens.items():
            value = value.replace(token, replacement)
    return value


def list_samples():
    """What the dropdown needs, without the events themselves."""
    return [
        {
            **{key: sample[key] for key in ("id", "label", "accuracy", "note", "source")},
            "parser": sample.get("parser"),
            "format": "text" if "text" in sample else "json",
        }
        for sample in SAMPLES
    ]


def render_sample(sample_id, now=None):
    """Return a sample as text with current timestamps, or None if it's unknown.

    Sources that send JSON come back as formatted JSON, and syslog sources as their bare line.
    """
    sample = next((s for s in SAMPLES if s["id"] == sample_id), None)
    if sample is None:
        return None
    tokens = _tokens(now or datetime.now(timezone.utc))
    if "text" in sample:
        return _fill(sample["text"], tokens)
    return json.dumps(_fill(sample["event"], tokens), indent=2)
