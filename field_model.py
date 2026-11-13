"""An approximation of how NG-SIEM parsers expose a raw log's fields to a rule.

CrowdStrike's parsing standard keeps original vendor fields under a `Vendor.` prefix, sets tags
such as #Vendor and #event.module, and maps some fields to ECS names like event.action. The
mappings and input readers below follow the logic of the CrowdStrike parsers in the tenant, as
read on 9 November 2026. Every match still says what it relied on, because parsers change.
"""
import csv
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from cql import closest

PREFIX = "Vendor."

# Per parser: the #Vendor tag, likely #event.module values, display names, the built-in sample
# that holds this source's raw format, how to read a text log ("reader"), and ECS field mappings
# to raw paths. A mapping's path can be a list, meaning the first one present, as with coalesce().
# Its second item transforms the raw value: "lower", "slug" (lowercase, spaces to dashes),
# "outcome:<success value>", "only:<value>" (set only for that value), or "map:<raw>=<value>,...".
PROFILES = {
    "okta-sso": {
        "vendor": "okta", "modules": ["sso", "okta"], "display": ("Okta", "Okta SSO"), "sample": "okta",
        "aliases": {
            "event.action": ("eventType", None), "user.name": ("actor.alternateId", None),
            "user.email": ("actor.alternateId", None), "source.ip": ("client.ipAddress", None),
            "client.ip": ("client.ipAddress", None), "message": ("displayMessage", None),
            "event.outcome": ("outcome.result", "lower"), "#event.outcome": ("outcome.result", "lower"),
            "user.target.name": ("target[0].alternateId", None),
        },
    },
    "microsoft-entra-id": {
        "vendor": "microsoft", "modules": ["azure", "entraid", "entra"], "display": ("Microsoft", "Entra ID"),
        "sample": "microsoft-entra",
        "aliases": {
            "user.name": ("properties.userPrincipalName", None), "user.email": ("properties.userPrincipalName", None),
            "source.ip": ("callerIpAddress", None), "event.action": ("operationName", "slug"),
            "event.outcome": ("properties.status.errorCode", "outcome:0"),
            "#event.outcome": ("properties.status.errorCode", "outcome:0"),
        },
    },
    "microsoft-windows": {
        "vendor": "microsoft", "modules": ["windows"], "display": ("Microsoft", "Windows"), "sample": "windows-system",
        "reader": "windows-xml",
        "aliases": {
            "event.code": ("Event.System.EventID", None), "host.name": ("Event.System.Computer", None),
            "event.action": (["Event.EventData.OperationType", "Event.EventData.Action"], None),
        },
    },
    "aws-cloudtrail": {
        "vendor": "aws", "modules": ["cloudtrail"], "display": ("AWS", "CloudTrail"), "sample": "aws-cloudtrail",
        "aliases": {
            "event.action": ("eventName", None), "event.provider": ("eventSource", None),
            "source.ip": ("sourceIPAddress", None), "cloud.account.id": ("recipientAccountId", None),
            "cloud.region": ("awsRegion", None), "user.name": ("userIdentity.userName", None),
            "user_agent.original": ("userAgent", None),
        },
    },
    "aws-security-hub": {
        "vendor": "aws", "modules": ["securityhub"], "display": ("AWS", "Security Hub"), "sample": "aws-securityhub",
        "aliases": {"cloud.account.id": ("AwsAccountId", None), "rule.name": ("Title", None)},
    },
    "proofpoint-tap": {
        "vendor": "proofpoint", "modules": ["tap"], "display": ("Proofpoint", "TAP"), "sample": "proofpoint-tap",
        "categories": ["email"],
        # The parser reads one message per event and names its category from eventType.
        "aliases": {
            "event.action": ("eventType", "map:messagesDelivered=messages-delivered,messagesBlocked=messages-blocked,"
                                          "clicksPermitted=clicks-permitted,clicksBlocked=clicks-blocked"),
            "#event.dataset": ("eventType", "map:messagesDelivered=tap.messagesdelivered,messagesBlocked=tap.messagesblocked,"
                                            "clicksPermitted=tap.clickspermitted,clicksBlocked=tap.clicksblocked"),
            "email.from.address": ("sender", None), "email.subject": ("subject", None),
            "source.ip": ("senderIP", None), "email.to.address": ("recipient[0]", None),
        },
    },
    "fortinet-fortigate": {
        "vendor": "fortinet", "modules": ["fortigate", "firewall"], "display": ("Fortinet", "FortiGate"),
        "sample": "fortinet-firewall",
        "aliases": {
            "source.ip": ("srcip", None), "destination.ip": ("dstip", None), "event.action": ("utmaction", "only:block"),
            "source.port": ("srcport", None), "destination.port": ("dstport", None),
        },
    },
    "paloalto-ngfw": {
        "vendor": "paloalto", "modules": ["firewall", "ngfw", "panos"], "display": ("Palo Alto", "NGFW"),
        "sample": "paloalto-ngfw", "reader": "paloalto-csv",
        "aliases": {
            "source.ip": ("SourceAddress", None), "destination.ip": ("DestinationAddress", None),
            "event.action": ("Action", None), "rule.name": ("RuleName", None), "user.name": ("SourceUser", None),
            "source.port": ("SourcePort", None), "destination.port": ("DestinationPort", None),
        },
    },
    "paloalto-prisma-access": {
        "vendor": "paloalto", "modules": ["prisma", "prismaaccess", "globalprotect"], "display": ("Palo Alto", "Prisma Access"),
        "sample": "paloalto-prisma",
        "aliases": {
            "user.name": ("SourceUser", None), "source.ip": (["SourceAddress", "SourceIP"], None),
            "event.action": (["Action", "EventName", "PolicyAction", "Subtype"], None),
        },
    },
    "google-workspace": {
        "vendor": "google", "modules": ["workspace", "google_workspace"], "display": ("Google", "Workspace"),
        "sample": "google-workspace",
        "aliases": {
            "event.action": ("events[0].name", None), "user.email": ("actor.email", None),
            "user.name": ("actor.email", None), "source.ip": ("ipAddress", None),
        },
    },
    "cloudflare-waf": {
        "vendor": "cloudflare", "modules": ["waf", "cloudflare"], "display": ("Cloudflare", "WAF"), "sample": "cloudflare",
        "aliases": {
            "source.ip": ("ClientIP", None), "client.ip": ("ClientIP", None), "url.domain": ("ClientRequestHost", None),
            "http.response.status_code": ("EdgeResponseStatus", None), "event.action": ("Action", None),
            "http.request.id": ("RayID", None),
        },
    },
    "checkpoint-ngfw": {
        "vendor": "checkpoint", "modules": ["firewall", "ngfw"], "display": ("Check Point", "NGFW"), "sample": "checkpoint-ngfw",
        "aliases": {"source.ip": ("src", None), "destination.ip": ("dst", None), "event.action": ("action", None)},
    },
    "cisco-firepower": {
        "vendor": "cisco", "modules": ["firepower", "ftd"], "display": ("Cisco", "Firepower"), "sample": "cisco-firepower",
        "aliases": {"source.ip": ("SrcIP", None), "destination.ip": ("DstIP", None), "event.action": ("AccessControlRuleAction", None)},
    },
    "vmware-vcenter": {
        "vendor": "vmware", "modules": ["vcenter", "vsphere"], "display": ("VMware", "vCenter"), "sample": "vmware-vsphere",
        "reader": "vcenter",
        "aliases": {},
    },
    "epic-ehr": {
        "vendor": "epic", "modules": ["ehr"], "display": ("Epic", "EHR"), "sample": "epic-ehr", "reader": "epic",
        "aliases": {"event.action": ("EventLog.E1Mid", None), "host.ip": ("Mnemonics.IP", None)},
    },
    "abnormal-emailsecurity": {
        "vendor": "abnormal", "modules": ["email-security"], "display": ("Abnormal", "Email Security"),
        "sample": "abnormal-security",
        "aliases": {"event.action": ("remediationStatus", None), "source.ip": ("senderIpAddress", None)},
    },
    "netskope-sse": {
        "vendor": "netskope", "modules": ["sse"], "display": ("Netskope", "SSE"), "sample": "netskope",
        "aliases": {
            "event.action": (["activity", "action"], "lower"), "user.name": (["user", "ur_normalized"], None),
            "source.ip": ("srcip", None),
        },
    },
    "snowflake-audit": {
        "vendor": "snowflake", "modules": ["audit"], "display": ("Snowflake", "Audit"), "sample": "snowflake",
        "aliases": {"event.action": ("EVENT_TYPE", None), "user.name": ("USER_NAME", None), "source.ip": ("CLIENT_IP", None)},
    },
    "claroty-xdome": {
        "vendor": "claroty", "modules": ["xdome"], "display": ("Claroty", "xDome"), "sample": "claroty-xdome",
        "aliases": {
            "event.id": ("event_id", None), "source.ip": ("src_ip", None), "destination.ip": ("dst_ip", None),
            "host.hostname": ("device_name", None), "user.name": ("username", None),
        },
    },
}

PARSER_TAGS = {"#event.module", "event.module", "#event.dataset", "event.dataset", "#event.kind", "#repo",
               "#ecs.version", "#Cps.version", "#observer.type", "#type", "@timestamp", "@ingesttimestamp"}

# The first columns of a PAN-OS TRAFFIC log after its common header, in the order the
# paloalto-ngfw parser reads them.
PANOS_TRAFFIC_COLUMNS = [
    "SourceAddress", "DestinationAddress", "NATSource", "NATDestination", "RuleName", "SourceUser",
    "DestinationUser", "Application", "VirtualSystem", "SourceZone", "DestinationZone", "InboundInterface",
    "OutboundInterface", "LogAction", "FUTUREUSE3", "SessionID", "RepeatCount", "SourcePort", "DestinationPort",
    "NATSourcePort", "NATDestinationPort", "Flags", "Protocol", "Action", "Bytes", "BytesSent", "BytesReceived",
    "Packets", "StartTime", "ElapsedTime", "Category", "FUTUREUSE4", "SequenceNumber", "ActionFlags",
    "SourceCountry", "DestinationCountry", "FUTUREUSE5", "PacketsSent", "PacketsReceived", "SessionEndReason",
    "DeviceGroupHierarchyLevel1", "DeviceGroupHierarchyLevel2", "DeviceGroupHierarchyLevel3",
    "DeviceGroupHierarchyLevel4", "VirtualSystemName", "DeviceName",
]
PANOS_HEADER = ["FUTUREUSE1", "ReceiveTime", "Serial", "Type", "SubType", "FUTUREUSE2", "TimeGenerated"]
SYSLOG_5424 = re.compile(r"^<(?P<pri>\d+)>(?P<version>\d+) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
                         r"(?P<msgid>\S+) (?P<sd>-|(?:\[[^\]]*\])+)\s*(?P<message>.*)$", re.S)
VCENTER_EVENT = re.compile(r"Event \[(?P<eventId>.*?)\] \[(?P<partInfo>.*?)\] \[(?P<createdTime>.*?)\] "
                           r"\[(?P<eventType>.*?)\] \[(?P<severity>.*?)\] \[(?P<user>.*?)\] \[(?P<target>.*?)\] "
                           r"\[(?P<chainId>.*?)\] \[(?P<desc>.*?)\]")


def profile_for_parser(parser):
    if not parser:
        return None, None
    if parser in PROFILES:
        return parser, PROFILES[parser]
    match = next((key for key in PROFILES if parser.startswith(key) or key.startswith(parser)), None)
    return (match, PROFILES[match]) if match else (None, None)


def profile_for_rule(vendor, module=None, sourcetype=None):
    """Find the parser a rule is written for, from its #Vendor, #event.module and @sourcetype."""
    if sourcetype:
        key, profile = profile_for_parser(sourcetype)
        if profile:
            return key, profile
    candidates = [(k, p) for k, p in PROFILES.items() if vendor and p["vendor"] == vendor.lower()]
    if module:
        moduled = [(k, p) for k, p in candidates if module.lower() in p["modules"]]
        candidates = moduled or candidates
    return candidates[0] if len(candidates) >= 1 else (None, None)


def flatten(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flatten(item, f"{path}.{key}" if path else str(key).replace(" ", "_"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from flatten(item, f"{path}[{index}]")
    else:
        text = "" if value is None else (json.dumps(value) if isinstance(value, bool) else str(value))
        yield path, text


_KV = re.compile(r'(?:(?<=\s)|^|(?<=,))\s*([A-Za-z_][\w.]*)\s*(?:=|:\s)\s*("(?:[^"\\]|\\.)*"|[^,\s]+(?:\s(?![A-Za-z_][\w.]*\s*(?:=|:\s))[^,\s=]+)*)')


def text_fields(text):
    """Key/value pairs from a syslog-style line, as kvParse would roughly see them."""
    fields = {}
    for key, value in _KV.findall(re.sub(r"^<\d+>\s*", "", text)):
        fields.setdefault(key, value.strip('"'))
    return fields


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _xml_fields(element, path, fields):
    """Flatten XML the way parseXml does: attributes become _name, Data Name="x" becomes x."""
    name = element.get("Name") if _local(element.tag) == "Data" and element.get("Name") else _local(element.tag)
    here = f"{path}.{name}" if path else name
    for attribute, value in element.attrib.items():
        if not (_local(element.tag) == "Data" and attribute == "Name"):
            fields[f"{here}._{_local(attribute)}"] = value
    children = list(element)
    if element.text and element.text.strip() and not children:
        fields[here] = element.text.strip()
    for child in children:
        _xml_fields(child, here, fields)
    return fields


def read_windows_xml(text):
    return _xml_fields(ET.fromstring(text.strip()), "", {})


def read_epic(text):
    header = SYSLOG_5424.match(text.strip())
    message = header.group("message") if header else text
    fields = {}
    for name, value in re.findall(r'<Mnemonic Name="([^"]+)">\s*<Value[^>]*>(.*?)</Value>', message, re.S):
        fields[f"Mnemonics.{name}"] = value.strip()
    rest = re.sub(r"<Mnemonics>.*?</Mnemonics>", "", message, flags=re.S)
    xml_start = rest.find("<")
    if xml_start >= 0:
        _xml_fields(ET.fromstring(rest[xml_start:]), "", fields)
    return fields


def read_vcenter(text):
    header = SYSLOG_5424.match(text.strip())
    message = header.group("message") if header else text
    fields = {"message": message}
    if header:
        fields["appname"] = header.group("app")
    event = VCENTER_EVENT.search(message)
    if event:
        fields.update({k: v for k, v in event.groupdict().items()})
    return fields


def read_paloalto_csv(text):
    line = text.strip()
    start = re.search(r"(?:^|\s)(\d*,\S)", line)
    row = next(csv.reader([line[start.start(1):] if start else line]))
    fields = dict(zip(PANOS_HEADER, row))
    if fields.get("Type") == "TRAFFIC":
        fields.update(zip(PANOS_TRAFFIC_COLUMNS, row[len(PANOS_HEADER):]))
    return {k: v for k, v in fields.items() if v != ""}


READERS = {
    "windows-xml": read_windows_xml, "epic": read_epic, "vcenter": read_vcenter, "paloalto-csv": read_paloalto_csv,
}


def read_text(text, profile):
    """A text log's fields as its parser would see them, without the Vendor. prefix."""
    reader = READERS.get((profile or {}).get("reader"))
    if reader:
        try:
            fields = reader(text)
            if fields:
                return fields
        except (ET.ParseError, ValueError, StopIteration, AttributeError):
            pass  # Not in the parser's format, so fall back to key=value pairs.
    return text_fields(text)


@dataclass
class Found:
    value: object = None
    basis: str = ""
    state: object = None
    note: str = ""
    raw: str = ""


def _first_path(path, raw):
    paths = path if isinstance(path, list) else [path]
    return next((p for p in paths if p in raw), paths[0])


class EventView:
    """The fields a rule would probably see for one event."""

    def __init__(self, event, parser=None):
        self.parser_key, self.profile = profile_for_parser(parser)
        self.parser = parser
        if isinstance(event, str):
            self.raw = read_text(event, self.profile)
            self.rawstring = event
            self.is_text = True
        else:
            self.raw = dict(flatten(event))
            self.rawstring = json.dumps(event)
            self.is_text = False

    def raw_name(self, name):
        if name.startswith(PREFIX):
            return name[len(PREFIX):]
        alias = (self.profile or {}).get("aliases", {}).get(name)
        return _first_path(alias[0], self.raw) if alias else name

    def lookup(self, name, op, expected):
        profile = self.profile
        if name == "#event.kind" and profile:
            return Found(profile.get("kind", "event"), f"set by the {self.parser} parser (assumed)")
        if name == "#repo" and profile and op == "!=" and str(expected).startswith(("xdr", "base_sensor", "detections")):
            return Found("third-party", "assumed: third-party data isn't in Falcon's own repositories", state=True)
        if name in ("#Vendor", "Vendor"):
            if profile:
                return Found(profile["vendor"], f"set by the {self.parser} parser (assumed)")
            if self.parser:
                # Parser names start with the vendor, as in vmware-esxi or okta-sso.
                return Found(self.parser.split("-")[0], f"assumed from the {self.parser} parser's name")
            return Found(basis="unmapped", note="Set by the parser. Select a connector so its parser is known.")
        if name == "@sourcetype":
            return Found(self.parser, "parser name (assumed)") if self.parser else Found(basis="unmapped")
        if name == "@rawstring":
            return Found(self.rawstring, "raw text")
        if name in ("#event.module", "event.module"):
            if profile and expected is not None and str(expected).lower() in profile["modules"]:
                return Found(str(expected), f"set by the {self.parser} parser (assumed)")
            return Found(basis="unmapped", note="Set by the parser, so it can't be checked from the raw log.")
        if name in PARSER_TAGS or name.startswith("#"):
            alias = (profile or {}).get("aliases", {}).get(name)
            if alias:
                return self._alias(name, alias)
            return Found(basis="unmapped", note="Set by the parser, so it can't be checked from the raw log.")
        if name.startswith(PREFIX):
            path = name[len(PREFIX):]
            if path in self.raw:
                return Found(self.raw[path], "raw field", raw=path)
            return Found(basis="missing", raw=path)
        alias = (profile or {}).get("aliases", {}).get(name)
        if alias:
            return self._alias(name, alias)
        if name in self.raw:
            return Found(self.raw[name], "raw field", raw=name)
        if "." in name:
            return Found(basis="unmapped", note="This field is created by the parser and no mapping for it is known.")
        return Found(basis="missing", raw=name)

    def array_values(self, array):
        """Values of an array field such as event.category[], with what they're based on."""
        name = array[:-2] if array.endswith("[]") else array
        if name == "event.category" and (self.profile or {}).get("categories"):
            return self.profile["categories"], f"set by the {self.parser} parser (assumed)"
        if name.startswith(PREFIX):
            path = name[len(PREFIX):]
            values = [v for k, v in self.raw.items() if re.fullmatch(re.escape(path) + r"\[\d+\]", k)]
            return values, "raw field"
        return None, "set by the parser"

    def _alias(self, name, alias):
        path, transform = alias
        path = _first_path(path, self.raw)
        if path not in self.raw:
            return Found(basis="missing (mapped)", raw=path)
        value = apply_transform(transform, self.raw[path])
        if value is None:
            return Found(basis="missing (mapped)", raw=path)
        return Found(value, f"mapped from {path} (approximate)", raw=path)

    def suggest_missing(self, name, op, kind, expected, basis):
        if basis == "unmapped":
            if name in ("#Vendor", "Vendor"):
                return f'Send this through a connector whose parser tags #Vendor="{expected}".'
            return f"{name} is set by the parser, so this can't be checked from the raw log."
        raw = self.raw_name(name)
        example = example_value(kind, expected)
        transform = ((self.profile or {}).get("aliases", {}).get(name) or (None, None))[1]
        if transform and example is not None:
            example = raw_value_for(transform, example)
        near = closest(raw, list(self.raw))
        if near:
            return f'There is no field "{raw}". Did you mean "{near}"? It needs the value "{example}".'
        if self.is_text:
            return f'Add {raw}={example} to the line.'
        return f'Add the field "{raw}" with the value "{example}".'

    def suggest_value(self, name, op, kind, expected, found):
        if name in ("#Vendor", "Vendor", "@sourcetype"):
            return (f'This depends on the parser, not the log: send it through a connector whose parser '
                    f'gives {name} = "{expected}".') if op != "!=" else f'Use a connector whose parser doesn\'t give {name} = "{expected}".'
        raw = found.raw or self.raw_name(name)
        if op == "!=":
            return f'Change "{raw}" so it isn\'t "{expected}".'
        example = example_value(kind, expected)
        transform = ((self.profile or {}).get("aliases", {}).get(name) or (None, None))[1]
        if transform and example is not None:
            raw_example = raw_value_for(transform, example)
            return f'Change "{raw}" to "{raw_example}" so the parser gives {name} = "{example}".'
        if kind != "regex" and str(found.value).lower() == str(example).lower():
            return f'Values are case-sensitive: change "{raw}" from "{found.value}" to "{example}".'
        if op in ("<", ">", "<=", ">="):
            return f'Change "{raw}" from "{found.value}" so it is {op} {expected}.'
        return f'Change "{raw}" from "{found.value}" to "{example}".'


def _mapping(transform):
    return dict(pair.split("=", 1) for pair in transform[len("map:"):].split(","))


def apply_transform(transform, value):
    """What a parser makes of a raw value. None means the parser sets nothing."""
    if not transform:
        return value
    if transform == "lower":
        return value.lower()
    if transform == "slug":
        return re.sub(r"\s+", "-", value.lower())
    if transform.startswith("outcome:"):
        return "success" if value == transform.split(":", 1)[1] else "failure"
    if transform.startswith("only:"):
        return value if value == transform.split(":", 1)[1] else None
    if transform.startswith("map:"):
        return _mapping(transform).get(value)
    return value


def raw_value_for(transform, value):
    """Undo a mapping's transform, giving the raw value that produces `value`."""
    if transform == "lower":
        return str(value).upper()
    if transform == "slug":
        return str(value).replace("-", " ").capitalize()
    if transform and transform.startswith("outcome:"):
        return transform.split(":", 1)[1] if str(value).lower() == "success" else "1"
    if transform and transform.startswith("map:"):
        return next((raw for raw, mapped in _mapping(transform).items() if mapped == value), value)
    return value


def example_value(kind, expected):
    """A concrete value that satisfies a condition, for suggestions and generated templates."""
    if kind == "regex":
        body = expected[0] if isinstance(expected, tuple) else str(expected)
        literal = body.strip("^$")
        if "|" in literal and "(" not in literal:
            literal = literal.split("|")[0]
        # \d, \s, \w and \b are classes, not escaped characters, so those need the regex sampler.
        complex_escape = re.search(r"\\[A-Za-z0-9]", literal)
        literal = re.sub(r"\\([^A-Za-z0-9])", r"\1", literal)
        if complex_escape or re.search(r"[\[\]().*+?{}|]", literal):
            # Too complex to read off as text, so build a string the pattern accepts.
            from regex_sample import sample
            flags = expected[1] if isinstance(expected, tuple) and len(expected) > 1 else ""
            return sample(body, flags)
        return literal
    text = str(expected)
    return text.replace("*", "test") if "*" in text else text


class ParsedView:
    """The fields a rule would see, read from a simulation of the connector's real parser.

    Same interface as EventView. Fields the simulation couldn't work out (lookup files, functions
    it doesn't reproduce) are reported as unknown, so the rule check says "can't fully check"
    instead of guessing. `lineage` tells suggestions which raw field the parser reads.
    """

    def __init__(self, raw_event, result, parser, lineage=None):
        self.parser = parser
        self.parser_key, self.profile = profile_for_parser(parser)
        self.result = result
        self.fields = result.fields
        self.tags = set(result.tag_fields)
        self.lineage = lineage
        if isinstance(raw_event, str):
            self.raw = read_text(raw_event, self.profile)
            self.rawstring = raw_event
            self.is_text = True
        else:
            self.raw = dict(flatten(raw_event))
            self.rawstring = json.dumps(raw_event)
            self.is_text = False

    def _name(self, name):
        return name[1:] if name.startswith("#") else name

    def raw_name(self, name):
        field = self._name(name)
        if self.lineage:
            source = self.lineage.raw_source(field)
            if source:
                return source
        return field[len(PREFIX):] if field.startswith(PREFIX) else field

    def lookup(self, name, op, expected):
        if name == "@rawstring":
            return Found(self.rawstring, "raw text")
        if name == "#repo":
            if op == "!=" and str(expected).startswith(("xdr", "base_sensor", "detections")):
                return Found("third-party", "assumed: third-party data isn't in Falcon's own repositories", state=True)
            return Found(basis="unknown: the repository is set at ingest, not by the parser")
        if self.result.dropped:
            return Found(basis="missing: the parser drops this log, so no event reaches NG-SIEM")
        field = self._name(name)
        if field == "@sourcetype" or field == "#type":
            return Found(self.parser, "parser name")
        if field in self.result.unknown:
            return Found(basis="unknown: the parser sets this with a lookup file or function the simulation can't run",
                         note=f"{name} can't be predicted from the raw log.")
        if field in self.fields:
            basis = "set by the parser (simulated)" if name.startswith("#") else "parsed (simulated)"
            return Found(self.fields[field], basis, raw=field)
        if self.result.error:
            return Found(basis="unknown: the parser couldn't be simulated")
        return Found(basis="missing after parsing", raw=field)

    def array_values(self, array):
        name = self._name(array[:-2] if array.endswith("[]") else array)
        values, i = [], 0
        while f"{name}[{i}]" in self.fields or f"{name}[{i}]" in self.result.unknown:
            if f"{name}[{i}]" in self.result.unknown:
                return None, "unknown: set by a lookup file or function the simulation can't run"
            values.append(self.fields[f"{name}[{i}]"])
            i += 1
        return values, "set by the parser (simulated)"

    def suggest_missing(self, name, op, kind, expected, basis):
        if str(basis).startswith("unknown"):
            return f"{name} can't be predicted from the raw log: the parser sets it with something the simulation can't run."
        example = example_value(kind, expected)
        hint = self.lineage.hint(self._name(name), example) if self.lineage else None
        if hint:
            return hint
        raw = self.raw_name(name)
        if self.is_text:
            return f"Add {raw}={example} to the line."
        return f'Add the field "{raw}" with the value "{example}".'

    def suggest_value(self, name, op, kind, expected, found):
        example = example_value(kind, expected)
        if op == "!=":
            return f'Change the log so the parser doesn\'t give {name} = "{expected}".'
        hint = self.lineage.hint(self._name(name), example) if self.lineage else None
        if hint:
            return hint
        if kind != "regex" and str(found.value).lower() == str(example).lower():
            return f'Values are case-sensitive: the parser gives "{found.value}", the rule wants "{example}".'
        return f'The parser gives {name} = "{found.value}"; the rule wants "{example}".'
