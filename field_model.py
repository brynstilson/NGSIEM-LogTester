"""An approximation of how NG-SIEM parsers expose a raw log's fields to a rule.

CrowdStrike's parsing standard keeps original vendor fields under a `Vendor.` prefix, sets tags
such as #Vendor and #event.module, and maps some fields to ECS names like event.action. The
real parsers aren't readable with this app's API scopes, so the ECS mappings below are
best-effort and every match says what it relied on.
"""
import json
import re
from dataclasses import dataclass

from cql import closest

PREFIX = "Vendor."

# Per parser: the #Vendor tag, likely #event.module values, display names, the built-in sample
# that holds this source's raw format, and approximate ECS field mappings to raw paths.
# A mapping's second item transforms the raw value: "lower", or "outcome:<success value>".
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
            "source.ip": ("callerIpAddress", None), "event.action": ("operationName", None),
            "event.outcome": ("resultType", "outcome:0"), "#event.outcome": ("resultType", "outcome:0"),
        },
    },
    "microsoft-windows": {
        "vendor": "microsoft", "modules": ["windows"], "display": ("Microsoft", "Windows"), "sample": "windows-system",
        "aliases": {"event.code": ("event_id", None), "host.name": ("computer_name", None)},
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
        # The SIEM API returns events in arrays named by type, and CrowdStrike's TAP rules filter on
        # the type: `event.action="delivered" Vendor.eventType="messagesDelivered"`.
        "envelopes": {
            "messagesDelivered": {"Vendor.eventType": "messagesDelivered", "event.action": "delivered"},
            "messagesBlocked": {"Vendor.eventType": "messagesBlocked", "event.action": "blocked"},
            "clicksPermitted": {"Vendor.eventType": "clicksPermitted"},
            "clicksBlocked": {"Vendor.eventType": "clicksBlocked"},
        },
        "aliases": {
            "email.from.address": ("sender", None), "email.subject": ("subject", None),
            "source.ip": ("senderIP", None), "email.to.address": ("recipient[0]", None),
        },
    },
    "fortinet-fortigate": {
        "vendor": "fortinet", "modules": ["fortigate", "firewall"], "display": ("Fortinet", "FortiGate"),
        "sample": "fortinet-firewall",
        "aliases": {
            "source.ip": ("srcip", None), "destination.ip": ("dstip", None), "event.action": ("action", None),
            "source.port": ("srcport", None), "destination.port": ("dstport", None),
        },
    },
    "paloalto-ngfw": {
        "vendor": "paloalto", "modules": ["firewall", "ngfw", "panos"], "display": ("Palo Alto", "NGFW"),
        "sample": "paloalto-ngfw",
        "aliases": {
            "source.ip": ("src", None), "destination.ip": ("dst", None), "event.action": ("action", None),
            "rule.name": ("rule", None), "source.port": ("sport", None), "destination.port": ("dport", None),
        },
    },
    "paloalto-prisma-access": {
        "vendor": "paloalto", "modules": ["prisma", "prismaaccess", "globalprotect"], "display": ("Palo Alto", "Prisma Access"),
        "sample": "paloalto-prisma",
        "aliases": {"user.name": ("SourceUserName", None), "source.ip": ("PublicIPv4", None)},
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
            "source.ip": ("ClientIP", None), "url.domain": ("ClientRequestHost", None),
            "http.response.status_code": ("EdgeResponseStatus", None), "event.action": ("SecurityAction", None),
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
        "aliases": {"user.name": ("userName", None), "source.ip": ("ipAddress", None)},
    },
    "epic-ehr": {"vendor": "epic", "modules": ["ehr"], "display": ("Epic", "EHR"), "sample": "epic-ehr", "aliases": {}},
    "claroty-xdome": {"vendor": "claroty", "modules": ["xdome"], "display": ("Claroty", "xDome"), "sample": "claroty-xdome", "aliases": {}},
}

PARSER_TAGS = {"#event.module", "event.module", "#event.dataset", "event.dataset", "#event.kind", "#repo",
               "#ecs.version", "#Cps.version", "#observer.type", "#type", "@timestamp", "@ingesttimestamp"}


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


def expand_envelopes(event, parser):
    """Split a vendor's batch envelope into events the way its parser would, with derived fields.

    Returns a list of (event, derived fields) pairs. Events outside an envelope come back as-is.
    """
    _, profile = profile_for_parser(parser)
    envelopes = (profile or {}).get("envelopes")
    if not envelopes or not isinstance(event, dict) or not any(key in event for key in envelopes):
        return [(event, {})]
    pairs = []
    for key, derived in envelopes.items():
        for item in event.get(key) or []:
            if isinstance(item, dict):
                pairs.append((item, derived))
    return pairs


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
    for key, value in _KV.findall(text):
        fields.setdefault(key, value.strip('"'))
    return fields


@dataclass
class Found:
    value: object = None
    basis: str = ""
    state: object = None
    note: str = ""
    raw: str = ""


class EventView:
    """The fields a rule would probably see for one event."""

    def __init__(self, event, parser=None, derived=None):
        self.parser_key, self.profile = profile_for_parser(parser)
        self.parser = parser
        self.derived = derived or {}
        if isinstance(event, str):
            self.raw = text_fields(event)
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
        return alias[0] if alias else name

    def lookup(self, name, op, expected):
        profile = self.profile
        if name in self.derived:
            return Found(self.derived[name], "set by the parser from the array the event came in (assumed)")
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
        if path not in self.raw:
            return Found(basis="missing (mapped)", raw=path)
        value = self.raw[path]
        if transform == "lower":
            value = value.lower()
        elif transform and transform.startswith("outcome:"):
            value = "success" if value == transform.split(":", 1)[1] else "failure"
        return Found(value, f"mapped from {path} (approximate)", raw=path)

    def suggest_missing(self, name, op, kind, expected, basis):
        if basis == "unmapped":
            if name in ("#Vendor", "Vendor"):
                return f'Send this through a connector whose parser tags #Vendor="{expected}".'
            return f"{name} is set by the parser, so this can't be checked from the raw log."
        envelopes = (self.profile or {}).get("envelopes") or {}
        for key, derived in envelopes.items():
            if derived.get(name) == expected:
                return f'The parser sets {name} from the batch array, so put the event inside {{"{key}": [ ... ]}}.'
        raw = self.raw_name(name)
        example = example_value(kind, expected)
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


def raw_value_for(transform, value):
    """Undo a mapping's transform, giving the raw value that produces `value`."""
    if transform == "lower":
        return str(value).upper()
    if transform and transform.startswith("outcome:"):
        return transform.split(":", 1)[1] if str(value).lower() == "success" else "1"
    return value


def example_value(kind, expected):
    """A concrete value that satisfies a condition, for suggestions and generated templates."""
    if kind == "regex":
        body = expected[0] if isinstance(expected, tuple) else str(expected)
        literal = body.strip("^$")
        if "|" in literal and "(" not in literal:
            literal = literal.split("|")[0]
        literal = re.sub(r"\\(.)", r"\1", literal)
        if re.search(r"[\[\]().*+?{}|]", literal):
            return None
        return literal
    text = str(expected)
    return text.replace("*", "test") if "*" in text else text
