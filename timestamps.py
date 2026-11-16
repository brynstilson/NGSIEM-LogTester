"""Writes the current time in the format a parser's parseTimestamp() expects (Java DateTimeFormatter
patterns, or the special epoch formats), so generated logs carry recent timestamps NG-SIEM can read.

Which timezone the time is written in:
- the format includes a zone (X, x, Z, z, V, O): the system's local time and offset, which is stated
  in the log, so NG-SIEM reads the instant exactly;
- the parser names a zone (parseTimestamp(..., timezone="Asia/Tokyo")): that zone;
- the log has a field the parser reads the zone from (timezoneField, or FortiGate's tz): the system's
  local time, with the system's zone written in that field by the caller (see system_zone_label());
- otherwise: UTC, the zone NG-SIEM assumes for a timestamp without one.
"""
import re
from datetime import datetime, timedelta, timezone

EPOCH = {"seconds": 1, "unixtime": 1, "unixtimeseconds": 1, "millis": 1000, "milliseconds": 1000,
         "unixtimemillis": 1000, "nanos": 1_000_000_000}
DEFAULT_FORMAT = "yyyy-MM-dd'T'HH:mm:ss[.SSSSSSSSS]XXXXX"
ZONE_LETTERS = set("XxZzVO")


def system_now():
    """The current time in the system's configured timezone (timezone-aware)."""
    return datetime.now().astimezone()


def offset_text(moment, colon=True):
    """The UTC offset of moment, as -07:00 (or -0700)."""
    minutes = int(moment.utcoffset().total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    minutes = abs(minutes)
    return f"{sign}{minutes // 60:02d}{':' if colon else ''}{minutes % 60:02d}"


def system_zone_label(style="utc"):
    """The system timezone, written for a log's zone field: UTC-07:00, -0700 or -07:00."""
    now = system_now()
    if style == "offset":
        return offset_text(now, colon=False)
    if style == "colon":
        return offset_text(now)
    return "UTC" if not now.utcoffset() else f"UTC{offset_text(now)}"


def zone_for(name):
    """A tzinfo for a parser's timezone parameter: an IANA name, UTC, GMT or UTC+hh:mm."""
    text = str(name or "").strip()
    if not text or text.upper() in ("UTC", "GMT", "Z", "ETC/GMT", "ETC/UTC"):
        return timezone.utc
    m = re.fullmatch(r"(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?", text, re.I)
    if m:
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(delta if m.group(1) == "+" else -delta)
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(text)
    except Exception:
        return timezone.utc


def has_zone(fmt):
    stripped = re.sub(r"'[^']*'", "", fmt or "")
    return any(c in ZONE_LETTERS for c in stripped)


def moment_for(fmt, now=None, tz=None, zone_field=False):
    """The time to write for fmt: see the module docstring for the timezone used."""
    now = now or system_now()
    if now.tzinfo is None:
        now = now.astimezone()
    if has_zone(fmt) or zone_field:
        return now.astimezone()  # system zone, stated in the log
    if tz:
        return now.astimezone(zone_for(tz))
    return now.astimezone(timezone.utc)


def format_timestamp(fmt, now=None, tz=None, zone_field=False):
    """The current time written in fmt, checked against the parser's own reading of fmt.

    tz is the parser's timezone parameter, if any; zone_field says the log carries the zone in a
    separate field. Optional [sections] are left out unless the result only parses with them.
    """
    from parser_sim import check_timestamp
    fmt = fmt or DEFAULT_FORMAT
    moment = moment_for(fmt, now, tz, zone_field)
    special = EPOCH.get(fmt.lower())
    if special:
        return str(int(moment.timestamp() * special))
    for optional in (False, True):
        text = _render(fmt, moment, optional)
        if check_timestamp(text, fmt, "UTC")[0]:
            return text
    return _render(fmt, moment, True)


def _render(fmt, now, optional):
    out, i, depth = [], 0, 0
    while i < len(fmt):
        c = fmt[i]
        if c == "'":
            j = fmt.find("'", i + 1)
            j = len(fmt) if j < 0 else j
            if optional or not depth:
                out.append(fmt[i + 1:j] or "'")
            i = j + 1
            continue
        if c in "[]":
            depth += 1 if c == "[" else -1
            i += 1
            continue
        if depth and not optional:
            i += 1
            continue
        if not c.isalpha():
            out.append(c)
            i += 1
            continue
        j = i
        while j < len(fmt) and fmt[j] == c:
            j += 1
        n = j - i
        i = j
        out.append(_field(c, n, now))
    return "".join(out)


def _field(c, n, now):
    if c in "yu":
        return now.strftime("%y") if n == 2 else now.strftime("%Y")
    if c in "ML":
        if n >= 4:
            return now.strftime("%B")
        if n == 3:
            return now.strftime("%b")
        return f"{now.month:0{n}d}"
    if c == "d":
        return f"{now.day:0{n}d}"
    if c == "D":
        return f"{now.timetuple().tm_yday:0{n}d}"
    if c in "Hk":
        return f"{now.hour:0{n}d}"
    if c in "hK":
        return f"{(now.hour % 12) or 12:0{n}d}"
    if c == "m":
        return f"{now.minute:0{n}d}"
    if c == "s":
        return f"{now.second:0{n}d}"
    if c in "Sn":
        digits = f"{now.microsecond:06d}000"
        return digits[:n] if c == "S" else digits[:9]
    if c == "a":
        return now.strftime("%p")
    if c in "Ee":
        return now.strftime("%A") if n >= 4 else now.strftime("%a")
    utc = not now.utcoffset()
    if c == "X":
        if utc:
            return "Z"
        return offset_text(now, colon=False)[:3] if n == 1 else offset_text(now, colon=n >= 3 and n != 4)
    if c == "x":
        return offset_text(now, colon=False)[:3] if n == 1 else offset_text(now, colon=n >= 3 and n != 4)
    if c == "Z":
        return offset_text(now, colon=False) if n <= 3 else ("GMT" + offset_text(now)) if n == 4 else offset_text(now)
    if c in "zVO":
        return "UTC" if utc else f"GMT{offset_text(now)}"
    return ""
