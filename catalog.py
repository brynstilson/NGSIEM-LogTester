"""Parser field catalog and sample completeness audit.

catalog_parser() lists, for one NG-SIEM parser, every field it can produce and how: the raw field it is
copied from, a constant it is set to, or a value it is extracted with, together with the case-branch
and match-arm conditions (CQL conditional evaluation) that must hold. It also lists each timestamp the
parser reads, with its parseTimestamp() format, and what a log must satisfy for the parser to keep it.

audit_event() simulates the parser on one raw log and reports what the log is missing: fields the
parser would have produced on the branch the log takes, but couldn't because the raw field they come
from isn't in the log, plus timestamps that wouldn't parse and logs the parser would drop.

Run `python catalog.py --out reports` to write the catalog for every parser in the tenant.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from lineage import describe_condition, lineage_for
from parser_sim import UNKNOWN, Simulator, _Event, simulate, simulator_for, SimError

INPUT_KINDS = ("copy", "format", "derived", "append-copy")


def _conditions(conds):
    return [d for d in (describe_condition(c) for c in conds) if d]


def catalog_parser(doc):
    """A JSON-ready description of one parser's fields, inputs, timestamps and requirements."""
    lineage = lineage_for(doc["script"])
    if lineage is None:
        return {"name": doc["name"], "version": doc.get("version"), "error": "The parser couldn't be read."}
    fields = {}
    raw_inputs = set()
    for target, producers in sorted(lineage.producers.items()):
        ways = []
        for p in producers:
            way = {"kind": p.kind}
            if p.source:
                way["from"] = p.source
                raw = lineage.raw_source(p.source)
                if raw:
                    way["raw_field"] = raw
                    raw_inputs.add(raw)
            if p.transform:
                way["transform"] = p.transform
            if p.kind in ("const", "append"):
                way["value"] = p.value
            elif p.kind == "format":
                way["format"] = f"{p.value[0]}%s{p.value[1]}"
            elif p.kind == "extract":
                way["pattern"] = p.value[0][:200]
            when = _conditions(p.conditions)
            if when:
                way["when"] = when
            ways.append(way)
        fields[target] = ways
    for target in fields:
        raw = lineage.raw_source(target)
        if raw:
            raw_inputs.add(raw)
    decoder = lineage.main_decoder()
    return {
        "name": doc["name"],
        "version": doc.get("version"),
        "vendor": doc.get("vendor"),
        "product": doc.get("product"),
        "format": lineage.format or "text (regex extraction)",
        "decoder_prefix": decoder.prefix if decoder else None,
        "tag_fields": doc.get("tag_fields") or [],
        "keeps_log_only_if": [[_conditions(option) for option in gate] for gate in lineage.gates],
        "timestamps": [{"field": t["field"], "format": t["format"], "timezone": t["timezone"],
                        "when": _conditions(t["conditions"])} for t in lineage.timestamps],
        "event_types": {"event.dataset": _values(lineage, "event.dataset"), "event.action": _values(lineage, "event.action")},
        "raw_inputs": sorted(raw_inputs),
        "fields": fields,
    }


def _values(lineage, field):
    out = []
    for p in lineage.producers.get(field, []):
        if p.kind == "const":
            out.append({"value": p.value, "when": _conditions(p.conditions)})
        elif p.kind == "format":
            out.append({"value": f"{p.value[0]}<{p.source}>{p.value[1]}", "when": _conditions(p.conditions)})
    return out


# ---------------------------------------------------------------- auditing a sample

def _holds(sim, ev, cond):
    """Whether a lineage condition holds on the simulated event: True, False or None (unknown)."""
    kind = cond[0]
    if kind == "true":
        return True
    if kind == "arm":
        _, field, pattern = cond
        if pattern[0] == "any":
            return True
        out = sim.match(("match", field, [(pattern, [])]), ev.copy())
        return out is not None
    try:
        result = sim.filter(cond, ev.copy())
    except Exception:  # A condition the simulator can't evaluate on its own.
        return None
    return None if result is UNKNOWN else bool(result)


def audit_event(doc, rawstring, raw_fields=None):
    """What a raw log lacks for this parser. raw_fields: the log's own field paths (for JSON logs)."""
    result = simulate(doc["script"], rawstring, doc.get("tag_fields") or [])
    report = {"parser": doc["name"], "dropped": result.dropped, "error": result.error,
              "timestamps": [t for t in result.timestamps if t.get("ok") is False],
              "missing_inputs": [], "produced": len(result.fields)}
    if result.dropped or result.error:
        return report
    lineage = lineage_for(doc["script"])
    try:
        sim = simulator_for(doc["script"])
    except SimError:
        return report
    final = _Event(dict(result.fields), set(result.unknown))
    seen = set()
    for target, producers in lineage.producers.items():
        if target in result.fields or target in result.unknown or target.startswith(("@", "_")) or target in seen:
            continue
        for p in producers:
            if p.kind not in INPUT_KINDS or not p.source:
                continue
            raw = lineage.raw_source(p.source)
            if not raw or (raw_fields is not None and raw in raw_fields):
                continue
            if p.source in result.fields:
                continue  # the source is there; the field is unset for another reason
            if all(_holds(sim, final, c) is True for c in p.conditions):
                report["missing_inputs"].append({"field": target, "raw_field": raw, "when": _conditions(p.conditions)})
                seen.add(target)
                break
    report["missing_inputs"].sort(key=lambda m: (m["field"].startswith("Vendor."), m["field"]))
    return report


# ---------------------------------------------------------------- command line

def _markdown(catalog):
    lines = ["# NG-SIEM parser field catalog", "",
             f"{len(catalog)} parsers. For each: the raw format, what a log needs for the parser to keep it, the",
             "timestamps it reads (with their parseTimestamp() formats), the event types it sets, and the raw",
             "fields it reads. The JSON file beside this one lists every field with each way it's produced.", ""]
    for entry in catalog:
        lines.append(f"## {entry['name']} ({entry.get('version')})")
        if entry.get("error"):
            lines += [entry["error"], ""]
            continue
        lines.append(f"- **Format:** {entry['format']}" + (f", fields under `{entry['decoder_prefix']}`" if entry.get("decoder_prefix") else ""))
        for gate in entry["keeps_log_only_if"]:
            options = ["; ".join(o) or "(no condition)" for o in gate]
            lines.append(f"- **Kept only if one of:** {' | '.join(options[:6])}")
        for t in entry["timestamps"]:
            when = f" when {'; '.join(t['when'])}" if t["when"] else ""
            zone = f", timezone {t['timezone']}" if t.get("timezone") else ""
            lines.append(f"- **Timestamp:** `{t['field']}` as `{t['format'] or 'default ISO 8601'}`{zone}{when}")
        datasets = entry["event_types"]["event.dataset"]
        if datasets:
            shown = [f"`{d['value']}`" + (f" ({'; '.join(d['when'])})" if d["when"] else "") for d in datasets[:12]]
            lines.append(f"- **event.dataset:** {', '.join(shown)}")
        lines.append(f"- **Raw fields read ({len(entry['raw_inputs'])}):** " + ", ".join(f"`{r}`" for r in entry["raw_inputs"][:80]))
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="reports", help="folder to write parser-field-catalog.json and .md")
    parser.add_argument("--cache", default=None, help="parser cache folder (default: the app's)")
    args = parser.parse_args(argv)
    from dotenv import load_dotenv
    from falcon_client import FalconClient
    from parsers import ParserStore
    load_dotenv()
    client = FalconClient(os.environ.get("FALCON_CLIENT_ID"), os.environ.get("FALCON_CLIENT_SECRET"),
                          os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"))
    store = ParserStore(client, cache_dir=args.cache)
    catalog = []
    for name in sorted(store.index()):
        doc = store.get(name)
        if doc:
            catalog.append(catalog_parser(doc))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "parser-field-catalog.json").write_text(json.dumps(catalog, indent=1), encoding="utf-8")
    (out / "parser-field-catalog.md").write_text(_markdown(catalog), encoding="utf-8")
    print(f"Catalogued {len(catalog)} parsers into {out.resolve()}")


if __name__ == "__main__":
    sys.exit(main())
