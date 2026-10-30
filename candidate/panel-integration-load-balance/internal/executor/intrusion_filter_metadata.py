"""Pure, bounded readable filter metadata, not compiled-object attestation.

The daemon's public getters expose regex text, NOT hidden regex flags or
private matcher state. Comparing this digest never grants mutation authority.
No package imports, IO, execution, socket or thread operation occurs here.
"""
import codecs
import hashlib
import json

FILTER_METADATA_FIELDS = (
    "usedns", "prefregex", "failregex", "ignoreregex", "maxlines", "datepattern",
    "ignorecommand", "ignorecache", "ignoreself", "ignoreip", "logencoding", "logtimezone",
)


def filter_metadata_fingerprint(version, values):
    if version not in ("0.11.2", "1.0.2", "1.1.0") or type(values) is not dict or set(values) != set(FILTER_METADATA_FIELDS):
        raise ValueError("filter metadata surface")
    value = dict(values)

    def text(item, maximum=24576):
        return type(item) is str and len(item.encode("utf-8")) <= maximum and "\x00" not in item

    if value["usedns"] not in ("yes", "warn", "no", "raw") or not text(value["usedns"], 4):
        raise ValueError("filter DNS mode")
    if value["prefregex"] is not None and not text(value["prefregex"]):
        raise ValueError("filter prefix")
    regexes = value["failregex"]
    if type(regexes) is not list or not 1 <= len(regexes) <= 128 or not all(text(v) for v in regexes):
        raise ValueError("filter regex capacity")
    if type(value["maxlines"]) is not int or not 1 <= value["maxlines"] <= 1024:
        raise ValueError("filter line capacity")
    pattern = value["datepattern"]
    if type(pattern) not in (list, tuple) or len(pattern) != 2 or pattern[0] is not None and not text(pattern[0]) or not text(pattern[1]):
        raise ValueError("filter date metadata")
    value["datepattern"] = list(pattern)
    # The closed supported disk grammar has no declarations for these
    # custom behaviors. Do not treat an unseen runtime exception as default.
    if type(value["ignoreregex"]) is not list or value["ignoreregex"] or type(value["ignoreip"]) is not list or value["ignoreip"] or value["ignorecache"] is not None or value["ignoreself"] is not True or value["logtimezone"] is not None:
        raise ValueError("unsupported live filter exceptions")
    if not (value["ignorecommand"] is False or type(value["ignorecommand"]) is str and value["ignorecommand"] == ""):
        raise ValueError("external ignore command not supported")
    value["ignorecommand"] = ""
    if not text(value["logencoding"], 64) or not value["logencoding"]:
        raise ValueError("filter encoding")
    value["logencoding"] = codecs.lookup(value["logencoding"]).name
    raw = json.dumps({"format": 1, "version": version, "values": value}, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > 65536:
        raise ValueError("filter metadata total capacity")
    return {"format": 1, "version": version, "sha256": hashlib.sha256(raw).hexdigest()}
