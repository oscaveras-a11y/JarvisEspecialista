"""Fixed specialist operations on verified copies, inside the monitored child."""
from cyber_core.errors import CoreError

TOOLS = ("audit-config", "analyze-capture", "extract-strings", "differentiate-content")
KEYS = {"audit-config": "config_audit", "analyze-capture": "capture",
        "extract-strings": "strings", "differentiate-content": "differentiation"}


def validate_options(tool, options):
    if tool not in TOOLS or not isinstance(options, dict):
        raise CoreError("Invalid specialist operation")
    allowed = {"max_sample", "min_length", "max_strings"} if tool == "extract-strings" else {"max_sample"}
    if set(options) - allowed:
        raise CoreError("Unknown specialist option")
    ceiling = 262144 if tool == "differentiate-content" else 16 * 1024 * 1024
    for key, value in options.items():
        limit = {"max_sample": ceiling, "min_length": 256, "max_strings": 100000}[key]
        if type(value) is not int or not 1 <= value <= limit:
            raise CoreError("Invalid specialist " + key + " limit")


def _sample(path, maximum, *, capture=False):
    with path.open("rb") as handle:
        data = handle.read(maximum)
        truncated = bool(handle.read(1))
    partial = False
    if capture and truncated and data and not data.endswith((b"\n", b"\r")):
        end = max(data.rfind(b"\n"), data.rfind(b"\r"))
        data, partial = data[:end + 1], True
    return data, truncated, partial


def execute(tool, path, options, secondary=None):
    validate_options(tool, options)
    default = {"audit-config": 1048576, "analyze-capture": 4194304,
               "extract-strings": 1048576, "differentiate-content": 65536}[tool]
    maximum = options.get("max_sample", default)
    sample, truncated, partial = _sample(path, maximum, capture=tool == "analyze-capture")
    if tool == "audit-config":
        from cyber_core.vulnerability import audit_config
        result = audit_config(sample.decode("utf-8", errors="replace"))
    elif tool == "extract-strings":
        from cyber_core.reverse_engineering.strings import extract_strings
        result = extract_strings(sample, min_length=options.get("min_length", 4),
                                 max_strings=options.get("max_strings", 1000))
    elif tool == "differentiate-content":
        from cyber_core.cryptanalysis.differentiate import differentiate
        result = differentiate(sample, sample_truncated=truncated)
    else:
        from cyber_core.protocol import analyze_capture, compare_captures
        text = sample.decode("utf-8", errors="replace")
        flags = {"sample_truncated": truncated, "partial_record_discarded": partial}
        if secondary is not None:
            other, other_truncated, other_partial = _sample(secondary, maximum, capture=True)
            result = compare_captures(text, other.decode("utf-8", errors="replace"))
            result["first"].update(flags)
            result["second"].update(sample_truncated=other_truncated, partial_record_discarded=other_partial)
            result["sample_truncated"] = truncated or other_truncated
            result["comparison_truncated"] |= truncated or other_truncated
            return result
        result = analyze_capture(text)
        result.update(flags)
    result["sample_truncated"] = truncated
    return result


def audit_event(tool, result):
    if tool == "audit-config":
        return "config_audited", {"summary": result["summary"], "findings": len(result["findings"])}
    if tool == "extract-strings":
        return "strings_extracted", {"counts": result["counts"], "min_length": result["min_length"]}
    if tool == "differentiate-content":
        return "content_differentiated", {"content_class": result["content_class"], "label": result["label"]}
    if "first" in result:
        return "capture_analyzed", {"messages": result["first"]["messages"],
                                    "second_messages": result["second"]["messages"]}
    return "capture_analyzed", {"messages": result["messages"], "unique_payloads": result["unique_payloads"]}
