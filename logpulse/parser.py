import hashlib
import re
from dataclasses import dataclass

MASK_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"), "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b\d+(?:\.\d+)?ms\b", re.IGNORECASE), "<LATENCY>"),
    (re.compile(r"\b\d+\b"), "<NUM>"),
]

FILE_HINT_RE = re.compile(r"([a-zA-Z0-9_./-]+\.(?:py|java|go|ts|js|rs))(?::\d+)?")
SYMBOL_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Fault|Timeout)|[a-z_][a-z0-9_]{3,}\(\))")


@dataclass(frozen=True)
class ParsedLog:
    level: str
    template_id: str
    template: str
    raw_line: str
    file_hints: tuple[str, ...]
    symbol_hints: tuple[str, ...]


def normalize_log_line(raw_line: str) -> ParsedLog:
    line = raw_line.strip()
    level = "INFO"
    for candidate in ("CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG"):
        if re.search(rf"\b{candidate}\b", line):
            level = "ERROR" if candidate == "CRITICAL" else ("WARN" if candidate == "WARNING" else candidate)
            break

    file_hints = tuple(dict.fromkeys(FILE_HINT_RE.findall(line)))
    symbol_hints = tuple(dict.fromkeys(m.rstrip("()") for m in SYMBOL_HINT_RE.findall(line)))

    masked = line
    for pattern, token in MASK_RULES:
        masked = pattern.sub(token, masked)

    # Strip leading timestamp/level prefix so identical errors share one template ID
    core_template = re.sub(r"^(?:<TS>\s*)?(?:\[?(?:INFO\vert{}WARN\vert{}ERROR\vert{}DEBUG)\]?\s*:?\s*)", "", masked).strip()
    template_id = hashlib.sha1(core_template.encode("utf-8")).hexdigest()[:10]

    return ParsedLog(
        level=level,
        template_id=template_id,
        template=core_template,
        raw_line=line,
        file_hints=file_hints,
        symbol_hints=symbol_hints,
    )
