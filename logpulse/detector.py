import math
import threading
from collections import deque
from dataclasses import dataclass, field

from logpulse.parser import ParsedLog, normalize_log_line


@dataclass
class TemplateStats:
    template_id: str
    template: str
    level: str
    total_count: int = 0
    recent_window_count: int = 0
    history_counts: deque[int] = field(default_factory=lambda: deque(maxlen=20))
    file_hints: set[str] = field(default_factory=set)
    symbol_hints: set[str] = field(default_factory=set)
    sample_raw: str = ""


@dataclass
class IncidentAlert:
    template_id: str
    template: str
    level: str
    current_rate: int
    baseline_mean: float
    z_score: float
    file_hints: list[str]
    symbol_hints: list[str]
    sample_raw: str


class LogAnomalyEngine:
    def __init__(self, bucket_size: int = 25, z_threshold: float = 3.0) -> None:
        self.bucket_size = bucket_size
        self.z_threshold = z_threshold
        self._lock = threading.Lock()
        self._events_in_bucket = 0
        self._templates: dict[str, TemplateStats] = {}
        self._active_incidents: dict[str, IncidentAlert] = {}

    def ingest_line(self, raw_line: str) -> ParsedLog:
        parsed = normalize_log_line(raw_line)
        with self._lock:
            stat = self._templates.get(parsed.template_id)
            if stat is None:
                stat = TemplateStats(
                    template_id=parsed.template_id,
                    template=parsed.template,
                    level=parsed.level,
                    sample_raw=parsed.raw_line,
                )
                self._templates[parsed.template_id] = stat

            stat.total_count += 1
            stat.recent_window_count += 1
            stat.file_hints.update(parsed.file_hints)
            stat.symbol_hints.update(parsed.symbol_hints)

            self._events_in_bucket += 1
            if self._events_in_bucket >= self.bucket_size:
                self._flush_bucket_locked()

        return parsed

    def flush(self) -> list[IncidentAlert]:
        with self._lock:
            return self._flush_bucket_locked()

    def _flush_bucket_locked(self) -> list[IncidentAlert]:
        new_alerts: list[IncidentAlert] = []
        for stat in self._templates.values():
            curr = stat.recent_window_count
            hist = list(stat.history_counts)

            if stat.level in ("ERROR", "WARN") and curr >= 3:
                if len(hist) >= 3:
                    mean = sum(hist) / len(hist)
                    variance = sum((x - mean) ** 2 for x in hist) / len(hist)
                    std = max(0.5, math.sqrt(variance))
                    z = (curr - mean) / std
                else:
                    mean = 0.0
                    z = float(curr) * 2.0

                if z >= self.z_threshold:
                    alert = IncidentAlert(
                        template_id=stat.template_id,
                        template=stat.template,
                        level=stat.level,
                        current_rate=curr,
                        baseline_mean=round(mean, 2),
                        z_score=round(z, 2),
                        file_hints=sorted(stat.file_hints),
                        symbol_hints=sorted(stat.symbol_hints),
                        sample_raw=stat.sample_raw,
                    )
                    self._active_incidents[stat.template_id] = alert
                    new_alerts.append(alert)

            stat.history_counts.append(curr)
            stat.recent_window_count = 0

        self._events_in_bucket = 0
        return new_alerts

    def get_incidents(self) -> list[IncidentAlert]:
        with self._lock:
            return sorted(self._active_incidents.values(), key=lambda a: a.z_score, reverse=True)

    def summary(self) -> dict[str, int]:
        with self._lock:
            return {
                "unique_templates": len(self._templates),
                "total_logs_ingested": sum(t.total_count for t in self._templates.values()),
                "active_incidents": len(self._active_incidents),
            }
