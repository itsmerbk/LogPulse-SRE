from dataclasses import asdict
from fastapi import FastAPI
from pydantic import BaseModel, Field

from logpulse.detector import LogAnomalyEngine
from logpulse.git_correlator import rank_suspect_commits

app = FastAPI(
    title="LogPulse-SRE",
    description="Streaming Log Anomaly Detector & Automated Git-Commit Root-Cause Correlator",
    version="1.0.0",
)

engine = LogAnomalyEngine(bucket_size=25, z_threshold=3.0)


class LogBatchIn(BaseModel):
    lines: list[str] = Field(..., min_length=1)


class CorrelateIn(BaseModel):
    repo_path: str
    template_id: str | None = None


@app.post("/v1/logs/ingest")
async def ingest_logs(batch: LogBatchIn):
    for line in batch.lines:
        engine.ingest_line(line)
    engine.flush()
    return {
        "summary": engine.summary(),
        "incidents": [asdict(i) for i in engine.get_incidents()],
    }


@app.get("/v1/incidents")
async def list_incidents():
    return {
        "summary": engine.summary(),
        "incidents": [asdict(i) for i in engine.get_incidents()],
    }


@app.post("/v1/correlate")
async def correlate_git_commit(req: CorrelateIn):
    incidents = engine.get_incidents()
    if not incidents:
        return {"status": "no_active_incidents", "suspects": []}

    target = next((i for i in incidents if i.template_id == req.template_id), incidents[0])
    suspects = rank_suspect_commits(req.repo_path, target)
    return {
        "incident": asdict(target),
        "suspect_commits": [asdict(s) for s in suspects],
    }
