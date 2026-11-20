# LogPulse-SRE

**Streaming Log Anomaly Detector & Automated Git-Commit Root-Cause Correlator**

LogPulse-SRE compresses noisy high-volume application logs into structural templates (masking UUIDs, IPv4 addresses, timestamps, hex values, and latencies), detects statistical error spikes using rolling Z-scores, and inspects `git log -p` diffs to automatically rank the exact commit that introduced an outage.

## Architecture

~~~mermaid
flowchart LR
    A[Raw Application Logs] -->|Regex Variable Masking| B[Structural Template Miner]
    B -->|Sliding Bucket Counters| C{Z-Score >= 3.0?}
    C -->|Normal Baseline| D[Update Rolling Mean & StdDev]
    C -->|Incident Surge| E[Extract Stack Files & Symbols]
    E -->|git log -p Diff Parser| F[Git Commit Root-Cause Ranker]
    F --> G[Ranked Suspect Commit + Diff Excerpt]
~~~

## Quickstart

~~~bash
git clone https://github.com/itsmerbk/logpulse-sre.git
cd logpulse-sre
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Run unit tests
pytest -v

# 2. Run end-to-end outage & Git root-cause correlation simulation
python -m logpulse.demo_incident

# 3. Start the SRE Ingestion & Correlation API (http://127.0.0.1:8097/docs)
uvicorn logpulse.app:app --reload --port 8097
~~~
