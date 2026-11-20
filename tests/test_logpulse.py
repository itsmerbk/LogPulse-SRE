from pathlib import Path
from logpulse.demo_incident import build_simulated_service_repo
from logpulse.detector import LogAnomalyEngine
from logpulse.git_correlator import rank_suspect_commits
from logpulse.parser import normalize_log_line


def test_variable_masking_clusters_dynamic_logs():
    line_a = "2026-11-20T10:01:02Z ERROR payment_router.py:4 KeyError tx=550e8400-e29b-41d4-a716-446655440001 ip=10.0.0.1 in 14ms"
    line_b = "2026-11-20T10:01:09Z ERROR payment_router.py:4 KeyError tx=661f9511-f30c-52e5-b827-557766559999 ip=192.168.1.44 in 89ms"
    p1 = normalize_log_line(line_a)
    p2 = normalize_log_line(line_b)
    assert p1.template_id == p2.template_id
    assert "payment_router.py" in p1.file_hints
    assert "KeyError" in p1.symbol_hints


def test_zscore_spike_and_git_commit_correlation(tmp_path: Path):
    repo = build_simulated_service_repo(tmp_path)
    engine = LogAnomalyEngine(bucket_size=20, z_threshold=3.0)

    for i in range(80):
        engine.ingest_line(f"2026-11-20T10:00:{i%60:02d}Z INFO healthy request id={i}")

    for j in range(18):
        engine.ingest_line(f"2026-11-20T10:05:{j:02d}Z ERROR payment_router.py:4 KeyError in settle_upi_transfer() id={j}")

    engine.flush()
    incidents = engine.get_incidents()
    assert len(incidents) == 1
    assert incidents[0].z_score >= 3.0

    suspects = rank_suspect_commits(repo, incidents[0])
    assert len(suspects) >= 1
    assert "settle_upi_transfer" in suspects[0].subject
    assert suspects[0].confidence_score >= 90.0
