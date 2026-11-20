import subprocess
import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from logpulse.detector import LogAnomalyEngine
from logpulse.git_correlator import rank_suspect_commits

console = Console()


def build_simulated_service_repo(base_dir: Path) -> Path:
    repo = base_dir / "payments-gateway"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Bharath Kumar"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "itsmerbk@users.noreply.github.com"], cwd=repo, check=True, capture_output=True)

    # Commit 1: Clean baseline code
    (repo / "payment_router.py").write_text(
        "def settle_upi_transfer(tx_id: str, metadata: dict) -> str:\n"
        "    bank_code = metadata.get('bank_code', 'DEFAULT')\n"
        "    return f'SETTLED:{tx_id}:{bank_code}'\n"
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "feat: add initial UPI transfer settlement router"], cwd=repo, check=True, capture_output=True)

    # Commit 2: Faulty deploy removing defensive .get() and raising KeyError on missing 'routing_vpa'
    (repo / "payment_router.py").write_text(
        "def settle_upi_transfer(tx_id: str, metadata: dict) -> str:\n"
        "    # Strict VPA lookup introduced in v2.4 deploy\n"
        "    vpa = metadata['routing_vpa']\n"
        "    if not vpa:\n"
        "        raise KeyError('Missing routing_vpa in settlement payload')\n"
        "    return f'SETTLED:{tx_id}:{vpa}'\n"
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "refactor: enforce strict routing_vpa lookup in settle_upi_transfer"], cwd=repo, check=True, capture_output=True)

    # Commit 3: Unrelated README update
    (repo / "README.md").write_text("# Payments Gateway Service\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "docs: update service deployment notes"], cwd=repo, check=True, capture_output=True)

    return repo


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = build_simulated_service_repo(Path(tmp))
        engine = LogAnomalyEngine(bucket_size=30, z_threshold=3.0)

        # 1. Stream 150 healthy baseline logs (5 buckets of 30 logs)
        for i in range(150):
            engine.ingest_line(
                f"2026-11-20T14:10:{i%60:02d}Z INFO settle_upi_transfer() completed tx=550e8400-e29b-41d4-a716-44665544{i:04d} from 10.24.1.{i%250} in {11 + (i%7)}ms"
            )

        # 2. Inject sudden deployment regression spike (28 errors in current bucket)
        for j in range(28):
            engine.ingest_line(
                f"2026-11-20T14:15:{j:02d}Z ERROR payment_router.py:4 KeyError in settle_upi_transfer() for tx=991e8400-e29b-41d4-a716-44665544{j:04d} ip=10.24.9.{j+10}"
            )
        engine.flush()

        summary = engine.summary()
        incidents = engine.get_incidents()
        top_incident = incidents[0]
        suspects = rank_suspect_commits(repo_path, top_incident)

        console.print(
            Panel.fit(
                f"[bold cyan]LogPulse-SRE Live Incident & Root-Cause Engine[/bold cyan]\n"
                f"Logs Ingested: [bold]{summary['total_logs_ingested']}[/bold]  |  "
                f"Clustered Templates: [bold green]{summary['unique_templates']}[/bold green] (compressed from 178 raw lines)  |  "
                f"Active Spikes: [bold red]{summary['active_incidents']}[/bold red]",
                border_style="bright_blue",
            )
        )

        inc_table = Table(title="Detected Statistical Log Anomaly", expand=True, border_style="red")
        inc_table.add_column("Template ID", style="cyan", width=12)
        inc_table.add_column("Z-Score", style="bold red", justify="right", width=9)
        inc_table.add_column("Spike Rate", justify="right", width=12)
        inc_table.add_column("Normalized Error Template", width=55)

        inc_table.add_row(
            top_incident.template_id,
            f"{top_incident.z_score}σ",
            f"{top_incident.current_rate} / bucket",
            top_incident.template,
        )
        console.print(inc_table)

        git_table = Table(title="Automated Git-Commit Root-Cause Ranking (git log -p)", expand=True, border_style="green")
        git_table.add_column("Commit", style="bold yellow", width=10)
        git_table.add_column("Confidence", style="bold green", justify="right", width=11)
        git_table.add_column("Matched Files / Symbols", style="cyan", width=30)
        git_table.add_column("Commit Subject & Culprit Diff Line", width=45)

        for s in suspects:
            matches = ", ".join(s.matched_files + s.matched_symbols)
            git_table.add_row(
                s.commit_hash,
                f"{s.confidence_score}%",
                matches,
                f"[bold]{s.subject}[/bold]\n[dim]+ {s.diff_excerpt}[/dim]",
            )
        console.print(git_table)


if __name__ == "__main__":
    main()
