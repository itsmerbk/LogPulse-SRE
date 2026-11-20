import subprocess
from dataclasses import dataclass
from pathlib import Path

from logpulse.detector import IncidentAlert


@dataclass
class CommitSuspect:
    commit_hash: str
    author: str
    subject: str
    confidence_score: float
    matched_files: list[str]
    matched_symbols: list[str]
    diff_excerpt: str


def rank_suspect_commits(repo_path: str | Path, incident: IncidentAlert, max_commits: int = 10) -> list[CommitSuspect]:
    repo = Path(repo_path).resolve()
    if not (repo / ".git").exists():
        return []

    proc = subprocess.run(
        ["git", "log", f"-n{max_commits}", "--pretty=format:===COMMIT===%H|%an|%s", "-p", "--unified=1"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return []

    raw_blocks = proc.stdout.split("===COMMIT===")[1:]
    suspects: list[CommitSuspect] = []

    for idx, block in enumerate(raw_blocks):
        lines = block.splitlines()
        header = lines[0].split("|", 2)
        if len(header) < 3:
            continue
        commit_hash, author, subject = header[0][:8], header[1], header[2]

        changed_files: list[str] = []
        added_lines: list[str] = []
        for line in lines[1:]:
            if line.startswith("+++ b/"):
                changed_files.append(line[6:].strip())
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:].strip())

        added_corpus = "\n".join(added_lines)

        matched_files = [
            f for f in changed_files
            if any(hint.endswith(f) or f.endswith(hint) for hint in incident.file_hints)
        ]
        matched_symbols = [
            sym for sym in incident.symbol_hints
            if sym in added_corpus or sym in subject
        ]

        recency_bonus = max(0.0, 10.0 - (idx * 2.0))
        score = (len(matched_files) * 50.0) + (len(matched_symbols) * 25.0) + (recency_bonus if (matched_files or matched_symbols) else 0.0)
        confidence = min(99.5, round(score, 1))

        if confidence > 0:
            excerpt = next((ln for ln in added_lines if any(s in ln for s in matched_symbols)), added_lines[0] if added_lines else subject)
            suspects.append(
                CommitSuspect(
                    commit_hash=commit_hash,
                    author=author,
                    subject=subject,
                    confidence_score=confidence,
                    matched_files=matched_files,
                    matched_symbols=matched_symbols,
                    diff_excerpt=excerpt[:95],
                )
            )

    suspects.sort(key=lambda s: s.confidence_score, reverse=True)
    return suspects
