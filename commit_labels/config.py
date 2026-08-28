"""Shared paths, env loading, and logging setup."""

from __future__ import annotations

import logging
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"          # untouched API payloads
INTERIM_DIR = DATA_DIR / "interim"  # normalized but unlabeled
PROCESSED_DIR = DATA_DIR / "processed"
REPOS_DIR = DATA_DIR / "repos"      # bare clones

CVES_PATH = INTERIM_DIR / "cves.jsonl"
TARGETS_PATH = INTERIM_DIR / "repo_targets.json"
COMMITS_PATH = INTERIM_DIR / "commits.parquet"
LABELED_PATH = PROCESSED_DIR / "commits_labeled.parquet"


def ensure_dirs() -> None:
    for d in (RAW_DIR, INTERIM_DIR, PROCESSED_DIR, REPOS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env reader so we don't need python-dotenv."""
    path = path or PROJECT_ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
