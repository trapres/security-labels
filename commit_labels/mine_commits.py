"""Script 2: clone the target repos and extract commits into a dataframe.

    python -m commit_labels.mine_commits --max-repos 20 --since "12 months ago"

Reads data/interim/repo_targets.json, writes data/interim/commits.parquet.

Each row carries an ``is_cve_fix`` flag and ``cve_id`` for commits that a CVE
advisory named directly. Those are your gold positives - keep them out of the
Snorkel training signal if you want an honest evaluation set.
"""

from __future__ import annotations

import argparse
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

from . import config
from .gitmine import (
    DEFAULT_REFS, GitError, clone_or_update, iter_commits, resolve_sha,
)

log = logging.getLogger("mine_commits")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--targets", type=Path, default=config.TARGETS_PATH,
        help="repo_targets.json from fetch_cves",
    )
    p.add_argument(
        "--out", type=Path, default=config.COMMITS_PATH,
    )
    p.add_argument(
        "--max-repos", type=int, default=25,
        help="cap how many repos to clone, highest-signal first (default: 25)",
    )
    p.add_argument(
        "--min-fix-commits", type=int, default=1,
        help="skip repos with fewer than N known fix commits (default: 1). "
             "Set to 0 to include repos we only know by CVE reference.",
    )
    p.add_argument(
        "--since", type=str, default="24 months ago",
        help="git --since expression bounding mined history "
             "(default: '24 months ago')",
    )
    p.add_argument("--until", type=str, default=None)
    p.add_argument(
        "--max-commits-per-repo", type=int, default=20000,
    )
    p.add_argument(
        "--refs", type=str, default=DEFAULT_REFS,
        help="which refs to walk (default: --branches). Avoid --all on "
             "blobless clones; see the README performance note.",
    )
    p.add_argument(
        "--jobs", type=int, default=4,
        help="parallel clones (default: 4)",
    )
    p.add_argument(
        "--no-stats", action="store_true",
        help="skip the file-path pass entirely; fastest, but the path-based "
             "labeling functions go dead",
    )
    p.add_argument(
        "--line-stats", action="store_true",
        help="also collect insertions/deletions. Implies --keep-full-clone: "
             "line counts need blob content, and on a blobless clone git "
             "refetches every blob one at a time (minutes per repo, and it "
             "fails outright on large histories).",
    )
    p.add_argument(
        "--keep-full-clone", action="store_true",
        help="clone blobs too (much slower and larger on disk)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config.setup_logging(args.verbose)
    config.ensure_dirs()

    if not args.targets.exists():
        log.error("%s not found - run fetch_cves first", args.targets)
        return 1

    payload = json.loads(args.targets.read_text())
    targets = [
        t for t in payload["targets"]
        if len(t["fix_commits"]) >= args.min_fix_commits
    ]
    targets = targets[: args.max_repos]

    if not targets:
        log.error(
            "No targets passed the filter. Try --min-fix-commits 0, or rerun "
            "fetch_cves over a longer window."
        )
        return 1

    log.info("Mining %d repos (of %d available)",
             len(targets), len(payload["targets"]))

    frames = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(_process_repo, t, args): t["full_name"]
            for t in targets
        }
        for i, fut in enumerate(as_completed(futures), 1):
            name = futures[fut]
            try:
                df = fut.result()
            except Exception as exc:  # noqa: BLE001 - one bad repo shouldn't stop the run
                log.warning("[%d/%d] %s failed: %s", i, len(targets), name, exc)
                continue
            if df is None or df.empty:
                log.info("[%d/%d] %s -> no commits in window",
                         i, len(targets), name)
                continue
            frames.append(df)
            log.info("[%d/%d] %s -> %d commits (%d cve fixes)",
                     i, len(targets), name, len(df), int(df["is_cve_fix"].sum()))

    if not frames:
        log.error("Nothing mined.")
        return 1

    commits = pd.concat(frames, ignore_index=True)
    commits = commits.drop_duplicates(subset=["repo", "sha"])

    args.out.parent.mkdir(parents=True, exist_ok=True)
    written = _write(commits, args.out)

    log.info(
        "Wrote %d commits from %d repos to %s (%d labeled CVE fixes)",
        len(commits), commits["repo"].nunique(), written,
        int(commits["is_cve_fix"].sum()),
    )
    return 0


def _process_repo(target: dict, args) -> pd.DataFrame | None:
    full_name = target["full_name"]
    dest = config.REPOS_DIR / full_name.replace("/", "__")

    full_clone = args.keep_full_clone or args.line_stats
    try:
        clone_or_update(target["clone_url"], dest, blobless=not full_clone)
    except GitError as exc:
        log.warning("clone failed for %s: %s", full_name, exc)
        return None

    # Advisories often cite abbreviated SHAs. Expand them so the join works.
    fix_map = {}
    for short_sha, cve_id in target.get("commit_to_cve", {}).items():
        full = resolve_sha(dest, short_sha) or short_sha
        fix_map[full.lower()] = cve_id
    for short_sha in target.get("fix_commits", []):
        full = (resolve_sha(dest, short_sha) or short_sha).lower()
        fix_map.setdefault(full, None)

    rows = []
    for commit in iter_commits(
        dest,
        full_name,
        since=args.since,
        until=args.until,
        max_commits=args.max_commits_per_repo,
        stats_mode=("none" if args.no_stats
                    else "numstat" if args.line_stats else "names"),
        refs=args.refs,
    ):
        row = commit.to_row()
        sha = commit.sha.lower()
        row["is_cve_fix"] = sha in fix_map
        row["cve_id"] = fix_map.get(sha)
        rows.append(row)

    if not rows:
        return None

    df = pd.DataFrame(rows)
    df["repo_cve_ids"] = ",".join(target.get("cve_ids", []))
    return df


def _write(df: pd.DataFrame, path: Path) -> Path:
    """Parquet if an engine is installed, else JSONL. ``files`` is a list
    column, which CSV would mangle, so we never fall back to CSV."""
    try:
        df.to_parquet(path, index=False)
        return path
    except (ImportError, ValueError) as exc:
        alt = path.with_suffix(".jsonl")
        log.warning("parquet unavailable (%s); writing %s instead", exc, alt)
        df.to_json(alt, orient="records", lines=True)
        return alt


if __name__ == "__main__":
    raise SystemExit(main())
