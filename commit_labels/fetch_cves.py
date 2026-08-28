"""Script 1: find CVEs from the last X months that map to GitHub repos.

    python -m commit_labels.fetch_cves --months 6

Writes two files:
  data/interim/cves.jsonl        one normalized CVE per line, GitHub refs resolved
  data/interim/repo_targets.json repos to clone, with known fix commits per repo

The second file is the input to ``mine_commits``.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone

from . import config
from .github_refs import RepoTarget, extract_from_references, pick_primary_repo
from .nvd import NvdClient, months_ago
from .osv import OsvClient

log = logging.getLogger("fetch_cves")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--months", type=int, default=6,
        help="how many months back to search (default: 6)",
    )
    p.add_argument(
        "--end", type=str, default=None,
        help="end of window as YYYY-MM-DD (default: today)",
    )
    p.add_argument(
        "--min-cvss", type=float, default=None,
        help="drop CVEs below this CVSS base score",
    )
    p.add_argument(
        "--require-patch-ref", action="store_true",
        help="keep only CVEs with a concrete commit/PR link (much cleaner, "
             "roughly 3-5x smaller)",
    )
    p.add_argument(
        "--no-osv", action="store_true",
        help="skip OSV enrichment (faster, but you lose most fix commits)",
    )
    p.add_argument(
        "--max-cves", type=int, default=None,
        help="stop after N CVEs; useful for a smoke test",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config.setup_logging(args.verbose)
    config.load_dotenv()
    config.ensure_dirs()

    end = (
        datetime.strptime(args.end, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if args.end
        else datetime.now(timezone.utc)
    )
    start = months_ago(args.months, end)
    log.info("Searching CVEs published %s .. %s", start.date(), end.date())

    nvd = NvdClient()
    if not nvd.api_key:
        log.warning(
            "No NVD_API_KEY set - throttling to 1 request per ~6.5s. "
            "A %d month window will take a while.", args.months
        )
    osv = None if args.no_osv else OsvClient()

    targets: dict = {}
    kept = 0
    seen = 0

    with config.CVES_PATH.open("w") as out:
        for cve in nvd.iter_cves_published_between(start, end):
            seen += 1
            if seen % 500 == 0:
                log.info("scanned %d CVEs, kept %d, %d repos",
                         seen, kept, len(targets))

            if args.min_cvss is not None:
                if cve.cvss_score is None or cve.cvss_score < args.min_cvss:
                    continue

            repos, patches = extract_from_references(cve.reference_urls)
            if not repos:
                continue
            if args.require_patch_ref and not patches:
                continue

            primary = pick_primary_repo(repos, patches)

            # OSV often knows a fix commit even when NVD's references don't.
            osv_fixes = osv.fix_commits(cve.cve_id) if osv else []

            record = cve.to_json()
            record["github_repos"] = sorted({r.key: r.full_name for r in repos}.values())
            record["primary_repo"] = primary.full_name if primary else None
            record["patch_refs"] = [
                {"repo": p.repo.full_name, "kind": p.kind,
                 "id": p.identifier, "url": p.url}
                for p in patches
            ]
            record["osv_fixes"] = [
                {"repo": f.repo.full_name, "commit": f.commit,
                 "source": f.source_id}
                for f in osv_fixes
            ]
            out.write(json.dumps(record) + "\n")
            kept += 1

            _accumulate(targets, cve.cve_id, repos, patches, osv_fixes, primary)

            if args.max_cves and kept >= args.max_cves:
                log.info("hit --max-cves limit")
                break

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "cves_scanned": seen,
        "cves_kept": kept,
        "targets": [t.to_json() for t in _rank(targets)],
    }
    config.TARGETS_PATH.write_text(json.dumps(payload, indent=2))

    n_fix = sum(len(t.fix_commits) for t in targets.values())
    log.info(
        "Done. %d CVEs scanned, %d kept, %d repos, %d known fix commits.",
        seen, kept, len(targets), n_fix,
    )
    log.info("  %s", config.CVES_PATH)
    log.info("  %s", config.TARGETS_PATH)
    return 0


def _accumulate(targets, cve_id, repos, patches, osv_fixes, primary) -> None:
    """Fold one CVE into the per-repo target index."""
    def target_for(repo):
        t = targets.get(repo.key)
        if t is None:
            t = targets[repo.key] = RepoTarget(repo=repo)
        return t

    # Only attribute the CVE to the primary repo when we could pick one;
    # otherwise every PoC repo inherits the CVE and pollutes the target list.
    for repo in (repos if primary is None else {primary}):
        target_for(repo).cve_ids.add(cve_id)

    for p in patches:
        t = target_for(p.repo)
        t.cve_ids.add(cve_id)
        if p.kind == "commit":
            t.fix_commits.add(p.identifier)
            t.commit_to_cve[p.identifier] = cve_id
        elif p.kind == "pull":
            t.fix_prs.add(p.identifier)

    for f in osv_fixes:
        t = target_for(f.repo)
        t.cve_ids.add(cve_id)
        t.fix_commits.add(f.commit)
        t.commit_to_cve[f.commit] = cve_id


def _rank(targets: dict) -> list:
    """Most useful repos first: known fix commits, then CVE count."""
    return sorted(
        targets.values(),
        key=lambda t: (-len(t.fix_commits), -len(t.cve_ids), t.repo.full_name),
    )


if __name__ == "__main__":
    raise SystemExit(main())
