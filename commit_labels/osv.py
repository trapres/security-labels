"""OSV.dev client, used to enrich NVD results with exact fix commits.

NVD tells you *that* a CVE exists and links to references. OSV frequently knows
the precise fixing commit SHA, because advisories there carry structured GIT
ranges::

    "affected": [{"ranges": [{"type": "GIT",
                              "repo": "https://github.com/owner/name",
                              "events": [{"introduced": "0"},
                                         {"fixed": "<sha>"}]}]}]

Those SHAs are the highest-quality positive labels available without manual
review, so it is worth the extra request per CVE.

No API key needed; be polite about request rate.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable

import requests

from .github_refs import GitHubRepo, parse_github_url

log = logging.getLogger(__name__)

VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
QUERY_URL = "https://api.osv.dev/v1/query"


@dataclass
class OsvFix:
    repo: GitHubRepo
    commit: str
    source_id: str  # the OSV/GHSA id that asserted it


class OsvClient:
    def __init__(self, timeout: int = 30, delay: float = 0.1):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "commit-labels/0.1 (research)"
        self._cache: dict = {}

    def get_vuln(self, vuln_id: str) -> dict | None:
        """Fetch one advisory. OSV resolves CVE ids through its alias index."""
        if vuln_id in self._cache:
            return self._cache[vuln_id]

        result = None
        for attempt in range(3):
            try:
                resp = self.session.get(
                    VULN_URL.format(vuln_id=vuln_id), timeout=self.timeout
                )
            except requests.RequestException as exc:
                log.debug("OSV %s failed: %s", vuln_id, exc)
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                result = resp.json()
                break
            if resp.status_code == 404:
                break
            if resp.status_code in (429, 500, 503):
                time.sleep(2 ** attempt * 2)
                continue
            break

        time.sleep(self.delay)
        self._cache[vuln_id] = result
        return result

    def fix_commits(self, vuln_id: str) -> list:
        """Return every GitHub fix commit OSV knows about for this id."""
        vuln = self.get_vuln(vuln_id)
        if not vuln:
            return []
        return list(extract_fixes(vuln))


def extract_fixes(vuln: dict) -> Iterable[OsvFix]:
    """Walk an OSV record's GIT ranges for ``fixed`` events."""
    source_id = vuln.get("id", "")
    seen = set()

    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo_url = rng.get("repo", "")
            repo, _ = parse_github_url(repo_url)
            if repo is None:
                continue
            for event in rng.get("events", []):
                sha = event.get("fixed")
                if not sha:
                    continue
                sha = sha.lower()
                key = (repo, sha)
                if key in seen:
                    continue
                seen.add(key)
                yield OsvFix(repo=repo, commit=sha, source_id=source_id)

    # Some records only carry the fix as a reference with type FIX.
    for ref in vuln.get("references", []):
        if ref.get("type") not in ("FIX", "ADVISORY"):
            continue
        repo, patch = parse_github_url(ref.get("url", ""))
        if patch is not None and patch.kind == "commit":
            key = (patch.repo, patch.identifier)
            if key not in seen:
                seen.add(key)
                yield OsvFix(
                    repo=patch.repo, commit=patch.identifier, source_id=source_id
                )
