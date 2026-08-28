"""Parse GitHub URLs out of advisory references.

The CVE -> repo mapping is the weakest link in this whole pipeline, so it lives
in one place with tests-by-inspection. Two things come out of a reference list:

  * ``GitHubRepo``   - owner/name of a repo the CVE plausibly concerns
  * ``PatchRef``     - a *specific* commit or PR that fixes it

PatchRefs are the valuable ones: they become gold positives for the labeling
step. Plain repo refs only tell us which history is worth mining.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, NamedTuple
from urllib.parse import urlparse

# Top-level GitHub paths that are never a user or org.
_RESERVED_OWNERS = {
    "about", "account", "advisories", "apps", "blog", "codespaces",
    "collections", "contact", "customer-stories", "dashboard", "enterprise",
    "events", "explore", "features", "gist", "join", "login", "logout",
    "marketplace", "new", "notifications", "orgs", "pricing", "pulls",
    "readme", "search", "security", "security-advisories", "sessions",
    "settings", "site", "sponsors", "stars", "topics", "trending", "users",
    "watching", "site-map", "signup", "issues", "organizations",
}

_GITHUB_HOSTS = {"github.com", "www.github.com", "api.github.com"}

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b", re.IGNORECASE)


class GitHubRepo(NamedTuple):
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def key(self) -> str:
        """Case-insensitive identity. GitHub treats ``PHPOffice/PhpSpreadsheet``
        and ``phpoffice/phpspreadsheet`` as one repo and advisories cite both
        spellings, so never key a dict on ``full_name`` directly."""
        return self.full_name.lower()

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"


@dataclass(frozen=True)
class PatchRef:
    """A reference that points at an actual fix."""

    repo: GitHubRepo
    kind: str          # "commit" | "pull" | "compare" | "release"
    identifier: str    # sha, PR number, tag, ...
    url: str


@dataclass
class RepoTarget:
    """Everything we know about one repo, aggregated across CVEs."""

    repo: GitHubRepo
    cve_ids: set = field(default_factory=set)
    fix_commits: set = field(default_factory=set)   # 40-char shas where known
    fix_prs: set = field(default_factory=set)
    # sha -> cve id, so mined commits can be joined back to their CVE
    commit_to_cve: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "owner": self.repo.owner,
            "name": self.repo.name,
            "full_name": self.repo.full_name,
            "clone_url": self.repo.clone_url,
            "cve_ids": sorted(self.cve_ids),
            "fix_commits": sorted(self.fix_commits),
            "fix_prs": sorted(self.fix_prs),
            "commit_to_cve": self.commit_to_cve,
        }


def _normalize_repo_name(name: str) -> str:
    # Strip things like ".git", trailing punctuation from prose-embedded URLs.
    name = name.strip()
    if name.endswith(".git"):
        name = name[:-4]
    return name.rstrip(".,);]'\"")


def parse_github_url(url: str) -> tuple[GitHubRepo | None, PatchRef | None]:
    """Return (repo, patch_ref). Either may be None."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None, None

    if parsed.netloc.lower() not in _GITHUB_HOSTS:
        return None, None

    parts = [p for p in parsed.path.split("/") if p]
    # api.github.com/repos/<owner>/<name>/...
    if parsed.netloc.lower() == "api.github.com":
        if len(parts) >= 3 and parts[0] == "repos":
            parts = parts[1:]
        else:
            return None, None

    if len(parts) < 2:
        return None, None

    owner, name = parts[0], _normalize_repo_name(parts[1])
    if owner.lower() in _RESERVED_OWNERS or not name:
        return None, None

    repo = GitHubRepo(owner, name)

    if len(parts) < 4:
        return repo, None

    section, value = parts[2], parts[3]

    if section == "commit" and _SHA_RE.match(value.lower()):
        return repo, PatchRef(repo, "commit", value.lower(), url)
    if section == "commits" and _SHA_RE.match(value.lower()):
        return repo, PatchRef(repo, "commit", value.lower(), url)
    if section == "pull" and value.isdigit():
        return repo, PatchRef(repo, "pull", value, url)
    if section == "compare":
        return repo, PatchRef(repo, "compare", value, url)
    if section == "releases" and value == "tag" and len(parts) >= 5:
        return repo, PatchRef(repo, "release", parts[4], url)

    return repo, None


def extract_from_references(urls: Iterable[str]) -> tuple[set, list]:
    """Pull every distinct repo and patch ref out of a list of URLs."""
    repos: set = set()
    patches: list = []
    for url in urls:
        repo, patch = parse_github_url(url)
        if repo is not None:
            repos.add(repo)
        if patch is not None:
            patches.append(patch)
    return repos, patches


def pick_primary_repo(repos: set, patches: list) -> GitHubRepo | None:
    """Best guess at *the* repo for a CVE.

    A CVE often references several repos (the vulnerable project, a PoC repo,
    an exploit writeup, a distro's packaging repo). Repos that carry an actual
    patch reference are far more likely to be the real project, so prefer them.
    """
    if patches:
        # Most-referenced patched repo wins.
        counts: dict = {}
        for p in patches:
            counts.setdefault(p.repo.key, [p.repo, 0])[1] += 1
        return max(counts.values(), key=lambda rv: rv[1])[0]
    unique = {r.key: r for r in repos}
    if len(unique) == 1:
        return next(iter(unique.values()))
    return None
