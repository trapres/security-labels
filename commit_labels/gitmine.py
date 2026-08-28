"""Clone repos and extract commit records via plain ``git`` subprocess calls.

Deliberately no GitPython: shelling out is faster for bulk log reads and lets us
use ``--filter=blob:none``, which is the difference between a 2 GB clone and a
40 MB one. We never need file contents, only messages and per-file stats.

Message bodies contain newlines, so a single ``git log --name-status`` pass
can't be parsed unambiguously - the file lines and the body lines are
indistinguishable. We do two passes with control-character separators instead
and join on SHA.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)

RS = "\x1e"  # record separator
FS = "\x1f"  # field separator

_META_FORMAT = FS.join([
    "%H", "%P", "%an", "%ae", "%aI", "%cn", "%ce", "%cI", "%s", "%b",
]) + RS


# Walk branches, not --all. On a blobless clone --all additionally walks every
# tag, and tag objects the partial clone never materialized trigger a one-at-a-
# time promisor refetch: measured 4m23s vs 1.0s on craftcms/cms (1454 tags), and
# on some repos it aborts with "in the commit graph file but not in the object
# database". Branch tips already reach essentially every commit a tag does.
DEFAULT_REFS = "--branches"

_GIT = [
    "git",
    # The commit-graph in a partial clone can advertise commits whose objects
    # are absent, which turns into a hard failure mid-walk. Reading it is only
    # an optimization, so switch it off.
    "-c", "core.commitGraph=false",
    # git reads .mailmap to rewrite author names. That's a *blob*, absent from
    # a blobless clone, and with lazy fetch off the whole log aborts with
    # "unable to read mailmap object at HEAD:.mailmap". We want the raw
    # committer identity anyway - lf_bot_author matches on the real address.
    "-c", "log.mailmap=false",
]


class GitError(RuntimeError):
    pass


@dataclass
class Commit:
    sha: str
    repo: str
    parents: list
    author_name: str
    author_email: str
    author_date: str
    committer_name: str
    committer_email: str
    committer_date: str
    subject: str
    body: str
    files: list = field(default_factory=list)
    insertions: int = 0
    deletions: int = 0

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1

    @property
    def message(self) -> str:
        return (self.subject + "\n\n" + self.body).strip()

    def to_row(self) -> dict:
        return {
            "sha": self.sha,
            "repo": self.repo,
            "parents": " ".join(self.parents),
            "n_parents": len(self.parents),
            "is_merge": self.is_merge,
            "author_name": self.author_name,
            "author_email": self.author_email,
            "author_date": self.author_date,
            "committer_name": self.committer_name,
            "committer_email": self.committer_email,
            "committer_date": self.committer_date,
            "subject": self.subject,
            "body": self.body,
            "message": self.message,
            "files": self.files,
            "n_files": len(self.files),
            "insertions": self.insertions,
            "deletions": self.deletions,
        }


def _run(
    args: list,
    cwd: Path | None = None,
    timeout: int = 1800,
    no_lazy_fetch: bool = False,
) -> str:
    env = None
    if no_lazy_fetch:
        # Only for cheap existence checks (resolve_sha), where "not here" is a
        # valid answer. Do NOT set this on a log walk: a blobless clone legitimately
        # needs a handful of on-demand fetches to complete a tree diff, and
        # disabling them turns a working repo into a hard failure.
        env = dict(os.environ, GIT_NO_LAZY_FETCH="1")
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        env=env,
    )
    if proc.returncode != 0:
        raise GitError(
            f"{' '.join(args[:4])}... exited {proc.returncode}: "
            f"{proc.stderr.strip()[:500]}"
        )
    return proc.stdout


def clone_or_update(
    clone_url: str,
    dest: Path,
    blobless: bool = True,
    timeout: int = 1800,
) -> Path:
    """Bare-clone a repo, or fetch if it's already on disk."""
    if (dest / "HEAD").exists() or (dest / ".git").exists():
        log.debug("fetching %s", dest.name)
        try:
            _run(["git", "fetch", "--all", "--prune", "--quiet"],
                 cwd=dest, timeout=timeout)
        except GitError as exc:
            log.warning("fetch failed for %s: %s", dest.name, exc)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["git", "clone", "--bare", "--quiet"]
    if blobless:
        # Commits + trees, no file contents. Enough for --name-status (tree
        # diffs compare blob OIDs, never blob bytes) but NOT for --numstat.
        args.append("--filter=blob:none")
    args += [clone_url, str(dest)]
    log.info("cloning %s", clone_url)
    _run(args, timeout=timeout)
    return dest


def iter_commits(
    repo_dir: Path,
    repo_name: str,
    since: str | None = None,
    until: str | None = None,
    max_commits: int | None = None,
    stats_mode: str = "names",
    refs: str = DEFAULT_REFS,
) -> Iterator[Commit]:
    """Yield Commit records from a cloned repo.

    ``stats_mode``:
      ``"names"``   changed file paths only, via ``--name-status``. Works on a
                    blobless clone because tree diffs never need blob content.
                    This is the default and the only sane option at scale.
      ``"numstat"`` also insertions/deletions. Requires blob content, so on a
                    ``--filter=blob:none`` clone git refetches every blob from
                    the promisor remote - minutes per repo, and it outright
                    fails on large histories. Use only with a full clone.
      ``"none"``    skip the second pass entirely.
    """
    window = (since, until, max_commits, refs)
    if stats_mode == "numstat":
        try:
            stats = _read_stats(repo_dir, *window, "--numstat")
        except GitError as exc:
            log.warning(
                "numstat failed for %s (%s); falling back to --name-status. "
                "Clone with --keep-full-clone if you need line counts.",
                repo_name, str(exc)[:120],
            )
            stats = _read_stats(repo_dir, *window, "--name-status")
    elif stats_mode == "names":
        stats = _read_stats(repo_dir, *window, "--name-status")
    else:
        stats = {}

    args = _GIT + ["log", refs, f"--pretty=tformat:{_META_FORMAT}"]
    args += _window_args(since, until, max_commits)

    raw = _run(args, cwd=repo_dir)
    for record in raw.split(RS):
        record = record.strip("\n")
        if not record.strip():
            continue
        fields = record.split(FS)
        if len(fields) < 10:
            log.debug("skipping malformed record in %s", repo_name)
            continue
        sha = fields[0].strip()
        files, ins, dels = stats.get(sha, ([], 0, 0))
        yield Commit(
            sha=sha,
            repo=repo_name,
            parents=fields[1].split() if fields[1].strip() else [],
            author_name=fields[2],
            author_email=fields[3],
            author_date=fields[4],
            committer_name=fields[5],
            committer_email=fields[6],
            committer_date=fields[7],
            subject=fields[8],
            body=fields[9],
            files=files,
            insertions=ins,
            deletions=dels,
        )


def _window_args(
    since: str | None, until: str | None, max_commits: int | None
) -> list:
    args = []
    if since:
        args.append(f"--since={since}")
    if until:
        args.append(f"--until={until}")
    if max_commits:
        args.append(f"--max-count={max_commits}")
    return args


def _read_stats(
    repo_dir: Path,
    since: str | None,
    until: str | None,
    max_commits: int | None,
    refs: str,
    mode: str,
) -> dict:
    """Second pass: sha -> (files, insertions, deletions).

    ``--format=%x1e%H`` emits just the marker and SHA, so every following
    non-blank line describes a file in the most recent SHA seen.

    ``--numstat`` lines are ``added \\t removed \\t path``.
    ``--name-status`` lines are ``status \\t path`` (or ``R100 \\t old \\t new``),
    in which case insertions/deletions stay at 0.
    """
    args = _GIT + ["log", refs, mode, f"--format={RS}%H"]
    args += _window_args(since, until, max_commits)

    raw = _run(args, cwd=repo_dir)
    numeric = mode == "--numstat"
    out: dict = {}
    current = None
    # NB: str.splitlines() also splits on \x1e (and \x1c, \x1d, \x85), which
    # would silently swallow the record marker. Split on \n explicitly.
    for line in raw.split("\n"):
        line = line.rstrip("\r")
        if line.startswith(RS):
            current = line[1:].strip()
            out[current] = ([], 0, 0)
            continue
        if not line.strip() or current is None:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue

        files, ins, dels = out[current]
        if numeric:
            added, removed = parts[0], parts[1]
            # Binary files report "-" instead of a count.
            ins += int(added) if added.isdigit() else 0
            dels += int(removed) if removed.isdigit() else 0
        # For renames (R/C) the destination path is last, which is what we want.
        files.append(parts[-1])
        out[current] = (files, ins, dels)
    return out


def resolve_sha(repo_dir: Path, ref: str) -> str | None:
    """Expand a short SHA to full form; None if the object isn't present."""
    try:
        return _run(_GIT + ["rev-parse", f"{ref}^{{commit}}"],
                    cwd=repo_dir, timeout=60, no_lazy_fetch=True).strip()
    except GitError:
        return None
