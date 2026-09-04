"""Extract advisory / fix-commit citations from changelog hunks.

    .venv/bin/python fetch_patch_citations.py [--jobs 8]

Writes data/interim/patch_citations.parquet with columns
(sha, patch_cites_advisory, patch_cites_fix_commit).

Mechanism C in Progress.md. Release commits and merges often say nothing
themselves while their *changelog* names the fix: mdex's release commit links
`([2817147](.../commit/2817147f5b87...))`, and craftcms's
`Merge branch '4.x-advisories'` ships a CHANGELOG entry citing two GHSAs. Both
signals live in exactly the hunks `fetch_diff_sample.py` throws away - it
strips doc files so the mitigation LFs don't fire on release-note prose - so
this fetches them separately and deliberately.

Scoping, and why it is affordable:

* Only **release-ish or merge** commits are fetched (7,128 of 72,166). A
  non-release commit that cites a CVE almost always says so in its message
  too, where `lf_cve_id` already sees it.
* Only **doc pathspecs** are fetched, not whole patches, so git materialises a
  handful of blobs instead of the entire tree diff. Measured at 282 ms per
  commit versus ~400 ms for a full `git show`, and far less data.

Staleness: `patch_cites_fix_commit` is seeded by POSITIVE_LFS votes, so editing
a positive LF can change it. Re-run this script after doing so, or accept that
the column reflects the older LF set.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

from commit_labels.features import is_release_subject, seed_positive_mask

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "interim" / "patch_citations.parquet"

# Changelogs, release notes, changesets. Git's default pathspec globbing lets
# `*` cross directory separators, so these reach nested package changelogs.
DOC_PATHSPECS = ["*.md", "*.rst", ".changeset/*", "*NEWS*", "*CHANGES*"]

ADVISORY_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b|\bGHSA(?:-[0-9a-z]{4}){3}\b",
                            re.IGNORECASE)
SHA_REF_RE = re.compile(r"\b([0-9a-f]{7,40})\b")

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--jobs", type=int, default=8)
args = p.parse_args()

df = pd.read_parquet(ROOT / "data" / "interim" / "commits.parquet")

print("applying the positive LFs to seed the fix-commit lookup...")
seed = seed_positive_mask(df)
# sha prefix -> is that commit positively voted on. Seven chars is what
# changelog generators emit; longer refs still match on their first seven.
positive_prefix = {}
for sha, is_pos in zip(df["sha"], seed):
    positive_prefix[sha[:7]] = bool(is_pos)

candidates = df[[is_release_subject(s) for s in df["subject"]]
                | df["is_merge"].to_numpy()]
print(f"candidates (release-ish or merge): {len(candidates):,} of {len(df):,}; "
      f"seed positives: {int(seed.sum()):,}")


def doc_patch(sha: str, repo: str, is_merge: bool) -> str:
    cmd = ["git", "-C", str(ROOT / "data" / "repos" / repo.replace("/", "__")),
           "show", "--patch", "--format=", "--no-color"]
    if is_merge:
        cmd.append("--first-parent")
    try:
        proc = subprocess.run(cmd + [sha, "--"] + DOC_PATHSPECS,
                              capture_output=True, text=True, errors="replace",
                              timeout=180)
        return proc.stdout if proc.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        return ""


def one(row) -> dict:
    text = doc_patch(row.sha, row.repo, bool(row.is_merge))
    added = "\n".join(l for l in text.split("\n")
                      if l.startswith("+") and not l.startswith("+++"))
    cites_fix = False
    for ref in set(SHA_REF_RE.findall(added)):
        pre = ref[:7]
        if pre == row.sha[:7]:
            continue                      # a commit citing itself proves nothing
        if positive_prefix.get(pre):
            cites_fix = True
            break
    return {
        "sha": row.sha,
        "patch_cites_advisory": bool(ADVISORY_ID_RE.search(added)),
        "patch_cites_fix_commit": cites_fix,
    }


rows = []
with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    for k, rec in enumerate(pool.map(one, candidates.itertuples()), 1):
        rows.append(rec)
        if k % 1000 == 0:
            print(f"  {k}/{len(candidates)}")

out = pd.DataFrame(rows)
OUT.parent.mkdir(parents=True, exist_ok=True)
out.to_parquet(OUT, index=False)

gold = df.set_index("sha")["is_cve_fix"]
adv = out[out.patch_cites_advisory]
fix = out[out.patch_cites_fix_commit]
print(f"\nwrote {OUT.relative_to(ROOT)}: {len(out):,} rows")
print(f"  patch_cites_advisory   : {len(adv):,} firings, "
      f"{int(gold.reindex(adv.sha).sum())} on gold")
print(f"  patch_cites_fix_commit : {len(fix):,} firings, "
      f"{int(gold.reindex(fix.sha).sum())} on gold")
