"""Fetch commit diffs for a bounded candidate + control sample.

    .venv/bin/python fetch_diff_sample.py [--control 3000] [--jobs 8]

Writes data/interim/diff_sample.parquet with columns (sha, repo, diff, stratum).

Why a sample and not the whole corpus: `git show` needs blob bytes, which a
blobless clone refetches from the promisor remote one commit at a time. Measured
at ~400 ms/commit and ~41 KB of patch text per commit, so all 72,166 commits
would be ~8 hours and ~3 GB. The strata below are chosen so every number in the
coverage report has a defensible denominator:

  gold      - all 49 advisory-confirmed fixes. Gives exact recall.
  positive  - every commit any positive message LF already votes on. This is
              where a diff LF has to earn its keep by confirming or denying.
  control   - a uniform random sample of everything else. Coverage measured here
              is an unbiased estimate of corpus-wide coverage, with a binomial
              CI you can actually quote.
"""
from __future__ import annotations

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
from snorkel.labeling import PandasLFApplier

from commit_labels.lfs import POSITIVE_LFS, SECURITY, _is_doc_path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "interim" / "diff_sample.parquet"
GOLD_CACHE = ROOT / "data" / "interim" / "gold_diffs"
MAX_PATCH_BYTES = 512_000   # bound disk, applied *after* prefiltering
MAX_FILE_SECTION = 200_000  # a bigger single-file patch is a minified bundle


def prefilter(patch: str) -> str:
    """Drop doc/changelog sections and minified bundles, then cap.

    Order matters. Capping the raw patch first loses the real hunk whenever a
    bundle sorts ahead of it: the craftcms XSS fix touches
    ElementTableSorter.js *after* 4.6 MB of cp.js and cp.js.map, so a naive
    [:512_000] left the LFs reading nothing but minified JavaScript.
    """
    out, cur, path = [], [], ""
    def flush():
        if not cur or not path:
            return
        body = "\n".join(cur)
        if _is_doc_path(path) or len(body) > MAX_FILE_SECTION:
            return
        out.append(body)
    for line in patch.split("\n"):
        if line.startswith("diff --git "):
            flush()
            parts = line.split(" b/", 1)
            path = parts[1] if len(parts) == 2 else ""
            cur = [line]
        else:
            cur.append(line)
    flush()
    return "\n".join(out)[:MAX_PATCH_BYTES]

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--control", type=int, default=3000)
p.add_argument("--jobs", type=int, default=8)
p.add_argument("--seed", type=int, default=42)
args = p.parse_args()

df = pd.read_parquet(ROOT / "data" / "interim" / "commits.parquet")

print(f"applying {len(POSITIVE_LFS)} positive LFs to pick the candidate stratum...")
L_pos = PandasLFApplier(lfs=POSITIVE_LFS).apply(df=df, progress_bar=False)
has_pos = (L_pos == SECURITY).any(axis=1)

gold_mask = df["is_cve_fix"].to_numpy()
pos_mask = has_pos & ~gold_mask
rest = np.flatnonzero(~gold_mask & ~pos_mask)
rng = np.random.default_rng(args.seed)
control = rng.choice(rest, size=min(args.control, len(rest)), replace=False)

strata = {}
for i in np.flatnonzero(gold_mask):
    strata[int(i)] = "gold"
for i in np.flatnonzero(pos_mask):
    strata[int(i)] = "positive"
for i in control:
    strata[int(i)] = "control"

print(f"gold={int(gold_mask.sum())}  positive={int(pos_mask.sum())}  "
      f"control={len(control)}  total={len(strata)}")


def one(idx: int) -> dict:
    row = df.iloc[idx]
    sha, repo = row["sha"], row["repo"]

    cached = GOLD_CACHE / f"{sha}.patch"
    if cached.exists():
        return {"sha": sha, "repo": repo, "stratum": strata[idx],
                "diff": prefilter(cached.read_text(errors="replace"))}

    d = ROOT / "data" / "repos" / repo.replace("/", "__")
    cmd = ["git", "-C", str(d), "show", "--patch", "--format=", "--no-color", "-M"]
    if bool(row["is_merge"]):
        cmd.append("--first-parent")
    try:
        proc = subprocess.run(cmd + [sha], capture_output=True, text=True,
                              errors="replace", timeout=180)
        diff = prefilter(proc.stdout) if proc.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        diff = ""
    return {"sha": sha, "repo": repo, "stratum": strata[idx], "diff": diff}


idxs = sorted(strata)
rows = []
with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    for k, rec in enumerate(pool.map(one, idxs), 1):
        rows.append(rec)
        if k % 500 == 0:
            print(f"  {k}/{len(idxs)}")

out = pd.DataFrame(rows)
empty = int((out["diff"].str.len() == 0).sum())
OUT.parent.mkdir(parents=True, exist_ok=True)
out.to_parquet(OUT, index=False)
print(f"wrote {OUT.relative_to(ROOT)}: {len(out):,} rows, "
      f"{out['diff'].str.len().sum() / 1e6:.0f} MB of patch text, "
      f"{empty} empty (failed or genuinely empty diff)")
print(out.groupby("stratum").size().to_string())
