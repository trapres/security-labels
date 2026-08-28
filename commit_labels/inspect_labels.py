"""Script 4: look at what the labeler actually did, so you can tune the LFs.

    python -m commit_labels.inspect_labels                 # summary + gold triage
    python -m commit_labels.inspect_labels --lf lf_vuln_class --n 20
    python -m commit_labels.inspect_labels --missed        # gold fixes we lost
    python -m commit_labels.inspect_labels --review 50 --out review.csv

This is the loop you'll spend the most time in. Iterating on ``lfs.py`` without
looking at samples is how you end up with confident nonsense.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from . import config
from .lfs import ABSTAIN, ALL_LFS, NOT_SEC, SECURITY

LF_NAMES = [lf.name for lf in ALL_LFS]


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--labeled", type=Path, default=config.LABELED_PATH)
    p.add_argument("--n", type=int, default=15, help="rows per sample")
    p.add_argument("--lf", type=str, default=None,
                   help="show commits a specific LF fired on")
    p.add_argument("--missed", action="store_true",
                   help="advisory-confirmed fixes we did NOT label security")
    p.add_argument("--repo", type=str, default=None, help="filter to one repo")
    p.add_argument("--review", type=int, default=None, metavar="N",
                   help="sample N predicted-security commits for hand review")
    p.add_argument("--out", type=Path, default=None,
                   help="write the --review sample to CSV")
    p.add_argument("--seed", type=int, default=0)
    return p.parse_args(argv)


def load(path: Path) -> pd.DataFrame:
    if path.exists():
        return pd.read_parquet(path)
    alt = path.with_suffix(".jsonl")
    if alt.exists():
        return pd.read_json(alt, lines=True)
    raise FileNotFoundError(f"{path} not found - run `label` first.")


def main(argv=None) -> int:
    args = parse_args(argv)
    df = load(args.labeled)
    if args.repo:
        df = df[df["repo"] == args.repo]

    if args.lf:
        return _show_lf(df, args.lf, args.n)
    if args.missed:
        return _show_missed(df)
    if args.review:
        return _review_sample(df, args.review, args.out, args.seed)

    _summary(df)
    _show_missed(df)
    return 0


def _summary(df: pd.DataFrame) -> None:
    print(f"{len(df)} commits, {df['repo'].nunique()} repos\n")
    counts = df["label"].value_counts()
    for value, name in ((SECURITY, "security"), (NOT_SEC, "not-sec"),
                        (ABSTAIN, "abstain")):
        n = int(counts.get(value, 0))
        print(f"  {name:9} {n:>7}  ({100*n/len(df):5.2f}%)")

    print("\nPer-repo security rate:")
    per = (
        df.assign(sec=df["label"] == SECURITY)
        .groupby("repo")
        .agg(commits=("sha", "size"), security=("sec", "sum"))
    )
    per["rate"] = (100 * per["security"] / per["commits"]).round(2)
    print(per.sort_values("rate", ascending=False).to_string())


def _show_lf(df: pd.DataFrame, lf_name: str, n: int) -> int:
    if lf_name not in df.columns:
        print(f"Unknown LF '{lf_name}'. Available:\n  " + "\n  ".join(LF_NAMES))
        return 1
    fired = df[df[lf_name] != ABSTAIN]
    print(f"{lf_name} fired on {len(fired)} / {len(df)} commits "
          f"({100*len(fired)/len(df):.2f}%)\n")
    sample = fired.sample(min(n, len(fired)), random_state=0)
    for _, r in sample.iterrows():
        print(f"[{r[lf_name]}] {r['repo']} {r['sha'][:10]}  {r['subject'][:100]}")
    return 0


def _show_missed(df: pd.DataFrame) -> int:
    if "is_cve_fix" not in df.columns or not df["is_cve_fix"].any():
        print("\nNo advisory-confirmed fixes in this dataset.")
        return 0
    gold = df[df["is_cve_fix"]]
    missed = gold[gold["label"] != SECURITY]
    print(f"\n=== {len(missed)} / {len(gold)} advisory-confirmed fixes not "
          f"labeled security ===")
    if missed.empty:
        return 0

    # Which negative LF vetoed each one? This is the fastest route to a better
    # LF set: a negative firing on a known fix is a bug in that LF.
    vetoes: dict = {}
    for _, r in missed[missed["label"] == NOT_SEC].iterrows():
        for name in LF_NAMES:
            if name in df.columns and r[name] == NOT_SEC:
                vetoes[name] = vetoes.get(name, 0) + 1
    if vetoes:
        print("\nNegative LFs vetoing a known fix (each one is a false negative):")
        for name, count in sorted(vetoes.items(), key=lambda kv: -kv[1]):
            print(f"  {name:32} {count}")

    n_abstain = int((missed["label"] == ABSTAIN).sum())
    print(f"\n{n_abstain} got no vote at all - no positive LF recognized them. "
          f"Read their subjects and add coverage:")
    for _, r in missed[missed["label"] == ABSTAIN].head(15).iterrows():
        print(f"  {r['cve_id'] or '-':18} {r['subject'][:90]}")
    return 0


def _review_sample(df, n: int, out: Path | None, seed: int) -> int:
    """Draw a sample to hand-label, so you can estimate real precision."""
    pool = df[df["label"] == SECURITY]
    if pool.empty:
        print("Nothing labeled security.")
        return 1
    sample = pool.sample(min(n, len(pool)), random_state=seed)
    cols = ["repo", "sha", "prob_security", "subject", "cve_id", "is_cve_fix"]
    sample = sample[cols].sort_values("prob_security", ascending=False)
    sample.insert(0, "verdict", "")  # you fill this in: 1 / 0

    if out:
        sample.to_csv(out, index=False)
        print(f"Wrote {len(sample)} rows to {out}.")
        print("Fill the 'verdict' column with 1 (security) or 0 (not), then "
              "precision = mean(verdict).")
    else:
        with pd.option_context("display.width", 200, "display.max_colwidth", 90):
            print(sample.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
