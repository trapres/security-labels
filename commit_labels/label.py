"""Script 3: apply the labeling functions and fit a Snorkel LabelModel.

    python -m commit_labels.label

Reads data/interim/commits.parquet, writes data/processed/commits_labeled.parquet
with ``label`` (-1/0/1) and ``prob_security`` columns, plus an LF analysis table
to stdout.

Read the LF analysis before you trust the output. The columns that matter:
  Coverage   - fraction of commits the LF votes on. Under ~1% it contributes
               almost nothing; over ~60% it is probably too loose.
  Overlaps   - fraction where another LF also votes.
  Conflicts  - fraction where another LF votes the *other* way. High conflict
               with high coverage means one of the two is wrong.
  Emp. Acc.  - only shown when you pass gold labels (we pass is_cve_fix).
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from snorkel.labeling import LFAnalysis, PandasLFApplier
from snorkel.labeling.model import LabelModel, MajorityLabelVoter

from . import config
from .features import add_release_window_feature
from .lfs import ABSTAIN, ALL_LFS, NOT_SEC, SECURITY

log = logging.getLogger("label")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--commits", type=Path, default=config.COMMITS_PATH)
    p.add_argument("--out", type=Path, default=config.LABELED_PATH)
    p.add_argument(
        "--threshold", type=float, default=0.5,
        help="P(security) above which a commit is labeled 1 (default: 0.5)",
    )
    p.add_argument("--epochs", type=int, default=500)
    p.add_argument("--lr", type=float, default=0.01)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--class-balance", type=float, default=None, metavar="P_SECURITY",
        help="prior P(security). Snorkel is sensitive to this on imbalanced "
             "data; try 0.02-0.05 for real repo history. Default: learned.",
    )
    p.add_argument(
        "--sample", type=int, default=None,
        help="fit on a random N-row sample (quick iteration on the LFs)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def load_commits(path: Path) -> pd.DataFrame:
    if path.exists():
        return pd.read_parquet(path)
    alt = path.with_suffix(".jsonl")
    if alt.exists():
        return pd.read_json(alt, lines=True)
    raise FileNotFoundError(
        f"Neither {path} nor {alt} exists - run mine_commits first."
    )


def main(argv=None) -> int:
    args = parse_args(argv)
    config.setup_logging(args.verbose)
    config.ensure_dirs()

    df = load_commits(args.commits)
    log.info("Loaded %d commits from %d repos", len(df), df["repo"].nunique())

    # Precompute the cross-row feature lf_release_of_security_fix depends on.
    # Must happen before any --sample downsampling: a release commit's window is
    # its neighbours, and sampling deletes them.
    df = add_release_window_feature(df)
    log.info(
        "release_window_positive set on %d commits",
        int(df["release_window_positive"].sum()),
    )

    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=args.seed).reset_index(drop=True)
        log.info("Sampled down to %d rows", len(df))

    applier = PandasLFApplier(lfs=ALL_LFS)
    L = applier.apply(df=df)

    # ---- LF analysis -----------------------------------------------------
    gold = None
    if "is_cve_fix" in df.columns and df["is_cve_fix"].any():
        gold = df["is_cve_fix"].astype(int).to_numpy()
        n_pos = int(gold.sum())
        log.info(
            "Using %d advisory-confirmed fixes as gold labels for LF accuracy. "
            "Note these are only *known* fixes - a commit with gold 0 may still "
            "be a real security fix, so 'Emp. Acc.' understates precision.",
            n_pos,
        )

    analysis = LFAnalysis(L=L, lfs=ALL_LFS).lf_summary(Y=gold)
    print("\n=== Labeling function analysis ===")
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print(analysis)

    n_abstain_all = int((L == ABSTAIN).all(axis=1).sum())
    log.info(
        "%d/%d commits (%.1f%%) got no LF vote at all",
        n_abstain_all, len(df), 100 * n_abstain_all / max(1, len(df)),
    )

    # ---- Baseline for comparison ----------------------------------------
    mv = MajorityLabelVoter(cardinality=2)
    mv_preds = mv.predict(L=L)

    # ---- LabelModel ------------------------------------------------------
    label_model = LabelModel(cardinality=2, verbose=args.verbose)
    balance = (
        [1 - args.class_balance, args.class_balance]
        if args.class_balance is not None
        else None
    )
    label_model.fit(
        L_train=L,
        n_epochs=args.epochs,
        lr=args.lr,
        log_freq=max(1, args.epochs // 5),
        seed=args.seed,
        class_balance=balance,
    )

    probs = label_model.predict_proba(L=L)
    prob_security = probs[:, SECURITY]
    preds = np.where(prob_security >= args.threshold, SECURITY, NOT_SEC)
    # Preserve abstention: a commit no LF voted on gets no label.
    preds = np.where((L == ABSTAIN).all(axis=1), ABSTAIN, preds)

    df = df.copy()
    df["label"] = preds
    df["prob_security"] = prob_security
    df["mv_label"] = mv_preds
    # LF names already start with "lf_", so don't prefix again.
    for lf, col in zip(ALL_LFS, L.T):
        df[lf.name] = col

    _report(df, gold, args.threshold)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    written = _write(df, args.out)
    log.info("Wrote %s", written)

    top = (
        df[df["label"] == SECURITY]
        .nlargest(15, "prob_security")[["repo", "sha", "prob_security", "subject"]]
    )
    print("\n=== Highest-confidence security commits ===")
    with pd.option_context("display.width", 200, "display.max_colwidth", 80):
        print(top.to_string(index=False))

    return 0


def _report(df: pd.DataFrame, gold, threshold: float) -> None:
    n_sec = int((df["label"] == SECURITY).sum())
    n_not = int((df["label"] == NOT_SEC).sum())
    n_abs = int((df["label"] == ABSTAIN).sum())
    print("\n=== Label distribution ===")
    print(f"  security : {n_sec:>7}  ({100*n_sec/len(df):.2f}%)")
    print(f"  not-sec  : {n_not:>7}  ({100*n_not/len(df):.2f}%)")
    print(f"  abstain  : {n_abs:>7}  ({100*n_abs/len(df):.2f}%)")

    if gold is None:
        return

    voted = df["label"] != ABSTAIN
    y_true = gold[voted.to_numpy()]
    y_pred = (df.loc[voted, "label"] == SECURITY).astype(int).to_numpy()

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())

    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    print("\n=== Against advisory-confirmed fixes ===")
    print(f"  known fixes recovered : {tp}/{tp+fn}  (recall {recall:.1%})")
    print(f"  additional flagged    : {fp}")
    print(
        "  Precision is NOT computable here: most of those 'additional' commits\n"
        "  are unlabeled, and many are genuine security fixes that simply never\n"
        "  got a CVE. Hand-review a sample of them to estimate it."
    )


def _write(df: pd.DataFrame, path: Path) -> Path:
    try:
        df.to_parquet(path, index=False)
        return path
    except (ImportError, ValueError) as exc:
        alt = path.with_suffix(".jsonl")
        log.warning("parquet unavailable (%s); writing %s", exc, alt)
        df.to_json(alt, orient="records", lines=True)
        return alt


if __name__ == "__main__":
    raise SystemExit(main())
