"""Coverage / conflict stats for the shipped labeling functions.

    .venv/bin/python gen_coverage_md.py [--out Coverage_Iteration1.md]
                                        [--class-balance 0.03]

Re-applies every LF in lfs.py to data/interim/commits.parquet (lfs.py is the
source of truth, not the stale columns in commits_labeled.parquet), then writes
a Markdown report: per-LF coverage/overlap/conflict, behaviour on the gold set
split by whether the gold commit actually contains code, and the end-to-end
LabelModel result.
"""
from __future__ import annotations

import argparse
import io
import re
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import numpy as np
import pandas as pd
from snorkel.labeling import LFAnalysis, PandasLFApplier
from snorkel.labeling.model import LabelModel, MajorityLabelVoter

from commit_labels.lfs import (ABSTAIN, ALL_LFS, NEGATIVE_LFS, NOT_SEC,
                               POSITIVE_LFS, SECURITY)

ROOT = Path(__file__).resolve().parent
DIFF_CACHE = ROOT / "data" / "interim" / "gold_diffs"

# Same classifier as gen_gold_md.py: does this commit's diff contain code?
CODE_EXT = re.compile(
    r"\.(c|h|cc|cpp|py|go|rs|ts|tsx|js|jsx|php|cr|ex|exs|java|rb|sh|yaml|yml|"
    r"json|conf|inc)$"
)
RELEASE_ISH = re.compile(
    r"(CHANGELOG|RELEASE|README|\.changeset/|docs?/|man/|\.md$|manifest\.json$|"
    r"Chart\.yaml$|mix\.exs$|constants\.go$|install(\.ps1)?$|app\.php$|VERSION)",
    re.IGNORECASE,
)

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--out", type=Path, default=ROOT / "Coverage_Iteration1.md")
p.add_argument("--commits", type=Path,
               default=ROOT / "data" / "interim" / "commits.parquet")
p.add_argument("--class-balance", type=float, default=0.03)
p.add_argument("--threshold", type=float, default=0.5)
p.add_argument("--epochs", type=int, default=500)
p.add_argument("--seed", type=int, default=42)
args = p.parse_args()

df = pd.read_parquet(args.commits)
gold = df["is_cve_fix"].astype(int).to_numpy()

t0 = time.time()
L = PandasLFApplier(lfs=ALL_LFS).apply(df=df, progress_bar=False)
apply_secs = time.time() - t0

names = [lf.name for lf in ALL_LFS]
pos_names = {lf.name for lf in POSITIVE_LFS}
n, m = L.shape

# ------------------------------------------------------------------ per-LF math
voted = L != ABSTAIN
any_other = np.zeros_like(voted)
conflict = np.zeros_like(voted)
for j in range(m):
    others = np.delete(L, j, axis=1)
    other_voted = (others != ABSTAIN).any(axis=1)
    any_other[:, j] = voted[:, j] & other_voted
    disagrees = ((others != ABSTAIN) & (others != L[:, [j]])).any(axis=1)
    conflict[:, j] = voted[:, j] & disagrees

gold_idx = np.flatnonzero(gold == 1)

# Split gold by "does the diff touch code": a release-only commit cannot be
# recovered from code or message signal, so it should not count against the
# positive LFs. Falls back to treating everything as code-bearing if the diff
# cache is missing.
release_only = set()
if DIFF_CACHE.exists():
    for i in gold_idx:
        patch_file = DIFF_CACHE / f"{df.iloc[i]['sha']}.patch"
        if not patch_file.exists():
            continue
        paths = set(re.findall(r"^diff --git a/.* b/(.*)$",
                               patch_file.read_text(errors="replace"), re.M))
        if paths and not any(CODE_EXT.search(q) and not RELEASE_ISH.search(q)
                             for q in paths):
            release_only.add(int(i))
code_gold = np.array([i for i in gold_idx if i not in release_only])

rows = []
for j, name in enumerate(names):
    pol = SECURITY if name in pos_names else NOT_SEC
    fires = voted[:, j]
    on_gold = int((L[gold_idx, j] == pol).sum())
    on_code_gold = int((L[code_gold, j] == pol).sum()) if len(code_gold) else 0
    rows.append({
        "lf": name,
        "polarity": "SECURITY" if pol == SECURITY else "NOT_SEC",
        "n_fired": int(fires.sum()),
        "coverage": fires.mean(),
        "overlaps": any_other[:, j].mean(),
        "conflicts": conflict[:, j].mean(),
        "gold_fires": on_gold,
        "code_gold_fires": on_code_gold,
    })
stats = pd.DataFrame(rows)
# Filled in after the LabelModel is fit, below.
stats["learned_acc"] = np.nan

# Snorkel's own table, captured verbatim so this report matches `label.py`.
buf = io.StringIO()
with redirect_stdout(buf), redirect_stderr(buf):
    summary = LFAnalysis(L=L, lfs=ALL_LFS).lf_summary(Y=gold)
with pd.option_context("display.width", 200, "display.max_columns", 20):
    snorkel_table = summary.to_string()

# ------------------------------------------------------------------ label model
mv_preds = MajorityLabelVoter(cardinality=2).predict(L=L)
lm = LabelModel(cardinality=2, verbose=False)
buf = io.StringIO()
with redirect_stdout(buf), redirect_stderr(buf):
    lm.fit(L_train=L, n_epochs=args.epochs, lr=0.01, seed=args.seed,
           class_balance=[1 - args.class_balance, args.class_balance])
lm_weights = lm.get_weights()
prob_sec = lm.predict_proba(L=L)[:, SECURITY]
preds = np.where(prob_sec >= args.threshold, SECURITY, NOT_SEC)
no_vote = (L == ABSTAIN).all(axis=1)
preds = np.where(no_vote, ABSTAIN, preds)

stats["learned_acc"] = lm_weights

# Threshold sweep: the probability mass turns out to be nearly degenerate, so
# "just lower the threshold" needs numbers attached.
sweep = []
for t in (0.9, 0.75, 0.5, 0.3, 0.27, 0.2, 0.1):
    flagged = prob_sec >= t
    sweep.append((t, int(flagged.sum()), flagged.mean(),
                  int((flagged & (gold == 1)).sum())))

lm_tp = int(((preds[gold_idx] == SECURITY)).sum())
lm_tp_code = int((preds[code_gold] == SECURITY).sum()) if len(code_gold) else 0
lm_flagged = int((preds == SECURITY).sum())
mv_tp = int((mv_preds[gold_idx] == SECURITY).sum())

# ------------------------------------------------------------------ gold detail
pos_cols = [names.index(lf.name) for lf in POSITIVE_LFS]
neg_cols = [names.index(lf.name) for lf in NEGATIVE_LFS]
gold_pos_votes = (L[np.ix_(gold_idx, pos_cols)] == SECURITY).sum(axis=1)
gold_neg_votes = (L[np.ix_(gold_idx, neg_cols)] == NOT_SEC).sum(axis=1)

# ------------------------------------------------------------------ write it
out: list[str] = []
w = out.append


def pct(x):
    return f"{100 * x:.2f}%"


w("# LF coverage — iteration 1")
w("")
w("Baseline measurement of the LFs shipped in `commit_labels/lfs.py`, before any "
  "tuning. Generated by `gen_coverage_md.py`; re-applies every LF to "
  "`data/interim/commits.parquet` rather than reading the stored columns in "
  "`commits_labeled.parquet`, so `lfs.py` is the only source of truth.")
w("")
w(f"- **{n:,} commits**, {df.repo.nunique()} repos, **{m} LFs** "
  f"({len(POSITIVE_LFS)} positive / {len(NEGATIVE_LFS)} negative)")
w(f"- Gold: **{len(gold_idx)}** advisory-confirmed fixes "
  f"({100 * len(gold_idx) / n:.3f}% of the corpus)")
if release_only:
    w(f"- Of those, **{len(release_only)} change no code** (version/changelog only "
      "— see `docs/cve-fix-commits.md`), so the code-bearing gold set is "
      f"**{len(code_gold)}**. Both numbers are reported throughout.")
w(f"- `PandasLFApplier` over the full corpus: {apply_secs:.1f}s")
w(f"- LabelModel: `--class-balance {args.class_balance}`, "
  f"`--threshold {args.threshold}`, {args.epochs} epochs, seed {args.seed}")
w("")

w("## Headline")
w("")
n_no_vote = int(no_vote.sum())
gold_no_pos = int((gold_pos_votes == 0).sum())
w(f"| Metric | Value |")
w("| --- | --- |")
w(f"| Commits with at least one LF vote | {n - n_no_vote:,} "
  f"({pct(1 - n_no_vote / n)}) |")
w(f"| Commits with no vote at all | {n_no_vote:,} ({pct(n_no_vote / n)}) |")
w(f"| Labeled `security` by LabelModel | {lm_flagged:,} ({pct(lm_flagged / n)}) |")
w(f"| Gold fixes recovered (all {len(gold_idx)}) | {lm_tp} "
  f"({lm_tp / len(gold_idx):.1%} recall) |")
if release_only:
    w(f"| Gold fixes recovered (code-bearing {len(code_gold)}) | {lm_tp_code} "
      f"({lm_tp_code / len(code_gold):.1%} recall) |")
w(f"| Gold fixes recovered by majority vote | {mv_tp} |")
w(f"| Gold fixes with **no positive LF vote** | {gold_no_pos} of "
  f"{len(gold_idx)} |")
w(f"| Gold fixes vetoed by ≥1 negative LF | "
  f"{int((gold_neg_votes > 0).sum())} of {len(gold_idx)} |")
w("")

w("## Per-LF coverage")
w("")
w("`coverage` = fraction of the corpus this LF votes on. `overlaps` = fraction "
  "where it votes *and* some other LF also votes. `conflicts` = fraction where "
  "another LF votes the opposite label. `on gold` counts how often the LF fires "
  "**in its own polarity** on an advisory-confirmed fix — for a positive LF that "
  "is a true positive, for a negative LF it is a false negative.")
w("")
w("| LF | Polarity | Fired | Coverage | Overlaps | Conflicts | on gold "
  f"({len(gold_idx)}) | on code-bearing gold ({len(code_gold)}) | learned acc. |")
w("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
for _, r in stats.iterrows():
    w(f"| `{r['lf']}` | {r['polarity']} | {r['n_fired']:,} | "
      f"{pct(r['coverage'])} | {pct(r['overlaps'])} | {pct(r['conflicts'])} | "
      f"{r['gold_fires']} | {r['code_gold_fires']} | "
      f"{r['learned_acc']:.3f} |")
w("")
_pos_acc = stats[stats.polarity == "SECURITY"].learned_acc
_neg_acc = stats[stats.polarity == "NOT_SEC"].learned_acc
w("`learned acc.` is `LabelModel.get_weights()` — the accuracy the model inferred "
  "for each LF *without* seeing gold. **Every positive LF came out below 0.5** "
  f"(range {_pos_acc.min():.2f}–{_pos_acc.max():.2f}, median "
  f"{_pos_acc.median():.2f}; the two highest are `lf_cwe_id` and "
  "`lf_bounds_check_in_parser`, which fire 5 and 4 times total, so the model has "
  "almost no evidence about them). **Every negative LF came out above "
  f"{_neg_acc.min():.2f}.** The model concluded the positives are worse than a "
  "coin flip. That single fact explains the recall number, and the next section "
  "shows how.")
w("")
dead = stats[stats.n_fired == 0]["lf"].tolist()
if dead:
    w(f"**Dead LFs ({len(dead)}): " + ", ".join(f"`{d}`" for d in dead)
      + ".** Zero votes on 72k commits — they cost nothing but contribute "
        "nothing, and the LabelModel cannot learn an accuracy for them.")
    w("")
thin = stats[(stats.n_fired > 0) & (stats.coverage < 0.01)]["lf"].tolist()
if thin:
    w("**Under 1% coverage: " + ", ".join(f"`{d}`" for d in thin)
      + ".** The README's own threshold for \"contributes almost nothing.\"")
    w("")

w("### Positive vs negative, in aggregate")
w("")
pos_stats = stats[stats.polarity == "SECURITY"]
neg_stats = stats[stats.polarity == "NOT_SEC"]
any_pos = (L[:, pos_cols] == SECURITY).any(axis=1)
any_neg = (L[:, neg_cols] == NOT_SEC).any(axis=1)
w("| Group | LFs | Union coverage | Sum of individual coverage |")
w("| --- | --- | --- | --- |")
w(f"| Positive | {len(pos_stats)} | {pct(any_pos.mean())} | "
  f"{pct(pos_stats.coverage.sum())} |")
w(f"| Negative | {len(neg_stats)} | {pct(any_neg.mean())} | "
  f"{pct(neg_stats.coverage.sum())} |")
w("")
w(f"Both polarities fire together on {pct((any_pos & any_neg).mean())} of the "
  f"corpus ({int((any_pos & any_neg).sum()):,} commits) — that is the conflict "
  "mass the LabelModel has to arbitrate.")
w("")

w("## Snorkel's own `LFAnalysis` table")
w("")
w("Verbatim, for comparison with what `python -m commit_labels.label` prints. "
  "`Emp. Acc.` here treats every non-gold commit as a true negative, which it is "
  "not — see the README's warning. Read `Coverage`/`Conflicts`, not `Emp. Acc.`")
w("")
w("```text")
w(snorkel_table)
w("```")
w("")

w("## Why recall is 2 and not 9")
w("")
w(f"Majority vote recovers **{mv_tp}** gold fixes; the fitted LabelModel recovers "
  f"**{lm_tp}**. The LFs are not what lost the other {mv_tp - lm_tp} — the model "
  "is. Every gold fix that any positive LF votes on:")
w("")
w("| Commit | Positive LFs firing | `prob_security` | Majority vote | LabelModel "
  f"@ {args.threshold} |")
w("| --- | --- | --- | --- | --- |")
for i in gold_idx:
    hits = [names[j] for j in pos_cols if L[i, j] == SECURITY]
    if not hits:
        continue
    row = df.iloc[i]
    w(f"| [`{row['sha'][:10]}`](docs/cve-fix-commits.md#{row['sha'][:12]}) | "
      + ", ".join(f"`{h}`" for h in hits)
      + f" | {prob_sec[i]:.4f} | "
      + ("security" if mv_preds[i] == SECURITY else str(mv_preds[i])) + " | "
      + ("**security**" if preds[i] == SECURITY else "not-sec") + " |")
w("")
w("One positive vote buys `prob_security` ≈ 0.27, which loses to the "
  f"`--threshold {args.threshold}` cutoff every time. Only the two commits where "
  "*two* positive LFs co-fired clear it. With the shipped configuration **a single "
  "positive LF vote can never produce a positive label**, no matter which LF it "
  "is — so adding another narrow, rarely-co-firing positive LF will not move "
  "recall on its own.")
w("")
w("Threshold sweep on the same fitted model:")
w("")
w("| Threshold | Flagged `security` | % of corpus | Gold recovered |")
w("| --- | --- | --- | --- |")
for t, cnt, frac, tp in sweep:
    mark = " ←current" if abs(t - args.threshold) < 1e-9 else ""
    w(f"| {t}{mark} | {cnt:,} | {pct(frac)} | {tp} of {len(gold_idx)} |")
w("")
w("The mass is nearly degenerate: every cutoff from 0.3 to 0.75 gives the exact "
  "same 311 commits, and the entire gain from 2 to 9 happens in the 0.20–0.27 "
  "band at a cost of ~1,700 extra flagged commits. So the real question for "
  "iteration 2 is not the threshold — it is why `class_balance = "
  f"{args.class_balance}` plus 10 near-disjoint positive LFs makes the model "
  "conclude the positives are anti-correlated with the class. Worth testing: "
  "fewer, broader positive LFs; a learned class balance; or Snorkel's dependency "
  "structure for the three advisory-style LFs the README already flags as "
  "correlated.")
w("")
w("*(The fit also emits `divide by zero`/`overflow` `RuntimeWarning`s from "
  "`label_model.py:419` — `log(mu)` on cells no LF ever populates. Expected with "
  "LFs this sparse, but it means the fit is running near the edge of its "
  "numerics.)*")
w("")

w("## Where the gold set is lost")
w("")
w(f"{gold_no_pos} of {len(gold_idx)} gold fixes get **no positive vote**, and "
  f"{int((gold_neg_votes > 0).sum())} are actively vetoed by a negative LF. "
  "Per-commit breakdown:")
w("")
w("| Commit | `subject` | Positive LFs firing | Negative LFs vetoing | Diff has "
  "code? |")
w("| --- | --- | --- | --- | --- |")
for k, i in enumerate(gold_idx):
    row = df.iloc[i]
    pos_hits = [names[j] for j in pos_cols if L[i, j] == SECURITY]
    neg_hits = [names[j] for j in neg_cols if L[i, j] == NOT_SEC]
    subj = (row["subject"] or "").replace("|", "\\|")
    w(f"| [`{row['sha'][:10]}`](docs/cve-fix-commits.md#{row['sha'][:12]}) "
      f"`{row['repo'].split('/')[-1]}` | {subj[:60]} | "
      + (", ".join(f"`{h}`" for h in pos_hits) or "—") + " | "
      + (", ".join(f"`{h}`" for h in neg_hits) or "—") + " | "
      + ("no — release only" if int(i) in release_only else "yes") + " |")
w("")

w("### Negative LFs firing on known fixes")
w("")
veto_counts = {}
for i in gold_idx:
    for j in neg_cols:
        if L[i, j] == NOT_SEC:
            veto_counts.setdefault(names[j], []).append(int(i))
if veto_counts:
    w("| LF | Gold fixes vetoed | of which code-bearing |")
    w("| --- | --- | --- |")
    for name, idxs in sorted(veto_counts.items(), key=lambda kv: -len(kv[1])):
        code_hits = [i for i in idxs if i not in release_only]
        w(f"| `{name}` | {len(idxs)} | {len(code_hits)} |")
    w("")
    w("A veto on a *code-bearing* gold fix is a bug in that LF. A veto on a "
      "release-only gold commit is the LF being right and the gold label being "
      "an artifact — those two cases need opposite remedies, which is why the "
      "column split matters.")
else:
    w("None.")
w("")

w("## Correlated positive LFs")
w("")
w("The README flags `lf_cve_id`, `lf_ghsa_id` and `lf_advisory_language` as "
  "co-firing on advisory-style messages; `LabelModel` assumes conditional "
  "independence and will be overconfident where they do. Pairwise co-fire counts "
  "across the corpus:")
w("")
w("| | " + " | ".join(f"`{lf.name.replace('lf_', '')}`"
                      for lf in POSITIVE_LFS) + " |")
w("| --- |" + " --- |" * len(POSITIVE_LFS))
for a in pos_cols:
    cells = []
    for b in pos_cols:
        both = int(((L[:, a] == SECURITY) & (L[:, b] == SECURITY)).sum())
        cells.append(f"**{both:,}**" if a == b else f"{both:,}")
    w(f"| `{names[a]}` | " + " | ".join(cells) + " |")
w("")
w("Diagonal is each LF's own vote count.")
w("")

w("## Coverage by repo")
w("")
w("Uneven coverage means the LFs are tuned to some projects' commit style and "
  "blind to others'.")
w("")
w("| Repo | Commits | Any vote | Any positive vote | Gold |")
w("| --- | --- | --- | --- | --- |")
by_repo = df.groupby("repo").indices
for repo in sorted(by_repo, key=lambda r: -len(by_repo[r])):
    idx = by_repo[repo]
    w(f"| `{repo}` | {len(idx):,} | {pct((~no_vote[idx]).mean())} | "
      f"{pct(any_pos[idx].mean())} | {int(gold[idx].sum())} |")
w("")

w("## What to change first")
w("")
w("Read off the numbers above, not from intuition:")
w("")
items = []
if dead:
    items.append(
        f"**{len(dead)} LF(s) never fire** "
        f"({', '.join('`' + d + '`' for d in dead)}). Either the trigger "
        "vocabulary is wrong or the fields they need are empty corpus-wide."
    )
items.append(
    f"**The model, not the vocabulary, is the current bottleneck.** "
    f"{mv_tp} of {len(gold_idx)} gold fixes already get a positive vote, and the "
    f"LabelModel converts only {lm_tp} of them. Fix that before writing a single "
    "new regex."
)
top_pos = pos_stats.sort_values("gold_fires", ascending=False).iloc[0]
items.append(
    f"**Positive union coverage is {pct(any_pos.mean())}** and "
    f"{gold_no_pos} of {len(gold_idx)} gold fixes get no positive vote at all. "
    f"The best single positive LF is `{top_pos['lf']}` at "
    f"{top_pos['gold_fires']} gold hits — with {top_pos['n_fired']:,} total "
    "firings, so it is not precise either."
)
items.append(
    f"**The negative side carries the corpus** ({pct(any_neg.mean())} union "
    f"coverage, learned accuracies above 0.95) and only vetoes "
    f"{int((gold_neg_votes > 0).sum())} gold fixes — "
    f"{len([i for i in gold_idx if any(L[i, j] == NOT_SEC for j in neg_cols) and int(i) not in release_only])}"
    " of them code-bearing. Loosen the vetoes last, not first."
)
items.append(
    "**`lf_huge_diff` is running on one leg.** Its `churn > 5000` branch is dead "
    "because `insertions`/`deletions` are `0` for every row (the mine ran without "
    "`--line-stats`); only `n_files > 50` can ever fire."
)
items.append(
    "**The diff is the unexploited signal.** Nothing above reads patch text; "
    f"`data/interim/gold_diffs/` has the patches for all {len(gold_idx)} gold "
    "commits, and `docs/cve-fix-commits.md` shows the message/diff join per "
    "commit."
)
for k, item in enumerate(items, 1):
    w(f"{k}. {item}")
w("")

args.out.write_text("\n".join(out) + "\n")
print(f"applied {m} LFs to {n:,} commits in {apply_secs:.1f}s")
print(f"wrote {args.out.name} ({args.out.stat().st_size:,} bytes, "
      f"{len(out)} lines)")
