"""Coverage stats for iteration 2: message LFs + the new diff LFs.

    .venv/bin/python gen_coverage2_md.py [--out Coverage_Iteration2.md]

Applies all 38 LFs (20 message + 18 diff) to data/interim/diff_sample.parquet -
the stratified sample built by fetch_diff_sample.py, since diffs do not exist
for the full 72k corpus - and writes a Markdown report with per-LF coverage,
per-family behaviour, gold recall, and LabelModel ablations.
"""
from __future__ import annotations

import argparse
import io
import math
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import numpy as np
import pandas as pd
from snorkel.labeling import LFAnalysis, PandasLFApplier
from snorkel.labeling.model import LabelModel, MajorityLabelVoter

from commit_labels.lfs import (ABSTAIN, ALL_LFS, ALL_LFS_WITH_DIFF,
                               DIFF_CONJUNCTION_LFS, DIFF_LF_FAMILIES,
                               DIFF_LFS, DIFF_MITIGATION_LFS,
                               DIFF_SURFACE_LFS, NEGATIVE_LFS, NOT_SEC,
                               POSITIVE_LFS, SECURITY, _hunks, _is_doc_path)

ROOT = Path(__file__).resolve().parent
GOLD_DIFFS = ROOT / "data" / "interim" / "gold_diffs"

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
p.add_argument("--out", type=Path, default=ROOT / "Coverage_Iteration2.md")
p.add_argument("--class-balance", type=float, default=0.03)
p.add_argument("--threshold", type=float, default=0.5)
p.add_argument("--epochs", type=int, default=500)
p.add_argument("--seed", type=int, default=42)
args = p.parse_args()


def wilson(k: int, n: int) -> tuple[float, float]:
    """95% Wilson interval for a proportion - honest CI on small counts."""
    if n == 0:
        return (0.0, 0.0)
    z, phat = 1.96, k / n
    denom = 1 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x: float) -> str:
    return f"{100 * x:.2f}%"


# ------------------------------------------------------------------- load
full = pd.read_parquet(ROOT / "data" / "interim" / "commits.parquet")
sample = pd.read_parquet(ROOT / "data" / "interim" / "diff_sample.parquet")
sample = sample.rename(columns={"diff": "diff_text"})[["sha", "stratum", "diff_text"]]

df = full.merge(sample, on="sha", how="inner")
assert len(df) == len(sample), f"join lost rows: {len(df)} vs {len(sample)}"

# Precompute hunk text once instead of 18 times per row inside the LFs.
added, removed = [], []
for text in df["diff_text"]:
    a, r = _hunks({"diff_text": text, "is_merge": False})
    added.append(a)
    removed.append(r)
df["diff_added"] = added
df["diff_removed"] = removed

gold = df["is_cve_fix"].to_numpy()
gold_idx = np.flatnonzero(gold)
control_idx = np.flatnonzero((df["stratum"] == "control").to_numpy())

release_only = set()
for i in gold_idx:
    f = GOLD_DIFFS / f"{df.iloc[i]['sha']}.patch"
    if not f.exists():
        continue
    paths = set(re.findall(r"^diff --git a/.* b/(.*)$", f.read_text(errors="replace"),
                           re.M))
    if paths and not any(CODE_EXT.search(q) and not RELEASE_ISH.search(q)
                         for q in paths):
        release_only.add(int(i))
code_gold = np.array([i for i in gold_idx if int(i) not in release_only])

# ------------------------------------------------------------------- apply
names = [lf.name for lf in ALL_LFS_WITH_DIFF]
L = PandasLFApplier(lfs=ALL_LFS_WITH_DIFF).apply(df=df, progress_bar=False)
col = {n: j for j, n in enumerate(names)}
msg_cols = [col[lf.name] for lf in ALL_LFS]
diff_cols = [col[lf.name] for lf in DIFF_LFS]
pos_msg_cols = [col[lf.name] for lf in POSITIVE_LFS]
neg_msg_cols = [col[lf.name] for lf in NEGATIVE_LFS]
mit_cols = [col[lf.name] for lf in DIFF_MITIGATION_LFS]
conj_cols = [col[lf.name] for lf in DIFF_CONJUNCTION_LFS]
surf_cols = [col[lf.name] for lf in DIFF_SURFACE_LFS]


def fit(cols: list[int], label: str) -> dict:
    """Fit a LabelModel on a subset of LF columns; return gold/flag counts."""
    sub = L[:, cols]
    mv = MajorityLabelVoter(cardinality=2).predict(L=sub)
    lm = LabelModel(cardinality=2, verbose=False)
    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        lm.fit(L_train=sub, n_epochs=args.epochs, lr=0.01, seed=args.seed,
               class_balance=[1 - args.class_balance, args.class_balance])
        probs = lm.predict_proba(L=sub)[:, SECURITY]
    no_vote = (sub == ABSTAIN).all(axis=1)
    preds = np.where(probs >= args.threshold, SECURITY, NOT_SEC)
    preds = np.where(no_vote, ABSTAIN, preds)
    return {
        "label": label, "n_lfs": len(cols),
        "gold": int((preds[gold_idx] == SECURITY).sum()),
        "code_gold": int((preds[code_gold] == SECURITY).sum()),
        "mv_gold": int((mv[gold_idx] == SECURITY).sum()),
        "flagged": int((preds == SECURITY).sum()),
        "flagged_control": int((preds[control_idx] == SECURITY).sum()),
        "no_vote": int(no_vote.sum()),
    }


ablations = [
    fit(msg_cols, "message LFs only (iteration 1)"),
    fit(msg_cols + mit_cols, "message + 6 mitigation LFs"),
    fit(msg_cols + mit_cols + conj_cols, "message + mitigation + conjunction"),
    fit(msg_cols + diff_cols, "all 38 (adds the 6 surface vetoes)"),
    fit(diff_cols, "diff LFs only"),
]

buf = io.StringIO()
with redirect_stdout(buf), redirect_stderr(buf):
    summary = LFAnalysis(L=L, lfs=ALL_LFS_WITH_DIFF).lf_summary(Y=gold.astype(int))

# ------------------------------------------------------------------- write
out: list[str] = []
w = out.append

w("# LF coverage — iteration 2 (diff-aware LFs)")
w("")
w("Iteration 1 measured 20 message LFs on all 72,166 commits and found the "
  "positive side recovering 2 of 49 gold fixes. This iteration adds **18 diff "
  "LFs** — six vulnerability classes × (surface touched, mitigation added, both) "
  "— and re-measures. Generated by `gen_coverage2_md.py`.")
w("")

w("## Why the denominator changed")
w("")
w("`git show` needs blob bytes, which the blobless clones refetch one commit at "
  "a time: **~400 ms and ~41 KB of patch per commit**, so all 72,166 would be "
  "roughly 8 hours and 3 GB. Diffs were therefore fetched for a stratified "
  "sample (`fetch_diff_sample.py` → `data/interim/diff_sample.parquet`, "
  f"{len(df):,} rows, "
  f"{df['diff_text'].str.len().sum() / 1e6:.0f} MB after dropping doc files and "
  "minified bundles):")
w("")
w("| Stratum | Rows | What it is for |")
w("| --- | --- | --- |")
for s, why in [("gold", "all 49 advisory-confirmed fixes — exact recall"),
               ("positive", "every commit a positive *message* LF already votes "
                            "on — where a diff LF must confirm or deny"),
               ("control", "uniform random sample of everything else — unbiased "
                           "estimate of corpus-wide coverage")]:
    w(f"| `{s}` | {int((df['stratum'] == s).sum()):,} | {why} |")
w("")
w("**Read every coverage number below against the right denominator.** "
  "Corpus-wide coverage is estimated on the `control` stratum only, with a 95% "
  "Wilson interval. Numbers on the whole sample are inflated by construction — "
  "the sample is 44% message-LF positives.")
w("")

w("## Headline")
w("")
w("| Metric | Iteration 1 | Iteration 2 |")
w("| --- | --- | --- |")
base, best = ablations[0], ablations[3]
w(f"| LFs | 20 | 38 |")
w(f"| Gold fixes with any positive vote | 9 of 49 | "
  f"{int(((L[np.ix_(gold_idx, pos_msg_cols + mit_cols + conj_cols)]) == SECURITY).any(axis=1).sum())} of 49 |")
w(f"| Gold recovered (LabelModel) | {base['gold']} of 49 | {best['gold']} of 49 |")
w(f"| Gold recovered (majority vote) | {base['mv_gold']} of 49 | "
  f"{best['mv_gold']} of 49 |")
w("")
w("*(Iteration-1 column is recomputed on these same "
  f"{len(df):,} rows so the comparison is apples-to-apples, not against the "
  "full-corpus fit.)*")
w("")

w("## Do the new LFs fire where they should?")
w("")
w("Per family, on the 49 gold fixes. `conjunction` is the surface∧mitigation LF "
  "the two halves exist to support.")
w("")
w("| Family | Surface LF vetoes on gold | Mitigation LF hits on gold | "
  "Conjunction hits on gold |")
w("| --- | --- | --- | --- |")
for fam, surf, mit, conj in DIFF_LF_FAMILIES:
    sv = int((L[gold_idx, col[surf.name]] == NOT_SEC).sum())
    mh = int((L[gold_idx, col[mit.name]] == SECURITY).sum())
    ch = int((L[gold_idx, col[conj.name]] == SECURITY).sum())
    w(f"| {fam} | {sv} | {mh} | {ch} |")
w("")
n_conj_gold = int((L[np.ix_(gold_idx, conj_cols)] == SECURITY).any(axis=1).sum())
n_mit_gold = int((L[np.ix_(gold_idx, mit_cols)] == SECURITY).any(axis=1).sum())
n_diffpos_gold = int((L[np.ix_(gold_idx, mit_cols + conj_cols)] == SECURITY)
                     .any(axis=1).sum())
n_surf_veto_gold = int((L[np.ix_(gold_idx, surf_cols)] == NOT_SEC).any(axis=1).sum())
w(f"- A conjunction LF fires on **{n_conj_gold} of 49** gold fixes "
  f"({n_conj_gold}/{len(code_gold)} of the code-bearing ones).")
w(f"- Some diff-positive LF fires on **{n_diffpos_gold} of 49** "
  f"(a mitigation LF on {n_mit_gold}; every conjunction hit implies its own "
  "mitigation hit, so these overlap by construction).")
w(f"- A surface LF vetoes **{n_surf_veto_gold} of 49**.")
w("")
w("Which gold commits, and what fired — the whole point of the exercise:")
w("")
w("| Commit | `subject` | Diff LFs firing |")
w("| --- | --- | --- |")
SHORT = {"SQL injection": "sqli", "XSS / DOM injection": "xss",
         "Path traversal": "path", "Missing authorization": "authz",
         "Memory safety": "mem", "Resource exhaustion": "dos"}
for i in gold_idx:
    hits = []
    for fam, surf, mit, conj in DIFF_LF_FAMILIES:
        tag = SHORT[fam.split(" (")[0]]
        if L[i, col[conj.name]] == SECURITY:
            hits.append(f"**{tag}:fix**")
        elif L[i, col[mit.name]] == SECURITY:
            hits.append(f"{tag}:mitigation")
        if L[i, col[surf.name]] == NOT_SEC:
            hits.append(f"~~{tag}:veto~~")
    if not hits:
        continue
    r = df.iloc[i]
    subj = (r["subject"] or "").replace("|", "\\|")[:52]
    w(f"| [`{r['sha'][:10]}`](docs/cve-fix-commits.md#{r['sha'][:12]}) "
      f"`{r['repo'].split('/')[-1]}` | {subj} | " + ", ".join(hits) + " |")
w("")

w("### The two gold fixes a surface LF still vetoes")
w("")
for i in gold_idx:
    vetoes = [DIFF_LF_FAMILIES[k][1].name for k in range(len(DIFF_LF_FAMILIES))
              if L[i, col[DIFF_LF_FAMILIES[k][1].name]] == NOT_SEC]
    if not vetoes:
        continue
    r = df.iloc[i]
    w(f"- [`{r['sha'][:10]}`](docs/cve-fix-commits.md#{r['sha'][:12]}) "
      f"`{r['repo']}` — {r['subject']} — vetoed by "
      + ", ".join(f"`{v}`" for v in vetoes))
w("")
w("`6f363ec6f7` is a genuine limit of patch-text matching: the fix *moves* a "
  "NULL check ahead of `net_buf_reset()`, so the added and removed line sets are "
  "identical and no regex over the hunk can tell the order changed. "
  "`77dcb20a74` deletes an unused JSONP branch — defensible either way.")
w("")

w("## Per-LF coverage, new diff LFs")
w("")
w("`control` is the corpus-wide estimate (n="
  f"{len(control_idx):,}, 95% Wilson CI). `sample` is the raw count over all "
  f"{len(df):,} diffed rows and is *not* a corpus rate.")
w("")
w("| LF | Polarity | Role | Fired (sample) | Control coverage | 95% CI | "
  "Gold hits |")
w("| --- | --- | --- | --- | --- | --- | --- |")
role = {}
for fam, surf, mit, conj in DIFF_LF_FAMILIES:
    role[surf.name] = "surface"
    role[mit.name] = "mitigation"
    role[conj.name] = "conjunction"
for lf in DIFF_LFS:
    j = col[lf.name]
    pol = NOT_SEC if role[lf.name] == "surface" else SECURITY
    fired = int((L[:, j] == pol).sum())
    k = int((L[control_idx, j] == pol).sum())
    lo, hi = wilson(k, len(control_idx))
    gh = int((L[gold_idx, j] == pol).sum())
    w(f"| `{lf.name}` | {'NOT_SEC' if pol == NOT_SEC else 'SECURITY'} | "
      f"{role[lf.name]} | {fired:,} | {pct(k / len(control_idx))} ({k}) | "
      f"{pct(lo)}–{pct(hi)} | {gh} |")
w("")

w("## LabelModel ablations")
w("")
w("Same rows, same seed, same `--class-balance "
  f"{args.class_balance}` / `--threshold {args.threshold}`; only the LF set "
  "changes. `flagged` counts commits labeled `security`.")
w("")
w("| LF set | LFs | Gold | Code-bearing gold | Majority vote | Flagged | "
  "Flagged in control |")
w("| --- | --- | --- | --- | --- | --- | --- |")
for a in ablations:
    w(f"| {a['label']} | {a['n_lfs']} | {a['gold']}/49 | "
      f"{a['code_gold']}/{len(code_gold)} | {a['mv_gold']}/49 | "
      f"{a['flagged']:,} | {a['flagged_control']:,} |")
w("")
w("The honest reading: **majority vote over the diff LFs is where the gain is**, "
  "and the fitted LabelModel still throws most of it away — the same pathology "
  "iteration 1 found, now with better LFs underneath it. The conjunction LFs are "
  "by construction perfectly correlated with their two components, which is "
  "exactly the conditional-independence violation Snorkel warns about, so the "
  "`message + mitigation + conjunction` row should be read as an upper bound on "
  "what this model class will do without an explicit dependency structure.")
w("")

w("## What the new positives fire on outside gold")
w("")
w(f"On the {len(control_idx):,}-commit random control stratum, these are the "
  "commits a conjunction LF flagged. This is the precision check, and it has to "
  "be read as positive-unlabeled: a commit here is *not* automatically a false "
  "positive, it is a commit no advisory named.")
w("")
w("| Commit | Repo | `subject` | Conjunction LF |")
w("| --- | --- | --- | --- |")
shown = 0
for i in control_idx:
    fired = [lf.name for lf in DIFF_CONJUNCTION_LFS if L[i, col[lf.name]] == SECURITY]
    if not fired:
        continue
    if shown >= 25:
        break
    r = df.iloc[i]
    subj = (r["subject"] or "").replace("|", "\\|")[:56]
    w(f"| `{r['sha'][:10]}` | `{r['repo'].split('/')[-1]}` | {subj} | "
      + ", ".join(f"`{f}`" for f in fired) + " |")
    shown += 1
total_ctrl_conj = int((L[np.ix_(control_idx, conj_cols)] == SECURITY)
                      .any(axis=1).sum())
w("")
w(f"{total_ctrl_conj} of {len(control_idx):,} control commits "
  f"({pct(total_ctrl_conj / len(control_idx))}) trip at least one conjunction "
  f"LF{'; the table shows the first 25' if total_ctrl_conj > 25 else ''}. "
  "Extrapolated to the corpus that is roughly "
  f"{int(total_ctrl_conj / len(control_idx) * len(full)):,} commits — a "
  "hand-reviewable pile, which is the point of building high-precision LFs "
  "rather than broad ones.")
w("")

w("## Snorkel `LFAnalysis`, all 38 LFs")
w("")
w("On the sample. `Coverage` here is sample coverage, not corpus coverage.")
w("")
w("```text")
with pd.option_context("display.width", 200, "display.max_columns", 20):
    w(summary.to_string())
w("```")
w("")

w("## What to change in iteration 3")
w("")
w("Ranked by control-stratum firing rate against gold hits — the closest thing "
  "to a precision proxy available without hand labeling. Corpus firings are the "
  "control rate extrapolated to all "
  f"{len(full):,} commits; since only 49 are known positives, a rate of even "
  "0.4% means a few hundred commits per gold hit, so \"precise\" here is "
  "relative, not absolute:")
w("")
w("| Conjunction LF | Gold hits | Control coverage | Verdict |")
w("| --- | --- | --- | --- |")
_rank = []
for fam, surf, mit, conj in DIFF_LF_FAMILIES:
    j = col[conj.name]
    k = int((L[control_idx, j] == SECURITY).sum())
    _rank.append((k / len(control_idx), int((L[gold_idx, j] == SECURITY).sum()),
                  conj.name, k))
for rate, gh, nm, k in sorted(_rank):
    est = int(rate * len(full))
    if not gh:
        verdict = "no gold evidence yet"
    elif rate <= 0.001:
        verdict = "high precision — keep as-is"
    elif rate <= 0.005:
        verdict = f"usable, but ~{est:,} corpus firings per {gh} gold hit(s) — hand-verify"
    elif rate <= 0.015:
        verdict = f"loose — ~{est:,} corpus firings"
    else:
        verdict = f"too loose — ~{est:,} corpus firings, tighten"
    w(f"| `{nm}` | {gh} | {pct(rate)} ({k}) | {verdict} |")
w("")
w("1. **`lf_diff_sqli_fix` is the model citizen**: 3 gold hits and zero control "
  "firings. That is what the surface∧mitigation construction was supposed to "
  "buy, and it worked because both halves are specific — `db_escape(`-style "
  "calls next to actual SQL keywords.")
w("2. **The memory family is the loosest** — `lf_diff_bounds_guard_added` at "
  "4.17% of control and `lf_diff_memory_safety_fix` at 1.73%. `if (x < len)` is "
  "just a loop bound in most C, and requiring a rejection statement in the same "
  "patch only narrowed it so far. Next step: require the guard and the "
  "rejection on *adjacent* lines rather than anywhere in the patch.")
w("3. **The surface vetoes barely matter.** Adding them changed neither gold "
  "recall nor the flagged count in the ablation table. They are cheap, they "
  "cost 2 gold fixes, and their real value is negative coverage in code files "
  "where `lf_docs_only`/`lf_tests_only` are silent — worth keeping, not worth "
  "tuning next.")
w("4. **The bottleneck is still the LabelModel, not the LFs.** Majority vote "
  "reaches 22 of 49; the fitted model converts 11. Iteration 1 diagnosed why "
  "(every positive LF learns an accuracy below 0.5); the conjunction LFs make it "
  "worse by being deterministic functions of their components. Fix the model "
  "configuration — dependency structure or learned class balance — before "
  "adding a seventh vulnerability class.")
w("")

w("## Method notes, and what these numbers do not say")
w("")
w("1. **The patterns were derived from the gold diffs**, not from memory — "
   "`db_escape()` wrapping in FrontAccounting, `dangerous_url?` in mdex, an "
   "ownership predicate in invidious, `if (len < SIZE) return -E...` in Zephyr, "
   "a `strings.Builder` replacing `+=` in fzf. That makes gold hits partly "
   "in-sample: the conjunction LFs were tuned until they fired on commits I had "
   "already read. Treat the 49-commit recall as a sanity check, not an unbiased "
   "estimate, and the control-stratum rates as the honest measurement.")
w("2. **Four defects found and fixed while building this**, each measured:")
w("   - mitigation LFs fired on CHANGELOG prose (a `chore(main): release 0.2.3` "
   "commit matched the XSS mitigation off its own release notes) → hunks from "
   "doc/changelog/`.changeset` files are now excluded")
w("   - `lf_diff_path_op_touched` vetoed all 7 cpython tarfile backports → "
   "surface LFs now withhold their veto when any changed file is security-named "
   "(those diffs touch `Misc/NEWS.d/next/Security/…`)")
w("   - the DoS surface matched any `for`/`while`/`push(`/`+=`, vetoing a real "
   "stack-exhaustion fix → narrowed to characteristically unbounded shapes")
w("   - \"mitigation present in added, absent in removed\" missed the "
   "FrontAccounting SQLi patch, where rewritten lines carry `db_escape` on both "
   "sides → replaced with a count-increase test")
w("   - merge commits fired the conjunctions constantly: a `--first-parent` "
   "diff is the entire side branch, so 7 of the first 25 control-stratum "
   "firings were `Merge branch 'main' into …` → `_hunks()` now returns empty "
   "for merges, which dropped control conjunction firings from 4.10% to 2.77% "
   "with no change in gold recall (`lf_merge_commit` already covers them)")
w("   Surface vetoes on gold went from 18 of 49 to 2 of 49 across those "
   "changes.")
w("3. **Truncation order matters more than the cap.** The craftcms XSS fix "
   "touches `ElementTableSorter.js` *after* 4.6 MB of `cp.js` and `cp.js.map`, "
   "so capping the raw patch at 512 KB left the LFs reading nothing but "
   "minified JavaScript and the fix scored zero. Both the fetcher and "
   "`_hunks()` now filter doc files and bundle-sized sections *first* and cap "
   "the remainder; that one change is the difference between `lf_diff_xss_fix` "
   "firing on that commit and not. 200 of the 5,451 sample rows were affected, "
   "and 472 rows have no code hunks at all once docs and bundles are removed.")
w("4. **\"Mitigation added\" needed two definitions.** Counting guard lines "
   "misses the Zephyr ND-validation fix, which expands existing `if (length < "
   "sizeof(...))` checks so the guard count stays level while `goto drop` "
   "statements multiply. The memory LF therefore fires when either guards *or* "
   "rejections increase.")
w("5. **`x.diff` is a trap.** On a pandas Series that attribute resolves to "
   "`Series.diff`, the method — every diff LF silently reads a bound method and "
   "abstains. Hence the column is `diff_text` and `_field()` has an isinstance "
   "guard.")
w("6. **Coverage on the `positive` stratum is not a corpus rate** and no number "
   "in this report treats it as one.")
w("7. **Still unmeasured: real precision.** Everything here is recall against 49 "
   "known positives plus firing rates. To get precision, hand-label a sample of "
   "the control-stratum firings above.")
w("")

args.out.write_text("\n".join(out) + "\n")
print(f"wrote {args.out.name} ({args.out.stat().st_size:,} bytes, {len(out)} lines)")
