# Tuning the labeling functions

Everything here is about `commit_labels/lfs.py`. Read the README first for the
pipeline; this is the deep end.

## The iteration loop

Use `--sample` so you get feedback in seconds instead of minutes:

```bash
$EDITOR commit_labels/lfs.py
.venv/bin/python -m commit_labels.label --sample 10000 --class-balance 0.03
.venv/bin/python -m commit_labels.inspect_labels --missed
```

When a change looks good, drop `--sample` and rerun on everything.

To test one LF in isolation without the full pipeline:

```python
import pandas as pd
from snorkel.labeling import PandasLFApplier, LFAnalysis
from commit_labels.lfs import lf_vuln_class

df = pd.read_parquet("data/interim/commits.parquet")
L = PandasLFApplier([lf_vuln_class]).apply(df)
print(LFAnalysis(L, [lf_vuln_class]).lf_summary())
print(df[L[:, 0] == 1]["subject"].head(30).to_string())
```

That last line matters more than the summary table. **Always read the commits
your LF fires on.** A regex that looks precise on paper picks up surprising
things — `\bdos\b` matches "DOS line endings", `stack overflow` matches links to
the website.

## Writing a good LF

A labeling function is a Python function returning `SECURITY` (1), `NOT_SEC`
(0), or `ABSTAIN` (-1). The contract Snorkel needs:

**Be precise, not comprehensive.** Aim for >80% precision on whatever slice you
do vote on. `LabelModel` estimates each LF's accuracy from agreement patterns
and downweights unreliable ones — but a high-coverage, low-precision LF that
*correlates* with the others will drag the whole model with it. Coverage is
cheap to add later; precision is not recoverable.

**Abstain generously.** `ABSTAIN` is free. A voting LF that's right 55% of the
time is worse than silence.

**Keep LFs independent.** `LabelModel` assumes conditional independence given
the true label. Three LFs that are really the same regex split three ways will
make the model overconfident wherever they co-fire. Check the `Overlaps` and
`Conflicts` columns; near-identical overlap means merge them.

**Write negatives.** Roughly 1–3% of commits are security fixes. Without
negative LFs the model has nothing anchoring the majority class. In the current
LF set the negatives carry most of the discriminative weight — they cover
8–10% of commits each at ~100% agreement with gold, while the positives cover
well under 2%.

## Anti-patterns

| Don't | Why |
| --- | --- |
| Use `is_cve_fix` (or `cve_id`) in an LF | That's the evaluation set. Circular. |
| Match bare `fix` / `security` | ~15% of all commits say "fix". No signal. |
| Add an LF without reading 20 firings | Regexes lie. |
| Tune `--threshold` before fixing LFs | You're moving a point on a bad curve. |
| Trust `Emp. Acc.` as precision | See the README warning — the gold set is positive-only. |

## Interpreting `LFAnalysis`

| Column | Read it as |
| --- | --- |
| `Polarity` | Which labels this LF ever emits. `[1]` = positive-only. |
| `Coverage` | Fraction voted on. <1% is near-useless; >60% is probably too loose. |
| `Overlaps` | Fraction where another LF also votes. |
| `Conflicts` | Fraction where another LF votes the *opposite*. High conflict + high coverage ⇒ one of them is wrong. |
| `Correct` / `Incorrect` / `Emp. Acc.` | Only vs. gold. **Recall is meaningful; precision is not** — the gold set marks known positives, never confirmed negatives. |

## Class balance

`LabelModel` is genuinely sensitive to the assumed prior. Left to learn it, on
data this imbalanced it tends to drift. Set it explicitly:

```bash
--class-balance 0.03    # asserts P(security) = 3%
```

Sanity check: security fixes are typically 1–3% of commits in an actively
maintained project. If your output says 20%, your positive LFs are too loose.
If it says 0.05%, they're too tight — or `--class-balance` is fighting them.

## Ideas worth trying, roughly by value per hour

1. **Diff-content LFs.** The single biggest win available. Message text can't
   see that a patch added a bounds check, swapped `strcpy` for `strncpy`, or
   introduced an `escape()` call. Requires `--keep-full-clone` plus `git show`
   per commit — scope it to candidates, not all 72k.

2. **Fix the over-aggressive vetoes.** `lf_version_bump` and `lf_feature_commit`
   each killed 5 known fixes in testing. Squash-merge repos land real fixes
   under `chore: release 1.2.3`. Consider abstaining when the diff also touches
   source files.

3. **CVE-fix neighborhood.** Commits sharing a PR number, a day, or a file set
   with a known fix are strong positives. Backports to release branches are
   near-duplicate subjects — cheap to detect and currently missed.

4. **Issue-tracker cross-reference.** `gh-87451`, `#6552`, `GHSA-...` in a
   message can be resolved against the GitHub API for a security label. Costs
   rate limit; high precision.

5. **A weak classifier as an LF.** Train logistic regression on TF-IDF over
   messages using the gold fixes as positives, then threshold it high. Snorkel
   handles a noisy model-as-LF fine — this is a normal pattern.

6. **File-extension priors.** Memory-safety CVEs concentrate in `.c`/`.cpp`;
   injection bugs in web templates. Weak on its own, useful in conjunction.

## After the LabelModel

The probabilistic labels are training data, not the end product. The standard
Snorkel move is to train a discriminative model on them, which generalizes past
what the LFs literally match:

```python
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

df = pd.read_parquet("data/processed/commits_labeled.parquet")
train = df[df.label != -1]                      # drop abstains

X = TfidfVectorizer(max_features=50_000, ngram_range=(1, 2)).fit_transform(
    train["message"]
)
clf = LogisticRegression(max_iter=1000)
clf.fit(X, train["label"], sample_weight=abs(train["prob_security"] - 0.5) * 2)
```

Weighting by confidence lets the model discount the commits the LabelModel was
unsure about. Hold out repos, not rows — commits within a repo share vocabulary
and authors, so a random row split will overstate your accuracy badly.

`torch` and `tensorflow` are already in the venv if you'd rather fine-tune a
transformer over commit messages.
