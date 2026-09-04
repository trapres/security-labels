"""Dataframe-level features that a per-row LF cannot compute for itself.

Snorkel hands an LF one row at a time, so any signal that depends on *other*
commits has to be precomputed into a column first. That is what this module is
for, and right now it holds exactly one such feature.

``release_window_positive`` — mechanism B in ``Progress.md``. An advisory often
names the *release* that shipped a fix rather than the fix itself: 15 of the 49
gold rows are release commits, 10 of which change no code at all
(``release: Zephyr 4.4.0`` is one line in ``VERSION``). Nothing in the commit
can tell you it shipped a security fix. What *can* tell you is the range: if any
commit between the previous release and this one carries a positive LF vote,
this release shipped it.

Two properties worth stating plainly:

* **It is chained.** The feature is seeded by the other positive LFs' votes, so
  its yield grows as they improve, and it is zero if they find nothing. It must
  never be seeded by its own LF's votes - that is a feedback loop, which is why
  ``DERIVED_LFS`` is excluded from the seed set.
* **It needs the whole corpus.** A sampled release commit's window is mostly
  unsampled commits, so compute this on ``commits.parquet`` and join the column
  onto any subset afterwards. Computing it on a sample undercounts badly.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd
from snorkel.labeling import PandasLFApplier

from .lfs import POSITIVE_LFS, SECURITY, VERSION_BUMP_RE

# Release/version commit subjects. Deliberately broad - it only selects *which*
# commits the window feature applies to, and a non-release commit that slips in
# still needs a positive vote in its window to fire.
RELEASE_SUBJECT_RE = re.compile(
    r"^(?:v?\d+\.\d+(?:\.\d+)?(?:-\w+)?)\s*$|version packages|^finish \d|"
    r"^release[: ]|^chore\(.*release",
    re.IGNORECASE,
)

FEATURE_COL = "release_window_positive"


def is_release_subject(subject: str | None) -> bool:
    s = (subject or "").strip()
    return bool(RELEASE_SUBJECT_RE.search(s) or VERSION_BUMP_RE.search(s))


def seed_positive_mask(df: pd.DataFrame) -> np.ndarray:
    """Votes from the content positives, used to seed the window feature.

    Excludes DERIVED_LFS by construction: this reads POSITIVE_LFS only.
    """
    L = PandasLFApplier(lfs=POSITIVE_LFS).apply(df=df, progress_bar=False)
    return (L == SECURITY).any(axis=1)


def release_windows(df: pd.DataFrame, seed_positive: np.ndarray) -> np.ndarray:
    """True for release commits whose range since the previous release has a hit.

    The range excludes the release commit itself - the claim is "the commits I
    am shipping contain a fix", not "I am a fix". Measured difference is small
    (251 firings excluding self vs 254 including it, same 5 gold hits) but the
    exclusive form avoids stacking a second, correlated vote onto a commit some
    other LF already voted on.

    Known limitation: "previous release" is per repo, ordered by author date,
    with no notion of branch. craftcms ships 4.x and 5.x release lines in
    parallel, so their windows interleave. Fixing that needs branch topology,
    which a blobless clone has but this feature does not use.
    """
    fires = np.zeros(len(df), dtype=bool)
    work = pd.DataFrame({
        "repo": df["repo"].to_numpy(),
        "author_date": df["author_date"].to_numpy(),
        "row": np.arange(len(df)),
        "seed": np.asarray(seed_positive, dtype=bool),
        "is_release": [is_release_subject(s) for s in df["subject"]],
    })
    for _, grp in work.groupby("repo", sort=False):
        grp = grp.sort_values("author_date")
        rows = grp["row"].to_numpy()
        is_rel = grp["is_release"].to_numpy()
        seed = grp["seed"].to_numpy()
        prev = -1
        for k in range(len(grp)):
            if not is_rel[k]:
                continue
            if seed[prev + 1:k].any():
                fires[rows[k]] = True
            prev = k
    return fires


def add_release_window_feature(
    df: pd.DataFrame, seed_positive: np.ndarray | None = None
) -> pd.DataFrame:
    """Return df with the ``release_window_positive`` column added.

    Call this on the full corpus before applying LFs. ``lf_release_of_security_fix``
    abstains everywhere if the column is missing, so forgetting it silently
    disables that LF rather than raising.
    """
    if seed_positive is None:
        seed_positive = seed_positive_mask(df)
    out = df.copy()
    out[FEATURE_COL] = release_windows(df, seed_positive)
    return out
