# README2 — the running delta

`README.md` documents the pipeline as shipped: four steps, 20 message-only
labeling functions, and an honest note that they recover 2 of 49
advisory-confirmed fixes. This file is the **differential story since then**,
maintained at HEAD. It covers what was added, what the numbers actually are
now, which claims in `README.md` are stale, and the traps that cost real time
to find.

Read `README.md` first for the pipeline. Read this for the current state.

---

## State at HEAD

| | `README.md` as written | HEAD |
| --- | --- | --- |
| Labeling functions | 20 (message text only) | **39** = 21 message/metadata + 18 diff |
| Signals available to an LF | `message`, `subject`, `files`, author, counts | + **patch text** (`diff_text`) |
| Pipeline steps | 4 | 4 + 2 side steps (diff dump, diff sample) |
| Gold recall (LabelModel) | 2 of 49 | **11 of 49** |
| Gold recall (majority vote) | — | **29 of 49** |

`ALL_LFS` now holds **21**: the original 20 plus `lf_security_note_path`, which
needs no diff and so belongs with the message/metadata set. `python -m
commit_labels.label` therefore no longer reproduces the numbers in
`Coverage_Iteration1.md` — that file is the 20-LF baseline and is preserved as
such in git (`482126b`); regenerate it only if you want to retire the baseline.
The diff LFs live in `DIFF_LFS`, and `ALL_LFS_WITH_DIFF` is the union.

`lf_security_note_path` fires when a commit changes code *and* a file under a
`security/` or `advisories/` directory. Measured on the full corpus: **546
firings (0.76%), 7 gold hits** — every one of them a cpython `gh-151987` row,
previously the largest single block of missed gold. It has the highest gold-hit
count of any positive LF in the set; the next best is `lf_vuln_class` at 3. See
`Progress.md` mechanism A.

### New files

| File | What it is |
| --- | --- |
| `gen_gold_md.py` | Dumps the gold set + CVE disclosures + diffs → `docs/cve-fix-commits.md` |
| `fetch_diff_sample.py` | Builds the stratified diff sample → `data/interim/diff_sample.parquet` |
| `gen_coverage_md.py` | Iteration-1 coverage report (20 message LFs, full corpus) |
| `gen_coverage2_md.py` | Diff-aware coverage report (all of `ALL_LFS_WITH_DIFF`, diff sample) |
| `docs/cve-fix-commits.md` | 49 gold commits: raw `message`, `git show` diff, NVD/GHSA/OSV links |
| `Coverage_Iteration1.md` | Baseline measurement of the shipped LFs |
| `Coverage_Iteration2.md` | Same, with the 18 diff LFs added, plus ablations |
| `Coverage_Iteration3.md` | Current: 39 LFs, after `lf_security_note_path` landed |

### New data artifacts (all under gitignored `data/`)

| Path | Size | Contents |
| --- | --- | --- |
| `data/interim/gold_diffs/` | 15 MB | `<sha>.patch` + `<sha>.stat` for all 49 gold commits, uncapped |
| `data/interim/diff_sample.parquet` | 27 MB | 5,451 rows × (`sha`, `repo`, `stratum`, `diff`), 85 MB of filtered patch text |

---

## Two side steps added to the pipeline

Neither replaces a numbered step in `README.md`; both hang off step 2's clones.

### Step 2a — dump the gold diffs

```bash
.venv/bin/python gen_gold_md.py            # ~19s cold, ~3s from cache
.venv/bin/python gen_gold_md.py --refresh-diffs
.venv/bin/python gen_gold_md.py --no-diffs
```

Runs `git show --patch --format= --no-color -M <sha>` per gold commit
(`--first-parent` for the one merge, which otherwise shows an empty diff),
caches the uncapped patch under `data/interim/gold_diffs/`, and writes
`docs/cve-fix-commits.md` with the raw commit message and the diff underneath
it. Display caps are stated inline wherever one fires; the `--stat` block is
never capped, so every changed path stays visible.

### Step 2b — build the diff sample

```bash
.venv/bin/python fetch_diff_sample.py --control 3000 --jobs 8   # ≈6 min at 8 jobs
```

**Why a sample.** `git show` needs blob bytes, which a blobless clone refetches
from the promisor remote one commit at a time. Measured on a random 60-commit
sample: **399 ms and 41 KB of patch per commit, 0 failures**. All 72,166 commits
would be roughly 8 hours and 3 GB. Three strata instead:

| Stratum | Rows | Purpose |
| --- | --- | --- |
| `gold` | 49 | every advisory-confirmed fix → exact recall |
| `positive` | 2,402 | every commit a positive *message* LF already votes on → where a diff LF confirms or denies |
| `control` | 3,000 | uniform random sample of the rest → unbiased corpus-wide coverage, with a Wilson CI |

472 of the 5,451 rows end up with no code hunks at all once docs and minified
bundles are filtered. That is not failure: 452 of them are doc-only commits, 11
are merges (excluded deliberately, see traps), and 13 have `n_files == 0`. Every
empty row is accounted for, so treat an empty `diff` as "nothing for a diff LF
to read", not as a fetch error.

---

## The diff LFs

Three LFs per vulnerability class, which is the structure the whole exercise is
built around:

| Role | Votes | Rationale |
| --- | --- | --- |
| surface (`…_touched`) | `NOT_SEC` | The **surface** changed — a SQL query, a DOM sink, a path operation. On its own this is not evidence of a fix; most SQL edits are ordinary. Withholds its veto if a mitigation appears (any family), if the message says anything security-flavoured, or if a changed file is security-named. |
| mitigation (`…_added` / `…_parameterized`) | `SECURITY` | A **mitigation** was newly added — an escape call, a bounds guard, a permission check. Hardening is hardening wherever it lands. |
| conjunction (`…_fix`) | `SECURITY` | **Surface ∧ mitigation.** The conjunction the two halves exist to support, and the highest-precision positive signal in the set. |

The triples, as registered in `DIFF_LF_FAMILIES`:

| Family | Surface | Mitigation | Conjunction |
| --- | --- | --- | --- |
| SQL injection | `lf_diff_sql_query_touched` | `lf_diff_sql_parameterized` | `lf_diff_sqli_fix` |
| XSS / DOM | `lf_diff_dom_sink_touched` | `lf_diff_output_escaping_added` | `lf_diff_xss_fix` |
| Path traversal | `lf_diff_path_op_touched` | `lf_diff_path_normalization_added` | `lf_diff_path_traversal_fix` |
| Missing authz | `lf_diff_resource_lookup_touched` | `lf_diff_authz_check_added` | `lf_diff_authz_fix` |
| Memory safety | `lf_diff_memory_api_touched` | `lf_diff_bounds_guard_added` | `lf_diff_memory_safety_fix` |
| Resource exhaustion | `lf_diff_unbounded_work_touched` | `lf_diff_resource_limit_added` | `lf_diff_dos_hardening_fix` |

"Newly added" is a **count increase** (`_added_more`), not "present in added,
absent in removed". The strict version misses the FrontAccounting SQLi patch,
where rewritten lines carry `db_escape` on both sides but more of them
afterwards.

### The six families, measured

Families were picked by CWE frequency across the 120 fetched CVEs, not by
intuition. Gold hits are out of 49; control coverage is the corpus-wide
estimate from the 3,000-commit control stratum.

| Family | CWEs | Conjunction gold hits | Conjunction control coverage |
| --- | --- | --- | --- |
| SQL injection | 89 | 3 | 0.00% (0 of 3,000) |
| Missing authorization | 862, 863, 639, 285 | 1 | 0.10% |
| XSS / DOM injection | 79 | 1 | 0.37% |
| Resource exhaustion | 400, 407, 770, 674 | 1 | 0.40% |
| Path traversal | 22, 23 | 3 | 0.47% |
| Memory safety | 125, 787, 190, 476 | 2 | 1.73% |

`lf_diff_sqli_fix` is the one that worked exactly as designed: 3 gold hits, zero
firings in 3,000 random commits. Both halves are specific — `db_escape(`-style
calls adjacent to real SQL keywords. The memory family is the loosest, because
`if (x < len)` is just a loop bound in most C.

**Patterns were derived from the gold diffs, not from memory.** `db_escape()`
wrapping in FrontAccounting, `dangerous_url?`/`@omitted_url` in mdex, an
ownership predicate (`playlist.author != user.try &.email`) in invidious,
`if (length < sizeof(...)) goto drop` in Zephyr, a `strings.Builder` replacing
`+=` in fzf. That makes gold hits partly in-sample — treat 49-commit recall as
a sanity check and the control rates as the honest measurement.

---

## What the numbers say now

### Iteration 1 — the shipped 20 LFs, full corpus (72,166 commits)

| Metric | Value |
| --- | --- |
| Commits with any LF vote | 25,970 (35.99%) |
| Positive union coverage / negative union coverage | 3.34% / 33.21% |
| Flagged `security` | 311 (0.43%) |
| Gold recovered — LabelModel / majority vote | **2 / 9** of 49 |
| Gold with no positive vote | 40 of 49 |

The finding that mattered: `LabelModel.get_weights()` puts **every positive LF
below 0.5** (range 0.27–0.45, median 0.28) while every negative sits above 0.96.
One positive vote therefore yields `prob_security` ≈ 0.27 and loses to the 0.5
threshold every time — the only 2 recovered are the 2 where two positive LFs
co-fired. **A single positive LF vote cannot produce a positive label in the
shipped configuration**, so adding another narrow regex LF cannot move recall by
itself. The threshold sweep confirms the mass is nearly degenerate: every cutoff
from 0.3 to 0.75 returns the identical 311 commits.

### Iteration 2 — 38 LFs, diff sample (5,451 commits)

| LF set | LFs | Gold | Majority vote | Flagged in control |
| --- | --- | --- | --- | --- |
| message only | 20 | 1 of 49 | 9 of 49 | 0 |
| message + 6 mitigation | 26 | 7 of 49 | 22 of 49 | 32 |
| message + mitigation + conjunction | 32 | 11 of 49 | 22 of 49 | 86 |
| all 38 (adds surface vetoes) | 38 | **11 of 49** | **22 of 49** | 86 |
| diff LFs only | 18 | 11 of 49 | 18 of 49 | 95 |

Diff-side detail: a conjunction LF fires on 10 of 49 gold fixes, some
diff-positive LF on 18 of 49, and the surface LFs veto only 2 of 49.

Two things to keep straight when comparing tables:

1. **The message-only row is 1, not 2.** It is a refit on the 5,451 sampled rows,
   not the full-corpus fit. Same LFs, different denominator.
2. **The bottleneck is still the model.** Majority vote reaches 22 of 49; the
   fitted LabelModel converts 11. The conjunction LFs make the
   conditional-independence violation worse by construction — each is a
   deterministic function of two other LFs — so read the 32-LF row as an upper
   bound for this model class without an explicit dependency structure.

### Iteration 3 — 39 LFs, after `lf_security_note_path` (same 5,451 commits)

| LF set | LFs | Gold | Majority vote | Flagged | Flagged in control |
| --- | --- | --- | --- | --- | --- |
| message/metadata only | 21 | 1 of 49 | 16 of 49 | 321 | 0 |
| message + 6 mitigation | 27 | 7 of 49 | 29 of 49 | 693 | 34 |
| message + mitigation + conjunction | 33 | 11 of 49 | 29 of 49 | 834 | 87 |
| all 39 (adds surface vetoes) | 39 | **11 of 49** | **29 of 49** | 834 | 87 |
| diff LFs only | 18 | 11 of 49 | 18 of 49 | 430 | 95 |

One LF, `lf_security_note_path`, moved majority vote from 22 to 29 and did not
move the fitted model at all. That is the cleanest demonstration of the point
above: **votes are cheap now, conversion is the constraint.** 29 of 49 rows have
a positive vote and the LabelModel emits 11 of them, because the new LF's
learned accuracy came out at 0.274 — the same sub-0.5 basin as every other
positive — so its single vote yields `prob_security` ≈ 0.27.

Full report: `Coverage_Iteration3.md`, generated with
`gen_coverage2_md.py --iteration 3`.

---

## Corrections to `README.md`

Things the README states that are now wrong, incomplete, or contradicted by
measurement. Fix them there or leave them and rely on this list, but do not
trust the original wording.

| README says | Actually |
| --- | --- |
| "the 20 labeling functions in `lfs.py`" (Step 3) | 38. `ALL_LFS` is still those 20; `ALL_LFS_WITH_DIFF` is the full set. |
| "the shipped LFs recover **2 of 49**" (Current state) | 2 of 49 for message-only on the full corpus — still true. 11 of 49 with the diff LFs on the sample; 22 of 49 by majority vote. |
| Item 1: "**Loosen the vetoes.** `lf_version_bump` and `lf_feature_commit` are killing real fixes" | **Backwards for 10 of the 49.** Those gold commits change no code at all — only version constants, changelogs and release manifests (`0.73.1`, `4.30`, `release: Zephyr 4.4.0`, three `chore(main): release …`, three craftcms `Finish 5.9.x`). The advisory cited the *release*, not the fix. `lf_version_bump` voting `0` there is correct and the gold label is the artifact. Recoverable gold is nearer **39**. The sharper LF is the inverse: *diff touches only version/changelog paths* → `NOT_SEC`. |
| Item 3: "Add a diff-content LF. … This needs `--keep-full-clone` and a `git show` per commit" | **`--keep-full-clone` is not needed.** `git show` works fine on a blobless clone — it lazily refetches just the blobs it needs, 399 ms/commit measured, 0 failures in a 60-commit probe and no unexplained empty results across 5,451. Only `--numstat` triggers the pathological refetch the README warns about, because line counts need every blob and `--name-status` does not. The "scope it to candidates" advice is right, and that is what `fetch_diff_sample.py` does. |
| Output schema: `cve_id` "which CVE, when known" | Single-valued, so a commit fixing several CVEs records only one. `647a18196c` is recorded as CVE-2026-40524 but also fixes CVE-2026-40523; three `mdex_native` commits also fix CVE-2026-53427. `repo_cve_ids` keeps the full list — per-CVE recall is understated by 2 CVEs. |
| `is_cve_fix` "an advisory named this commit" | True, but four CVEs (`CVE-2026-58169/58170/58171/58173`, all `HKUDS/Vibe-Trading`) cite SHAs that do not exist in the clone at all — `git cat-file -t` fails. Rewritten history or a fork. 1,819 commits mined from that repo, zero recoverable gold. |

---

## Traps

Each of these was found by measurement and each would be expensive to
rediscover. Numbers are the measured impact.

1. **`x.diff` silently reads a method.** On a pandas Series that attribute
   resolves to `Series.diff`, so every diff LF reads a bound method and
   abstains — no error, no vote. Hence the column is `diff_text` and `_field()`
   has an `isinstance(val, str)` guard. Any column name colliding with a Series
   attribute (`diff`, `pop`, `count`, `size`, `min`, `max`, `mask`) is the same
   trap.

2. **Filter before you truncate.** The craftcms XSS fix touches
   `ElementTableSorter.js` *after* 4.6 MB of `cp.js` and `cp.js.map`, so capping
   the raw patch at 512 KB left the LFs reading nothing but minified JavaScript
   and the fix scored zero. Both `fetch_diff_sample.py` and `_hunks()` now drop
   doc files and bundle-sized sections *first*, then cap the remainder. 200 of
   5,451 sample rows were affected; it is the difference between
   `lf_diff_xss_fix` firing on that commit and not.

3. **Changelogs describe the fix in prose.** Without excluding doc hunks, a
   `chore(main): release 0.2.3` commit fires the XSS mitigation LF off its own
   release notes. Judge code, not release notes.

4. **Merge commits match everything.** A `--first-parent` diff is the entire
   side branch, so 7 of the first 25 control-stratum conjunction firings were
   `Merge branch 'main' into …`. `_hunks()` now returns empty for merges;
   control conjunction firings dropped 4.10% → 2.77% with no change in gold
   recall (`lf_merge_commit` already covers them).

5. **Over-broad surfaces veto real fixes.** First cut of the surface LFs vetoed
   **18 of 49** gold fixes — including all 7 cpython tarfile backports, whose
   diffs touch `Misc/NEWS.d/next/Security/…`, and a genuine stack-exhaustion fix
   caught by a DoS surface that matched any `for`/`while`/`push(`/`+=`. After
   narrowing the surfaces and adding the three withholding conditions, vetoes
   are **2 of 49**.

6. **One gold fix is invisible to patch matching, permanently.**
   `6f363ec6f7` (Zephyr mcumgr) *moves* a NULL check ahead of
   `net_buf_reset()`. The added and removed line sets are identical, so no regex
   over hunk text can tell the order changed. Not a bug to fix — a limit to
   remember.

---

## Reproduce from a clean checkout

```bash
# steps 1-2 exactly as README.md describes, then:
.venv/bin/python gen_gold_md.py                                  # gold diffs + docs/cve-fix-commits.md
.venv/bin/python gen_coverage_md.py                              # Coverage_Iteration1.md
.venv/bin/python fetch_diff_sample.py --control 3000 --jobs 8    # diff_sample.parquet
.venv/bin/python gen_coverage2_md.py --iteration 3               # Coverage_Iteration3.md
```

Runtimes on the 12-repo / 72,166-commit corpus: `gen_gold_md.py` 3s warm,
`gen_coverage_md.py` 24s (LF application over 72k dominates),
`fetch_diff_sample.py` ≈6 min at `--jobs 8`, `gen_coverage2_md.py` 42s (five
LabelModel fits).

Both coverage scripts take `--class-balance` / `--threshold` and default to
`0.03` / `0.5`, matching the README's recommendation.

### Re-running after an LF edit

Editing `lfs.py` invalidates only the label matrix and the model fits. Every
expensive input — NVD/OSV responses, the clones, `commits.parquet`, the gold
patches, the diff sample — is already on disk, so the loop is one command:

```bash
# edited a message LF (the original 20)?
.venv/bin/python gen_coverage_md.py  --out /tmp/iter1.md    # ~28s
# edited a diff LF?
.venv/bin/python gen_coverage2_md.py --out /tmp/iter2.md    # ~25s
```

Write to `--out` while iterating so the committed baselines stay put, then
regenerate in place when you are happy. Measured breakdown of the 25s: 21s is
applying the 38 LFs to 5,451 rows, 3s is five LabelModel fits, and 1s is
everything else. Model fitting is *not* the cost — regex over patch text is.

Two edits do require re-running `fetch_diff_sample.py` (≈6 min):

1. **Any change to `POSITIVE_LFS`.** The `positive` stratum is *defined* by
   applying them, so membership drifts. Gold recall and control-stratum coverage
   are unaffected — only that stratum goes stale — so this is usually deferrable.
2. **Any change to `DOC_EXT`, `DOC_NAME_RE`, or `_is_doc_path`.** The stored
   patches were prefiltered with them, and the prefiltering is baked into the
   parquet.

For a tighter loop than either report, run the LFs against the 49 cached gold
patches directly (~2s) — that is enough to see whether a new pattern fires
where you intended before paying for a full report.

Diff predicates are memoized per `sha` (`_PRED_CACHE`, `_HUNK_CACHE`), which is
what keeps the application at 21s rather than 34s: each surface LF consults
every family's mitigation predicate for the cross-family veto guard, so an
un-memoized row runs ~120 regex passes over its hunk text. In a long-lived
process — a notebook where you re-run cells after editing patterns — call
`lfs.clear_diff_cache()` first, or the cache will hand back results computed
with the old regexes.

---

## Open items, in priority order

1. **Fix the model, not the LFs.** 29 of 49 gold fixes now get a positive vote
   and the LabelModel converts 11 — mechanism A added 7 votes and 0 labels, so
   this is now unambiguously the binding constraint. Try a dependency structure
   for the deliberately-correlated groups
   (`lf_cve_id`/`lf_ghsa_id`/`lf_advisory_language`, each
   surface/mitigation/conjunction triple, and the new
   `lf_security_note_path`/`lf_security_paths_and_fix` pair, which co-fire 227
   times), or a learned class balance, before adding another mechanism.
2. **Tighten the memory family.** `lf_diff_bounds_guard_added` fires on 4.17% of
   control and `lf_diff_memory_safety_fix` on 1.73% (≈1,250 corpus firings for 2
   gold hits). Require the guard and its rejection on *adjacent* lines rather
   than anywhere in the patch.
3. **Get a real precision number.** Everything measured so far is recall against
   49 known positives plus firing rates. Hand-label the control-stratum firings
   listed in `Coverage_Iteration2.md` — that is the only way out of the
   positive-unlabeled bind, and `inspect_labels --review 50 --out review.csv`
   already exists for it.
4. **Make `cve_id` a set**, or add `cve_ids`, to recover the 2 CVEs currently
   masked by a commit that fixes several.
5. **Add the release-only negative LF** described in the corrections table.
6. **Consider SSRF/open-redirect as family 7** (CWE-918 ×3, CWE-601) — the next
   most common class not yet covered.

---

## Maintaining this file

Update it when any of these change, and keep the numbers sourced from a
regenerated report rather than edited by hand:

- **LF count or `lfs.py` structure** → the State-at-HEAD table and the families
  table.
- **A new coverage iteration** → add a section under "What the numbers say now";
  keep the older iterations' numbers, since the point of this file is the delta.
  Bump `--iteration` and add a matching entry to `CHANGES_SINCE` in
  `gen_coverage2_md.py`, so re-running the same command reproduces the same
  document rather than silently re-framing an old one.
- **A README claim that measurement contradicts** → the corrections table, with
  the number that contradicts it.
- **Time lost to a non-obvious failure** → the traps list. That section has the
  highest ratio of value to length in this repo.
