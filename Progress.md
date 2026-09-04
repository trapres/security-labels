# Progress — what it would take to reach 40 of 49

> **Status:** mechanisms A, B and C are shipped and verified.
> **A** (`lf_security_note_path`): gold votes 22 → 29, majority vote 22 → 29.
> **B** (`lf_release_of_security_fix` + `commit_labels/features.py`): gold votes
> **29 → 34**, majority vote 29 → 33. LabelModel conversion **unchanged at 11
> through both**, which is the prediction in "The second bottleneck" holding
> three iterations running. Reports: `Coverage_Iteration3.md`,
> `Coverage_Iteration4.md`. The rest of this document is the original analysis;
> its baseline is 22 of 49.

Iteration 2 gets a positive vote on **22 of 49** gold fixes and converts **11**
into a `security` label. This is an analysis of the other 27: what they are, why
they are missed, and what each candidate mechanism would actually buy. Every
number below was measured against the corpus, not estimated — the speculation is
confined to the "what it would take" arithmetic and is labelled as such.

**Short answer: more vulnerability classes will not get you to 40.** Only about
4 of the 27 misses are class-coverage failures. 15 are release commits with no
fix content, and 7 are one cpython fix counted seven times. Crypto CWEs
specifically would return **zero** on this gold set.

40 of 49 *is* reachable — it is exactly the ceiling, since 9 rows are unwinnable
by construction — but the measured path there runs through two release-commit
association mechanisms and a file-path LF, not through new CWE coverage. If you
would rather have headroom than a perfect-play target, re-attributing the
release-commit labels lifts the ceiling to 48; see "Recommendation".

---

## Where the 27 misses actually come from

| Bucket | Rows | Why it misses | Reachable? |
| --- | --- | --- | --- |
| **Release / version commits** | **15** | The advisory cited the *release* that shipped the fix, not the fix. Ten change no code at all; the rest bump a version string or a lockfile. `zephyr 684c9e8f32` is literally `-EXTRAVERSION = rc3` / `+EXTRAVERSION =`. | Only via release↔advisory association, not content |
| **cpython `gh-151987` and its 6 backports** | **7** | One logical fix, seven rows. The patch *passes an existing* `filter_function` through a call — no check is added, no security word appears. | Yes — see mechanism A |
| **Concurrency / lifecycle** | **4** | UAF (`ef47bdf328`), race (`c67b59f891`), NULL-check reorder (`6f363ec6f7`), dead-branch deletion (`77dcb20a74`). The fix is *ordering, locking, or removal* — there is no added mitigation token to find. | Partly — see mechanisms D, E |
| **Merge commit carrying the fix** | **1** | `2c2579c7f1` has `n_files == 0`; its `--first-parent` diff holds the real authorization patch and a changelog citing two GHSAs, but diff LFs deliberately abstain on merges. | Yes — see mechanism C |

That is the whole of it: 15 + 7 + 4 + 1 = 27.

### CWEs among the missed rows

```
CWE-281 ×7   CWE-79 ×7   CWE-639 ×4   CWE-862 ×3   CWE-416 ×2   CWE-87 ×2
CWE-674 ×2   CWE-407 ×1  CWE-22 ×1    CWE-346 ×1   CWE-601 ×1   CWE-940 ×1
CWE-200 ×1   CWE-362 ×1  CWE-476 ×1
```

Read this carefully, because it is misleading at first glance. All 7 CWE-79
misses and all 4 CWE-639 misses are **release commits** — we already catch XSS
and IDOR fixes when the fix itself is the commit (`162321e899` XSS,
`77ad41678b` IDOR). The CWE column is telling you about the *advisory*, not
about a gap in the labeler.

The only genuinely class-shaped gaps are **CWE-416 / 362 / 476** (concurrency
and lifecycle) and **CWE-281** (permission propagation).

---

## "Would more CWE classes help? Crypto?"

Measured, not guessed:

| Question | Answer |
| --- | --- |
| Crypto CWEs among the 27 misses | **0** |
| Crypto CWEs anywhere in the 120 fetched CVEs | CWE-327 ×2, CWE-916 ×1 |
| Gold commits carrying a crypto CWE | 1 (`894adaf713`, CWE-89 + CWE-916) — **already caught** by the SQLi conjunction |

A crypto family (`weak hash → strong hash`, `ECB → GCM`, `Math.random →
crypto.randomBytes`, hardcoded key removal) is a reasonable thing to own
eventually, and it would be cheap to write. On *this* gold set it buys exactly
nothing, and the same is true of the other obvious additions: SSRF (CWE-918 ×3
in the CVE set, 0 in gold), deserialization (CWE-502 ×3, 0 in gold), CSRF (0),
open redirect (CWE-601 ×1, and that row is a release commit).

The reason is structural. Six families already cover the *shapes* that show up
when a fix is a normal code change: escape, parameterize, normalize, gate,
bound, limit. What is left over is not another shape — it is commits where the
fix content isn't in the commit at all, or where the fix is an absence
(a removed branch, a reordered statement, a lock taken).

**Build more classes when the corpus grows, not to move this number.** A
6-month CVE window over 25 repos would put real SSRF, deserialization and crypto
fixes in the gold set; right now they are absent from it.

---

## Measured levers

Each of these I implemented far enough to measure. Cost is corpus-wide firings,
which for a 0.068% base rate is the honest way to read precision.

| # | Mechanism | Gold gain | Measured cost | Firings per gold hit |
| --- | --- | --- | --- | --- |
| **A** ✅ | **Touches a `security/` or `advisories/` directory** — file list only, no diff needed. **Shipped as `lf_security_note_path`.** | **+7** (verified) | 546 of 72,166 (0.76%) | ~78 |
| **B** ✅ | Release commit whose range since the previous release contains a positively-voted commit. **Shipped as `lf_release_of_security_fix`.** | **+5** of 15 (verified) | 251 of 72,166 (0.35%) | ~50 |
| **B′** | Same, restricted to high-confidence positives (`lf_cve_id`, `lf_ghsa_id`, `lf_advisory_language`, `lf_vuln_class`) | +4 of 15 | 162 of 1,442 | ~40 |
| **C** ✅ | Added patch text cites a **positively-labeled commit SHA** (release changelogs link their fixes). **Shipped as `lf_patch_cites_fix_commit`, non-merges only.** | **+2** of 15 (verified) | 49 firings | ~25 |
| **C2** ❌ | CVE/GHSA id in added changelog text. **Rejected.** The projected "+1 merge" survives only with merges included, and craftcms CHANGELOG lines propagate through every branch merge: 344 merge firings for that one row. Without merges: 18 firings, **0 gold**. A focus test on added-line count does not separate them — the smallest contaminated merges add one line containing a GHSA id. | +1 merge, or 0 | 362 with merges / 18 without | ~362 or ∞ |
| **D** | `VULN_CLASS_RE` over **added comment lines only** | +1 new (2 gold total) | 8 of 3,000 control (0.27%) | ~190 |
| **E** | Concurrency / lifecycle family (speculative — not implemented) | +1 to +3 | unknown | unknown |

**B and C are disjoint** — checked, not assumed. B recovers `34be9170f0`,
`684c9e8f32`, `a8eda73630`, `b636a220d8`, `c6cf5a5bd7`; C recovers
`b6f613b1e3`, `c05684d9e7`. Together they take **7 of the 15** release rows,
leaving 8. Both shipped; verified at +5 and +2 respectively.

Notes that matter:

- **A is the best single lever in the set** and the cheapest to write: no diff
  required, it reads `files`. It catches all seven cpython rows because the fix
  adds `Misc/NEWS.d/next/Security/2026-06-23-…rst`. Projects that keep security
  notes in a dedicated directory hand you the label. `lf_security_paths_and_fix`
  already looks at security paths but requires a fix verb in the message, and
  "Pass filter_function to TarFile._extract_one()" has none — which is exactly
  why those 7 are missed today.
- **B and C are chained.** They fire on a release only if the underlying fix is
  already positively labeled, so their yield grows as everything else improves.
  Today B recovers 5 of 15; with A in place, cpython-style releases join the
  reachable set too.
- **C is the most precise thing measured in this whole exercise** — ~38 corpus
  firings — because `release-please` and `changesets` changelogs literally link
  the fix commit (`* **delta:** omit dangerous URL by default ([2817147](…))`).
  It only works in repos that generate changelogs that way: mdex, tinacms,
  electron-builder. fzf's `0.73.1`, craftcms's `Finish 5.9.23` and seaweedfs's
  `4.30` cite nothing.
- **D is worth having for its own sake.** The rfcomm race fix
  (`c67b59f891`) is 17 added lines of which most are a comment explaining "the
  race condition where the disconnection process is triggered by both the local
  and peer devices at the same time." The message says only "fix race condition
  in session disconnect", which `VULN_CLASS_RE` rejects because its `race
  condition` pattern demands a nearby security/exploit/vuln word. **Patch
  comments name the bug class more often than commit messages do**, and nothing
  in the current 38 LFs reads them.

---

## The arithmetic to 40 — and the exact ceiling

Stacking the measured levers, with B and C verified disjoint:

```
 22   iteration 2, as it stands
 +7   A — security-note directory                     →  29
 +5   B — release-range proximity                     →  34
 +2   C — release changelog cites a labeled fix       →  36
 +1   C — merge-aware advisory citation (2c2579c7f1)  →  37
 +1   D — vuln class named in an added comment        →  38
+1-2  E — concurrency/lifecycle family (speculative)  →  39-40
```

**The measured path reaches 38. The content-reachable ceiling is exactly 40.**
That is not a round number chosen for effect — it falls out of the nine rows
that no content-based mechanism can reach:

| Unreachable | Rows | Why |
| --- | --- | --- |
| Release commits with no in-range positive and no changelog link | **8** | `2cb9eb2f60`, `50b1db3a69`, `7eb7f8905e`, `887cc875cf`, `ad0bd9289f`, `b6caf84e9d`, `bed3a9c421`, `ce4bef7595`. Diffs are `EXTRAVERSION = rc3 → ""`, `'version' => '5.9.22' → '5.9.23'`, `4.30 → 4.34`. There is no signal in them. None. |
| `6f363ec6f7` NULL-check reorder | **1** | Added and removed line sets are **identical**; the fix is statement order. Permanently invisible to patch-text matching. |

49 − 9 = **40**. So your target is achievable, but only exactly: it requires
every mechanism above to land *and* mechanism E to pick up both remaining hard
cases — `ef47bdf328` (fix by substituting a safer close) and `77dcb20a74` (fix
by deleting a branch). Neither is a bounds check or an escape call; both are
plausible with paired remove/add token rules, at low confidence.

Two consequences worth being clear about:

1. **Half the remaining gain comes from release-commit mechanisms, not from
   vulnerability classes.** B and C contribute 7 of the 18 rows needed. They are
   also *chained* — they fire only when the underlying fix is already labeled —
   so they get better for free as A, D and E land, and B's yield today (5 of 15)
   understates its ceiling.
2. **Do not solve it with a `lf_is_a_release` detector.** Matching the version
   being set against the advisory's "fixed in" field would sweep up all 15
   rows, but that is the very join that put them in the gold set — scoring
   yourself with it is circular. It would also fire on 1,442 corpus commits
   (2.00%) while `lf_version_bump` and `lf_feature_commit` vote the opposite way
   with learned accuracy 1.00.

### Recommendation: raise the ceiling rather than squeeze it

Reaching 40 with the labels as they stand means landing every mechanism
perfectly, including the two hardest rows, for a metric where 9 of 49 rows are
unwinnable by construction. Two better options:

1. **Re-attribute the gold set.** For each advisory that names a release, walk
   the commits between the previous release and that release and attribute the
   CVE to the commit that actually changed the affected code. OSV gives you the
   fixed version; the release commit gives you the boundary. This converts 15
   structurally unreachable rows into 15 ordinary ones, makes `is_cve_fix` mean
   "the commit that fixed it" rather than "a commit the advisory mentioned", and
   lifts the ceiling from 40 to 48 — at which point **40 of 49 stops being a
   perfect-play requirement and becomes a comfortable target.**
2. **Report against fix-content rows.** Keep the labels, but publish recall over
   the 34 rows that contain fix content and state the release-commit count
   separately. Today that reads **22 of 34 (65%)** rather than 22 of 49 (45%),
   and it is the number that actually tracks LF quality.

Option 1 is the real fix. Option 2 costs an afternoon and stops the metric from
lying to you in the meantime.

---

## The second bottleneck: votes are not labels

Even at 40 votes, today's model would convert roughly half. From iteration 2:

| | Gold with a positive vote | Converted to a `security` label |
| --- | --- | --- |
| Iteration 1 (message only) | 9 | 2 |
| Iteration 2 (38 LFs) | 22 | 11 |

The diagnosis in `Coverage_Iteration1.md` still holds: every positive LF learns
an accuracy below 0.5, so one positive vote yields `prob_security` ≈ 0.27 and
loses to the 0.5 threshold. Adding mechanisms A–E raises the vote count; it does
nothing about conversion. Expect roughly `0.5 × votes` until the model
configuration changes — dependency structure for the correlated groups (the
three advisory-style message LFs, and each surface/mitigation/conjunction
triple), or a learned class balance.

If you want one number to move, it is **22 → 11**, not **22 → 40**.

---

## Suggested order of work

1. ~~**`lf_security_note_path`** (mechanism A)~~ — **done.** Shipped and
   verified: 546 corpus firings (0.76%), 7 gold hits, gold votes **22 → 29**,
   majority vote **22 → 29**. The final form requires at least one non-doc file
   in the commit, which drops 48 firings (Zephyr's
   `doc/security/vulnerabilities.rst` commits, which document CVEs rather than
   fix them) for zero loss of gold. **LabelModel conversion did not move: 11 of
   49 before and after**, because the LF's learned accuracy is 0.274 like every
   other positive, so its single vote yields `prob_security` ≈ 0.27 and loses to
   the 0.5 threshold. Mechanism A validated the prediction in "The second
   bottleneck" exactly.
2. **Fix the model conversion.** Dependency structure or learned class balance.
   Doubles the value of every LF already written. **Now the only thing that
   matters:** A and B together added 12 votes and 0 labels.
3. **Re-attribute the release-commit gold labels** (recommendation 1). Turns 15
   dead rows into live ones and removes the artifact documented in `README2.md`.
4. **`lf_diff_comment_vuln_class`** (mechanism D). Cheap, 0.27% control
   coverage, and it reads a signal channel nothing else touches.
5. **`lf_diff_changelog_cites_fix`** (mechanism C). Most precise mechanism
   measured; only pays off in changelog-generating repos.
6. **Concurrency/lifecycle family** (mechanism E). The one genuine class gap:
   added `atomic_*`, lock/unlock pairs, refcount changes, deferred close/free,
   `k_sem`/`mutex` introduction, and remove-then-add-safer-variant pairs.
7. **Everything else** — crypto, SSRF, deserialization, CSRF — after the corpus
   grows past a 6-month window, where those CVEs actually exist in gold.

---

## Method note

Measured here, on the real corpus: the 27-row classification, the CWE tallies,
mechanism A (594 firings / 7 gold), mechanism B and B′ (release-range windows
over all 1,442 release commits), mechanism C (150 randomly sampled non-gold
release commits, raw patches refetched), mechanism D (added-comment matching
across the 5,451-row diff sample with its 3,000-commit control stratum), and the
release-commit count.

Speculative and flagged as such: mechanism E's yield, the "+1 to +3" in the
arithmetic, and the claim that option 1 makes 40 attainable. The per-lever gold
gains are exact counts on 49 rows, which is a small denominator — a single
reclassified commit moves any of them by a full point.

Reproduce the numbers with `gen_coverage2_md.py` for the baseline, then the
mechanisms individually; none of them needs a refetch beyond the 150 raw patches
in mechanism C.
