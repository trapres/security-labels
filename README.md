# commit_labels

Find CVEs from the last *X* months that map to GitHub repos, mine those repos'
commit history, and weakly label the commits as security-relevant with
[Snorkel](https://snorkel.readthedocs.io/) labeling functions.

The pipeline is four independent steps. Each writes a file the next one reads,
so you can rerun any stage without redoing the ones before it.

```
   NVD API 2.0            OSV.dev
  (date-ranged        (exact fix commit
   CVE search)             SHAs)
        \                   /
         \                 /
      1. fetch_cves  ──────────►  data/interim/cves.jsonl
                                  data/interim/repo_targets.json
                                            │
      2. mine_commits ◄─────────────────────┘   (git clone + git log)
                     ──────────►  data/interim/commits.parquet
                                            │
      3. label ◄────────────────────────────┘   (Snorkel LFs + LabelModel)
                     ──────────►  data/processed/commits_labeled.parquet
                                            │
      4. inspect_labels ◄───────────────────┘   (tune the LFs, repeat)
```

---

## Setup

The `.venv/` already has most of what's needed. To be safe:

```bash
cd ~/Projects/commit_labels
.venv/bin/pip install -r requirements.txt
```

API keys are optional but strongly recommended:

```bash
cp env.example .env
$EDITOR .env
```

| Key | Why | Get one |
| --- | --- | --- |
| `NVD_API_KEY` | 5 req/30s → 50 req/30s. Step 1 is ~10x faster. | <https://nvd.nist.gov/developers/request-an-api-key> (free, instant) |
| `GITHUB_TOKEN` | Only needed if you add REST calls; cloning is unauthenticated. | `gh auth token` |

Every command below assumes `.venv/bin/python`. Run them from the repo root.

---

## Quick smoke test (~2 minutes)

Proves the whole chain works before you commit to a real run:

```bash
.venv/bin/python -m commit_labels.fetch_cves --months 1 --max-cves 20 --require-patch-ref
.venv/bin/python -m commit_labels.mine_commits --max-repos 3 --since "6 months ago"
.venv/bin/python -m commit_labels.label --class-balance 0.03
.venv/bin/python -m commit_labels.inspect_labels
```

---

## Step 1 — `fetch_cves`

```bash
.venv/bin/python -m commit_labels.fetch_cves --months 6 --require-patch-ref
```

Queries NVD for every CVE published in the window, keeps the ones whose
references point at a GitHub repo, then asks OSV.dev for the exact fixing
commit SHA.

| Flag | Default | Notes |
| --- | --- | --- |
| `--months N` | `6` | How far back to search. |
| `--end YYYY-MM-DD` | today | End of the window, for reproducible runs. |
| `--require-patch-ref` | off | Keep only CVEs with a concrete commit/PR link. Cuts the output ~3-5x and removes most noise. **Recommended.** |
| `--min-cvss X` | none | Drop CVEs below this CVSS base score. |
| `--no-osv` | off | Skip OSV enrichment. Faster, but you lose most fix commits — which are the whole point. |
| `--max-cves N` | none | Stop early. For smoke tests. |

**Runtime.** NVD is the bottleneck without a key: one request per ~6.5s,
2000 CVEs per request, and NVD publishes roughly 3–4k CVEs/month. A 6-month
window is ~12 requests ≈ 80s, plus one OSV call per *kept* CVE. Budget 5–15
minutes for 6 months without a key, well under a minute of API time with one.

### Outputs

`data/interim/cves.jsonl` — one CVE per line:

```jsonc
{
  "cve_id": "CVE-2026-16313",
  "published": "2026-08-14T...",
  "description": "...",
  "cvss_score": 7.6,
  "cvss_severity": "HIGH",
  "cwes": ["CWE-93"],
  "reference_urls": ["..."],
  "patch_urls": ["..."],                    // refs NVD tagged "Patch"
  "github_repos": ["doug-gilbert/sg3_utils"],
  "primary_repo": "doug-gilbert/sg3_utils", // best guess at THE project
  "patch_refs": [{"repo": "...", "kind": "pull", "id": "83", "url": "..."}],
  "osv_fixes": [{"repo": "...", "commit": "<40-char sha>", "source": "GHSA-..."}]
}
```

`data/interim/repo_targets.json` — repos to clone, ranked by how many known fix
commits they have. `commit_to_cve` is the map that becomes your gold labels.

### How CVE → repo mapping works (and where it goes wrong)

This is the weakest link in the pipeline. It all lives in `github_refs.py`.

A CVE's reference list often contains several GitHub URLs: the real project, a
proof-of-concept exploit repo, a researcher's writeup, a distro packaging repo.
`pick_primary_repo()` prefers repos that carry an actual patch link, on the
theory that nobody links a *patch* in an exploit repo. It's a heuristic and it
misses. When you see a junk repo in `repo_targets.json`, that's why.

Two things that already bit us and are handled:

- **Reserved paths.** `github.com/advisories/GHSA-...` is not a repo named
  `advisories/GHSA-...`. See `_RESERVED_OWNERS`.
- **Case.** Advisories cite both `PHPOffice/PhpSpreadsheet` and
  `phpoffice/phpspreadsheet`. GitHub treats those as one repo, so targets are
  deduped on `GitHubRepo.key` (lowercased). Never key a dict on `full_name`.

---

## Step 2 — `mine_commits`

```bash
.venv/bin/python -m commit_labels.mine_commits --max-repos 25 --since "24 months ago" --jobs 6
```

Bare-clones each target and extracts commit records.

| Flag | Default | Notes |
| --- | --- | --- |
| `--max-repos N` | `25` | Highest-signal repos first. Start small. |
| `--min-fix-commits N` | `1` | Only mine repos with ≥N known fix commits. `0` includes repos we know only by reference. |
| `--since EXPR` | `"24 months ago"` | Any `git --since` expression. |
| `--max-commits-per-repo N` | `20000` | Guards against monorepos. |
| `--jobs N` | `4` | Parallel clones. `6`–`8` is fine on a fast link. |
| `--refs` | `--branches` | See the performance note below. |
| `--no-stats` | off | Skip file paths entirely. Fastest, but the path-based LFs go dead. |
| `--line-stats` | off | Also collect insertions/deletions. Implies a full clone — see below. |
| `--keep-full-clone` | off | Clone blobs too. |

**Measured on 12 repos** (including cpython and zephyr, capped at 20k commits
each): 72,166 commits in 5m20s, 654 MB of clones. Clones are cached — rerunning
does a `git fetch` instead.

### Performance notes worth knowing

These cost real debugging time, so they're worth stating plainly:

1. **Clones are blobless** (`--filter=blob:none`) — commits and trees only, no
   file contents. That's a ~10x size reduction and we never need file bytes.

2. **`--name-status` works on a blobless clone; `--numstat` does not.** Tree
   diffs compare blob *OIDs*, so changed filenames are free. Line counts need
   blob *bytes*, so on a blobless clone git refetches every blob one at a time
   from the promisor remote. That took 10m26s for 12 repos and hard-failed on
   10 of them. Hence: file paths by default, and `--line-stats` implies a full
   clone. `insertions`/`deletions` are `0` unless you pass it.

3. **We walk `--branches`, not `--all`.** `--all` adds every tag, and tag
   objects a partial clone never materialized trigger the same one-at-a-time
   refetch. On craftcms/cms (1454 tags): **4m23s with `--all` vs 1.0s with
   `--branches`.** Branch tips already reach essentially every commit a tag
   does.

4. **`core.commitGraph` and `log.mailmap` are both disabled.** A partial clone's
   commit-graph can advertise commits whose objects are absent, and `.mailmap`
   is itself a blob. Either one aborts the whole log walk. Disabling mailmap
   also gives us raw author addresses, which is what `lf_bot_author` wants.

A repo that still fails is logged and skipped; one bad repo never kills the run.

### Output schema — `data/interim/commits.parquet`

| Column | Type | Notes |
| --- | --- | --- |
| `sha`, `repo` | str | |
| `parents`, `n_parents`, `is_merge` | str/int/bool | |
| `author_name`, `author_email`, `author_date` | str | ISO-8601 dates |
| `committer_name`, `committer_email`, `committer_date` | str | |
| `subject`, `body`, `message` | str | `message` = subject + body |
| `files`, `n_files` | list[str], int | empty with `--no-stats` |
| `insertions`, `deletions` | int | **0 unless `--line-stats`** |
| `is_cve_fix` | bool | **gold label** — an advisory named this commit |
| `cve_id` | str/None | which CVE, when known |
| `repo_cve_ids` | str | comma-separated, all CVEs for the repo |

---

## Step 3 — `label`

```bash
.venv/bin/python -m commit_labels.label --class-balance 0.03
```

Applies the 20 labeling functions in `lfs.py`, fits a Snorkel `LabelModel`, and
writes per-commit probabilities.

| Flag | Default | Notes |
| --- | --- | --- |
| `--class-balance P` | learned | Prior P(security). **Set this.** Snorkel is very sensitive to it on imbalanced data; `0.02`–`0.05` matches real repo history. |
| `--threshold X` | `0.5` | P(security) cutoff. |
| `--epochs`, `--lr` | `500`, `0.01` | |
| `--sample N` | none | Fit on N random rows. Use while iterating on LFs. |

Output adds `label` (`-1` abstain / `0` not-sec / `1` security),
`prob_security`, `mv_label` (majority-vote baseline), and one column per LF.

Commits no LF voted on stay at `-1` rather than being forced to a class.

### ⚠️ Read this before you trust `Emp. Acc.`

The LF analysis table prints an empirical-accuracy column when gold labels
exist, and **it will look catastrophic**: `lf_cve_id` scored `0.0097` on our
test run. That number is not precision, and the LF is not broken.

`is_cve_fix` is true only for the ~49 commits an advisory *explicitly named*.
A cpython commit titled `Apply CVE-2021-4189 PASV fix to ftplib` is obviously a
security fix, but it isn't in that list, so it counts as "Incorrect." The gold
set marks **known** positives, never *"everything else is negative."*

So: **recall against gold is meaningful. Precision is not.** To estimate real
precision, hand-review a sample:

```bash
.venv/bin/python -m commit_labels.inspect_labels --review 50 --out review.csv
# fill in the 'verdict' column with 1/0, then precision = mean(verdict)
```

The columns that *are* immediately useful:

- **Coverage** — fraction of commits the LF votes on. Below ~1% it contributes
  almost nothing; above ~60% it's probably too loose.
- **Conflicts** — fraction where another LF votes the other way. High conflict
  *and* high coverage means one of the two is wrong.

---

## Step 4 — `inspect_labels`

The loop you'll actually live in.

```bash
.venv/bin/python -m commit_labels.inspect_labels                      # summary + triage
.venv/bin/python -m commit_labels.inspect_labels --lf lf_vuln_class   # what an LF fires on
.venv/bin/python -m commit_labels.inspect_labels --missed             # gold fixes we lost
.venv/bin/python -m commit_labels.inspect_labels --review 50 --out review.csv
.venv/bin/python -m commit_labels.inspect_labels --repo python/cpython
```

`--missed` is the highest-value view. It splits missed gold fixes into two
buckets with different remedies:

```
=== 47 / 49 advisory-confirmed fixes not labeled security ===

Negative LFs vetoing a known fix (each one is a false negative):
  lf_version_bump                  5      <- these LFs are too aggressive
  lf_feature_commit                5
  lf_bot_author                    4

30 got no vote at all - no positive LF recognized them:
  CVE-2026-53429     fix: avoid leaking escaped tag literals
  CVE-2026-54888     fix: stack-safe comrak document conversion
  CVE-2026-8023      net: http_server: Normalize URL path before lookup
```

A negative LF firing on a known fix is a bug in that LF — fix it. An abstain
means no positive LF has vocabulary for that phrasing — add it.

---

## Current state, honestly

On the 12-repo / 72k-commit test run, the shipped LFs recover **2 of 49**
advisory-confirmed fixes. That is a starting point, not a finished labeler.
The negative LFs are in good shape (coverage 8–10% at ~100% agreement with
gold); the positive LFs are too narrow.

That's the expected shape of a first Snorkel iteration, and the `--missed`
output above is the worklist. Concretely:

1. **Loosen the vetoes.** `lf_version_bump` and `lf_feature_commit` are killing
   real fixes — a release commit *can* be the security fix, especially in repos
   that squash. Consider abstaining instead of voting `0` when the diff also
   touches non-version files.
2. **Widen positive vocabulary.** The abstain list is full of real phrasings the
   LFs don't know: "avoid leaking", "stack-safe", "normalize URL path before
   lookup", "unbounded ... ranges". Note these are mostly *implicit* — no
   security word appears at all.
3. **Add a diff-content LF.** The biggest available win. Message text alone
   can't see that a patch added a bounds check. This needs `--keep-full-clone`
   and a `git show` per commit, so scope it to candidates rather than all 72k.
4. **Exploit the CVE-fix neighborhood.** Commits adjacent to a known fix (same
   PR, same day, same files, backports to release branches) are strong
   positives. Multi-branch backports already show up as near-duplicates.

### Known limitations

- **`pick_primary_repo` is a heuristic.** Expect junk repos in the target list.
- **`is_cve_fix` is incomplete, not exhaustive.** Never treat `0` as a
  confirmed negative — this is a positive-unlabeled problem.
- **Backports inflate counts.** One cpython fix appears 7 times across release
  branches. De-duplicate on `subject` before computing per-fix statistics.
- **Correlated LFs.** `lf_cve_id`, `lf_ghsa_id`, and `lf_advisory_language` all
  fire on advisory-style messages. `LabelModel` assumes conditional
  independence by default, so it will be overconfident where they co-fire.
- **Don't feed `is_cve_fix` in as an LF.** It's the evaluation set. If it
  becomes a labeling function, every score you produce is circular.

---

## Layout

```
commit_labels/
  config.py          paths, .env loading, logging
  github_refs.py     GitHub URL parsing, CVE→repo mapping
  nvd.py             NVD CVE API 2.0 client (date-ranged search)
  osv.py             OSV.dev client (exact fix commits)
  fetch_cves.py      step 1 CLI
  gitmine.py         clone + git log extraction
  mine_commits.py    step 2 CLI
  lfs.py             the 20 Snorkel labeling functions   <- you'll edit this most
  label.py           step 3 CLI
  inspect_labels.py  step 4 CLI
data/
  raw/  interim/  processed/  repos/
```

`data/` is gitignored, including the clones.
