"""Dump the advisory-confirmed (gold) fix commits, their diffs, and their CVE
disclosures to docs/cve-fix-commits.md.

Everything commit-side is verbatim: the `message` column exactly as lfs.py reads
it, plus the patch as `git show` produces it. Nothing is summarized.

The patch is the one signal the current LFs cannot see. Message text alone can't
tell you a hunk added a bounds check, so this pulls `git show` for the ~49 gold
commits only - the README's "scope it to candidates rather than all 72k".

Usage:
    .venv/bin/python gen_gold_md.py                # diffs from cache, fetch if absent
    .venv/bin/python gen_gold_md.py --refresh-diffs
    .venv/bin/python gen_gold_md.py --no-diffs
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "docs" / "cve-fix-commits.md"
DIFF_CACHE = ROOT / "data" / "interim" / "gold_diffs"

# Rendering caps. The full patch always lands in DIFF_CACHE uncapped; these only
# bound what gets inlined into the Markdown. Every cap that fires prints a note
# with the elided count - a silent truncation reads as "this is the whole diff".
MAX_LINE_CHARS = 500        # per-line: truncate, keeping the +/-/context prefix
MAX_FILE_PATCH_BYTES = 40_000   # whole-file skip: minified bundles, source maps
MAX_LINES_PER_FILE = 150
MAX_FILES_PER_COMMIT = 20
MAX_LINES_PER_COMMIT = 600


# --------------------------------------------------------------------- diffs
def repo_dir(full_name: str) -> Path:
    """Mirror mine_commits.py: data/repos/<owner>__<name>."""
    return ROOT / "data" / "repos" / full_name.replace("/", "__")


def _git(args: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(cwd)] + args,
        capture_output=True, text=True, errors="replace", timeout=300,
    )
    return proc.returncode, proc.stdout if proc.returncode == 0 else proc.stderr


def fetch_diff(repo: str, sha: str, is_merge: bool, refresh: bool) -> dict:
    """Return {'stat', 'patch', 'error'} for one commit, caching to disk.

    Blobless clones (--filter=blob:none) have no file contents, so `git show`
    lazily refetches the blobs it needs from the promisor remote. That is the
    same one-at-a-time refetch the README warns about for --numstat, which is
    why this is scoped to the gold commits: ~50 commits is seconds, 72k is not.
    """
    cache = DIFF_CACHE / f"{sha}.patch"
    stat_cache = DIFF_CACHE / f"{sha}.stat"
    if not refresh and cache.exists() and stat_cache.exists():
        return {"stat": stat_cache.read_text(), "patch": cache.read_text(),
                "error": None}

    d = repo_dir(repo)
    if not d.exists():
        return {"stat": "", "patch": "", "error": f"clone missing: {d}"}

    # --first-parent is what makes a merge show anything at all; without it
    # `git show` prints an empty diff for merge commits.
    common = ["--format=", "--no-color", "-M"]
    if is_merge:
        common.append("--first-parent")

    rc_s, stat = _git(["show", "--stat"] + common + [sha], d)
    if rc_s != 0:
        return {"stat": "", "patch": "", "error": stat.strip()[:400]}
    rc_p, patch = _git(["show", "--patch"] + common + [sha], d)
    if rc_p != 0:
        return {"stat": stat, "patch": "", "error": patch.strip()[:400]}

    DIFF_CACHE.mkdir(parents=True, exist_ok=True)
    stat_cache.write_text(stat)
    cache.write_text(patch)
    return {"stat": stat, "patch": patch, "error": None}


def split_files(patch: str) -> list[tuple[str, list[str]]]:
    """Split a patch into (path, lines) per file, in patch order."""
    out: list[tuple[str, list[str]]] = []
    cur_path: str | None = None
    cur: list[str] = []
    for line in patch.split("\n"):
        if line.startswith("diff --git "):
            if cur_path is not None:
                out.append((cur_path, cur))
            # "diff --git a/x b/x" -> prefer the b/ side (post-rename path)
            parts = line.split(" b/", 1)
            cur_path = parts[1] if len(parts) == 2 else line[len("diff --git "):]
            cur = [line]
        elif cur_path is not None:
            cur.append(line)
    if cur_path is not None:
        out.append((cur_path, cur))
    return out


def render_patch(patch: str, sha: str) -> tuple[list[str], list[str]]:
    """Cap a patch for inlining. Returns (diff_lines, notes)."""
    per_file = split_files(patch)
    notes: list[str] = []
    body: list[str] = []
    budget = MAX_LINES_PER_COMMIT

    shown_files = per_file[:MAX_FILES_PER_COMMIT]
    if len(per_file) > len(shown_files):
        notes.append(
            f"{len(per_file) - len(shown_files)} of {len(per_file)} changed files "
            f"not shown (cap: {MAX_FILES_PER_COMMIT})"
        )

    for path, lines in shown_files:
        if budget <= 0:
            notes.append(
                f"hit the {MAX_LINES_PER_COMMIT}-line per-commit cap before "
                f"`{path}`"
            )
            break

        size = sum(len(ln) + 1 for ln in lines)
        if size > MAX_FILE_PATCH_BYTES:
            # A minified bundle or source map: megabytes on one or two lines,
            # unreadable either way. Keep the header so the path stays visible.
            body.extend(lines[:4])
            body.append(f"[file patch elided: {size:,} bytes]")
            budget -= 5
            notes.append(f"`{path}` content elided ({size:,} bytes — "
                         "minified or generated)")
            continue

        take = min(len(lines), MAX_LINES_PER_FILE, budget)
        clipped = 0
        for ln in lines[:take]:
            if len(ln) > MAX_LINE_CHARS:
                # Keep the +/-/space prefix: add-vs-remove is the whole signal.
                body.append(f"{ln[:MAX_LINE_CHARS]}  [… line truncated, "
                            f"{len(ln):,} chars total]")
                clipped += 1
            else:
                body.append(ln)
        budget -= take
        if clipped:
            notes.append(f"`{path}`: {clipped} long line(s) truncated at "
                         f"{MAX_LINE_CHARS} chars")
        if take < len(lines):
            body.append(
                f"[... {len(lines) - take} more diff line(s) in {path} elided ...]"
            )
            notes.append(
                f"`{path}` truncated at {take} of {len(lines)} diff lines"
            )

    while body and not body[-1].strip():
        body.pop()
    return body, notes


# --------------------------------------------------------------------- inputs
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--no-diffs", action="store_true",
                    help="skip git show entirely; message-only output")
parser.add_argument("--refresh-diffs", action="store_true",
                    help="re-run git show even if the patch is cached")
args = parser.parse_args()

cves = {}
for line in (ROOT / "data/interim/cves.jsonl").open():
    rec = json.loads(line)
    cves[rec["cve_id"]] = rec

df = pd.read_parquet(ROOT / "data/interim/commits.parquet")
gold = df[df.is_cve_fix].copy()

by_cve = defaultdict(list)
for _, row in gold.iterrows():
    by_cve[row["cve_id"]].append(row)

diffs: dict[str, dict] = {}
if not args.no_diffs:
    for _, r in gold.iterrows():
        diffs[r["sha"]] = fetch_diff(
            r["repo"], r["sha"], bool(r["is_merge"]), args.refresh_diffs
        )
    failed = [s for s, d in diffs.items() if d["error"]]
    print(f"diffs: {len(diffs) - len(failed)} ok, {len(failed)} failed, "
          f"cached in {DIFF_CACHE.relative_to(ROOT)}")
    for s in failed:
        print(f"  !! {s[:12]}: {diffs[s]['error']}")


# --------------------------------------------------------------------- helpers
def advisory_urls(rec):
    seen, out = set(), []
    for u in rec["reference_urls"]:
        if ("/security/advisories/GHSA-" in u or "/advisories/GHSA-" in u) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def other_refs(rec):
    adv = set(advisory_urls(rec))
    seen, out = set(), []
    for u in rec["reference_urls"]:
        if u in adv or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def commit_url(repo, sha):
    return f"https://github.com/{repo}/commit/{sha}"


def esc(s):
    return (s or "").replace("|", "\\|")


ordered = sorted(by_cve, key=lambda c: (cves[c]["primary_repo"] or "", c))

L = []
w = L.append

# --------------------------------------------------------------------- preamble
w("# Advisory-confirmed fix commits (gold set)")
w("")
w(
    "Every commit in `data/interim/commits.parquet` with `is_cve_fix == True`, joined "
    "back to its CVE record in `data/interim/cves.jsonl`, **with its diff**. This is "
    "the exact set the `Emp. Acc.` / `--missed` numbers in the README are measured "
    "against."
)
w("")
w(f"- **{len(gold)} commits** across **{len(by_cve)} CVEs** and "
  f"**{gold.repo.nunique()} repos**")
w(f"- Drawn from a corpus of {len(df):,} mined commits and {len(cves)} fetched CVEs")
w("- A commit is in here because an advisory (via OSV.dev) or an NVD reference named "
  "its SHA — nothing about the commit's own text put it here.")
w("")
w("## What is verbatim and what is not")
w("")
w("Nothing commit-side is summarized or paraphrased. Three *different* kinds of text "
  "appear, and they are labeled everywhere they occur:")
w("")
w("| Block | Source | Is it LF input? |")
w("| --- | --- | --- |")
w("| **Raw commit message** — fenced ```` ```text ```` | `message` column of "
  "`commits.parquet`, i.e. `subject + \"\\n\\n\" + body`, byte-for-byte as "
  "`git log` produced it | **Yes.** This is what `lfs.py` regexes run against. |")
w("| `files`, author, `n_files`, `is_merge` | same parquet row | **Yes.** "
  "`lf_security_path`, `lf_bot_author`, `lf_test_only`, `lf_huge_diff`, etc. |")
w("| **Diff** — fenced ```` ```diff ```` | `git show -M` against the cached clone, "
  "verbatim | **Not yet.** No shipped LF sees patch text. This is the join you'd be "
  "adding. |")
w("| **NVD description** — collapsed `<details>` under each CVE | NVD's own advisory "
  "prose, copied verbatim from `cves.jsonl` | **No.** Not visible to any LF. Kept "
  "because it is useful vocabulary when you write new positive LFs. |")
w("")
w("The LF-visible fields, per `lfs.py`: `message`, `subject`, `files`, `n_files`, "
  "`author_name`, `author_email`, `is_merge`, `insertions`, `deletions`. Every one of "
  "them is reproduced below unmodified.")
w("")
w("One fidelity note, since \"verbatim\" should mean something precise: `gitmine.py` "
  "builds `message` as `(subject + \"\\n\\n\" + body).strip()`, so a run of blank "
  "lines between the subject and the body collapses to one, and leading/trailing "
  "blank lines are dropped. No words change. Spot-checked 17 of these commits against "
  "`git log -1 --format=%B` in the cached clones: 16 byte-identical, 1 differing only "
  "by that collapsed blank line. Since the LFs read `message`, what is printed here "
  "*is* their input — not the raw `%B`.")
w("")
w("> Caveats that matter when reading this as training data: several of these are "
  "**release/version-bump commits** (`0.73.1`, `chore(main): release 0.2.3`) that "
  "advisories cite as \"the fixed version\" rather than the patch itself, and several "
  "CVEs map to **multiple commits** because of backports across release branches. "
  "`insertions`/`deletions` are `0` corpus-wide — the run did not pass `--line-stats`.")
w("")

# --------------------------------------------------------------------- diff notes
if not args.no_diffs:
    total_patch = sum(len(d["patch"]) for d in diffs.values())
    n_err = sum(1 for d in diffs.values() if d["error"])
    w("## About the diffs")
    w("")
    w("Produced by `git show --patch --format= --no-color -M <sha>` in the cached "
      "bare clone (`--first-parent` for the one merge commit, which otherwise shows "
      "an empty diff). The clones are blobless, so `git show` lazily refetches the "
      "blobs it needs — fine for 49 commits (~19s cold), which is exactly why this "
      "is scoped to gold rather than all 72k.")
    w("")
    w(f"Full uncapped patches are cached at `data/interim/gold_diffs/<sha>.patch` "
      f"({total_patch / 1e6:.1f} MB for {len(diffs)} commits"
      + (f", {n_err} failed" if n_err else "") + "). "
      "Read those, not this Markdown, if you want to prototype a diff LF against "
      "raw text.")
    w("")
    w("What's inlined below is **capped**, and every cap that fired is reported "
      "inline next to the diff it affected:")
    w("")
    w(f"- a file whose patch exceeds {MAX_FILE_PATCH_BYTES // 1000} KB keeps its "
      "header and loses its body — that's the minified-bundle case, and it is "
      "almost all of the volume above (`craftcms/cms` ships two ~5 MB bundles, "
      "`cp.js` and `cp.js.map`, inside an XSS fix)")
    w(f"- individual lines are truncated at {MAX_LINE_CHARS} chars, keeping the "
      "`+`/`-` prefix, since add-vs-remove is the signal")
    w(f"- at most {MAX_LINES_PER_FILE} diff lines per file, and "
      f"{MAX_FILES_PER_COMMIT} files / {MAX_LINES_PER_COMMIT} diff lines per commit")
    w("")
    w("The `git show --stat` block above each diff is never capped, so every changed "
      "path is visible even when its hunks aren't.")
    w("")

# --------------------------------------------------------------------- index
w("## Index")
w("")
w("| CVE | Severity | CWE | Repo | Commits |")
w("| --- | --- | --- | --- | --- |")
for cve_id in ordered:
    rec = cves[cve_id]
    score = rec.get("cvss_score")
    sev = f"{rec.get('cvss_severity') or '?'} {score}" if score else "—"
    cwe = ", ".join(rec.get("cwes") or []) or "—"
    w(f"| [{cve_id}](#{cve_id.lower()}) | {sev} | {cwe} | `{rec['primary_repo']}` | "
      f"{len(by_cve[cve_id])} |")
w("")

# --------------------------------------------------------------------- per CVE
w("---")
w("")
w("## Details")
w("")

for cve_id in ordered:
    rec = cves[cve_id]
    rows = sorted(by_cve[cve_id], key=lambda r: r["author_date"])

    w(f"### {cve_id}")
    w("")
    score = rec.get("cvss_score")
    meta = [
        f"**Repo:** `{rec['primary_repo']}`",
        f"**CVSS:** {score} ({rec.get('cvss_severity')})" if score else "**CVSS:** —",
        f"**CWE:** {', '.join(rec.get('cwes') or []) or '—'}",
        f"**Published:** {rec['published'][:10]}",
    ]
    w(" · ".join(meta))
    w("")
    w("**Disclosure**")
    w("")
    w(f"- NVD: <https://nvd.nist.gov/vuln/detail/{cve_id}>")
    for u in advisory_urls(rec):
        w(f"- GitHub advisory: <{u}>")
    osv_sources = []
    for f in rec.get("osv_fixes") or []:
        src = f.get("source")
        if src and src not in osv_sources:
            osv_sources.append(src)
    for src in osv_sources:
        w(f"- OSV: <https://osv.dev/vulnerability/{src}>")
    refs = other_refs(rec)
    if refs:
        w("- Other references:")
        for u in refs:
            w(f"  - <{u}>")
    w("")

    # ---- commit text first, then the diff: this is the LF input
    w(f"**Fix commits ({len(rows)})** — raw `message`, then the diff, verbatim")
    w("")
    for r in rows:
        sha = r["sha"]
        w(f"<a id=\"{sha[:12]}\"></a>")
        w(f"**`{sha}`** · [`{r['repo']}` on GitHub]({commit_url(r['repo'], sha)})")
        w("")
        w(f"- `author_name` / `author_email`: {r['author_name']} "
          f"<{r['author_email']}>")
        w(f"- `author_date`: {r['author_date']} · `committer_date`: "
          f"{r['committer_date']}")
        w(f"- `is_merge`: {bool(r['is_merge'])} · `n_parents`: {r['n_parents']} · "
          f"`n_files`: {r['n_files']} · `insertions`/`deletions`: "
          f"{r['insertions']}/{r['deletions']}")
        w(f"- `repo_cve_ids`: `{r['repo_cve_ids']}`")
        w("")
        w("```text")
        for ln in (r["message"] or "").rstrip("\n").split("\n"):
            w(ln)
        w("```")
        w("")
        files = list(r["files"]) if r["files"] is not None else []
        if files:
            w(f"`files` ({len(files)}):")
            w("")
            w("```text")
            for fp in files:
                w(str(fp))
            w("```")
        else:
            w("`files`: *(empty — merge commit or `--no-stats`)*")
        w("")

        # ---- the diff
        d = diffs.get(sha)
        if d is None:
            w("*Diff omitted (`--no-diffs`).*")
            w("")
            continue
        if d["error"]:
            w(f"*Diff unavailable: `{d['error']}`*")
            w("")
            continue

        stat = d["stat"].strip("\n")
        if stat:
            w("`git show --stat`:")
            w("")
            w("```text")
            for ln in stat.split("\n"):
                w(ln)
            w("```")
            w("")

        body, notes = render_patch(d["patch"], sha)
        if body:
            w("Diff:")
            w("")
            w("```diff")
            L.extend(body)
            w("```")
            w("")
        else:
            w("*Empty diff.*")
            w("")
        if notes:
            w(f"<sub>Capped for display — full patch: "
              f"`data/interim/gold_diffs/{sha}.patch`. "
              + "; ".join(notes) + ".</sub>")
            w("")

    # ---- advisory prose last, collapsed, clearly not commit text
    desc = (rec["description"] or "").strip()
    if desc:
        w("<details>")
        w("<summary><b>NVD advisory description</b> — advisory prose, NOT commit "
          "text; no LF sees this</summary>")
        w("")
        for para in desc.split("\n"):
            para = para.strip()
            if para:
                w(f"> {para}")
                w(">")
        if L[-1] == ">":
            L.pop()
        w("")
        w("</details>")
        w("")

# ------------------------------------------------- release-only gold commits
# Only computable now that we have the diffs, and it changes how you read the
# README's "loosen the vetoes" item.
CODE_EXT = re.compile(
    r"\.(c|h|cc|cpp|py|go|rs|ts|tsx|js|jsx|php|cr|ex|exs|java|rb|sh|yaml|yml|"
    r"json|conf|inc)$"
)
RELEASE_ISH = re.compile(
    r"(CHANGELOG|RELEASE|README|\.changeset/|docs?/|man/|\.md$|manifest\.json$|"
    r"Chart\.yaml$|mix\.exs$|constants\.go$|install(\.ps1)?$|app\.php$|VERSION)",
    re.IGNORECASE,
)

if not args.no_diffs:
    release_only = []
    for _, r in gold.iterrows():
        d = diffs.get(r["sha"])
        if not d or d["error"]:
            continue
        paths = [p for p, _ in split_files(d["patch"])]
        if paths and not any(
            CODE_EXT.search(p) and not RELEASE_ISH.search(p) for p in paths
        ):
            release_only.append((r, paths))

    w("---")
    w("")
    w("## What the diffs say about the gold set")
    w("")
    w(f"**{len(release_only)} of the {len(gold)} gold commits change no code at "
      "all.** Their diffs touch only version constants, changelogs, and release "
      "manifests. The advisory cited the *release* that carried the fix, not the "
      "fix:")
    w("")
    w("| Commit | `subject` | Files in the diff |")
    w("| --- | --- | --- |")
    for r, paths in release_only:
        w(f"| [`{r['sha'][:10]}`](#{r['sha'][:12]}) `{r['repo']}` | "
          f"{esc(r['subject'])} | "
          + ", ".join(f"`{p}`" for p in paths[:6])
          + (f" +{len(paths) - 6} more" if len(paths) > 6 else "") + " |")
    w("")
    w("(Classifier: a commit counts as release-only if no changed path has a code "
      "extension after excluding changelog/doc/version-manifest names. It is a "
      "heuristic — the file lists are printed so you can disagree.)")
    w("")
    w("This cuts against README item 1, \"loosen the vetoes.\" On these "
      f"{len(release_only)} commits `lf_version_bump` voting `0` is *right*; the "
      "gold label is the artifact. Loosening it to chase them trades real precision "
      "for fake recall. The recoverable target is nearer "
      f"**{len(gold) - len(release_only)} commits**, and the sharper LF is the "
      "inverse one the diff now makes possible: *diff touches only version/changelog "
      "files* → `NOT_SEC`, regardless of what the message says.")
    w("")
    w("Two more things only the diff can tell you:")
    w("")
    w("- **`2c2579c7f103` (`craftcms/cms`) has `n_files == 0` and an empty `files` "
      "list**, so every path-based LF is dead on it — `--name-status` prints nothing "
      "for a merge. Its `--first-parent` diff is the actual authorization-bypass "
      "patch (`+ requireVolumePermissionByAsset(...)` in `AssetsController.php`). "
      "Message text is `Merge branch '4.x-advisories' into 4.x`.")
    w("- **The patch carries the vocabulary the messages lack.** The commits the "
      "README lists as un-voted-on abstains have explicit shapes in their diffs: an "
      "added bounds check (`+ if ((uint32_t)pos + len > dns_msg->msg_size)`), an "
      "added permission gate, a switch from string concatenation to an escaped "
      "attribute object. That's the join to build.")
    w("")

# --------------------------------------------------------------------- gaps
w("---")
w("")
w("## Gaps in this gold set")
w("")
mined_repos = {r.lower() for r in df.repo.unique()}
corpus_shas = set(df.sha)
with_commit_ref = [
    r for r in cves.values()
    if r["osv_fixes"] or any(p["kind"] == "commit" for p in r["patch_refs"])
]
w(f"Of {len(cves)} fetched CVEs, {len(with_commit_ref)} carry a concrete fix-commit "
  f"reference, but only {len(by_cve)} produced a labeled commit. Most of that gap is "
  "simply repos that were never mined (`--max-repos`). Two failure modes are *not* "
  "that, and both cost you gold labels:")
w("")

masked, unreachable = [], []
for rec in with_commit_ref:
    cid = rec["cve_id"]
    if cid in by_cve or (rec["primary_repo"] or "").lower() not in mined_repos:
        continue
    refs = sorted({f["commit"] for f in rec["osv_fixes"]}
                  | {p["id"] for p in rec["patch_refs"] if p["kind"] == "commit"})
    if any(s in corpus_shas for s in refs):
        masked.append((cid, rec["primary_repo"], refs))
    else:
        unreachable.append((cid, rec["primary_repo"], refs))

w("**1. One commit, several CVEs — `cve_id` only keeps one.** The commit *is* in the "
  "corpus and *is* flagged `is_cve_fix`, but it is attributed to a sibling CVE, so "
  "these CVEs look absent:")
w("")
for cid, repo, refs in sorted(masked):
    other = df.loc[df.sha.isin(refs), "cve_id"].dropna().unique()
    w(f"- [{cid}](https://nvd.nist.gov/vuln/detail/{cid}) — `{repo}` — "
      f"{', '.join('`' + s[:10] + '`' for s in refs)} "
      f"(recorded as {', '.join(sorted(other))})")
w("")
w("`repo_cve_ids` preserves the full list, so a per-commit CVE *set* would recover "
  "these. Until then, per-CVE recall is understated.")
w("")
w("**2. Advisory SHAs that don't exist in the clone.** The repo was mined, but the "
  "referenced commits are unreachable from any branch tip — rewritten/force-pushed "
  "history, or the advisory cites a fork. Zero recoverable gold here:")
w("")
for cid, repo, refs in sorted(unreachable):
    w(f"- [{cid}](https://nvd.nist.gov/vuln/detail/{cid}) — `{repo}` — "
      f"{', '.join('`' + s[:10] + '`' for s in refs)}")
w("")

# --------------------------------------------------------------------- appendix
w("---")
w("")
w("## Appendix: flat commit table")
w("")
w(f"Same {len(gold)} rows, sorted by repo then date — the scannable view. `subject` "
  "is verbatim; only `|` is backslash-escaped so the table renders.")
w("")
w("| Repo | SHA | Author date | `subject` | CVE | `n_files` |")
w("| --- | --- | --- | --- | --- | --- |")
for _, r in gold.sort_values(["repo", "author_date"]).iterrows():
    w(f"| `{r['repo']}` | [`{r['sha'][:10]}`](#{r['sha'][:12]}) | "
      f"{r['author_date'][:10]} | {esc(r['subject'])} | "
      f"[{r['cve_id']}](#{str(r['cve_id']).lower()}) | "
      f"{r['n_files']} |")
w("")

OUT.write_text("\n".join(L) + "\n")
print(f"wrote {OUT.relative_to(ROOT)} ({OUT.stat().st_size:,} bytes, {len(L)} lines)")
