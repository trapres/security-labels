"""Dump the advisory-confirmed (gold) fix commits + their CVE disclosures to Markdown."""
import json
from collections import defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path("/Users/jared.carlson/Projects/commit_labels")
OUT = ROOT / "docs" / "cve-fix-commits.md"

cves = {}
for line in (ROOT / "data/interim/cves.jsonl").open():
    rec = json.loads(line)
    cves[rec["cve_id"]] = rec

df = pd.read_parquet(ROOT / "data/interim/commits.parquet")
gold = df[df.is_cve_fix].copy()

by_cve = defaultdict(list)
for _, row in gold.iterrows():
    by_cve[row["cve_id"]].append(row)


def advisory_urls(rec):
    seen, out = set(), []
    for u in rec["reference_urls"]:
        if "/security/advisories/GHSA-" in u or "/advisories/GHSA-" in u:
            if u not in seen:
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

w("# Advisory-confirmed fix commits (gold set)")
w("")
w(
    "Every commit in `data/interim/commits.parquet` with `is_cve_fix == True`, joined "
    "back to its CVE record in `data/interim/cves.jsonl`. This is the exact set the "
    "`Emp. Acc.` / `--missed` numbers in the README are measured against."
)
w("")
w(f"- **{len(gold)} commits** across **{len(by_cve)} CVEs** and "
  f"**{gold.repo.nunique()} repos**")
w(f"- Drawn from a corpus of {len(df):,} mined commits and {len(cves)} fetched CVEs")
w("- A commit is in here because an advisory (via OSV.dev) or an NVD reference named "
  "its SHA — nothing about the commit's own text put it here.")
w("")
w("> Caveats that matter when reading this as training data: several of these are "
  "**release/version-bump commits** (`0.73.1`, `chore(main): release 0.2.3`) that "
  "advisories cite as \"the fixed version\" rather than the patch itself, and several "
  "CVEs map to **multiple commits** because of backports across release branches. "
  "`insertions`/`deletions` are `0` corpus-wide — the run did not pass `--line-stats`.")
w("")

# ---------------------------------------------------------------- index table
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

# ---------------------------------------------------------------- per CVE
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
    w("**Description**")
    w("")
    for para in (rec["description"] or "").split("\n"):
        para = para.strip()
        if para:
            w(f"> {para}")
            w(">")
    if L[-1] == ">":
        L.pop()
    w("")

    w(f"**Fix commits ({len(rows)})**")
    w("")
    for r in rows:
        w(f"- [`{r['sha'][:12]}`]({commit_url(r['repo'], r['sha'])}) — "
          f"{esc(r['subject'])}")
        w(f"  - `{r['repo']}` · {r['author_name']} <{r['author_email']}> · "
          f"authored {r['author_date'][:10]} · committed {r['committer_date'][:10]}"
          + (" · **merge**" if r["is_merge"] else "")
          + f" · {r['n_files']} file(s)")
        body = (r["body"] or "").strip()
        if body:
            w("")
            w("    ```")
            for ln in body.split("\n"):
                w(f"    {ln}")
            w("    ```")
        files = list(r["files"]) if r["files"] is not None else []
        if files:
            shown = files[:12]
            w("")
            w("    <details><summary>files</summary>")
            w("")
            for fp in shown:
                w(f"    - `{fp}`")
            if len(files) > len(shown):
                w(f"    - …and {len(files) - len(shown)} more")
            w("")
            w("    </details>")
        w("")
    w("")

# ---------------------------------------------------------------- gaps
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

# ---------------------------------------------------------------- flat table
w("---")
w("")
w("## Appendix: flat commit table")
w("")
w("Same 49 rows, sorted by repo then date — the scannable view.")
w("")
w("| Repo | SHA | Author date | Subject | CVE | Files |")
w("| --- | --- | --- | --- | --- | --- |")
for _, r in gold.sort_values(["repo", "author_date"]).iterrows():
    w(f"| `{r['repo']}` | [`{r['sha'][:10]}`]({commit_url(r['repo'], r['sha'])}) | "
      f"{r['author_date'][:10]} | {esc(r['subject'])} | "
      f"[{r['cve_id']}](https://nvd.nist.gov/vuln/detail/{r['cve_id']}) | "
      f"{r['n_files']} |")
w("")

OUT.write_text("\n".join(L) + "\n")
print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes, {len(L)} lines)")
