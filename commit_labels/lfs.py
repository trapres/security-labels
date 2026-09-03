"""Snorkel labeling functions for "is this commit security-relevant?"

Label space::

    ABSTAIN = -1
    NOT_SEC =  0
    SECURITY = 1

Design notes, since these matter more than the individual regexes:

* **Precision over coverage.** A LabelModel can work around a low-coverage LF
  but it cannot recover from a high-coverage, low-precision one that correlates
  with the others. Every keyword list here is narrow on purpose.
* **Both polarities.** Most people write only positive LFs and then wonder why
  the LabelModel collapses. Negative LFs (docs-only, test-only, version bumps,
  merge commits) carry most of the discriminative weight in this dataset,
  because the vast majority of commits are not security fixes.
* **Correlated LFs are a real problem.** ``lf_cve_id``, ``lf_ghsa_id`` and
  ``lf_advisory_language`` all fire on advisory-style messages. Pass their
  indices to ``LabelModel.fit`` via a dependency structure, or accept some
  overconfidence. ``LFAnalysis`` conflict/overlap tables will show you this.
* **Do not use ``is_cve_fix`` as an LF.** It is ground truth for evaluation.
  If you feed it in, your LabelModel scores become meaningless.
"""

from __future__ import annotations

import re

from snorkel.labeling import labeling_function

ABSTAIN = -1
NOT_SEC = 0
SECURITY = 1


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

# Named vulnerability classes. High precision: these words rarely show up in
# a commit message that isn't about the vulnerability.
VULN_CLASSES = [
    r"buffer overflow", r"heap overflow", r"stack overflow(?!\s+question)",
    r"integer overflow", r"integer underflow", r"out[- ]of[- ]bounds",
    r"\boob\b", r"use[- ]after[- ]free", r"\buaf\b", r"double[- ]free",
    r"null pointer deref\w*", r"type confusion", r"memory (?:leak|corruption)",
    r"format string",
    r"sql injection", r"\bsqli\b", r"command injection",
    r"code injection", r"template injection", r"\bssti\b",
    r"header injection", r"crlf injection", r"log injection",
    r"cross[- ]site scripting", r"\bxss\b",
    r"cross[- ]site request forgery", r"\bcsrf\b", r"\bxsrf\b",
    r"server[- ]side request forgery", r"\bssrf\b",
    r"path traversal", r"directory traversal", r"zip slip", r"\.\./",
    r"insecure deserializ\w*", r"unsafe deserializ\w*",
    r"deserialization (?:flaw|vuln\w*|issue)",
    r"\bxxe\b", r"xml external entit\w*", r"billion laughs",
    r"prototype pollution", r"open redirect", r"session fixation",
    r"privilege escalation", r"\bprivesc\b", r"sandbox escape",
    r"symlink attack", r"race condition.*(?:security|exploit|vuln)",
    r"toctou", r"time[- ]of[- ]check",
    r"timing attack", r"side[- ]channel", r"padding oracle",
    r"denial of service", r"\bdos attack\b", r"regex denial",
    r"\bredos\b", r"catastrophic backtracking", r"algorithmic complexity attack",
    r"arbitrary (?:code|command|file) (?:execution|read|write|upload)",
    r"remote code execution", r"\brce\b", r"\blfi\b", r"\brfi\b",
    r"credential (?:leak|exposure|disclosure)",
    r"information (?:leak|disclosure|exposure)",
    r"authentication bypass", r"auth bypass", r"authorization bypass",
    r"access control (?:bypass|issue|flaw)",
    r"insecure (?:default|permission|randomness|temporary file)",
    r"weak (?:cipher|crypto\w*|hash|random|prng)",
    r"insufficient entropy", r"hardcoded (?:secret|password|credential|key)",
    r"\bsupply chain attack\b", r"dependency confusion", r"typosquat\w*",
]
VULN_CLASS_RE = re.compile("|".join(VULN_CLASSES), re.IGNORECASE)

# Words that indicate a fix action. Alone they mean nothing.
FIX_VERBS_RE = re.compile(
    r"\b(fix(?:e[sd]|ing)?|patch(?:e[sd]|ing)?|resolv\w+|address(?:e[sd])?|"
    r"prevent(?:s|ed|ing)?|mitigat\w+|harden(?:s|ed|ing)?|correct(?:s|ed)?|"
    r"guard(?:s|ed)? against|avoid(?:s|ed)?|reject(?:s|ed)?|sanitiz\w+|"
    r"escap(?:e|es|ed|ing)|validat\w+|restrict\w+|disallow\w+)\b",
    re.IGNORECASE,
)

# Generic security nouns. Medium precision, needs a fix verb nearby.
SECURITY_NOUNS_RE = re.compile(
    r"\b(vulnerab\w+|exploit\w*|attack\w*|malicious|untrusted|adversar\w+|"
    r"security (?:issue|bug|fix|flaw|hole|risk|problem|vulnerability)|"
    r"secur(?:e|ity)|insecure|unsafe|unsanitized|unvalidated|unescaped|"
    r"spoof\w+|tamper\w+|forge\w+|hijack\w+|poison\w+)\b",
    re.IGNORECASE,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)


# Coordinated-disclosure boilerplate. Very strong signal - projects only write
# this when a fix came out of a security report.
ADVISORY_RE = re.compile(
    r"(reported by|reported to us by|discovered by|found by|"
    r"credit(?:s)? to|thanks to .{0,60}(?:for (?:the )?report|for finding|"
    r"for responsib\w+ disclos\w+)|"
    r"responsibl\w+ disclos\w+|coordinated disclosure|security advisory|"
    r"huntr\.dev|hackerone\.com|bugcrowd\.com|oss-fuzz|"
    r"security@|/security/advisories/|nvd\.nist\.gov)",
    re.IGNORECASE,
)

# Paths whose modification is security-relevant regardless of wording.
SECURITY_PATH_RE = re.compile(
    r"(^|/)(auth[nz]?|oauth|saml|jwt|login|session|password|passwd|secret|"
    r"credential|crypto|cipher|tls|ssl|x509|cert|acl|permission|sandbox|"
    r"sanitiz\w*|escape|validator?|csrf|cors|security)",
    re.IGNORECASE,
)

# Parser / decoder paths - historically where memory-safety CVEs live.
PARSER_PATH_RE = re.compile(
    r"(parse|parser|lexer|decode|decoder|deserial|unmarshal|codec|"
    r"png|jpeg|jpg|gif|tiff|zip|tar|gzip|xml|yaml|json|asn1|regex)",
    re.IGNORECASE,
)

DOC_EXT = {
    ".md", ".rst", ".txt", ".adoc", ".org", ".pdf", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".po", ".pot",
}
DOC_NAME_RE = re.compile(
    r"(^|/)(readme|changelog|changes|news|history|authors|contributors|"
    r"license|copying|notice|code_of_conduct|contributing)",
    re.IGNORECASE,
)
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|testdata|fixtures|e2e|"
    r"benchmarks?|examples?|demos?)(/|$)|"
    r"(^|/)[^/]*(_test|test_|\.test|\.spec)[^/]*$",
    re.IGNORECASE,
)
CI_PATH_RE = re.compile(
    r"(^|/)(\.github|\.gitlab-ci\.yml|\.travis\.yml|\.circleci|"
    r"azure-pipelines|jenkinsfile|\.pre-commit-config|dockerfile|"
    r"\.editorconfig|\.gitignore)",
    re.IGNORECASE,
)

BOT_EMAIL_RE = re.compile(
    r"(dependabot|renovate|greenkeeper|snyk-bot|github-actions|"
    r"\[bot\]|noreply@github\.com$|weblate|crowdin|transifex)",
    re.IGNORECASE,
)

VERSION_BUMP_RE = re.compile(
    r"^\s*(chore(\(\w+\))?:\s*)?(bump|release|prepare|update)\s+"
    r"(version|release)?\s*(to\s+)?v?\d+\.\d+",
    re.IGNORECASE,
)

TYPO_RE = re.compile(
    r"\b(typo|spelling|grammar|whitespace|indentation|reformat|"
    r"gofmt|rustfmt|black|prettier|clang-format|lint(ing)?|"
    r"rename variable|comment only|nit)\b",
    re.IGNORECASE,
)


def _msg(x) -> str:
    return (getattr(x, "message", None) or "") if hasattr(x, "message") else ""


def _files(x) -> list:
    files = getattr(x, "files", None)
    if files is None:
        return []
    try:
        return [str(f) for f in files]
    except TypeError:
        return []


# --------------------------------------------------------------------------
# Positive LFs
# --------------------------------------------------------------------------

@labeling_function()
def lf_cve_id(x):
    """Message cites a CVE. Near-perfect precision."""
    return SECURITY if CVE_RE.search(_msg(x)) else ABSTAIN


@labeling_function()
def lf_ghsa_id(x):
    return SECURITY if GHSA_RE.search(_msg(x)) else ABSTAIN


@labeling_function()
def lf_cwe_id(x):
    return SECURITY if CWE_RE.search(_msg(x)) else ABSTAIN


@labeling_function()
def lf_vuln_class(x):
    """Names a specific vulnerability class."""
    return SECURITY if VULN_CLASS_RE.search(_msg(x)) else ABSTAIN


@labeling_function()
def lf_fix_plus_security_noun(x):
    """A fix verb and a security noun within the same message.

    Weaker than lf_vuln_class - "fix insecure default" counts, but so does
    "fix attack surface docs". Kept because it catches fixes that never name
    the bug class.
    """
    msg = _msg(x)
    return (
        SECURITY
        if FIX_VERBS_RE.search(msg) and SECURITY_NOUNS_RE.search(msg)
        else ABSTAIN
    )


@labeling_function()
def lf_advisory_language(x):
    """Coordinated-disclosure boilerplate: 'Reported by', 'Thanks to ...'."""
    return SECURITY if ADVISORY_RE.search(_msg(x)) else ABSTAIN


@labeling_function()
def lf_security_backport(x):
    """Backports and 'security release' commits on maintenance branches."""
    msg = _msg(x).lower()
    if "security" not in msg:
        return ABSTAIN
    if re.search(r"\b(backport|cherry[- ]pick|security release|"
                 r"security update|security fix)\b", msg):
        return SECURITY
    return ABSTAIN


@labeling_function()
def lf_security_paths_and_fix(x):
    """Touches auth/crypto/session code with fix-like wording."""
    msg = _msg(x)
    if not FIX_VERBS_RE.search(msg):
        return ABSTAIN
    files = _files(x)
    if not files:
        return ABSTAIN
    hits = sum(1 for f in files if SECURITY_PATH_RE.search(f))
    # Require the change to be *focused* on security code, not incidentally
    # brushing it during a wide refactor.
    if hits and hits >= max(1, len(files) // 2):
        return SECURITY
    return ABSTAIN


# A dedicated directory for advisory notes: cpython's Misc/NEWS.d/next/Security,
# a project's security/ or advisories/ tree. Narrower than SECURITY_PATH_RE,
# which also matches auth/crypto/session source files.
SECURITY_NOTE_DIR_RE = re.compile(r"(^|/)(security|advisories)/", re.IGNORECASE)


@labeling_function()
def lf_security_note_path(x):
    """Changes code *and* a file under a security/ or advisories/ directory.

    Projects that keep advisory notes in a dedicated directory hand you the
    label. cpython's tarfile fix ships
    ``Misc/NEWS.d/next/Security/2026-06-23-...rst`` next to ``Lib/tarfile.py``
    and its message - "Pass filter_function to TarFile._extract_one()" - says
    nothing about security, which is why the 7 rows of that fix and its
    backports were the largest single block of missed gold.

    ``lf_security_paths_and_fix`` does not cover this: it wants a fix verb in
    the message, and there isn't one.

    The non-doc requirement is load-bearing. Without it this also fires on
    Zephyr's ``doc/security/vulnerabilities.rst`` commits, which *document*
    CVEs rather than fix them: 48 extra corpus firings for zero extra gold, and
    all of them in direct conflict with ``lf_docs_only`` (learned accuracy
    1.00).
    """
    files = _files(x)
    if not any(SECURITY_NOTE_DIR_RE.search(f) for f in files):
        return ABSTAIN
    return SECURITY if any(not _is_doc_path(f) for f in files) else ABSTAIN


@labeling_function()
def lf_bounds_check_in_parser(x):
    """Small change to a parser/decoder that adds a bounds or length check.

    This is the classic shape of a memory-safety CVE fix in C/C++/Rust.
    """
    msg = _msg(x)
    files = _files(x)
    if not files or len(files) > 4:
        return ABSTAIN
    if not any(PARSER_PATH_RE.search(f) for f in files):
        return ABSTAIN
    if re.search(
        r"\b(bounds?[- ]check|length check|size check|overflow check|"
        r"check (?:the )?(?:length|size|bounds|limit)|"
        r"validate (?:the )?(?:length|size|input|offset)|"
        r"missing (?:bounds|length|size|null) check|"
        r"limit (?:the )?(?:size|length|depth|recursion))\b",
        msg, re.IGNORECASE,
    ):
        return SECURITY
    return ABSTAIN


@labeling_function()
def lf_crash_on_untrusted_input(x):
    """Fixes a crash/hang reachable from attacker-controlled input."""
    msg = _msg(x)
    if not re.search(r"\b(crash|panic|abort|hang|infinite loop|assert\w*|"
                     r"segfault|segmentation fault|stack exhaustion|"
                     r"excessive memory|oom)\b", msg, re.IGNORECASE):
        return ABSTAIN
    if re.search(r"\b(malformed|crafted|malicious|untrusted|invalid input|"
                 r"fuzz\w*|attacker|remote (?:user|peer|client)|"
                 r"hostile)\b", msg, re.IGNORECASE):
        return SECURITY
    return ABSTAIN


# --------------------------------------------------------------------------
# Negative LFs - these do the heavy lifting on a naturally imbalanced corpus
# --------------------------------------------------------------------------

@labeling_function()
def lf_docs_only(x):
    """Every touched file is documentation or an asset."""
    files = _files(x)
    if not files:
        return ABSTAIN
    for f in files:
        ext = ("." + f.rsplit(".", 1)[-1].lower()) if "." in f else ""
        if ext in DOC_EXT or DOC_NAME_RE.search(f) or f.lower().startswith("docs/"):
            continue
        return ABSTAIN
    return NOT_SEC


@labeling_function()
def lf_tests_only(x):
    """Test-only changes. Note: a CVE fix's *test* often lands separately,
    so this is correct as a negative even when the wording sounds scary."""
    files = _files(x)
    if not files:
        return ABSTAIN
    return NOT_SEC if all(TEST_PATH_RE.search(f) for f in files) else ABSTAIN


@labeling_function()
def lf_ci_only(x):
    files = _files(x)
    if not files:
        return ABSTAIN
    return NOT_SEC if all(CI_PATH_RE.search(f) for f in files) else ABSTAIN


@labeling_function()
def lf_merge_commit(x):
    """Merge commits carry the branch name, not a description of the change."""
    if getattr(x, "is_merge", False) and not CVE_RE.search(_msg(x)):
        return NOT_SEC
    return ABSTAIN


@labeling_function()
def lf_bot_author(x):
    """Dependabot/Renovate/translation bots.

    Judgment call: a Dependabot bump *can* remediate a CVE downstream, but it
    is not itself a patch to a vulnerability, and these commits are numerous
    enough to swamp the positives. Flip to ABSTAIN if you disagree.
    """
    email = getattr(x, "author_email", "") or ""
    name = getattr(x, "author_name", "") or ""
    if BOT_EMAIL_RE.search(email) or BOT_EMAIL_RE.search(name):
        return NOT_SEC if not CVE_RE.search(_msg(x)) else ABSTAIN
    return ABSTAIN


@labeling_function()
def lf_version_bump(x):
    subject = getattr(x, "subject", "") or ""
    if VERSION_BUMP_RE.search(subject) and not CVE_RE.search(_msg(x)):
        return NOT_SEC
    return ABSTAIN


@labeling_function()
def lf_typo_or_style(x):
    subject = getattr(x, "subject", "") or ""
    if TYPO_RE.search(subject) and not SECURITY_NOUNS_RE.search(_msg(x)):
        return NOT_SEC
    return ABSTAIN


@labeling_function()
def lf_feature_commit(x):
    """Conventional-commit feature/refactor prefixes with no security wording."""
    subject = (getattr(x, "subject", "") or "").strip()
    if re.match(r"^(feat|feature|refactor|style|perf|build|ci|chore|docs)"
                r"(\([^)]*\))?!?:", subject, re.IGNORECASE):
        if not SECURITY_NOUNS_RE.search(_msg(x)) and not VULN_CLASS_RE.search(_msg(x)):
            return NOT_SEC
    return ABSTAIN


@labeling_function()
def lf_huge_diff(x):
    """Sweeping changes are vendoring, generated code, or reformats - not
    targeted vulnerability fixes."""
    n_files = getattr(x, "n_files", 0) or 0
    churn = (getattr(x, "insertions", 0) or 0) + (getattr(x, "deletions", 0) or 0)
    if (n_files > 50 or churn > 5000) and not CVE_RE.search(_msg(x)):
        return NOT_SEC
    return ABSTAIN


@labeling_function()
def lf_empty_message(x):
    """No usable text and no files - nothing to reason about."""
    if len(_msg(x).strip()) < 8 and not _files(x):
        return NOT_SEC
    return ABSTAIN


# --------------------------------------------------------------------------
# Diff-based LFs
# --------------------------------------------------------------------------
# These read patch text (``x.diff``), which no message LF can see. They only
# fire on rows where a diff was fetched - see fetch_diff_sample.py - and
# ABSTAIN everywhere else, so mixing them with the message LFs is safe.
#
# Structure, per vulnerability class, three LFs:
#
#   lf_diff_<class>_touched     the *surface* changed (a SQL query, a DOM sink,
#                               a path operation). On its own this is not
#                               evidence of a security fix - most SQL edits are
#                               ordinary - so it votes NOT_SEC, and only when no
#                               mitigation appears and the message says nothing
#                               security-flavoured. That last guard is what
#                               keeps it from vetoing real fixes.
#   lf_diff_<class>_mitigated   a *mitigation* was newly added (an escape call,
#                               a bounds guard, a permission check). Votes
#                               SECURITY on its own; hardening is hardening
#                               wherever it lands.
#   lf_diff_<class>_fix         surface AND mitigation. The conjunction the two
#                               halves exist to support, and the highest-
#                               precision positive signal available.
#
# The conjunction is by construction correlated with its two components. That
# breaks LabelModel's conditional-independence assumption on purpose, so the
# coverage report fits with and without the components to show the cost.
#
# Patterns were derived from the gold diffs in data/interim/gold_diffs/, not
# from memory: db_escape() wrapping in FrontAccounting, dangerous_url?/omitted
# URL in mdex, an ownership predicate in invidious, `if (len < SIZE) return
# ERR` in Zephyr, a strings.Builder replacing += in fzf.

MAX_DIFF_CHARS = 200_000    # bound regex work on huge patches
MAX_DIFF_LINE = 500         # skip minified bundle lines entirely

def _field(x, name: str) -> str:
    """Read a string field off a Series row, namedtuple, or dict.

    Deliberately not ``getattr(x, "diff")``: on a pandas Series that resolves
    to ``Series.diff``, the *method*, and every diff LF silently reads a bound
    method instead of the patch. Hence the ``diff_text`` column name and the
    isinstance guard.
    """
    try:
        val = x[name]
    except (KeyError, TypeError, IndexError):
        val = getattr(x, name, None)
    return val if isinstance(val, str) else ""


# Per-row memo for the diff predicates, keyed by sha. Each surface LF consults
# every family's mitigation predicate (the cross-family veto guard), so without
# this a row runs ~120 regex passes over its hunk text. Measured on the 5,451-row
# diff sample: applying all 38 LFs takes 34s without the memo, 21s with it. Call
# clear_diff_cache() if you mutate diffs in a live process.
_PRED_CACHE: dict[str, dict[str, bool]] = {}


def clear_diff_cache() -> None:
    _PRED_CACHE.clear()
    _HUNK_CACHE.clear()


def _memo(fn):
    """Cache a diff predicate per (sha, predicate). No sha -> no caching."""
    name = fn.__name__

    def wrapper(x):
        key = _field(x, "sha")
        if not key:
            return fn(x)
        slot = _PRED_CACHE.setdefault(key, {})
        if name not in slot:
            slot[name] = fn(x)
        return slot[name]

    wrapper.__name__ = name
    wrapper.__doc__ = fn.__doc__
    return wrapper


def _field_bool(x, name: str) -> bool:
    try:
        val = x[name]
    except (KeyError, TypeError, IndexError):
        val = getattr(x, name, False)
    return bool(val) if isinstance(val, (bool, int)) else False


def _diff(x) -> str:
    # Note: no truncation here. Truncating the raw patch drops the interesting
    # hunk whenever a minified bundle sorts ahead of it - measured on the
    # craftcms XSS fix, where ElementTableSorter.js follows 4.6 MB of cp.js and
    # cp.js.map. _hunks() caps the *filtered* text instead.
    return _field(x, "diff_text")


_HUNK_CACHE: dict[str, tuple[str, str]] = {}


def _hunks(x) -> tuple[str, str]:
    """Return (added_text, removed_text) for one row's diff.

    Only hunk bodies - file headers (``+++``/``---``) and minified lines are
    dropped. Prefers precomputed ``diff_added``/``diff_removed`` columns when
    the caller supplied them, because Snorkel calls every LF separately per row
    and re-splitting a 200 KB patch 18 times is pure waste.
    """
    # A merge's --first-parent diff is the whole side branch, not "the change",
    # so it matches almost any pattern. Measured on the control stratum: 7 of
    # the first 25 conjunction firings were `Merge branch 'main' into ...`.
    # lf_merge_commit already votes NOT_SEC on these, so nothing is lost.
    if bool(_field_bool(x, "is_merge")):
        return "", ""

    key = _field(x, "sha")
    if key and key in _HUNK_CACHE:
        return _HUNK_CACHE[key]

    pre_a = _field(x, "diff_added")
    if pre_a:
        result = (pre_a, _field(x, "diff_removed"))
        if key:
            _HUNK_CACHE[key] = result
        return result

    text = _diff(x)
    if not text:
        return "", ""
    added, removed = [], []
    kept = 0
    skip_file = False
    for line in text.split("\n"):
        if kept > MAX_DIFF_CHARS:
            break
        if line.startswith("diff --git "):
            # Changelogs and release notes *describe* the fix in prose, which
            # matches every mitigation regex here. Measured: without this, a
            # `chore(main): release 0.2.3` commit fires the XSS mitigation LF
            # off its own CHANGELOG entry. Judge code, not release notes.
            parts = line.split(" b/", 1)
            path = parts[1] if len(parts) == 2 else ""
            skip_file = _is_doc_path(path)
            continue
        if skip_file or len(line) > MAX_DIFF_LINE:
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
            kept += len(line)
        elif line.startswith("-"):
            removed.append(line[1:])
            kept += len(line)
    result = ("\n".join(added), "\n".join(removed))
    if key:
        _HUNK_CACHE[key] = result
    return result


def _is_doc_path(path: str) -> bool:
    ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""
    return bool(
        ext in DOC_EXT or ext == ".rst"
        or DOC_NAME_RE.search(path)
        or path.lower().startswith("docs/")
        or "/changelog" in path.lower()
        or ".changeset/" in path.lower()
    )


def _added_more(pattern: re.Pattern, added: str, removed: str) -> bool:
    """True when `pattern` occurs more often after the change than before.

    Stricter alternatives fail on real fixes: "present in added, absent in
    removed" misses the FrontAccounting SQLi patch, where a rewritten query
    line carries `db_escape` on both sides but more of them afterwards.
    """
    return len(pattern.findall(added)) > len(pattern.findall(removed))


def _any_mitigation(x) -> bool:
    """Did this diff add a mitigation of *any* family?

    Cross-family guard for the surface LFs. Measured: without it the DoS
    surface LF vetoed the electron-builder redaction fix while three other
    families' mitigation LFs were voting SECURITY on the same commit.
    """
    return (_sql_mitigated(x) or _xss_mitigated(x) or _path_mitigated(x)
            or _authz_mitigated(x) or _mem_mitigated(x) or _dos_mitigated(x))


def _touches_security_path(x) -> bool:
    """Does the change touch a file that is itself security-named?

    Used only to *withhold* a negative vote. Measured: without it,
    `lf_diff_path_op_touched` vetoed all 7 cpython tarfile-filter backports,
    whose diffs include `Misc/NEWS.d/next/Security/...`.
    """
    return any(SECURITY_PATH_RE.search(f) for f in _files(x))


def _msg_is_security_flavoured(x) -> bool:
    """Guard for the surface LFs: never veto a commit that *says* security."""
    msg = _msg(x)
    return bool(
        CVE_RE.search(msg) or GHSA_RE.search(msg) or CWE_RE.search(msg)
        or VULN_CLASS_RE.search(msg) or SECURITY_NOUNS_RE.search(msg)
        or ADVISORY_RE.search(msg)
    )


def _ext_hit(x, exts: tuple[str, ...]) -> bool:
    return any(f.lower().endswith(exts) for f in _files(x))


# ---- SQL injection (CWE-89) ---------------------------------------------
SQL_SURFACE_RE = re.compile(
    r"\bSELECT\s+[^;\n]{0,200}\bFROM\b|\bINSERT\s+INTO\b|"
    r"\bUPDATE\s+[`\"\w.]+\s+SET\b|\bDELETE\s+FROM\b|"
    r"\b(db_query|db_fetch|db_insert|db_update|mysqli?_query|mysql_query|"
    r"pg_query|pg_exec|sqlite3_exec|cursor\.execute|executemany|raw_sql|"
    r"sql_\w+|PG_DB\.(?:exec|query)|->query\()|"
    r"\$sql\b|\b(?:sql|query)\s*(?:\.=|=)\s*[\"'`]",
    re.IGNORECASE,
)
# Newly added parameterization / escaping.
SQL_PARAM_RE = re.compile(
    r"\b(db_escape|db_quote|real_escape_string|pg_escape_(?:string|literal|identifier)|"
    r"quote_ident|quote_identifier|bindParam|bindValue|bind_param|"
    r"PreparedStatement|db_query_params|prepare(?:d)?_?(?:statement)?\(|"
    r"sqlalchemy\.(?:text|bindparam)|paramstyle|placeholders?)\b|"
    r"=\s*\$\d+\b|VALUES\s*\([^)\n]{0,60}\?|"
    r"WHERE[^\n]{0,80}=\s*\?|\.execute\([^)\n]{0,80},\s*[\(\[]",
    re.IGNORECASE,
)
# Raw interpolation of a variable straight into a query - the thing a fix removes.
SQL_RAW_INTERP_RE = re.compile(
    r"[\"'`][^\"'`\n]{0,120}\b(?:WHERE|VALUES|SET|FROM|AND|OR|LIMIT)\b"
    r"[^\"'`\n]{0,120}(?:\$\w+|\#\{|\$\{|\"\s*\.\s*\$|%\(|\+\s*\w+)",
    re.IGNORECASE,
)


@_memo
def _sql_surface(x) -> bool:
    a, r = _hunks(x)
    return bool(SQL_SURFACE_RE.search(a) or SQL_SURFACE_RE.search(r))


@_memo
def _sql_mitigated(x) -> bool:
    a, r = _hunks(x)
    if _added_more(SQL_PARAM_RE, a, r):
        return True
    # Interpolation present before and gone after is the same fix, inverted.
    return _added_more(SQL_RAW_INTERP_RE, r, a)


@labeling_function()
def lf_diff_sql_query_touched(x):
    """A SQL query changed but nothing was parameterized or escaped."""
    if not _sql_surface(x) or _sql_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_sql_parameterized(x):
    """Escaping/binding newly introduced, or raw interpolation removed."""
    return SECURITY if _sql_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_sqli_fix(x):
    """A touched query *and* new parameterization: the SQLi-fix shape."""
    return SECURITY if _sql_surface(x) and _sql_mitigated(x) else ABSTAIN


# ---- XSS / DOM injection (CWE-79) --------------------------------------
XSS_SINK_RE = re.compile(
    r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|"
    r"dangerouslySetInnerHTML|v-html|createContextualFragment|mark_safe|"
    r"SafeString|html_safe|Html\.raw|htmlSafe|render_markup)\b|"
    r"\.html\(|\$\(\s*[\"'`]\s*<|\{\{\{|\|\s*safe\b|\braw\(",
    re.IGNORECASE,
)
XSS_ESCAPE_RE = re.compile(
    r"\b(escapeHtml|escape_html|escapeHTML|htmlspecialchars|htmlentities|"
    r"sanitiz\w*|DOMPurify|purify|textContent|innerText|createTextNode|"
    r"encodeURIComponent|escapeAttr|esc_(?:html|attr|url)|html\.escape|"
    r"cgi\.escape|escapeExpression|strip_tags|dangerous_url|is_safe_url|"
    r"safe_url|sanitize_url|allowlist|allow_list|escape_javascript)\b|"
    r"\.text\(",
    re.IGNORECASE,
)


# HTML assembled by string concatenation. Replacing it with an attribute
# object or a text node is the idiom the craftcms XSS fix uses, and no escape
# function appears anywhere in that patch.
XSS_HTML_CONCAT_RE = re.compile(
    r"[\"'`]\s*<[^>\n]{0,200}[\"'`]\s*\+|\+\s*[\"'`][^<\n]{0,40}>\s*[\"'`]"
)


@_memo
def _xss_surface(x) -> bool:
    a, r = _hunks(x)
    return bool(XSS_SINK_RE.search(a) or XSS_SINK_RE.search(r))


@_memo
def _xss_mitigated(x) -> bool:
    a, r = _hunks(x)
    if _added_more(XSS_ESCAPE_RE, a, r):
        return True
    # Concatenated HTML on the way out, or a sink deleted outright.
    return (_added_more(XSS_HTML_CONCAT_RE, r, a)
            or _added_more(XSS_SINK_RE, r, a))


@labeling_function()
def lf_diff_dom_sink_touched(x):
    """An HTML/DOM sink changed with no escaping added."""
    if not _xss_surface(x) or _xss_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_output_escaping_added(x):
    """Escaping/sanitizing of rendered output newly introduced."""
    return SECURITY if _xss_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_xss_fix(x):
    """A touched DOM sink *and* new escaping: the XSS-fix shape."""
    return SECURITY if _xss_surface(x) and _xss_mitigated(x) else ABSTAIN


# ---- Path traversal (CWE-22 / CWE-23) ----------------------------------
PATH_SURFACE_RE = re.compile(
    r"\b(os\.path\.join|filepath\.Join|path\.Join|path\.join|Paths\.get|"
    r"fopen|file_get_contents|file_put_contents|move_uploaded_file|"
    r"readFile|read_file|writeFile|write_file|os\.open|io\.open|"
    r"unlink|rmdir|mkdir|copyfile|sendFile|send_file|serveFile|"
    r"basename|dirname|realpath)\b|"
    r"\b(?:file_?name|file_?path|upload_?dir|attach_dir|target_?path)\b",
    re.IGNORECASE,
)
PATH_MITIG_RE = re.compile(
    r"\b(filepath\.Clean|path\.Clean|path\.normalize|os\.path\.realpath|"
    r"realpath|abspath|normpath|remove_dot_segments|"
    r"is_relative_to|strings\.HasPrefix|"
    r"secure_filename|sanitize_filename|isValid\w*Path|validate\w*[Pp]ath|"
    r"path_traversal|dot_segments|"
    r"allowed_(?:extensions|types|paths))\b|"
    r"in_array\([^)\n]{0,60}(?:ftype|extension|\bext\b|mime|suffix|filetype)|"
    # '..' as a literal being *tested for*, not '../' as a path separator:
    # the latter matches every relative import in a JS/TS codebase.
    r"['\"`]\.\.['\"`]|%2e%2e|%2f|%5c",
    re.IGNORECASE,
)


@_memo
def _path_surface(x) -> bool:
    a, r = _hunks(x)
    return bool(PATH_SURFACE_RE.search(a) or PATH_SURFACE_RE.search(r))


@_memo
def _path_mitigated(x) -> bool:
    a, r = _hunks(x)
    return _added_more(PATH_MITIG_RE, a, r)


@labeling_function()
def lf_diff_path_op_touched(x):
    """A filesystem path operation changed with no normalization added."""
    if not _path_surface(x) or _path_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_path_normalization_added(x):
    """Canonicalization, prefix confinement, or '..' rejection introduced."""
    return SECURITY if _path_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_path_traversal_fix(x):
    """A touched path operation *and* new normalization."""
    return SECURITY if _path_surface(x) and _path_mitigated(x) else ABSTAIN


# ---- Missing / broken authorization (CWE-862, 863, 639, 285) -----------
AUTHZ_SURFACE_RE = re.compile(
    r"\b(params\[|env\.params|req\.(?:params|query|body)|"
    r"request\.(?:GET|POST|args|params|form)|url_params|path_params|"
    r"find_by|findById|find_one|findOne|get_object_or_404|"
    r"\$_(?:GET|POST|REQUEST)|route_params)\b",
    re.IGNORECASE,
)
AUTHZ_MITIG_RE = re.compile(
    r"\b(require\w*Permission|requirePermission|checkPermission|check_permission|"
    r"authoriz\w+|authenticat\w+|current_user|currentUser|has_role|hasRole|"
    r"is_admin|isAdmin|login_required|requireLogin|require_login|"
    r"ensure_signed_in|permission_denied|StatusForbidden|StatusUnauthorized|"
    r"Gate::|policy_scope|verify_authorized|access_denied)\b|"
    r"\b(?:author|owner|user_id|owner_id|account_id)\b\s*(?:!=|==|<>)|"
    r"(?:!=|==)\s*(?:current_)?user\b|"
    r"error_(?:json|atom)\(4\d\d|abort\(4\d\d|status\s*[:=]\s*4(?:01|03)",
    re.IGNORECASE,
)


@_memo
def _authz_surface(x) -> bool:
    a, r = _hunks(x)
    return bool(AUTHZ_SURFACE_RE.search(a) or AUTHZ_SURFACE_RE.search(r))


@_memo
def _authz_mitigated(x) -> bool:
    a, r = _hunks(x)
    return _added_more(AUTHZ_MITIG_RE, a, r)


@labeling_function()
def lf_diff_resource_lookup_touched(x):
    """A request-parameter-driven lookup changed with no access check added."""
    if not _authz_surface(x) or _authz_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_authz_check_added(x):
    """A permission gate or ownership predicate newly introduced."""
    return SECURITY if _authz_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_authz_fix(x):
    """A touched lookup *and* a new access check: the IDOR/missing-authz shape."""
    return SECURITY if _authz_surface(x) and _authz_mitigated(x) else ABSTAIN


# ---- Memory safety (CWE-119/120/122/125/787/190/476) -------------------
SYS_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".rs", ".go", ".zig")
MEM_SURFACE_RE = re.compile(
    r"\b(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|sprintf|snprintf|"
    r"alloca|malloc|calloc|realloc|kmalloc|net_buf_\w+|from_raw_parts|"
    r"get_unchecked|copy_from_slice|as_mut_ptr|transmute)\b|"
    r"\bunsafe\s*\{|\bsizeof\b|\b(?:rdlength|payload_len|data_len|buf_len)\b",
    re.IGNORECASE,
)
# A size comparison inside an `if`. On its own this is just a loop bound -
# measured at 5.0% of the control stratum, which for a 0.07% base rate is
# noise - so _mem_mitigated() additionally requires a rejection in the same
# patch.
MEM_GUARD_RE = re.compile(
    r"\bif\s*\(?[^\n]{0,90}(?:<|>|<=|>=)[^\n]{0,70}"
    r"(?:len\b|_len\b|length|size|_SIZE|_LEN|count|capacity|\bcap\()",
)
MEM_REJECT_RE = re.compile(
    r"\breturn\s+-E[A-Z]{2,}|\breturn\s+(?:false|NULL|-1|None|Err\()|"
    r"\bgoto\s+\w+|\bbreak;|\bErr\(|\bthrow\b|panic!|"
    r"\b(?:ASSERT|assert|BUILD_ASSERT)\(|_ERR\w*\b|_ERROR\w*\b",
)
# Unconditionally mitigating: checked arithmetic and NULL guards.
MEM_MITIG_RE = re.compile(
    r"\b(checked_(?:add|sub|mul|div)|saturating_\w+|overflowing_\w+|"
    r"try_into|try_from|bounds?_check|__builtin_(?:add|mul|sub)_overflow|"
    r"INT_MAX|SIZE_MAX|UINT\d+_MAX|Max(?:Int|Uint)\d*)\b|"
    r"==\s*NULL\s*\)|!=\s*NULL\s*\)|\bis_null\(\)",
)


@_memo
def _mem_surface(x) -> bool:
    if not _ext_hit(x, SYS_EXTS):
        return False
    a, r = _hunks(x)
    return bool(MEM_SURFACE_RE.search(a) or MEM_SURFACE_RE.search(r))


@_memo
def _mem_mitigated(x) -> bool:
    if not _ext_hit(x, SYS_EXTS):
        return False
    a, r = _hunks(x)
    if _added_more(MEM_MITIG_RE, a, r):
        return True
    if not MEM_GUARD_RE.search(a):
        return False
    return _added_more(MEM_GUARD_RE, a, r) or _added_more(MEM_REJECT_RE, a, r)


@labeling_function()
def lf_diff_memory_api_touched(x):
    """A raw-memory API changed in systems code with no new guard."""
    if not _mem_surface(x) or _mem_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_bounds_guard_added(x):
    """A length/size/NULL guard or checked arithmetic newly introduced."""
    return SECURITY if _mem_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_memory_safety_fix(x):
    """A touched memory API *and* a new guard: the memory-safety-CVE shape."""
    return SECURITY if _mem_surface(x) and _mem_mitigated(x) else ABSTAIN


# ---- Resource exhaustion / algorithmic DoS (CWE-400/407/770/674/1333) --
# Deliberately narrow. An earlier version matched any `for`/`while`/`push(`/
# `+=`, which made the surface veto fire on 4 gold fixes including a real
# stack-exhaustion patch. Only shapes that are *characteristically* unbounded.
DOS_SURFACE_RE = re.compile(
    r"\b(recurs\w+|read_to_end|read_to_string|ReadAll|read_all|readAll|"
    r"regexp?\.(?:Compile|MustCompile|compile)|new RegExp|Regex::new|"
    r"ContentLength|content_length)\b|"
    r"\bloop\s*\{|(?:\w+)\s*\+=\s*(?:\w+\(|[\"\'`])",
    re.IGNORECASE,
)
DOS_MITIG_RE = re.compile(
    r"\b(max_(?:depth|len|length|size|lines|nodes|iterations|recursion)|"
    r"MAX_(?:DEPTH|LEN|LENGTH|SIZE|LINES|NODES|ITER\w*)|"
    r"\w+_limit\b|recursion_limit|depth_limit|"
    r"with_capacity|\.take\(|clamp\b|"
    r"strings\.Builder|StringBuilder|bytes\.Buffer|MaxBytesReader|"
    r"timeout|deadline|rate_limit|throttle|backpressure)\b|"
    r"\(1\.\.=\w+\)\.contains|\.min\(\w|\.max\(\w",
    re.IGNORECASE,
)


@_memo
def _dos_surface(x) -> bool:
    a, r = _hunks(x)
    return bool(DOS_SURFACE_RE.search(a) or DOS_SURFACE_RE.search(r))


@_memo
def _dos_mitigated(x) -> bool:
    a, r = _hunks(x)
    return _added_more(DOS_MITIG_RE, a, r)


@labeling_function()
def lf_diff_unbounded_work_touched(x):
    """A loop/recursion/accumulation changed with no bound introduced."""
    if not _dos_surface(x) or _dos_mitigated(x):
        return ABSTAIN
    if _msg_is_security_flavoured(x) or _touches_security_path(x):
        return ABSTAIN
    return ABSTAIN if _any_mitigation(x) else NOT_SEC


@labeling_function()
def lf_diff_resource_limit_added(x):
    """A depth/size/time bound or a non-quadratic accumulator introduced."""
    return SECURITY if _dos_mitigated(x) else ABSTAIN


@labeling_function()
def lf_diff_dos_hardening_fix(x):
    """Touched unbounded work *and* added a bound: the DoS-fix shape."""
    return SECURITY if _dos_surface(x) and _dos_mitigated(x) else ABSTAIN


# Grouped for the coverage report: (family, surface, mitigation, conjunction).
DIFF_LF_FAMILIES = [
    ("SQL injection (CWE-89)", lf_diff_sql_query_touched,
     lf_diff_sql_parameterized, lf_diff_sqli_fix),
    ("XSS / DOM injection (CWE-79)", lf_diff_dom_sink_touched,
     lf_diff_output_escaping_added, lf_diff_xss_fix),
    ("Path traversal (CWE-22/23)", lf_diff_path_op_touched,
     lf_diff_path_normalization_added, lf_diff_path_traversal_fix),
    ("Missing authorization (CWE-862/863/639/285)",
     lf_diff_resource_lookup_touched, lf_diff_authz_check_added,
     lf_diff_authz_fix),
    ("Memory safety (CWE-125/787/190/476)", lf_diff_memory_api_touched,
     lf_diff_bounds_guard_added, lf_diff_memory_safety_fix),
    ("Resource exhaustion (CWE-400/407/770/674)",
     lf_diff_unbounded_work_touched, lf_diff_resource_limit_added,
     lf_diff_dos_hardening_fix),
]

DIFF_LFS = [lf for fam in DIFF_LF_FAMILIES for lf in fam[1:]]
DIFF_SURFACE_LFS = [fam[1] for fam in DIFF_LF_FAMILIES]
DIFF_MITIGATION_LFS = [fam[2] for fam in DIFF_LF_FAMILIES]
DIFF_CONJUNCTION_LFS = [fam[3] for fam in DIFF_LF_FAMILIES]


POSITIVE_LFS = [
    lf_cve_id,
    lf_ghsa_id,
    lf_cwe_id,
    lf_vuln_class,
    lf_fix_plus_security_noun,
    lf_advisory_language,
    lf_security_backport,
    lf_security_paths_and_fix,
    lf_security_note_path,
    lf_bounds_check_in_parser,
    lf_crash_on_untrusted_input,
]

NEGATIVE_LFS = [
    lf_docs_only,
    lf_tests_only,
    lf_ci_only,
    lf_merge_commit,
    lf_bot_author,
    lf_version_bump,
    lf_typo_or_style,
    lf_feature_commit,
    lf_huge_diff,
    lf_empty_message,
]

ALL_LFS = POSITIVE_LFS + NEGATIVE_LFS

# Message LFs plus the diff LFs. Kept separate from ALL_LFS so that
# `python -m commit_labels.label` on the full corpus - where no diff column
# exists - keeps producing exactly the iteration-1 numbers.
ALL_LFS_WITH_DIFF = ALL_LFS + DIFF_LFS
