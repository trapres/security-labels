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


POSITIVE_LFS = [
    lf_cve_id,
    lf_ghsa_id,
    lf_cwe_id,
    lf_vuln_class,
    lf_fix_plus_security_noun,
    lf_advisory_language,
    lf_security_backport,
    lf_security_paths_and_fix,
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
