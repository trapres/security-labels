# Results

The real purpose of this document is just an example of what a
"Results Report" might look like for a lightweight effort. That is, 
this research itself is an artifact.

## Discussion

Weak supervision is not a widely discussed topic in Machine Learning or around
the general community when talking about LLM's (Large Language Models). However
it plays a key role in creating datasets that will be used to train or fine-tune
these models. 

The basic premise of Weak Supervision is that, while still requiring supervision, 
the person doing the labelling is much more efficient when starting from simple 
heuristics and building up a labelling model that can be used to label the data
they want to use to further the model, or other Machine Learning techniques 
(which is an important point -- good data can be reused in a number of places!).

### Why is this Important?

This is important to Chainguard because Chainguard has the challenge of keeping up
with a number (and let's agree that 'number' is the polite term) of repositories
and committers. Open source security demands responsiveness to a huge amount of 
data. Labelling important features of that data can be very beneficial in a number
of ways.

For this experiment, we simply took a quick approach of using quick and dirty
heuristics to see how well we might label CVE related commits. While this in and
of itself might be of interest, the important piece to remember is that
these heuristics, the actual code, can be reused -- the team can reuse whatever
code they create and adjust as necessary!

## How it Works

One of the wonderful things about Weak Supervision is that it starts very simply. 
You (or an AI) can guess what heuristics (likely very simple functions) yet grow
increasingly complex labelling functions. You can start with a regex (`re.search(...)`) and grow to your own classifier, or whatever else you like. 

These labelling functions (LFs) are the backbone of labelling, but the actual 
labelling process can vary quite a bit. For example:

Simply majority vote -- we label X based on the aggregate votes of the LF's is
a simple strategy that treats all LF's as equals (which they tend *not* to be), 
no matter how complicated they are. 

The LF's outputs create a Labelling Model (LM), which can then be used on
data not trained against (to see how robust the model is).


## Coverage Quality

As expected, each iteration of LF's increased our ability to find CVE related commits. The baseline was 20 message/metadata LFs over 72,166 commits: regexes for CVE/GHSA ids (e.g. `\bCVE-\b`), advisory language, and "fix + security <noun>" phrasing, plus negative LFs reading file lists (docs-only, tests-only, version bumps, bot authors). That recovered a positive vote on only 9 of the 
49 advisory-confirmed gold fixes. This is due to most fixes just saying something
simple, such as "fixed struct X...". 

Iteration 2 moved out of reading messages in and of themselves and looked at
the diffs, resulting in 18 LFs built as six vulnerability families × three roles
(the vulnerable *surface* was touched, a *mitigation* was added, and the
conjunction of both) — which took gold votes from 9 to 22. Note these match on
diff content, not CWE keywords: a `db_escape()` wrapper appearing, a
`if (len < SIZE) return -E...` bound being added. 

The remaining gaps were *not* missing CWE classes. A "security" or
"advisories" directory appearing in a commit's file list turned out to be the
single best indicator in the whole exercise — `lf_security_note_path` needs no diff
at all, fires on 546 of 72,166 commits (0.76%). Those 546 look like a lot of
FP's against 7 gold hits, but they mostly aren't: hand-reading 40 random
non-gold firings found 38 to be genuine security fixes (**~95% precision, 95%
Wilson [83.5%, 98.6%]**) — they are simply fixes no advisory in our window
linked to.

The remaining LF's looked at release association and at
added *code comments* in the diff, taking coverage to 37 of 49. The 
ceiling looks to be 40 of 49, as 9 don't have any real hints or evidence
at all. 

| Step | Mechanism / LF | LFs | Corpus cost | Gold votes | Majority | LabelModel |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline (iter 1) | 20 message/metadata regexes | 20 | — | 9 of 49 | 9 | 2 |
| Iter 2 | 18 diff LFs: 6 vuln families × surface/mitigation/conjunction | 38 | sample-based | 22 | 22 | 11 |
| **A** (iter 3) | `lf_security_note_path` — commit touches a `security/`/`advisories/` dir **and** real code | 39 | 546 (0.76%), ~95% precision (hand-read n=40) | **+7 → 29** | 29 | 11 |
| **B** (iter 4) | `lf_release_of_security_fix` — release commit whose range since the last release contains a positively-voted commit | 40 | 251 (0.35%), ~50 per hit | **+5 → 34** | 33 | 11 |
| **C** (iter 5) | `lf_patch_cites_fix_commit` — changelog links the SHA of a commit the positive LFs already voted on | 41 | 49 firings, ~25 per hit | **+2 → 36** | 33 | 11 |
| **D** (iter 6) | `lf_diff_comment_names_concurrency_bug` — added *code comment* names a race / UAF / deadlock / TOCTOU | 42 | ~105 (0.27%) | **+1 → 37** | 34 | **12** |

Coverage more than quadrupled (9 → 37) while
LabelModel conversion crawled from 2 to 12, and it sat pinned at 11 for four
consecutive iterations — A and B together added twelve gold votes and *zero*
labels. The cause is structural, not a shortage of LFs: every positive LF learns
an accuracy near 0.27 against a 0.068% base rate, so a single positive vote
yields `prob_security` ≈ 0.27 and loses to the 0.5 threshold no matter how good
that vote is.

## Result

Using relatively simple LF's we were able to reach most of the related commits —
37 of 49 carry a positive vote, and majority vote converts 34 of them — and we
identified various aspects of repositories worth tracking (advisories and
security notes, release notes), simple code diffs, etc.,. 

The Labeling Model (the derived model using the various LF's on the corpus) is 
not particularly accurate in this case, in that we would expect a reasonable
number of FPs to dominate the TP's. 

What the iterations taught us is that **votes are not labels**, and
the two numbers move independently. 

The fundamental reason for this is that **so many** commits do not correspond to 
a CVE, and so we have a lot more confidence in labelling that a commit does *not*
include a CVE related commit than we do that a commit is related. When the positives
(49) are so few as compared to the negatives this often happens. 


## Next Steps

This was a contrived exercise to explore Weak-Supervision and related
Data Programming techniques. 

## Resources

* Snorkel

[A Good Tutorial and Overview of Snorkel](https://www.youtube.com/watch?v=JWAHTrHreeM&t=1159s)

* Weak Supervision

There are a couple of books on the subject, if you're really eager to dive
into the topic. 
 
* 

