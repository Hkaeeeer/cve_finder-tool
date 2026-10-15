# FIXES — v4.0.1 bug-fix batch

This batch fixes 8 defects found in a full code review + live testing of v4.0.0,
and adds the missing project-hygiene files. Every fix is tagged `FIX (bug-N)`
in the source so you can find the reasoning inline.

## Bugs fixed

### bug-1 (CRITICAL) — `search --keyword CVE-...` crashed
`python cve_hunter.py search --keyword CVE-2021-44228` triggered the
auto-redirect to `scan`, but the `search` argparse namespace lacks the
scan-only attributes, so it crashed with:

```
✗ Error: 'Namespace' object has no attribute 'no_github'
```

**Fix:** `cmd_search` now fills the scan-only attributes (`no_github`,
`no_local`, `use_msf`, `no_kev`, `verbose`, `exploit`, `report`,
`check_version`) with scan defaults before redirecting.

### bug-2 — `search -q` ignored pipe-friendly mode
`-q/--plain` is documented as "no colors or tables", and `scan`/`batch`
honored it — but `search` always printed the rich summary table (and a
"Searching NVD..." spinner frame), breaking `| grep` pipelines.

**Fix:** `cmd_search` now calls `_print_plain(results)` in plain mode and
prints a single clean `No results found.` line when empty.

### bug-3 — race condition in all rate limiters (batch mode)
`NVDClient`, `EPSSClient`, `PoCInGitHubSearcher` and `GitHubAdvisoryClient`
tracked last-request time in a plain `self._last_ts`. In `batch` (thread
pool) several workers called `_rate_limit()` concurrently: all read the same
stale timestamp, slept the same interval, then hit the API simultaneously —
defeating the limiter and triggering avoidable 403/429 backoff loops.

**Fix:** every `_rate_limit()` is now guarded by a `threading.Lock`, so
requests are correctly serialized across worker threads.

### bug-4 — CSV formula injection (CWE-1236)
`export_csv` wrote third-party data (NVD descriptions, product names,
reference URLs) into cells unsanitized. A description starting with
`=`, `+`, `-` or `@` would execute as a formula when the exported file is
opened in Excel/LibreOffice — a real vector for a tool whose output gets
shared in reports.

**Fix:** new `_csv_safe()` helper quote-prefixes any string cell starting
with `=`, `+`, `-`, `@`, tab or CR. Non-string values pass through.

### bug-5 — `_version_has_suffix` stripped every "v"
`stripped.replace("v", "")` removed *all* "v" characters, so `"1.0v2"` was
classified as suffix-free and then silently compared as `(1, 0)` — producing
wrong AFFECTED / NOT-AFFECTED verdicts for versions like that.

**Fix:** only a *leading* `v` decoration (`"v1.0"`) is stripped; a `v`
anywhere else now correctly counts as a suffix (→ comparison refused,
operator told to verify manually).

### bug-6 — CVSS v2 vectors silently under-rated ~19%
The accessibility factors regexed `PR:` / `UI:`, which don't exist in CVSS v2
vectors (`AV:N/AC:L/Au:N/...`). Every v2-only CVE silently got the 0.9 × 0.9
defaults instead of its real privilege factor.

**Fix:** new `_pr_ui_factors()` maps v2's `Au:N/L/H` onto the PR factors and
treats UI as 1.0 (v2 has no user-interaction metric). The risk breakdown now
shows the mapping transparently, e.g. `PR(=Au:N)=1.0, UI=n/a (v2)=1.0`.

### bug-7 — dead code in `export_csv`
`row["cwes"] = ...` assigned a column that was never in the headers list, so
`extrasaction="ignore"` always dropped it. Removed (`cwe_chain` already
covers the information).

### bug-8 — no-op comprehension in `export_markdown`
`[r if hasattr(r, "to_dict") else r for r in results]` returns `r` in both
branches — it did nothing. Removed; the function expects `CVERecord`
objects (same as `_print_summary` / `_print_plain`).

## Project hygiene (new files)

| File | Purpose |
|------|---------|
| `cve_hunter.py` | main script, **renamed** from `cve_hunter 16.py` (spaces in filenames break shell commands and the README examples) |
| `requirements.txt` | `requests`, `rich` |
| `.gitignore` | Python caches + `cve_hunter_results.*` export artifacts |
| `tests/test_fixes.py` | regression tests for this batch — `python3 tests/test_fixes.py`, no pytest needed |

## How to apply

Option A — patch (keeps your current file name):

```bash
git apply cve_hunter_fixes.patch
```

Option B — clean layout (recommended): replace the script with
`cve_hunter.py` from this folder and copy the new files in, then:

```bash
git add -A
git commit -m "v4.0.1: fix search redirect crash, plain mode, thread-safe rate limiting, CSV injection hardening, CVSS v2 factors, version suffix bug; add tests + hygiene files"
git push
```

## Verification

- `python3 tests/test_fixes.py` — 39 checks, all green
- Live regression: `scan`, `batch --export csv`, `search -q`, `search --keyword CVE-...` (redirect), `--check-version`, markdown export — all re-run post-fix
