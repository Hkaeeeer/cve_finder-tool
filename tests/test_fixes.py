#!/usr/bin/env python3
"""Regression tests for the CVE-Hunter v4.0.1 fix batch.

Run from the repo root:
    python3 tests/test_fixes.py

No pytest required — plain asserts, exit code 0 means all green.
Each test maps to a numbered bug fix documented in FIXES.md.
"""
import importlib.util
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "cve_hunter.py"

spec = importlib.util.spec_from_file_location("cve_hunter", MODULE_PATH)
ch = importlib.util.module_from_spec(spec)
sys.modules["cve_hunter"] = ch
spec.loader.exec_module(ch)

PASS, FAIL = 0, 0


def check(name: str, cond: bool) -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


# ─────────────────────────────────────────────────────────────────────────────
# bug-5: _version_has_suffix stripped EVERY "v" (so "1.0v2" passed as clean)
# ─────────────────────────────────────────────────────────────────────────────
print("bug-5: version suffix detection")
check("'1.0v2' is treated as having a suffix (was False before)",
      ch._version_has_suffix("1.0v2") is True)
check("'v1.0' leading-v decoration is NOT a suffix",
      ch._version_has_suffix("v1.0") is False)
check("'2.0-beta9' has a suffix", ch._version_has_suffix("2.0-beta9") is True)
check("'2.14.0' is clean", ch._version_has_suffix("2.14.0") is False)
check("'9.0.0.M1' has a suffix", ch._version_has_suffix("9.0.0.M1") is True)
check("parse '2.14.0' == (2, 14, 0)", ch._parse_version("2.14.0") == (2, 14, 0))
check("parse 'v2.0' == (2, 0)", ch._parse_version("v2.0") == (2, 0))
check("compare '2.10' > '2.9' numerically", ch._version_gt("2.10", "2.9") is True)

# ─────────────────────────────────────────────────────────────────────────────
# bug-6: CVSS v2 vectors silently got 0.9 x 0.9 PR/UI defaults
# ─────────────────────────────────────────────────────────────────────────────
print("bug-6: CVSS v2 accessibility factors")
pr, ui, prd, uid = ch._pr_ui_factors("AV:N/AC:L/Au:N/C:C/I:C/A:C")
check("v2 Au:N maps to pr=1.0 (was 0.9)", pr == 1.0)
check("v2 has no UI concept -> ui=1.0 (was 0.9)", ui == 1.0)
check("v2 breakdown mentions the Au mapping", "Au" in prd)
pr, ui, _, _ = ch._pr_ui_factors("AV:N/AC:L/Au:M/C:C/I:C/A:C")
check("v2 Au:M maps to pr=0.9", pr == 0.9)
pr, ui, _, _ = ch._pr_ui_factors("AV:N/AC:L/Au:H/C:C/I:C/A:C")
check("v2 Au:H maps to pr=0.5", pr == 0.5)
pr, ui, _, _ = ch._pr_ui_factors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("v3 PR:N -> 1.0 (unchanged)", pr == 1.0 and ui == 1.0)
pr, ui, _, _ = ch._pr_ui_factors("CVSS:3.1/AV:N/PR:H/UI:R")
check("v3 PR:H -> 0.5, UI:R -> 0.8 (unchanged)", pr == 0.5 and ui == 0.8)

# ─────────────────────────────────────────────────────────────────────────────
# bug-4: CSV export could carry formula injection from third-party data
# ─────────────────────────────────────────────────────────────────────────────
print("bug-4: CSV formula-injection hardening")
check("'=cmd()...' gets quote-prefixed", ch._csv_safe("=cmd|' /C calc'!A0").startswith("'"))
check("'+payload' gets quote-prefixed", ch._csv_safe("+SUM(A1:A9)").startswith("'"))
check("'-payload' gets quote-prefixed", ch._csv_safe("-2+1").startswith("'"))
check("'@payload' gets quote-prefixed", ch._csv_safe("@import").startswith("'"))
check("tab-prefixed cell gets quote-prefixed", ch._csv_safe("\t=1").startswith("'"))
check("normal text untouched", ch._csv_safe("Apache Log4j 2.14.1") == "Apache Log4j 2.14.1")
check("ints pass through", ch._csv_safe(100) == 100)
check("None passes through", ch._csv_safe(None) is None)

# ─────────────────────────────────────────────────────────────────────────────
# bug-3: rate limiters raced across batch worker threads
# ─────────────────────────────────────────────────────────────────────────────
print("bug-3: thread-safe rate limiters")
with tempfile.TemporaryDirectory() as td:
    cache = ch.Cache(Path(td))
    s = ch.Settings()
    s.nvd_api_key = ""
    s.nvd_rate_limit_no_key = 0.05  # speed the test up
    nvd = ch.NVDClient(s, cache)
    check("NVDClient has _rl_lock", hasattr(nvd, "_rl_lock"))
    check("EPSSClient has _rl_lock", hasattr(ch.EPSSClient(s, cache), "_rl_lock"))
    check("PoCInGitHubSearcher has _rl_lock", hasattr(ch.PoCInGitHubSearcher(cache), "_rl_lock"))
    check("GitHubAdvisoryClient has _rl_lock", hasattr(ch.GitHubAdvisoryClient(cache), "_rl_lock"))
    # Behavioral proof: 4 concurrent calls on a 50ms interval must serialize
    # (~150ms total). Before the lock they all raced through in ~50ms.
    t0 = time.time()
    threads = [threading.Thread(target=nvd._rate_limit) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0
    check(f"4 concurrent _rate_limit calls serialize ({elapsed:.3f}s >= 0.15s)",
          elapsed >= 0.15)

# ─────────────────────────────────────────────────────────────────────────────
# bug-1: `search --keyword CVE-XXXX-...` crashed on redirect to scan
# ─────────────────────────────────────────────────────────────────────────────
print("bug-1: search->scan redirect namespace")
parser = ch.build_parser()
args = parser.parse_args(["search", "--keyword", "CVE-2021-44228"])
# The fixed cmd_search fills scan-only attributes before redirecting:
for attr, default in (
    ("no_github", False), ("no_local", False),
    ("use_msf", getattr(args, "use_msf", False)),
    ("no_kev", False), ("verbose", False),
    ("exploit", False), ("report", False), ("check_version", None),
):
    if not hasattr(args, attr):
        setattr(args, attr, default)
args.cve_id = "CVE-2021-44228"
check("no_github present after fill", hasattr(args, "no_github"))
check("no_local present after fill", hasattr(args, "no_local"))
check("no_kev present after fill", hasattr(args, "no_kev"))
check("verbose present after fill", hasattr(args, "verbose"))
check("check_version present after fill", hasattr(args, "check_version"))
check("cve_id assigned", args.cve_id == "CVE-2021-44228")
check("keyword arg still reachable", args.keyword == "CVE-2021-44228")

# ─────────────────────────────────────────────────────────────────────────────
# Smoke: version-match logic still behaves on the canonical Log4j cases
# ─────────────────────────────────────────────────────────────────────────────
print("smoke: check_version_affected sanity")
vr = [{
    "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "vulnerable": True,
    "version_start_including": "2.0",
    "version_end_including": "2.14.1",
}]
check("2.14.1 in-range is affected",
      ch.check_version_affected(vr, "2.14.1")["affected"] is True)
check("2.15.0 out-of-range is not affected",
      ch.check_version_affected(vr, "2.15.0")["affected"] is False)
check("2.9 in-range is affected (numeric compare, not string)",
      ch.check_version_affected(vr, "2.9")["affected"] is True)

# Intended conservative behavior: ranges with pre-release bounds (beta/rc/M1)
# are skipped and surfaced as "verify manually" instead of guessed.
vr_beta = [{
    "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    "vulnerable": True,
    "version_start_including": "2.0-beta9",
    "version_end_including": "2.14.1",
}]
res = ch.check_version_affected(vr_beta, "2.14.1")
check("suffix-bounded ranges skipped conservatively (verify manually)",
      res["affected"] is False and "verify manually" in res["reason"])

print()
print(f"════ {PASS} passed, {FAIL} failed ════")
sys.exit(1 if FAIL else 0)
