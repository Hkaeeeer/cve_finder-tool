# CVE-Hunter

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB?logo=python&logoColor=white)
![Passive intel](https://img.shields.io/badge/scope-100%25%20passive%20intel-green)
![No telemetry](https://img.shields.io/badge/telemetry-none-success)

> **Triage CVEs the way an attacker would — not the way a patch manager would.**

CVE-Hunter is a command-line tool that pulls vulnerability intelligence from a dozen sources — NVD, EPSS, CISA KEV, Exploit-DB, GitHub PoCs, GHSA/OSV, Vulners, Shodan, GreyNoise, Nuclei templates, Trickest, Metasploit — into one command and ranks the results by real-world exploitability: reach, evidence quality, and attacker payoff.

## Why this isn't just another CVE tool

Most CVE tools sort by CVSS and call it triage: in KEV? Top priority. High EPSS? High priority. CVE-Hunter asks the questions an attacker asks before touching a target:

- **"Can I reach it?"** Network-reachable without authentication (`UNAUTH·NETWORK`) is a different animal from local-only with privileges. Accessibility is a first-class factor in the score, not an afterthought.
- **"What's the evidence?"** A verified Exploit-DB entry is not a passing GitHub mention. Mentions never raise a score — so you never get a false `TRY FIRST` from noise.
- **"What does it give me?"** `FOOTHOLD`, `PRIV-ESC`, `LOOT` — outcomes in attacker terms, not patch-cycle language.
- **"What don't I know?"** If a source fails mid-scan, the tool says so (`evidence incomplete`) instead of confidently reporting "no exploit exists." Most tools give you false confidence here.

## The risk model, in one table

Every CVE gets a 0–100 score built from four dimensions:

| Dimension | What drives it |
|---|---|
| **Likelihood** | EPSS percentile, exploit availability, CISA KEV presence |
| **Impact** | CVSS impact metrics and outcome category |
| **Accessibility** | Attack vector, required privileges, user interaction (CVSS v2/v3/v4 aware) |
| **Confidence** | Evidence quality — verified exploit &gt; curated PoC &gt; mere mention |

Missing data lowers confidence instead of silently pretending to be complete. The score is designed to be honest, not confident.

## Quick start

```bash
git clone https://github.com/Hkaeeeer/cve_finder-tool.git
cd cve_finder-tool
pip install -r requirements.txt        # requests + rich, that's it
python cve_hunter.py scan CVE-2021-44228
```

Python 3.8+ · Linux / macOS · no setup, no accounts, no keys needed to start.

## Screenshots

![CVE-Hunter](Screenshot%202026-06-28%20154141.png)
![CVE-Hunter](Screenshot%202026-06-28%20154042.png)

## Usage

**Check one CVE and get the verdict:**
```bash
python cve_hunter.py scan CVE-2021-44228
```
One glance tells you: try this first or park it, network or local, does a working exploit exist, and a 0–100 risk score with the reasoning behind it.

**Full picture for a report:**
```bash
python cve_hunter.py scan CVE-2021-44228 --report --verbose
```
Adds references, remediation, CAPEC/ATT&CK mapping, and the decoded CVSS vector.

**Rank a whole list from a scan:**
```bash
python cve_hunter.py batch cves.txt
```
One CVE per line. Scanned in parallel, sorted most → least critical. Keep only one outcome with `--filter-outcome FOOTHOLD`.

**Export to notes or a report:**
```bash
python cve_hunter.py batch cves.txt --export markdown    # also: json, csv
```

**"This target runs version X — is it actually affected?"**
```bash
python cve_hunter.py scan CVE-2021-44228 --check-version 2.14.1
```
You type the version yourself — CVE-Hunter never touches the target (100% passive). It answers AFFECTED / NOT AFFECTED from NVD's version ranges, and refuses to guess when the range is ambiguous.

**Find CVEs by name when you don't have an ID:**
```bash
python cve_hunter.py search --keyword "log4j" --limit 20
python cve_hunter.py search --keyword "confluence rce" --deep    # pulls PoCs per result
```
Paste a CVE ID by accident? It quietly redirects to `scan`.

**No internet (exams, air-gapped boxes):**
```bash
python cve_hunter.py import-nvd /path/to/nvd/feeds/     # once, while online
python cve_hunter.py --offline scan CVE-2021-44228      # zero network calls after that
```

**Pipe-friendly output:**
```bash
python cve_hunter.py scan CVE-2021-44228 -q
```
One clean line — no colors, no tables, safe for `grep`/`awk`.

### Handy flags

- `-q` — plain single-line output for piping.
- `--no-kev` / `--no-github` / `--no-local` — skip a source to go faster.
- `--use-msf` — opt-in Metasploit module search (never runs msfconsole unless you ask).
- `--filter-outcome FOOTHOLD` — batch mode: keep only one outcome type (`FOOTHOLD` / `PRIV-ESC` / `LOOT` / ...).
- `--debug` — show every source's status and timing, for when a result looks thin.

## Optional: fuller results with keys

Works out of the box with zero keys. Two free keys are worth the minute:

```bash
python cve_hunter.py config set-key --nvd-key YOUR_KEY          # ~6s → 1.2s per request
python cve_hunter.py config set-key --github-token YOUR_TOKEN   # better PoC lookups
```

An NVD key is free and strongly recommended — without one you ride the public rate limit (~6 seconds per scan). Vulners, Shodan and GreyNoise keys unlock additional enrichment: `python cve_hunter.py config set-key --help`.

## Development

```bash
python3 tests/test_fixes.py    # regression checks — plain asserts, no pytest needed
```

## What this tool is (and isn't)

CVE-Hunter is a **triage and ranking** tool. It compresses hours of initial analysis into seconds and tells you where to start — but the final call (is the target actually vulnerable, does the exploit actually work) is yours to confirm hands-on. The output is only as good as the sources: if NVD is missing a CWE for a vuln, CVE-Hunter will be missing it too.

Use it only against systems you're authorized to test.
