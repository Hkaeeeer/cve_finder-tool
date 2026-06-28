# CVE-Hunter

A command-line tool that pulls vulnerability data from several sources (NVD, EPSS, CISA KEV, Exploit-DB, GitHub PoCs, OSV, Nuclei) into one place and ranks it by priority — from an attacker's point of view, not a patch-management one.

## Why this isn't just another CVE tool

Most CVE tools give you a simple priority: in KEV? Top priority. High CVSS + high EPSS? High priority. This one digs deeper:

- **A multi-dimensional risk model** that factors in attacker accessibility (does it need auth? network or local?) and the quality of the exploit evidence — not just CVSS + EPSS.
- **It tells the difference between kinds of evidence.** A verified Exploit-DB entry is not the same as a passing mention in a GitHub search. The latter never raises the score, so you don't get a false "try this first."
- **It tells you when it doesn't know.** If a source fails, it won't confidently claim "no exploit exists" — it flags the data as incomplete. Most tools give you false confidence here.
- **Output in attacker terms:** `TRY FIRST` / `FOOTHOLD` / `UNAUTH·NETWORK` instead of patch-cycle language.

## Offline mode

Built to work without internet (exams, air-gapped environments). Import a local NVD snapshot once, then run with zero network calls.

## Install

```bash
git clone https://github.com/USERNAME/cve-hunter.git
cd cve-hunter
pip install requests rich
```

## Usage

**The basics — check a CVE and see its priority:**
```bash
python cve_hunter.py scan CVE-2021-44228
```
Gives you the verdict in one line: should you try it first (`TRY FIRST`), network or local, whether a working exploit exists, and a risk score.

**I want the full picture (for a report):**
```bash
python cve_hunter.py scan CVE-2021-44228 --report --verbose
```
Adds references, remediation, CAPEC/ATT&CK mapping, and the full decoded CVSS vector.

**I have a list of CVEs from a scan or report — rank them for me:**
```bash
python cve_hunter.py batch cves.txt
```
One CVE per line. Scans them all in parallel and sorts from most to least critical.

**Export it so I can drop it into my notes (Obsidian):**
```bash
python cve_hunter.py batch cves.txt --export markdown
```
Export also supports `json` and `csv`.

**This target is running version X — is it actually affected?**
```bash
python cve_hunter.py scan CVE-2021-44228 --check-version 2.14.1
```
You type the version yourself (the tool never scans the target). It tells you AFFECTED or not, based on NVD's version ranges.

**I don't have a CVE number — let me search by name:**
```bash
python cve_hunter.py search --keyword "log4j" --limit 20
```
For a deeper search that pulls PoCs for each result:
```bash
python cve_hunter.py search --keyword "confluence rce" --deep
```

**On an exam / air-gapped box with no internet:**
```bash
# Once, while you're online: import a local NVD snapshot
python cve_hunter.py import-nvd /path/to/nvd/feeds/

# After that, run with no network at all
python cve_hunter.py --offline scan CVE-2021-44228
```

**Pipe the output into something else (grep/awk):**
```bash
python cve_hunter.py scan CVE-2021-44228 -q
```
One clean line, no colors or tables.

### Handy flags

- `--no-kev` / `--no-github` / `--no-local` — skip a source if you want it faster.
- `--use-msf` — enables Metasploit module search (off by default — it won't run msfconsole unless you ask).
- `--filter-outcome FOOTHOLD` — in batch mode, show only one outcome type (FOOTHOLD / PRIV-ESC / LOOT ...).
- `--debug` — shows the status of every source (ok / failed / timing) — useful when a result comes back thin.

## Optional: deeper sources

Some sources need API keys or local clones to return fuller results:

```bash
python cve_hunter.py config set-key --nvd-key YOUR_KEY        # raises the rate limit
python cve_hunter.py config set-key --github-token YOUR_TOKEN # better PoC lookups
```

An NVD key is free and **strongly recommended** — without it you'll hit the rate limit (~6 seconds per scan).

## A note on what this tool is

This is a **triage and ranking** tool, not a source of final truth. It cuts down your initial analysis and tells you "start here" — but the final call (is the target actually vulnerable, does the exploit work) is something you confirm by hands-on testing. The output is only as good as the source data: if NVD is missing a CWE for a vuln, the tool will be missing it too.

Only use it against systems you're authorized to test.

## License

MIT
