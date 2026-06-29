#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-Hunter — CVE analysis & prioritization tool.

Enriches CVEs with CVSS, EPSS, CISA KEV, exploit evidence, and rule-based
classification to help penetration testers prioritize what to try first.

Usage:
  python cve_hunter.py scan CVE-2021-44228
  python cve_hunter.py scan CVE-2021-44228 --verbose
  python cve_hunter.py batch cves.txt --export csv
  python cve_hunter.py search --keyword "log4j" --limit 20
  python cve_hunter.py search --cpe "cpe:2.3:a:apache:log4j"
  python cve_hunter.py config set-key --nvd-key YOUR_KEY

Requirements:
  pip install requests rich
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
import time
from configparser import ConfigParser
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

__version__ = "4.0.0"

# ════════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════════
DEFAULT_CONFIG_DIR = Path.home() / ".cve-hunter"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.ini"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
CPE_PATTERN = re.compile(r"^cpe:2\.3:[ao]:[^:]+:[^:]+", re.IGNORECASE)

BANNER = """[bold cyan]
   ____ ___  ____ _   _ _____ ___   ____ ___  ____
  / ___/ _ \\| __ ) | | | ____/ _ \\ / ___/ _ \\|  _ \\
 | |  | | | |  _ \\| | | |  _|| | | | |  | | | | |_) |
 | |__| |_| | |_) | |_| | |__| |_| | |__| |_| |  _ <
  \\____\\___/|____/ \\___/|_____\\___/ \\____\\___/|_| \\_\\
[/bold cyan][dim]v{version} — CVE Analysis & Prioritization[/dim]"""

# ── CWE → Category Map (extended to 100+ entries for accuracy) ──────────────
CWE_MAP: Dict[str, Dict[str, str]] = {
    # ── Remote Code Execution (RCE) ──
    "CWE-78":    {"cat": "RCE", "sub": "OS Command Injection",
                  "desc": "Improper neutralization of special elements used in an OS command"},
    "CWE-94":    {"cat": "RCE", "sub": "Code Injection",
                  "desc": "Improper control of generation of code (Code Injection)"},
    "CWE-95":    {"cat": "RCE", "sub": "Eval Injection",
                  "desc": "Improper neutralization of directives in dynamically evaluated code"},
    # FIX (accuracy-6): CWE-96 is "Improper Neutralization of Directives in
    # Statically Saved Code" (Static Code Injection) — NOT "PHP File Injection".
    # Source: https://cwe.mitre.org/data/definitions/96.html
    "CWE-96":    {"cat": "Injection", "sub": "Static Code Injection",
                  "desc": "Improper neutralization of directives in Statically Saved Code"},
    # FIX (accuracy-6): CWE-97 is "Improper Neutralization of Server-Side
    # Includes (SSI) Within a Web Page" (SSI Injection) — NOT "PHP File Inclusion".
    # Source: https://cwe.mitre.org/data/definitions/97.html
    "CWE-97":    {"cat": "Injection", "sub": "Server-Side Includes (SSI) Injection",
                  "desc": "Improper neutralization of Server-Side Includes (SSI) Within a Web Page"},
    "CWE-1336":  {"cat": "RCE", "sub": "Server-Side Template Injection (SSTI)",
                  "desc": "Improper neutralization of special elements used in a template engine"},
    "CWE-502":   {"cat": "RCE", "sub": "Unsafe Deserialization",
                  "desc": "Deserialization of untrusted data"},
    # FIX (accuracy-6): CWE-1236 is "Improper Neutralization of Formula
    # Elements in a CSV File" (CSV/Formula Injection) — NOT "Command
    # Delimiter Injection" / RCE. Recategorized from RCE → Injection.
    # Source: https://cwe.mitre.org/data/definitions/1236.html
    "CWE-1236":  {"cat": "Injection", "sub": "CSV/Formula Injection",
                  "desc": "Improper neutralization of Formula Elements in a CSV File"},
    "CWE-434":   {"cat": "RCE", "sub": "Unrestricted File Upload",
                  "desc": "Unrestricted upload of file with dangerous type"},
    "CWE-917":   {"cat": "RCE", "sub": "Expression Language Injection",
                  "desc": "Improper neutralization of special elements in expression language"},
    # FIX (accuracy-6): CWE-91 is "XML Injection (aka Blind XPath Injection)" —
    # this is an injection/info-leak weakness, not RCE. Recategorized.
    # Source: https://cwe.mitre.org/data/definitions/91.html
    "CWE-91":    {"cat": "Injection", "sub": "XML/XPath Injection",
                  "desc": "XML Injection (aka Blind XPath Injection)"},
    # ── SQL Injection ──
    "CWE-89":    {"cat": "SQLi", "sub": "SQL Injection",
                  "desc": "Improper neutralization of special elements used in an SQL command"},
    "CWE-943":   {"cat": "SQLi", "sub": "SQLi via Delimiter",
                  "desc": "Improper neutralization of special elements in data query logic"},
    # ── XSS ──
    "CWE-79":    {"cat": "XSS", "sub": "Cross-Site Scripting (XSS)",
                  "desc": "Improper neutralization of input during web page generation"},
    # ── SSRF ──
    "CWE-918":   {"cat": "SSRF", "sub": "Server-Side Request Forgery (SSRF)",
                  "desc": "Server-Side Request Forgery"},
    # ── CSRF ──
    "CWE-352":   {"cat": "CSRF", "sub": "Cross-Site Request Forgery (CSRF)",
                  "desc": "Cross-Site Request Forgery"},
    # ── Path Traversal / LFI / RFI ──
    "CWE-22":    {"cat": "LFI", "sub": "Path Traversal",
                  "desc": "Improper limitation of a pathname to a restricted directory ('Path Traversal')"},
    "CWE-23":    {"cat": "LFI", "sub": "Relative Path Traversal",
                  "desc": "Relative Path Traversal"},
    "CWE-35":    {"cat": "LFI", "sub": "Path Traversal via File",
                  "desc": "Path Traversal: '.../...//opposite'"},
    "CWE-59":    {"cat": "LFI", "sub": "Link Following",
                  "desc": "Improper Link Resolution Before File Access"},
    "CWE-98":    {"cat": "RFI", "sub": "PHP File Inclusion (RFI)",
                  "desc": "Improper Control of Filename for an Include/Require Statement"},
    "CWE-377":   {"cat": "LFI", "sub": "Insecure Temporary File",
                  "desc": "Insecure Temporary File"},
    "CWE-409":   {"cat": "LFI", "sub": "Improper Handling of Highly Compressed Data",
                  "desc": "Improper Handling of Highly Compressed Data (Data Amplification)"},
    # ── Authentication / Authorization bypass ──
    "CWE-287":   {"cat": "AuthBypass", "sub": "Improper Authentication",
                  "desc": "Improper Authentication"},
    "CWE-306":   {"cat": "AuthBypass", "sub": "Missing Authentication for Critical Function",
                  "desc": "Missing Authentication for Critical Function"},
    "CWE-862":   {"cat": "AuthBypass", "sub": "Missing Authorization",
                  "desc": "Missing Authorization"},
    "CWE-863":   {"cat": "AuthBypass", "sub": "Incorrect Authorization",
                  "desc": "Incorrect Authorization"},
    "CWE-307":   {"cat": "AuthBypass", "sub": "No Rate Limiting on Login (Brute-force)",
                  "desc": "Improper Restriction of Excessive Authentication Attempts"},
    "CWE-798":   {"cat": "AuthBypass", "sub": "Use of Hard-coded Credentials",
                  "desc": "Use of Hard-coded Credentials"},
    "CWE-1390":  {"cat": "AuthBypass", "sub": "Weak Authentication",
                  "desc": "Weak Authentication"},
    "CWE-521":   {"cat": "AuthBypass", "sub": "Weak Password Requirements",
                  "desc": "Weak Password Requirements"},
    "CWE-640":   {"cat": "AuthBypass", "sub": "Weak Password Recovery Mechanism",
                  "desc": "Weak Password Recovery Mechanism for Forgotten Password"},
    "CWE-288":   {"cat": "AuthBypass", "sub": "Authentication Bypass Using Alternate Name",
                  "desc": "Authentication Bypass Using an Alternate Path or Channel"},
    "CWE-295":   {"cat": "AuthBypass", "sub": "Improper Certificate Validation",
                  "desc": "Improper Certificate Validation"},
    # ── Privilege Escalation ──
    "CWE-269":   {"cat": "PrivEsc", "sub": "Improper Privilege Management",
                  "desc": "Improper Privilege Management"},
    "CWE-250":   {"cat": "PrivEsc", "sub": "Execution with Unnecessary Privileges",
                  "desc": "Execution with Unnecessary Privileges"},
    "CWE-276":   {"cat": "PrivEsc", "sub": "Incorrect Default Permissions",
                  "desc": "Incorrect Default Permissions"},
    "CWE-732":   {"cat": "PrivEsc", "sub": "Incorrect Permission Assignment",
                  "desc": "Incorrect Permission Assignment for Critical Resource"},
    "CWE-266":   {"cat": "PrivEsc", "sub": "Privilege Chaining",
                  "desc": "Privilege Chaining"},
    # ── Information Disclosure ──
    "CWE-200":   {"cat": "InfoLeak", "sub": "Information Exposure",
                  "desc": "Exposure of Sensitive Information to an Unauthorized Actor"},
    "CWE-215":   {"cat": "InfoLeak", "sub": "Debug Info Exposure",
                  "desc": "Insertion of Sensitive Information Into Debugging Code"},
    "CWE-532":   {"cat": "InfoLeak", "sub": "Log File Info Exposure",
                  "desc": "Insertion of Sensitive Information into Log File"},
    "CWE-209":   {"cat": "InfoLeak", "sub": "Error Message Info Exposure",
                  "desc": "Generation of Error Message Containing Sensitive Information"},
    "CWE-538":   {"cat": "InfoLeak", "sub": "Sensitive Info in File",
                  "desc": "File and Directory Information Exposure"},
    "CWE-611":   {"cat": "XXE", "sub": "XML External Entity (XXE)",
                  "desc": "Improper Restriction of XML External Entity Reference"},
    "CWE-909":   {"cat": "XXE", "sub": "XML Schema Validation",
                  "desc": "Improper Neutralization of Special Elements in XML"},
    # ── Memory corruption ──
    "CWE-119":   {"cat": "MemCorrupt", "sub": "Buffer Overflow (Generic)",
                  "desc": "Improper Restriction of Operations within the Bounds of a Memory Buffer"},
    "CWE-120":   {"cat": "MemCorrupt", "sub": "Classic Buffer Overflow",
                  "desc": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)"},
    "CWE-125":   {"cat": "MemCorrupt", "sub": "Out-of-bounds Read",
                  "desc": "Out-of-bounds Read"},
    "CWE-787":   {"cat": "MemCorrupt", "sub": "Out-of-bounds Write",
                  "desc": "Out-of-bounds Write"},
    "CWE-788":   {"cat": "MemCorrupt", "sub": "Access of Memory Location After End of Buffer",
                  "desc": "Access of Memory Location After End of Buffer"},
    "CWE-416":   {"cat": "MemCorrupt", "sub": "Use After Free",
                  "desc": "Use After Free"},
    "CWE-415":   {"cat": "MemCorrupt", "sub": "Double Free",
                  "desc": "Double Free"},
    "CWE-190":   {"cat": "MemCorrupt", "sub": "Integer Overflow or Wraparound",
                  "desc": "Integer Overflow or Wraparound"},
    "CWE-191":   {"cat": "MemCorrupt", "sub": "Integer Underflow",
                  "desc": "Integer Underflow (Wrap or Wraparound)"},
    "CWE-476":   {"cat": "MemCorrupt", "sub": "NULL Pointer Dereference",
                  "desc": "NULL Pointer Dereference"},
    "CWE-122":   {"cat": "MemCorrupt", "sub": "Heap-based Buffer Overflow",
                  "desc": "Heap-based Buffer Overflow"},
    "CWE-124":   {"cat": "MemCorrupt", "sub": "Buffer Underwrite",
                  "desc": "Buffer Underwrite ('Buffer Underflow')"},
    "CWE-131":   {"cat": "MemCorrupt", "sub": "Incorrect Calculation of Buffer Size",
                  "desc": "Incorrect Calculation of Buffer Size"},
    "CWE-680":   {"cat": "MemCorrupt", "sub": "Integer Overflow to Buffer Overflow",
                  "desc": "Integer Overflow to Buffer Overflow"},
    # ── DoS ──
    "CWE-400":   {"cat": "DoS", "sub": "Uncontrolled Resource Consumption",
                  "desc": "Uncontrolled Resource Consumption"},
    "CWE-770":   {"cat": "DoS", "sub": "Allocation of Resources Without Limits",
                  "desc": "Allocation of Resources Without Limits or Throttling"},
    "CWE-405":   {"cat": "DoS", "sub": "Asymmetric Resource Consumption",
                  "desc": "Asymmetric Resource Consumption"},
    "CWE-407":   {"cat": "DoS", "sub": "Inefficient Algorithmic Complexity",
                  "desc": "Inefficient Algorithmic Complexity"},
    # ── Open Redirect ──
    "CWE-601":   {"cat": "OpenRedirect", "sub": "URL Redirection to Untrusted Site",
                  "desc": "URL Redirection to Untrusted Site ('Open Redirect')"},
    # ── Race Condition ──
    "CWE-362":   {"cat": "Race", "sub": "Race Condition (TOCTOU)",
                  "desc": "Concurrent Execution using Shared Resource with Improper Synchronization"},
    "CWE-367":   {"cat": "Race", "sub": "Time-of-check Time-of-use (TOCTOU)",
                  "desc": "Time-of-check Time-of-use (TOCTOU) Race Condition"},
    "CWE-421":   {"cat": "Race", "sub": "Race Condition During File Access",
                  "desc": "Race Condition During File Access"},
    # ── Cryptography ──
    "CWE-327":   {"cat": "Crypto", "sub": "Use of Broken or Risky Cryptographic Algorithm",
                  "desc": "Use of a Broken or Risky Cryptographic Algorithm"},
    "CWE-328":   {"cat": "Crypto", "sub": "Use of Weak Hash",
                  "desc": "Use of Weak Hash"},
    "CWE-326":   {"cat": "Crypto", "sub": "Inadequate Encryption Strength",
                  "desc": "Inadequate Encryption Strength"},
    "CWE-329":   {"cat": "Crypto", "sub": "Not Using Random IV",
                  "desc": "Not Using a Random IV with CBC Mode"},
    "CWE-330":   {"cat": "Crypto", "sub": "Use of Insufficiently Random Values",
                  "desc": "Use of Insufficiently Random Values"},
    "CWE-347":   {"cat": "Crypto", "sub": "Improper Verification of Cryptographic Signature",
                  "desc": "Improper Verification of Cryptographic Signature"},
    # ── Injection (other) ──
    "CWE-77":    {"cat": "Injection", "sub": "Command Injection (Generic)",
                  "desc": "Improper Neutralization of Special Elements used in a Command"},
    "CWE-90":    {"cat": "Injection", "sub": "LDAP Injection",
                  "desc": "Improper Neutralization of Special Elements used in an LDAP Query"},
    "CWE-643":   {"cat": "Injection", "sub": "XPath Injection",
                  "desc": "Improper Neutralization of Data within XPath Expressions"},
    "CWE-919":   {"cat": "Injection", "sub": "NoSQL Injection",
                  "desc": "Improperly Controlled Modification of Dynamically-Determined Object Attributes"},
    # ── Code Quality / Other ──
    "CWE-20":    {"cat": "InputVal", "sub": "Improper Input Validation",
                  "desc": "Improper Input Validation"},
    "CWE-74":    {"cat": "Injection", "sub": "Generic Injection",
                  "desc": "Improper Neutralization of Special Elements in Output Used by a Downstream Component"},
    "CWE-444":   {"cat": "DoS", "sub": "HTTP Request Smuggling",
                  "desc": "Inconsistent Interpretation of HTTP Requests"},
    "CWE-93":    {"cat": "Injection", "sub": "CRLF Injection",
                  "desc": "Improper Neutralization of CRLF Sequences ('CRLF Injection')"},
    "CWE-113":   {"cat": "Injection", "sub": "HTTP Response Splitting",
                  "desc": "Improper Neutralization of CRLF Sequences in HTTP Headers"},
    "CWE-134":   {"cat": "MemCorrupt", "sub": "Format String Vulnerability",
                  "desc": "Use of Externally-Controlled Format String"},
    "CWE-489":   {"cat": "InfoLeak", "sub": "Active Debug Code",
                  "desc": "Active Debug Code"},
    "CWE-668":   {"cat": "InfoLeak", "sub": "Resource Exposure",
                  "desc": "Exposure of Resource to Wrong Sphere"},
    "CWE-73":    {"cat": "Injection", "sub": "External File Inclusion",
                  "desc": "External Control of File Name or Path"},
    "CWE-494":   {"cat": "AuthBypass", "sub": "Download of Code Without Integrity",
                  "desc": "Download of Code Without Integrity Check"},
    "CWE-829":   {"cat": "AuthBypass", "sub": "Inclusion of Functionality from Untrusted Source",
                  "desc": "Inclusion of Functionality from Untrusted Control Sphere"},
    "CWE-915":   {"cat": "Injection", "sub": "Prototype Pollution",
                  "desc": "Improperly Controlled Modification of Dynamically-Determined Object Attributes"},
    "CWE-1321":  {"cat": "Injection", "sub": "Prototype Pollution (JSON)",
                  "desc": "Improperly Controlled Modification of Object Prototype Attributes"},
    # Note: CWE-79 (XSS) and CWE-94 (Code Injection) are defined earlier in
    # this dict; do NOT re-define them here.
}

# Keyword fallback — used when CWE is missing or generic.
# Keywords are matched with word boundaries (\b) and case-insensitivity.
# Multi-word phrases (e.g. "remote code execution") are matched as literals
# with word boundaries at the start and end. Short tokens (e.g. "rce", "xss")
# are matched as whole words only — never as substrings.
KEYWORD_MAP: List[Dict[str, Any]] = [
    {"cat": "RCE", "sub": "Code Execution",
     "kw": ["remote code execution", "arbitrary code execution", "rce",
            "execute arbitrary code", "execute arbitrary commands",
            "command execution", "arbitrary command", "remote command execution",
            "code execution", "shell injection"]},
    {"cat": "PrivEsc", "sub": "Privilege Escalation",
     "kw": ["privilege escalation", "privesc", "escalate privileges",
            "elevation of privilege", "gain elevated privileges"]},
    {"cat": "SQLi", "sub": "SQL Injection",
     "kw": ["sql injection", "sql query", "sqli", "blind sql"]},
    {"cat": "XSS", "sub": "Cross-Site Scripting",
     "kw": ["cross-site scripting", "xss", "stored xss", "reflected xss",
            "dom-based xss"]},
    {"cat": "SSRF", "sub": "SSRF",
     "kw": ["server-side request forgery", "ssrf"]},
    {"cat": "XXE", "sub": "XXE",
     "kw": ["xml external entity", "xxe"]},
    {"cat": "LFI", "sub": "Path Traversal",
     "kw": ["path traversal", "directory traversal", "lfi", "local file inclusion"]},
    {"cat": "RFI", "sub": "Remote File Inclusion",
     "kw": ["remote file inclusion", "rfi"]},
    {"cat": "CSRF", "sub": "CSRF",
     "kw": ["cross-site request forgery", "csrf", "xsrf"]},
    # Note: "dos" is matched as a whole word — no trailing-space hack needed.
    {"cat": "DoS", "sub": "Denial of Service",
     "kw": ["denial of service", "dos", "crash", "panic", "exhaust memory"]},
    {"cat": "AuthBypass", "sub": "Auth Bypass",
     "kw": ["authentication bypass", "auth bypass", "bypass authentication",
            "unauthenticated", "without authentication"]},
    {"cat": "InfoLeak", "sub": "Info Disclosure",
     "kw": ["information disclosure", "info leak", "leak sensitive",
            "disclose sensitive", "memory leak"]},
    {"cat": "MemCorrupt", "sub": "Memory Corruption",
     "kw": ["buffer overflow", "heap overflow", "stack overflow",
            "use-after-free", "out-of-bounds", "double free", "off-by-one"]},
    {"cat": "OpenRedirect", "sub": "Open Redirect",
     "kw": ["open redirect", "url redirect", "unvalidated redirect"]},
    {"cat": "Injection", "sub": "LDAP Injection",
     "kw": ["ldap injection"]},
    {"cat": "Injection", "sub": "CRLF Injection",
     "kw": ["crlf injection", "http response splitting"]},
]

# Negation patterns — if a keyword match is preceded by one of these, the
# match is suppressed. This prevents "not vulnerable to SQL injection" from
# classifying as SQLi. Matched case-insensitively as a literal prefix on the
# 40 characters before the keyword hit.
_NEGATION_PATTERNS = (
    "not vulnerable", "is not vulnerable", "are not vulnerable",
    "no longer", "cannot", "can not", "isn't", "doesn't",
    "not affected", "not impacted", "not susceptible",
    "does not allow", "does not permit",
)


def _keyword_match(description_lower: str) -> Optional[Dict[str, str]]:
    """Match a keyword rule against the description using word boundaries.

    Returns the first matching rule dict (cat/sub) or None. Negation
    patterns immediately before a keyword hit suppress that hit.
    """
    for rule in KEYWORD_MAP:
        for kw in rule["kw"]:
            # Build a regex with word boundaries on both ends.
            # re.escape handles hyphens etc.; \b on both sides ensures we
            # don't match substrings.
            pattern = r"\b" + re.escape(kw) + r"\b"
            m = re.search(pattern, description_lower)
            if not m:
                continue
            # Negation check: look at the 40 chars preceding the match.
            start_ctx = max(0, m.start() - 40)
            preceding = description_lower[start_ctx:m.start()]
            if any(neg in preceding for neg in _NEGATION_PATTERNS):
                continue
            return {"cat": rule["cat"], "sub": rule["sub"]}
    return None

# CWEs that are too generic to be the primary classification
GENERIC_CWES = {
    "CWE-20", "CWE-200", "CWE-264", "CWE-284", "CWE-693", "CWE-755",
    "CWE-1188", "CWE-1321", "CWE-1039", "CWE-19", "CWE-288", "CWE-118",
}

# Priority order — pick the most severe/specific when multiple match
CATEGORY_PRIORITY = {
    "RCE": 1, "MemCorrupt": 2, "PrivEsc": 3, "SQLi": 4, "AuthBypass": 5,
    "SSRF": 6, "XXE": 7, "RFI": 8, "LFI": 9, "XSS": 10, "CSRF": 11,
    "Injection": 12, "OpenRedirect": 13, "DoS": 14, "InfoLeak": 15,
    "Crypto": 16, "Race": 17, "InputVal": 18,
}

# Exploit detection in NVD references.
# Strict: only the "Exploit" / "Exploit-db" tag means "this is an actual exploit/PoC".
# "Third Party Advisory" is too broad (it covers Oracle CPU advisories, vendor
# patch notices, etc.) — those are classified as advisories instead.
EXPLOIT_TAGS = {"Exploit", "Exploit-db"}
EXPLOIT_URL_HINTS = (
    "exploit-db.com/exploit", "packetstormsecurity.com/files",
    "seclists.org/fulldisclosure", "seclists.org/bugtraq",
    "raw.githubusercontent.com", "packetstorm.com/files",
    "0day.today/exploit", "coresecurity.com",
    "secpod.com", "exploit.kitploit.com",
    # Note: generic "github.com/" is intentionally NOT here — it would match
    # every GitHub URL including GitHub Security Advisories. Only raw / gist
    # URLs (which actually host PoC code) are treated as exploit hints.
    "gist.github.com",
)

# Vendor advisory URL patterns — these are NOT exploits, just patch announcements.
# We separate them so the pentester sees actionable info first.
VENDOR_ADVISORY_HINTS = (
    "access.redhat.com/errata", "access.redhat.com/security",
    "ubuntu.com/security", "usn.ubuntu.com",
    "debian.org/security", "lists.debian.org",
    "security.netapp.com", "support.f5.com",
    "support.hpe.com", "h20566.www2.hpe.com",
    "support.oracle.com", "www.oracle.com/security",
    "www.oracle.com/technetwork/security-advisory",
    "www.oracle.com/technetwork/security",
    "msrc.microsoft.com", "technet.microsoft.com",
    "access.redhat.com/errata", "rhn.redhat.com",
    "security.gentoo.org", "bugs.gentoo.org",
    "bugzilla.suse.com", "download.suse.com",
    "support.novell.com",
    "cert-portal.siemens.com",
    "security.samsung.com",
    "github.com/advisories",  # GitHub Security Advisories (not PoCs)
    "lists.apache.org",
    "access.redhat.com",
    # Vulnerability databases (VDBs) — descriptive, not exploits
    "securityfocus.com/bid", "www.securityfocus.com",
    "securitytracker.com", "www.securitytracker.com",
    "kb.cert.org", "www.kb.cert.org",
    "exchange.xforce.ibmcloud.com",
    "cve.mitre.org",
)

# CISA KEV catalog (Known Exploited Vulnerabilities)
# PRIMARY: cisagov/kev-data mirror — cisa.gov is now Akamai-gated (403) for many
# server IPs. The cisagov/kev-data repo is the official GitHub mirror and has
# the SAME schema as the original cisa.gov feed. The cisa.gov URL is kept as
# a fallback for users running from networks where Akamai allows it.
CISA_KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
CISA_KEV_URL_FALLBACK = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ════════════════════════════════════════════════════════════════════════════
# Core data model (Phase 2) — typed records used throughout the tool.
# ════════════════════════════════════════════════════════════════════════════
# Replaces the ad-hoc Dict[str, Any] returns from earlier versions. These
# dataclasses document the schema, catch typos at dev time, and make the
# render/export code far less brittle.

from enum import Enum


class ExploitMaturity(str, Enum):
    """Exploit maturity ladder — replaces boolean has_exploit + raw counts.

    Ordered from strongest evidence to weakest. The decision tree in
    ``CVEHunter._compute_maturity()`` picks the *highest* level supported by
    available evidence. ``UNPROVEN`` means no evidence was found AND no
    material source failed (per Phase 1 sources_status, a failed source
    never produces a confident UNPROVEN — see ``_evidence_incomplete``).
    """
    IN_THE_WILD = "in_the_wild"   # present in CISA KEV (or VulnCheck KEV)
    FUNCTIONAL = "functional"     # high-rank MSF / verified EDB / multi-PoC / EPSS>=0.36
    POC = "poc"                   # >=1 PoC repo / single low-quality exploit
    UNPROVEN = "unproven"         # no evidence (sources ok)


@dataclass
class CVSSRecord:
    """A single CVSS assessment from NVD, tagged with version + source type.

    source_type is one of: "Primary", "Secondary", "Adp" (NVD-published
    adaptation). ``version`` is e.g. "4.0", "3.1", "3.0", "2.0".
    """
    version: str
    score: float
    severity: str
    vector: str
    exploitability: Optional[float]
    impact: Optional[float]
    source_type: str  # "Primary" | "Secondary" | "Adp" | ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version, "score": self.score,
            "severity": self.severity, "vector": self.vector,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "source_type": self.source_type,
        }


@dataclass
class CWEEntry:
    """A single CWE with its NVD provenance (Primary vs Secondary)."""
    cwe_id: str           # e.g. "CWE-502"
    source_type: str      # "Primary" | "Secondary" | ""


@dataclass
class ExploitEvidence:
    """A single piece of exploit/PoC evidence, deduplicated by normalized URL."""
    source: str           # "nvd_ref" | "github" | "exploitdb" | "msf" | "nuclei"
    url: str              # canonical URL or local path
    quality: str          # "high" | "medium" | "low"
    evidence_type: str    # "exploit" | "poc" | "advisory" | "module"
    extra: Dict[str, Any] = field(default_factory=dict)
    trust: str = "curated"  # "curated" (nomi-sec, trickest, EDB, MSF, NVD ref, nuclei) | "mention" (raw search)


@dataclass
class Classification:
    """Result of rule-based classification (replaces the ad-hoc dict)."""
    primary: str                       # primary category, e.g. "RCE"
    subcategory: str                   # e.g. "Unsafe Deserialization"
    chain: List[str] = field(default_factory=list)   # all recognized CWEs
    confidence: str = "low"            # "high" | "medium" | "low"
    basis: str = "generic"             # "cwe_primary" | "cwe_secondary" | "keyword" | "generic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary": self.primary, "subcategory": self.subcategory,
            "chain": self.chain, "confidence": self.confidence, "basis": self.basis,
        }


@dataclass
class Risk:
    """Composite risk score (Phase 2: dimensional, confidence-weighted)."""
    score: int                          # 0-100
    label: str
    breakdown: List[str] = field(default_factory=list)
    likelihood: float = 0.0             # 0.0-1.0 (max-style combine)
    impact: float = 0.0                 # 0.0-1.0 (CVSS impact subscore normalized)
    accessibility: float = 0.0          # 0.0-1.0 (AV/PR/UI derived)
    confidence_factor: float = 1.0      # 0.5 (low) | 0.8 (medium) | 1.0 (high)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score, "label": self.label, "breakdown": self.breakdown,
            "likelihood": round(self.likelihood, 3),
            "impact": round(self.impact, 3),
            "accessibility": round(self.accessibility, 3),
            "confidence_factor": self.confidence_factor,
        }


@dataclass
class CVERecord:
    """The full enriched CVE record, the central type of the tool.

    Replaces the Dict[str, Any] that scan() used to return. All downstream
    rendering, export, and risk-scoring code consumes this type.
    """
    cve_id: str
    description: str
    cvss_all: List[CVSSRecord]
    cvss_selected: Optional[CVSSRecord]
    cvss_source_disagreement: bool
    cwes: List[CWEEntry]
    references: List[Dict[str, Any]]
    cpes: List[str]
    version_ranges: List[Dict[str, Any]]
    patch_versions: List[Dict[str, str]]
    published: str
    modified: str
    vuln_status: str
    provisional: bool
    epss: Optional[Dict[str, Any]]
    classification: Classification
    remote_exploitable: Optional[bool]
    vector_category_conflict: Optional[str]
    exploit_evidence: List[ExploitEvidence]
    exploit_maturity: ExploitMaturity
    evidence_incomplete: bool
    cisa_kev: Optional[Dict[str, Any]]
    sources_status: Dict[str, str]
    # Phase 3 fields:
    capec_attack: Dict[str, List[str]] = field(default_factory=dict)
    vulncheck_kev: Optional[Dict[str, Any]] = None
    nuclei_template: bool = False
    # Shodan/GreyNoise enrichment (Phase 5)
    shodan_exposure: Optional[Dict[str, Any]] = None
    greynoise_activity: Optional[Dict[str, Any]] = None
    risk: Optional[Risk] = None

    # --- convenience accessors used by old rendering code ---
    @property
    def cvss(self) -> Optional[CVSSRecord]:
        return self.cvss_selected
    @property
    def cvss_score(self) -> float:
        return self.cvss_selected.score if self.cvss_selected else 0.0
    @property
    def cvss_severity(self) -> str:
        return self.cvss_selected.severity if self.cvss_selected else ""
    @property
    def cvss_vector(self) -> str:
        return self.cvss_selected.vector if self.cvss_selected else ""
    @property
    def cvss_vector_decoded(self) -> List[Tuple[str, str, str]]:
        return decode_cvss_vector(self.cvss_vector)
    @property
    def category(self) -> str:
        return self.classification.primary
    @property
    def subcategory(self) -> str:
        return self.classification.subcategory
    @property
    def cwe_ids(self) -> List[str]:
        return [c.cwe_id for c in self.cwes]
    @property
    def exploit_refs(self) -> List[str]:
        return [e.url for e in self.exploit_evidence if e.evidence_type in ("exploit", "poc")]
    @property
    def advisory_refs(self) -> List[str]:
        # References classified as vendor advisories by detect_exploit_in_refs.
        # We keep the raw list here for backwards-compat with render code.
        return [r["url"] for r in self.references
                if any(h in (r.get("url") or "").lower()
                       for h in VENDOR_ADVISORY_HINTS)]
    @property
    def other_refs(self) -> List[str]:
        exploit_set = set(self.exploit_refs)
        advisory_set = set(self.advisory_refs)
        return [r["url"] for r in self.references
                if r["url"] not in exploit_set and r["url"] not in advisory_set]
    @property
    def has_exploit_ref(self) -> bool:
        return any(e.evidence_type in ("exploit", "poc") for e in self.exploit_evidence)
    @property
    def github_pocs(self) -> List[Dict[str, Any]]:
        return [e.extra for e in self.exploit_evidence if e.source == "github"]
    @property
    def searchsploit(self) -> List[Dict[str, Any]]:
        return [e.extra for e in self.exploit_evidence if e.source == "exploitdb"]
    @property
    def searchsploit_available(self) -> bool:
        return any(e.source == "exploitdb" for e in self.exploit_evidence) or \
               any(e.extra.get("_searchsploit_available") for e in self.exploit_evidence)
    @property
    def msf_modules(self) -> List[Dict[str, Any]]:
        return [e.extra for e in self.exploit_evidence if e.source == "msf"]
    @property
    def msf_available(self) -> bool:
        return any(e.source == "msf" for e in self.exploit_evidence) or \
               any(e.extra.get("_msf_available") for e in self.exploit_evidence)
    @property
    def exploit_count(self) -> int:
        return len(self.exploit_evidence)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a plain dict for JSON export + backwards compat."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss": self.cvss_selected.to_dict() if self.cvss_selected else None,
            "cvss_all": [c.to_dict() for c in self.cvss_all],
            "cvss_selected": self.cvss_selected.to_dict() if self.cvss_selected else None,
            "cvss_source_disagreement": self.cvss_source_disagreement,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "cvss_version": self.cvss_selected.version if self.cvss_selected else "",
            "cvss_vector": self.cvss_vector,
            "cvss_vector_decoded": self.cvss_vector_decoded,
            "cwes": self.cwe_ids,
            "cwe_entries": [{"cwe_id": c.cwe_id, "source_type": c.source_type} for c in self.cwes],
            "cpes": self.cpes,
            "version_ranges": self.version_ranges,
            "patch_versions": self.patch_versions,
            "references": self.references,
            "published": self.published,
            "modified": self.modified,
            "vuln_status": self.vuln_status,
            "provisional": self.provisional,
            "epss": self.epss,
            "category": self.classification.primary,
            "subcategory": self.classification.subcategory,
            "classification": self.classification.to_dict(),
            "remote_exploitable": self.remote_exploitable,
            "vector_category_conflict": self.vector_category_conflict,
            "exploit_evidence": [
                {"source": e.source, "url": e.url, "quality": e.quality,
                 "type": e.evidence_type, "trust": e.trust, **e.extra}
                for e in self.exploit_evidence
            ],
            "exploit_maturity": self.exploit_maturity.value,
            "evidence_incomplete": self.evidence_incomplete,
            "cisa_kev": self.cisa_kev,
            "sources_status": self.sources_status,
            "risk": self.risk.to_dict() if self.risk else None,
            # Phase 3 fields:
            "capec_attack": self.capec_attack,
            "vulncheck_kev": self.vulncheck_kev,
            "shodan_exposure": self.shodan_exposure,
            "greynoise_activity": self.greynoise_activity,
            "nuclei_template": self.nuclei_template,
            # Backwards-compat fields used by old render code:
            "has_exploit_ref": self.has_exploit_ref,
            "exploit_refs": self.exploit_refs,
            "advisory_refs": self.advisory_refs,
            "other_refs": self.other_refs,
            "github_pocs": self.github_pocs,
            "searchsploit": self.searchsploit,
            "searchsploit_available": self.searchsploit_available,
            "msf_modules": self.msf_modules,
            "msf_available": self.msf_available,
            "exploit_count": self.exploit_count,
        }


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════
def validate_cve(cve_id: str) -> bool:
    return bool(CVE_PATTERN.match(cve_id.strip()))

def validate_cpe(cpe: str) -> bool:
    return bool(CPE_PATTERN.match(cpe.strip()))

def severity_from_score(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    if score > 0: return "Low"
    return "None"

def severity_color(severity: str) -> str:
    return {"Critical": "bright_red", "High": "red", "Medium": "yellow",
            "Low": "green", "None": "white"}.get(severity, "white")

def category_color(category: str) -> str:
    palette = {
        "RCE": "bright_red", "PrivEsc": "red", "SQLi": "magenta",
        "MemCorrupt": "red", "AuthBypass": "yellow", "SSRF": "cyan",
        "XXE": "cyan", "LFI": "blue", "RFI": "blue", "XSS": "green",
        "CSRF": "green", "DoS": "yellow", "InfoLeak": "white",
        "OpenRedirect": "white", "Crypto": "cyan", "Race": "yellow",
        "Injection": "magenta", "InputVal": "dim", "Unknown": "dim",
    }
    return palette.get(category, "white")

def truncate(text: str, max_len: int = 200) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= max_len else text[:max_len - 3] + "..."

def safe_get(d: Optional[dict], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict): return default
        cur = cur.get(k)
        if cur is None: return default
    return cur if cur is not None else default

# ── CVSS vector decoder (NEW in v3.0) ────────────────────────────────────────
CVSS_METRIC_LABELS = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S":  "Scope",
    "C":  "Confidentiality Impact",
    "I":  "Integrity Impact",
    "A":  "Availability Impact",
}
CVSS_VALUE_LABELS = {
    "AV:N": "Network",   "AV:A": "Adjacent",   "AV:L": "Local",   "AV:P": "Physical",
    "AC:L": "Low",       "AC:H": "High",
    "PR:N": "None",      "PR:L": "Low",        "PR:H": "High",
    "UI:N": "None",      "UI:R": "Required",
    "S:U":  "Unchanged", "S:C": "Changed",
    "C:N":  "None",      "C:L": "Low",         "C:H": "High",
    "I:N":  "None",      "I:L": "Low",         "I:H": "High",
    "A:N":  "None",      "A:L": "Low",         "A:H": "High",
}

def decode_cvss_vector(vector: str) -> List[Tuple[str, str, str]]:
    """Parse CVSS vector string into list of (metric, raw, label)."""
    if not vector: return []
    # Strip prefix like "CVSS:3.1/"
    parts = vector.split("/", 1)
    metrics_str = parts[1] if len(parts) > 1 else parts[0]
    results = []
    for token in metrics_str.split("/"):
        token = token.strip()
        if ":" not in token: continue
        metric, value = token.split(":", 1)
        full_key = f"{metric}:{value}"
        metric_label = CVSS_METRIC_LABELS.get(metric, metric)
        value_label = CVSS_VALUE_LABELS.get(full_key, value)
        results.append((metric_label, full_key, value_label))
    return results


def extract_attack_vector(cvss_vector: str) -> Optional[str]:
    """Extract just the AV value from CVSS vector ('N', 'A', 'L', or 'P')."""
    if not cvss_vector: return None
    m = re.search(r"AV:([NAPL])", cvss_vector)
    return m.group(1) if m else None


def detect_vector_category_conflict(category: str, cvss_vector: str) -> Optional[str]:
    """Detect when CVSS Attack Vector conflicts with the vuln category.

    Returns a warning message if there's a conflict, else None.

    Examples:
      - Category=RCE but AV:L (local) → suspicious (PrintNightmare case)
      - Category=PrivEsc but AV:N (network) → suspicious (Zerologon case)
    """
    av = extract_attack_vector(cvss_vector)
    if not av: return None

    # RCE typically should be network-reachable; AV:L is suspicious
    if category == "RCE" and av == "L":
        return ("CVSS indicates Local (AV:L) but description suggests RCE. "
                "Verify whether this is a remote or local exploit — NVD's CVSS "
                "may be misassigned.")
    # PrivEsc typically local; AV:N may indicate remote privesc (rare but possible)
    if category == "PrivEsc" and av == "N":
        return ("CVSS indicates Network (AV:N) for a Privilege Escalation. "
                "This may be a remote privesc (e.g. AD-related) — verify "
                "exploitation path manually.")
    return None

# ── CPE parser (NEW in v3.0) ─────────────────────────────────────────────────
def parse_cpe(cpe: str) -> Optional[Dict[str, str]]:
    """Parse CPE 2.3 format string.
    Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    if not cpe: return None
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part_map = {"a": "Application", "o": "OS", "h": "Hardware"}
    return {
        "raw": cpe,
        "part": parts[2],
        "part_label": part_map.get(parts[2], parts[2]),
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if len(parts) > 5 else "*",
        "update": parts[6] if len(parts) > 6 else "*",
        "edition": parts[7] if len(parts) > 7 else "*",
    }

def cpe_human_readable(cpe: str) -> str:
    """Human-readable CPE: 'Apache log4j 2.14.0 (Application)'."""
    p = parse_cpe(cpe)
    if not p: return cpe
    parts = [p["vendor"].replace("_", " ").title(),
             p["product"].replace("_", " ").title()]
    if p["version"] not in ("*", "-"): parts.append(p["version"])
    return f"{' '.join(parts)} ({p['part_label']})"

# ════════════════════════════════════════════════════════════════════════════
# Settings
# ════════════════════════════════════════════════════════════════════════════
@dataclass
class Settings:
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_rate_limit_no_key: float = 6.0
    nvd_rate_limit_with_key: float = 1.2

    epss_base_url: str = "https://api.first.org/data/v1/epss/"

    github_token: str = ""
    github_api_url: str = "https://api.github.com/search/repositories"

    cisa_kev_url: str = CISA_KEV_URL

    cache_dir: Path = field(default_factory=lambda: DEFAULT_CONFIG_DIR / "cache")
    cache_ttl_hours: int = 24
    default_export_dir: Path = field(default_factory=lambda: Path.cwd())

    # Phase 3: local mirror paths for curated PoC sources
    poc_in_github_path: Optional[Path] = None   # clone of nomi-sec/PoC-in-GitHub
    trickest_path: Optional[Path] = None        # clone of trickest/cve
    nuclei_path: Optional[Path] = None          # clone of projectdiscovery/nuclei-templates
    vulncheck_api_key: str = ""                  # optional VulnCheck KEV API key
    vulners_api_key: str = ""                    # optional Vulners API key (else source skips with no_key)
    shodan_api_key: str = ""                     # optional Shodan API key (exposure counts)
    greynoise_api_key: str = ""                  # optional GreyNoise API key (active exploitation)
    # Phase 4: discovery engine tuning
    discovery_workers: int = 6                   # concurrent source workers for deep enrichment
    deep_default_limit: int = 25                 # default --deep-limit for `search --deep`
    max_pocs_default: int = 15                   # default cap for displayed PoC leads

    @property
    def nvd_request_interval(self) -> float:
        return self.nvd_rate_limit_with_key if self.nvd_api_key else self.nvd_rate_limit_no_key

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    s = Settings()
    parser = ConfigParser()
    if DEFAULT_CONFIG_FILE.exists():
        parser.read(DEFAULT_CONFIG_FILE)
        if parser.has_section("nvd"):
            s.nvd_api_key = parser.get("nvd", "api_key", fallback="")
        if parser.has_section("github"):
            s.github_token = parser.get("github", "token", fallback="")
        if parser.has_section("cache"):
            s.cache_ttl_hours = parser.getint("cache", "ttl_hours", fallback=s.cache_ttl_hours)
        # Phase 3: local mirror paths
        if parser.has_section("paths"):
            for key, attr in [("poc_in_github", "poc_in_github_path"),
                              ("trickest", "trickest_path"),
                              ("nuclei", "nuclei_path")]:
                val = parser.get("paths", key, fallback="")
                if val:
                    setattr(s, attr, Path(val))
        if parser.has_section("vulncheck"):
            s.vulncheck_api_key = parser.get("vulncheck", "api_key", fallback="")
        if parser.has_section("vulners"):
            s.vulners_api_key = parser.get("vulners", "api_key", fallback="")
        if parser.has_section("shodan"):
            s.shodan_api_key = parser.get("shodan", "api_key", fallback="")
        if parser.has_section("greynoise"):
            s.greynoise_api_key = parser.get("greynoise", "api_key", fallback="")
        # Hardening: chmod 600 if looser
        try:
            st = os.stat(DEFAULT_CONFIG_FILE)
            if (st.st_mode & 0o077) != 0:
                os.chmod(DEFAULT_CONFIG_FILE, 0o600)
        except OSError:
            pass
    s.nvd_api_key = os.environ.get("NVD_API_KEY", s.nvd_api_key)
    s.github_token = os.environ.get("GITHUB_TOKEN", s.github_token)
    s.vulncheck_api_key = os.environ.get("VULNCHECK_API_KEY", s.vulncheck_api_key)
    s.vulners_api_key = os.environ.get("VULNERS_API_KEY", s.vulners_api_key)
    s.shodan_api_key = os.environ.get("SHODAN_API_KEY", s.shodan_api_key)
    s.greynoise_api_key = os.environ.get("GREYNOISE_API_KEY", s.greynoise_api_key)
    s.ensure_dirs()
    return s


def save_config(nvd_key: str = "", github_token: str = "",
                poc_in_github_path: str = "", trickest_path: str = "",
                nuclei_path: str = "", vulncheck_key: str = "",
                vulners_key: str = "",
                shodan_key: str = "", greynoise_key: str = "") -> Path:
    """Persist API keys to ~/.cve-hunter/config.ini with mode 0600.

    Keys are stored plaintext (the file is chmod 600 to keep them out of
    group/other). On every write we explicitly re-chmod in case the file
    already existed with looser permissions.
    """
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    parser = ConfigParser()
    if DEFAULT_CONFIG_FILE.exists():
        parser.read(DEFAULT_CONFIG_FILE)
    def set_val(section, key, value):
        if not value: return
        if not parser.has_section(section): parser.add_section(section)
        parser.set(section, key, value)
    set_val("nvd", "api_key", nvd_key)
    set_val("github", "token", github_token)
    # Phase 3: local mirror paths + VulnCheck key
    set_val("paths", "poc_in_github", poc_in_github_path)
    set_val("paths", "trickest", trickest_path)
    set_val("paths", "nuclei", nuclei_path)
    set_val("vulncheck", "api_key", vulncheck_key)
    set_val("vulners", "api_key", vulners_key)
    set_val("shodan", "api_key", shodan_key)
    set_val("greynoise", "api_key", greynoise_key)
    # Write atomically-ish: write then chmod. We use os.open to create the
    # file with mode 0600 from the start when it doesn't yet exist; for
    # existing files we chmod after writing.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(DEFAULT_CONFIG_FILE, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        parser.write(f)
    # Always re-chmod — if the file pre-existed with looser perms, the open
    # above keeps its mode; force it to 0600.
    os.chmod(DEFAULT_CONFIG_FILE, 0o600)
    return DEFAULT_CONFIG_FILE


# ════════════════════════════════════════════════════════════════════════════
# Cache
# ════════════════════════════════════════════════════════════════════════════
# Cache schema version. Bump this whenever the cached record structure
# changes (added/removed/renamed fields, type changes, etc.). On mismatch
# the existing cache is transparently invalidated and rebuilt from scratch
# so stale v3 records never get served by a v4 tool.
CACHE_SCHEMA_VERSION = "4.0"


class Cache:
    SCHEMA = """CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY, value TEXT NOT NULL, ts REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS cache_meta (
        k TEXT PRIMARY KEY, v TEXT NOT NULL);"""

    def __init__(self, cache_dir: Path, ttl_hours: int = 24) -> None:
        self.db_path = cache_dir / "cve_hunter.db"
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600
        self._init_db()

    def _init_db(self) -> None:
        """Create schema and check schema version; invalidate on mismatch."""
        with closing(self._conn()) as c:
            with c:
                c.executescript(self.SCHEMA)
            # Check stored schema version. executescript above already
            # committed, so a plain SELECT works here.
            row = c.execute(
                "SELECT v FROM cache_meta WHERE k = ?", ("schema_version",)
            ).fetchone()
            if row is None:
                # First run — store current version. If there happen to be
                # leftover rows from a pre-versioned cache, clear them.
                cur = c.execute("SELECT COUNT(*) FROM cache")
                existing = cur.fetchone()[0]
                # Wrap the writes in a transaction so they actually commit.
                with c:
                    if existing > 0:
                        c.execute("DELETE FROM cache")
                    c.execute(
                        "INSERT OR REPLACE INTO cache_meta (k, v) VALUES (?, ?)",
                        ("schema_version", CACHE_SCHEMA_VERSION),
                    )
            elif row[0] != CACHE_SCHEMA_VERSION:
                # Schema mismatch — invalidate everything and store new version.
                with c:
                    c.execute("DELETE FROM cache")
                    c.execute(
                        "INSERT OR REPLACE INTO cache_meta (k, v) VALUES (?, ?)",
                        ("schema_version", CACHE_SCHEMA_VERSION),
                    )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def get(self, key: str) -> Optional[Any]:
        with closing(self._conn()) as c:
            row = c.execute("SELECT value, ts FROM cache WHERE key = ?", (key,)).fetchone()
        if not row: return None
        value_json, ts = row
        if time.time() - ts > self.ttl_seconds: return None
        try: return json.loads(value_json)
        except json.JSONDecodeError: return None

    def set(self, key: str, value: Any) -> None:
        with closing(self._conn()) as c:
            with c:
                c.execute("INSERT OR REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)",
                          (key, json.dumps(value), time.time()))

    def clear(self) -> int:
        with closing(self._conn()) as c:
            with c:
                cur = c.execute("DELETE FROM cache")
                # Keep cache_meta so schema_version persists.
                return cur.rowcount


# ════════════════════════════════════════════════════════════════════════════
# NVD Client
# ════════════════════════════════════════════════════════════════════════════
class NVDClient:
    def __init__(self, settings: Settings, cache: Cache,
                 offline: bool = False) -> None:
        self.s = settings
        self.cache = cache
        self.offline = offline
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0",
            "Accept": "application/json",
        })
        if settings.nvd_api_key:
            self.session.headers["apiKey"] = settings.nvd_api_key
        self._last_ts = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_ts
        wait = self.s.nvd_request_interval - elapsed
        if wait > 0: time.sleep(wait)
        self._last_ts = time.time()

    def _get(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fetch from NVD with exponential backoff on failures.

        Handles:
          - requests.RequestException (ConnectionError, ReadTimeout) → retry
          - HTTP 403/429/5xx → retry with backoff
          - HTTP 404 → return None (CVE not found)
          - JSONDecodeError (malformed response, e.g. HTML maintenance page)
            → retry once, then return None (graceful degradation)
        """
        resp = None
        for attempt in range(5):
            self._rate_limit()
            try:
                resp = self.session.get(self.s.nvd_base_url, params=params, timeout=20)
            except requests.RequestException as exc:
                if attempt == 4: raise RuntimeError(f"NVD request failed: {exc}")
                # Exponential backoff: 2, 4, 8, 16 seconds
                time.sleep(2 ** (attempt + 1))
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    # NVD occasionally returns HTML (maintenance page) or
                    # truncated JSON under heavy load. Retry; if all 5
                    # attempts fail with JSONDecodeError, treat as not found.
                    if attempt == 4: return None
                    time.sleep(2 ** (attempt + 1))
                    continue
            if resp.status_code in (403, 429, 500, 502, 503, 504):
                # Exponential backoff: 5, 10, 20, 40, 80 seconds (capped at 60)
                wait = min(5 * (2 ** attempt), 60)
                time.sleep(wait)
                continue
            if resp.status_code == 404: return None
            raise RuntimeError(f"NVD HTTP {resp.status_code}: {resp.text[:200]}")
        raise RuntimeError(
            f"NVD failed after 5 attempts (last: {resp.status_code if resp else 'unknown'})")

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cve_id = cve_id.upper()
        cached = self.cache.get(f"nvd:{cve_id}")
        if cached is not None: return cached
        # Offline mode: no network calls — only use cache (populated by
        # `import-nvd` command).
        if self.offline: return None
        data = self._get({"cveId": cve_id})
        if data is None: return None
        vulns = safe_get(data, "vulnerabilities", default=[])
        if not vulns: return None
        record = self._normalize(vulns[0])
        self.cache.set(f"nvd:{cve_id}", record)
        return record

    def search(self, *, keyword: Optional[str] = None, cpe_name: Optional[str] = None,
               pub_start: Optional[str] = None, pub_end: Optional[str] = None,
               max_results: int = 50) -> List[Dict[str, Any]]:
        # Offline mode: keyword/CPE search requires the NVD API; not
        # available offline. Return empty — user should use `scan` with
        # specific CVE IDs from the imported snapshot.
        if self.offline: return []
        params: Dict[str, Any] = {"resultsPerPage": min(max_results, 2000)}
        if keyword: params["keywordSearch"] = keyword
        if cpe_name: params["cpeName"] = cpe_name
        if pub_start: params["pubStartDate"] = pub_start
        if pub_end: params["pubEndDate"] = pub_end
        data = self._get(params)
        if data is None: return []
        vulns = safe_get(data, "vulnerabilities", default=[])
        return [self._normalize(v) for v in vulns]

    @staticmethod
    def _normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a raw NVD vulnerability entry into a normalized dict.

        Phase 2 changes:
          - CVSS: capture ALL entries across cvssMetricV40/V31/V30/V2, each
            tagged with version + source/type (Primary/Secondary/Adp). The
            caller (CVEHunter) picks cvss_selected per the policy in task 2.
          - CWE: capture each CWE's NVD type (Primary vs Secondary) alongside
            the CWE id, so classify() can use provenance for confidence.
        """
        cve = safe_get(raw, "cve", default={})
        descriptions = safe_get(cve, "descriptions", default=[])
        description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            (descriptions[0].get("value") if descriptions else ""),
        )

        # ---- CVSS multi-source capture (Phase 2 task 2) ----
        metrics = safe_get(cve, "metrics", default={})
        cvss_all: List[Dict[str, Any]] = []
        # Order matters for "prefer higher version" tie-breaking later, but
        # we capture every entry from every metric block.
        metric_blocks = [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2",  "2.0"),
        ]
        for key, default_version in metric_blocks:
            entries = safe_get(metrics, key, default=[])
            for entry in entries:
                cvss_data = safe_get(entry, "cvssData", default={})
                if not cvss_data:
                    continue
                raw_sev = (cvss_data.get("baseSeverity")
                           or safe_get(entry, "baseSeverity", default="")) or ""
                cvss_all.append({
                    "version": cvss_data.get("version", default_version),
                    "score": float(cvss_data.get("baseScore", 0.0) or 0.0),
                    "severity": raw_sev.title() if raw_sev else "",
                    "vector": cvss_data.get("vectorString", ""),
                    # FIX (accuracy-3): exploitabilityScore and impactScore are
                    # SIBLINGS of cvssData inside entry, NOT inside cvssData
                    # itself. Reading them from cvss_data always returned None,
                    # making the S:C impact-discount dead code and exporting
                    # null impact values.
                    "exploitability": entry.get("exploitabilityScore"),
                    "impact": entry.get("impactScore"),
                    "source_type": entry.get("type", ""),  # Primary/Secondary/Adp
                })

        # ---- CWE with provenance (Phase 2 task 3) ----
        weaknesses = safe_get(cve, "weaknesses", default=[])
        cwe_entries: List[Dict[str, str]] = []
        seen_cwes: set = set()
        for w in weaknesses:
            wtype = w.get("type", "")  # "Primary" | "Secondary"
            for desc in safe_get(w, "description", default=[]):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cid = desc["value"]
                    if cid in seen_cwes:
                        # Keep first occurrence's type, but record if we saw
                        # it as Primary later (Primary wins).
                        for ce in cwe_entries:
                            if ce["cwe_id"] == cid and wtype == "Primary":
                                ce["source_type"] = "Primary"
                        continue
                    seen_cwes.add(cid)
                    cwe_entries.append({"cwe_id": cid, "source_type": wtype})

        refs_raw = safe_get(cve, "references", default=[])
        references = [{"url": r.get("url"), "source": r.get("source"),
                       "tags": r.get("tags", [])} for r in refs_raw]
        configs = safe_get(cve, "configurations", default=[])
        cpes: List[str] = []
        for cfg in configs:
            for node in safe_get(cfg, "nodes", default=[]):
                for m in safe_get(node, "cpeMatch", default=[]):
                    if m.get("criteria"): cpes.append(m["criteria"])
        cpes = list(dict.fromkeys(cpes))
        # Extract version ranges from CPE matches
        version_ranges: List[Dict[str, Any]] = []
        for cfg in configs:
            for node in safe_get(cfg, "nodes", default=[]):
                for m in safe_get(node, "cpeMatch", default=[]):
                    if m.get("criteria"):
                        vr = {
                            "cpe": m["criteria"],
                            "vulnerable": m.get("vulnerable", True),
                            "human": cpe_human_readable(m["criteria"]),
                        }
                        if m.get("versionStartIncluding"):
                            vr["version_start_including"] = m["versionStartIncluding"]
                        if m.get("versionStartExcluding"):
                            vr["version_start_excluding"] = m["versionStartExcluding"]
                        if m.get("versionEndIncluding"):
                            vr["version_end_including"] = m["versionEndIncluding"]
                        if m.get("versionEndExcluding"):
                            vr["version_end_excluding"] = m["versionEndExcluding"]
                        version_ranges.append(vr)
        return {
            "cve_id": safe_get(cve, "id", default=""),
            "description": description,
            "cvss_all": cvss_all,
            "cwe_entries": cwe_entries,
            "references": references,
            "cpes": cpes,
            "version_ranges": version_ranges,
            "published": safe_get(cve, "published", default=""),
            "modified": safe_get(cve, "lastModified", default=""),
            "vuln_status": safe_get(cve, "vulnStatus", default=""),
        }


# ════════════════════════════════════════════════════════════════════════════
# Source status tracking (NEW in v4)
# ════════════════════════════════════════════════════════════════════════════
# Per-source status for each CVE. Values:
#   ok          — source responded successfully (regardless of whether it
#                 had data for this CVE).
#   ratelimited — HTTP 403/429 from the source.
#   error       — network error, non-200, or parse failure.
#   skipped     — user disabled this source via a flag.
#   unavailable — local tool (searchsploit/msfconsole) not installed.
#   notfound    — NVD says this CVE ID does not exist.
#
# Material sources (nvd, epss, kev, github) failing ⇒ the tool must NOT
# report confident "no exploit" / "not in KEV" — see CVEHunter.scan.
SOURCE_OK = "ok"
SOURCE_RATELIMITED = "ratelimited"
SOURCE_ERROR = "error"
SOURCE_SKIPPED = "skipped"
SOURCE_UNAVAILABLE = "unavailable"
SOURCE_NOTFOUND = "notfound"
SOURCE_NO_KEY = "no_key"           # source requires an API key that wasn't provided
SOURCE_NEEDS_TOKEN = "needs_token" # source requires an auth token that wasn't provided


# ════════════════════════════════════════════════════════════════════════════
# Debug logger (NEW in v4) — per-source timing/status
# ════════════════════════════════════════════════════════════════════════════
class DebugLog:
    """Collects per-source timing/status entries for --debug output."""

    def __init__(self) -> None:
        self.entries: List[Tuple[str, str, float, str]] = []
        # (source, cve_id_or_query, elapsed_seconds, status)

    def log(self, source: str, key: str, elapsed: float, status: str) -> None:
        self.entries.append((source, key, elapsed, status))

    def dump(self, console: "Console") -> None:
        if not self.entries:
            return
        console.print("\n[bold cyan]── Debug: per-source status ──[/bold cyan]")
        t = Table(show_header=True, header_style="bold")
        t.add_column("Source", style="cyan")
        t.add_column("Key", overflow="fold")
        t.add_column("Time", justify="right")
        t.add_column("Status")
        for source, key, elapsed, status in self.entries:
            color = {"ok": "green", "ratelimited": "yellow",
                     "error": "red", "skipped": "dim",
                     "unavailable": "dim", "notfound": "yellow"}.get(status, "white")
            t.add_row(source, key, f"{elapsed:.2f}s", f"[{color}]{status}[/{color}]")
        console.print(t)


# ════════════════════════════════════════════════════════════════════════════
# EPSS Client
# ════════════════════════════════════════════════════════════════════════════
class EPSSClient:
    def __init__(self, settings: Settings, cache: Cache,
                 debug: Optional[DebugLog] = None) -> None:
        self.s = settings
        self.cache = cache
        self.debug = debug
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CVE-Hunter/4.0", "Accept": "application/json"})
        self._last_ts = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_ts
        if elapsed < 1.0: time.sleep(1.0 - elapsed)
        self._last_ts = time.time()

    def get(self, cve_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (data, status). data is None when not found or unavailable."""
        cve_id = cve_id.upper()
        cached = self.cache.get(f"epss:{cve_id}")
        if cached is not None:
            if self.debug: self.debug.log("epss", cve_id, 0.0, SOURCE_OK)
            return cached, SOURCE_OK
        t0 = time.time()
        self._rate_limit()
        try:
            resp = self.session.get(self.s.epss_base_url, params={"cve": cve_id}, timeout=20)
        except requests.RequestException:
            if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code in (403, 429):
            if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return None, SOURCE_RATELIMITED
        if resp.status_code != 200:
            if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        entries = safe_get(data, "data", default=[])
        if not entries:
            # Successful response, just no EPSS data for this CVE.
            if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_OK)
            return None, SOURCE_OK
        entry = entries[0]
        result = {
            "epss": float(entry.get("epss", 0.0)),
            "percentile": float(entry.get("percentile", 0.0)),
            "date": safe_get(data, "_meta", "date", default=""),
        }
        self.cache.set(f"epss:{cve_id}", result)
        if self.debug: self.debug.log("epss", cve_id, time.time() - t0, SOURCE_OK)
        return result, SOURCE_OK

    def bulk(self, cve_ids: List[str]) -> Tuple[Dict[str, Dict[str, Any]], str]:
        """Bulk-fetch EPSS for many CVEs.

        Returns (map, overall_status). overall_status is SOURCE_OK if at least
        one batch succeeded, SOURCE_RATELIMITED/SOURCE_ERROR if all failed,
        SOURCE_OK if everything was cached.
        """
        cve_ids = [c.upper() for c in cve_ids]
        result: Dict[str, Dict[str, Any]] = {}
        missing: List[str] = []
        for c in cve_ids:
            cached = self.cache.get(f"epss:{c}")
            if cached is not None: result[c] = cached
            else: missing.append(c)
        if not missing:
            return result, SOURCE_OK
        worst_status = SOURCE_OK
        for i in range(0, len(missing), 100):
            batch = missing[i:i + 100]
            t0 = time.time()
            self._rate_limit()
            try:
                resp = self.session.get(self.s.epss_base_url,
                                        params={"cve": ",".join(batch)}, timeout=30)
            except requests.RequestException:
                if self.debug: self.debug.log("epss", f"bulk({len(batch)})", time.time() - t0, SOURCE_ERROR)
                worst_status = SOURCE_ERROR if worst_status != SOURCE_RATELIMITED else worst_status
                continue
            if resp.status_code in (403, 429):
                if self.debug: self.debug.log("epss", f"bulk({len(batch)})", time.time() - t0, SOURCE_RATELIMITED)
                worst_status = SOURCE_RATELIMITED
                continue
            if resp.status_code != 200:
                if self.debug: self.debug.log("epss", f"bulk({len(batch)})", time.time() - t0, SOURCE_ERROR)
                worst_status = SOURCE_ERROR if worst_status != SOURCE_RATELIMITED else worst_status
                continue
            try:
                data = resp.json()
            except json.JSONDecodeError:
                if self.debug: self.debug.log("epss", f"bulk({len(batch)})", time.time() - t0, SOURCE_ERROR)
                worst_status = SOURCE_ERROR if worst_status != SOURCE_RATELIMITED else worst_status
                continue
            for entry in safe_get(data, "data", default=[]):
                cid = entry.get("cve", "").upper()
                if not cid: continue
                rec = {
                    "epss": float(entry.get("epss", 0.0)),
                    "percentile": float(entry.get("percentile", 0.0)),
                    "date": safe_get(data, "_meta", "date", default=""),
                }
                result[cid] = rec
                self.cache.set(f"epss:{cid}", rec)
            if self.debug: self.debug.log("epss", f"bulk({len(batch)})", time.time() - t0, SOURCE_OK)
        return result, worst_status


# ════════════════════════════════════════════════════════════════════════════
# Exploit reference classification
# ════════════════════════════════════════════════════════════════════════════
# Note: The old ExploitSearcher class (raw GitHub search) was removed in
# Phase 4. It was replaced by PoCInGitHubSearcher (curated nomi-sec index)
# in Phase 3, which produces cleaner results and supports local mirrors.


def detect_exploit_in_refs(references: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Classify NVD references into: exploit_refs, advisories, and other.

    A reference counts as a vendor advisory if its URL matches
    VENDOR_ADVISORY_HINTS — checked FIRST so GitHub Security Advisories
    (github.com/advisories) and other vendor advisory URLs are never
    miscounted as exploits.

    A reference counts as an exploit if it has the `Exploit` / `Exploit-db`
    tag OR its URL matches EXPLOIT_URL_HINTS (specific exploit-hosting sites).
    """
    exploits: List[str] = []
    advisories: List[str] = []
    other: List[str] = []
    for ref in references:
        tags = ref.get("tags", [])
        url = ref.get("url") or ""
        url_lower = url.lower()
        # Check advisory FIRST — vendor advisories (including GitHub Security
        # Advisories at github.com/advisories) must not be misclassified as
        # exploits even if the URL host looks PoC-ish.
        is_advisory = any(h in url_lower for h in VENDOR_ADVISORY_HINTS)
        if is_advisory:
            advisories.append(url)
            continue
        is_exploit = (any(t in EXPLOIT_TAGS for t in tags)
                      or any(h in url_lower for h in EXPLOIT_URL_HINTS))
        if is_exploit:
            exploits.append(url)
        else:
            other.append(url)
    return {
        "has_exploit_ref": bool(exploits),
        "exploit_refs": list(dict.fromkeys(exploits)),
        "advisory_refs": list(dict.fromkeys(advisories)),
        "other_refs": list(dict.fromkeys(other)),
    }


# ════════════════════════════════════════════════════════════════════════════
# Curated PoC URLs (no API key required for either curated source)
# NOTE: The nomi-sec/PoC-in-GitHub repo was made private/deleted in 2024 —
# its raw URLs now always return 404. We keep NOMISEC_RAW_BASE for backwards
# compatibility with local-mirror mode, but the live TIER 1 source is now
# the motikan2010 mirror, which proxies the same data and remains online.
# ════════════════════════════════════════════════════════════════════════════
NOMISEC_RAW_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
NOMISEC_MIRROR_API = "https://poc-in-github.motikan2010.net/api/v1/"


# ════════════════════════════════════════════════════════════════════════════
# Shared hard-exclusion helper — drops forks + known aggregators
# ════════════════════════════════════════════════════════════════════════════
_AGGREGATOR_FULLNAMES = {
    "nomi-sec/poc-in-github", "trickest/cve", "cveproject/cvelist",
    "projectdiscovery/nuclei-templates",
}
_AGGREGATOR_KEYWORDS = (
    "list of all", "all cve", "cve list", "awesome cve",
    "cve database", "cve collection",
)


def _poc_is_excluded(repo: Dict[str, Any]) -> bool:
    """Return True if the repo should be dropped entirely (fork or aggregator)."""
    if repo.get("fork") is True:
        return True
    full_name = (repo.get("name") or repo.get("full_name") or "").lower()
    if full_name in _AGGREGATOR_FULLNAMES:
        return True
    if "awesome" in full_name and "cve" in full_name:
        return True
    desc = (repo.get("description") or "").lower()
    name_lower = full_name
    for kw in _AGGREGATOR_KEYWORDS:
        if kw in desc or kw in name_lower:
            return True
    return False


# ════════════════════════════════════════════════════════════════════════════
# PoC-in-GitHub (nomi-sec) — curated primary PoC source
# ════════════════════════════════════════════════════════════════════════════
class PoCInGitHubSearcher:
    """Searches for PoC repositories using a tiered curated-first strategy.

    TIER 0 — Local mirror (offline): read per-year JSON from a cloned copy.
    TIER 1 — motikan2010 mirror API (PRIMARY curated online source).
            Proxies the nomi-sec dataset; remains online after the
            nomi-sec/PoC-in-GitHub repo was made private.
    TIER 2 — nomi-sec raw per-CVE JSON (SECONDARY curated, usually 404).
            Kept as backup in case motikan2010 is down.
    TIER 3 — Raw GitHub search (DEGRADED fallback only): unverified mentions.

    Tiers 1 and 2 are AUTHORITATIVE — a 200 with empty array or a 404 means
    the CVE has no curated PoCs, and the search STOPS (no fallback to TIER 3).
    TIER 3 runs ONLY when both TIER 1 and TIER 2 are unreachable. Its results
    are tagged provenance="mention" and CANNOT raise exploit maturity.

    Each returned dict includes: {name, url, stars, description, updated,
    language, fork, provenance} where provenance is "curated" or "mention".
    """

    GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 local_path: Optional[Path] = None,
                 offline: bool = False,
                 github_token: str = "") -> None:
        self.cache = cache
        self.debug = debug
        self.local_path = local_path
        self.offline = offline
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0",
            "Accept": "application/vnd.github+json",
        })
        if github_token:
            self.session.headers["Authorization"] = f"Bearer {github_token}"
        self._last_ts = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_ts
        wait = 7.0 if not self.session.headers.get("Authorization") else 1.0
        if elapsed < wait: time.sleep(wait - elapsed)
        self._last_ts = time.time()

    @staticmethod
    def _normalize_repo(raw: Dict[str, Any], provenance: str) -> Dict[str, Any]:
        """Normalize a repo object from any source into the standard format."""
        return {
            "name": raw.get("full_name") or raw.get("name") or "",
            "url": raw.get("html_url") or raw.get("url") or "",
            "stars": int(raw.get("stargazers_count") or raw.get("stars") or 0),
            "description": raw.get("description") or "",
            "updated": raw.get("pushed_at") or raw.get("updated_at") or raw.get("updated") or "",
            "language": raw.get("language") or "",
            "fork": bool(raw.get("fork", False)),
            "provenance": provenance,
        }

    def search(self, cve_id: str, max_results: int = 10) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (results, status). status follows SOURCE_* conventions.

        Phase 4 — Always-On Aggregation:
        Every reachable source is queried; a 404/empty/error from one source
        NEVER stops the others. Curated and search results MERGE into one
        deduplicated candidate list. The old "curated 404 → STOP" behavior is
        GONE — a 404 just means "no curated PoC from that source", and we
        continue to gather candidates from the others.

        Aggregated statuses:
          SOURCE_OK            — at least one source returned data (even empty 200)
          SOURCE_RATELIMITED   — at least one source was rate-limited AND no
                                  source returned data
          SOURCE_ERROR         — every source failed (network/HTTP error)
          SOURCE_SKIPPED       — offline mode
        """
        cve_id = cve_id.upper()
        cache_key = f"pocingit:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("poc_in_github", cve_id, 0.0, SOURCE_OK)
            return cached[:max_results], SOURCE_OK

        t0 = time.time()
        m = re.match(r"CVE-(\d{4})-", cve_id)
        if not m:
            return [], SOURCE_ERROR
        year = m.group(1)

        # TIER 0 — Local mirror (offline)
        if self.local_path:
            local_file = self.local_path / f"{year}.json"
            if local_file.exists():
                try:
                    with open(local_file, "r", encoding="utf-8") as f:
                        all_pocs = json.load(f)
                    results = self._filter_and_normalize(all_pocs, cve_id, max_results, "curated")
                    self.cache.set(cache_key, results)
                    if self.debug: self.debug.log("poc_in_github", cve_id, time.time() - t0, SOURCE_OK)
                    return results, SOURCE_OK
                except (json.JSONDecodeError, OSError):
                    pass

        # Offline mode: TIER 0 only
        if self.offline:
            if self.debug: self.debug.log("poc_in_github", cve_id, 0.0, SOURCE_SKIPPED)
            return [], SOURCE_SKIPPED

        # ---- ALWAYS-ON AGGREGATION ----
        # Each source contributes candidates independently. We collect
        # (results, status) per source, then merge + dedup at the end.
        # A 404 from a curated source means "no curated PoCs from THAT
        # source" — discovery continues to other sources.
        merged: Dict[str, Dict[str, Any]] = {}  # normalized_url → repo dict
        any_ok = False
        any_ratelimited = False
        any_error = False
        any_data_returned = False  # at least one source returned 200 (even if empty)

        # Helper: merge a list of normalized repos into `merged`.
        # On collision (same normalized URL): curated wins over mention;
        # within the same trust tier, keep the one with more stars.
        def _merge(repos: List[Dict[str, Any]]) -> None:
            nonlocal any_data_returned
            for r in repos:
                if not r.get("url"): continue
                norm = _normalize_url(r["url"])
                if not norm: continue
                existing = merged.get(norm)
                if existing is None:
                    merged[norm] = r
                else:
                    # Curated wins; mention loses. Same tier → higher stars.
                    cur_trust = existing.get("trust") or existing.get("provenance", "")
                    new_trust = r.get("trust") or r.get("provenance", "")
                    existing_is_curated = (cur_trust == "curated")
                    new_is_curated = (new_trust == "curated")
                    if new_is_curated and not existing_is_curated:
                        merged[norm] = r
                    elif existing_is_curated == new_is_curated:
                        if int(r.get("stars", 0)) > int(existing.get("stars", 0)):
                            merged[norm] = r
                any_data_returned = True

        # ---- TIER 1 — motikan2010 mirror API (PRIMARY curated) ----
        try:
            resp1 = self.session.get(NOMISEC_MIRROR_API,
                                     params={"cve_id": cve_id}, timeout=30)
        except requests.RequestException:
            resp1 = None
        if resp1 is not None:
            if resp1.status_code == 200:
                try:
                    data1 = resp1.json()
                except json.JSONDecodeError:
                    data1 = {}
                raw_list1: List[Dict[str, Any]] = []
                if isinstance(data1, dict):
                    for key in ("pocs", "results", "items"):
                        val = data1.get(key)
                        if isinstance(val, list):
                            raw_list1 = val
                            break
                elif isinstance(data1, list):
                    raw_list1 = data1
                results1 = [self._normalize_repo(r, "curated") for r in raw_list1]
                results1 = [r for r in results1 if not _poc_is_excluded(r)]
                _merge(results1)
                any_ok = True
            elif resp1.status_code in (403, 429):
                any_ratelimited = True
            elif resp1.status_code == 404:
                # Authoritative "no curated PoCs from motikan2010" — but
                # discovery CONTINUES (we may still find GitHub mentions).
                any_data_returned = True
            else:
                any_error = True

        # ---- TIER 2 — nomi-sec raw per-CVE JSON (SECONDARY curated) ----
        # Usually 404 now (repo gated), but we try it for resilience.
        tier2_url = f"{NOMISEC_RAW_BASE}/{year}/{cve_id}.json"
        try:
            resp2 = self.session.get(tier2_url, timeout=30)
        except requests.RequestException:
            resp2 = None
        if resp2 is not None:
            if resp2.status_code == 200:
                try:
                    raw_list2 = resp2.json()
                    if not isinstance(raw_list2, list):
                        raw_list2 = []
                except json.JSONDecodeError:
                    raw_list2 = []
                results2 = [self._normalize_repo(r, "curated") for r in raw_list2]
                results2 = [r for r in results2 if not _poc_is_excluded(r)]
                _merge(results2)
                any_ok = True
            elif resp2.status_code in (403, 429):
                any_ratelimited = True
            elif resp2.status_code == 404:
                any_data_returned = True
            else:
                any_error = True

        # ---- TIER 3 — Multi-query GitHub repo search (mention-tier) ----
        # Phase 4: run multiple query variants in sequence and union results.
        # Each variant is rate-limited independently; 403/429 on one variant
        # does NOT abort the others. We try up to 3 variants, then stop early
        # if we have enough candidates.
        tier3_queries = [
            cve_id,
            f"{cve_id} exploit",
            f"{cve_id} poc",
        ]
        tier3_status = None
        for q in tier3_queries:
            if len(merged) >= max_results * 2: break  # enough candidates
            self._rate_limit()
            try:
                resp3 = self.session.get(
                    self.GITHUB_SEARCH_URL,
                    params={"q": q, "sort": "stars", "order": "desc",
                            "per_page": min(max_results, 30)},
                    timeout=20,
                )
            except requests.RequestException:
                any_error = True
                tier3_status = SOURCE_ERROR
                continue
            if resp3.status_code in (403, 429):
                any_ratelimited = True
                tier3_status = SOURCE_RATELIMITED
                # GitHub rate limit hit — no point trying more variants.
                break
            if resp3.status_code != 200:
                any_error = True
                tier3_status = SOURCE_ERROR
                continue
            try:
                data3 = resp3.json()
            except json.JSONDecodeError:
                any_error = True
                tier3_status = SOURCE_ERROR
                continue
            items = safe_get(data3, "items", default=[])
            results3 = [self._normalize_repo(it, "mention") for it in items]
            results3 = [r for r in results3 if not _poc_is_excluded(r)]
            _merge(results3)
            any_ok = True
            tier3_status = SOURCE_OK

        # ---- TIER 4 — GitHub code search (mention-tier, needs token) ----
        # Only runs if we have a token; degrades cleanly with SOURCE_NEEDS_TOKEN.
        if self.session.headers.get("Authorization") and len(merged) < max_results * 2:
            self._rate_limit()
            try:
                resp4 = self.session.get(
                    "https://api.github.com/search/code",
                    params={"q": f'"{cve_id}"', "per_page": min(max_results, 30)},
                    timeout=20,
                )
            except requests.RequestException:
                any_error = True
                resp4 = None
            if resp4 is not None:
                if resp4.status_code == 200:
                    try:
                        data4 = resp4.json()
                    except json.JSONDecodeError:
                        data4 = {}
                    code_items = safe_get(data4, "items", default=[])
                    code_repos: List[Dict[str, Any]] = []
                    for it in code_items:
                        if not isinstance(it, dict): continue
                        repo = it.get("repository") or {}
                        # Synthesize a normalized repo entry from the code-search hit.
                        # The parent repo gets a code-search provenance flag so
                        # render code can show "found via code search".
                        norm_repo = self._normalize_repo(repo, "mention")
                        if norm_repo.get("url"):
                            ex = norm_repo.setdefault("extra", {})
                            ex["code_search_hit"] = True
                            ex["file_path"] = it.get("path", "")
                            code_repos.append(norm_repo)
                    code_repos = [r for r in code_repos if not _poc_is_excluded(r)]
                    _merge(code_repos)
                    any_ok = True
                elif resp4.status_code in (403, 429):
                    any_ratelimited = True

        # ---- Build the final ranked candidate list ----
        # Sort: curated first, then by stars descending. Cap at max_results * 2
        # so render code has room to apply its own --max-pocs cap later.
        final_list = list(merged.values())
        final_list.sort(
            key=lambda r: (
                0 if r.get("provenance") == "curated" else 1,
                -int(r.get("stars", 0) or 0),
            )
        )
        final_list = final_list[: max(max_results * 2, 20)]

        # ---- Decide aggregate status ----
        if any_ok or any_data_returned:
            # At least one source returned 200 (possibly empty list) → authoritative.
            self.cache.set(cache_key, final_list)
            if self.debug:
                self.debug.log("poc_in_github", cve_id, time.time() - t0, SOURCE_OK)
            return final_list, SOURCE_OK
        if any_ratelimited:
            if self.debug:
                self.debug.log("poc_in_github", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return final_list, SOURCE_RATELIMITED
        if any_error:
            if self.debug:
                self.debug.log("poc_in_github", cve_id, time.time() - t0, SOURCE_ERROR)
            return final_list, SOURCE_ERROR
        # No source returned anything — treat as ok with empty list.
        self.cache.set(cache_key, [])
        if self.debug:
            self.debug.log("poc_in_github", cve_id, time.time() - t0, SOURCE_OK)
        return [], SOURCE_OK

    @staticmethod
    def _filter_and_normalize(all_pocs: List[Dict[str, Any]],
                               cve_id: str, max_results: int,
                               provenance: str = "curated") -> List[Dict[str, Any]]:
        """Filter for a specific CVE and normalize to the standard format."""
        filtered = [p for p in all_pocs
                    if (p.get("cve_id") or "").upper() == cve_id]
        filtered.sort(key=lambda p: int(p.get("stargazers_count") or p.get("stars") or 0), reverse=True)
        results = []
        for p in filtered[:max_results]:
            norm = PoCInGitHubSearcher._normalize_repo(p, provenance)
            if not _poc_is_excluded(norm):
                results.append(norm)
        return results


# ════════════════════════════════════════════════════════════════════════════
# PoC-host detection helper — used by NVD refs, OSV refs, GHSA refs, Vulners
# generic web refs to decide whether a URL is itself a PoC/exploit pointer
# (and therefore worth surfacing as exploit evidence, not just an advisory).
# ════════════════════════════════════════════════════════════════════════════
POC_HOSTS = (
    "github.com/",                  # any GitHub repo (curated or mention)
    "exploit-db.com/exploits",      # ExploitDB verified entry
    "packetstormsecurity.com/files",# PacketStorm exploit archive
    "seclists.org/fulldisclosure",  # Full Disclosure list (often carries PoC)
    "seclists.org/bugtraq",
    "gist.github.com",              # GitHub gists (often mini PoCs)
    "raw.githubusercontent.com",    # raw PoC source files
    "projectdiscovery.github.io",   # Nuclei templates
    "packetstormsecurity.com/pages/exploit",
    "0day.today/exploit",           # 0day.today exploit database
    "cxsecurity.com/exploit",       # CXSECURITY exploit archive
    "secploit.com/exploit",
    "exploitalert.com",
)

ADVISORY_HOSTS = (
    "nvd.nist.gov", "cve.mitre.org", "kb.cert.org", "us-cert.gov",
    "cisa.gov", "cert.ssi.gouv.fr", "gov.uk", "security.gentoo.org",
    "access.redhat.com", "ubuntu.com/security", "debian.org/security",
    "security.netapp.com", "support.apple.com", "msrc.microsoft.com",
    "portal.msrc.microsoft.com", "learn.microsoft.com",
    "github.com/advisories", "github.com/security",
    "github.blog", "lists.apache.org", "httpd.apache.org",
    "jvndb.jvn.jp", "jvn.jp", "www.kb.cert.org",
    "security.snyk.io", "security.tracker.debian.org",
    "vulncheck.com", "vuldb.com", "first.org", "oracle.com/security-alerts",
    "vmware.com/security", "support.broadcom.com",
)


def _is_poc_url(url: str) -> bool:
    """Heuristic: does this URL point at a PoC/exploit host?"""
    if not url: return False
    u = url.lower()
    return any(h in u for h in POC_HOSTS)


def _is_advisory_url(url: str) -> bool:
    """Heuristic: does this URL point at a vendor/security advisory?"""
    if not url: return False
    u = url.lower()
    return any(h in u for h in ADVISORY_HOSTS)


# ════════════════════════════════════════════════════════════════════════════
# OSV.dev — open, free, no-key vulnerability database (Google-maintained).
# Surface EVIDENCE/FIX/WEB/ADVISORY references and PoC-host references.
# ════════════════════════════════════════════════════════════════════════════
class OSVClient:
    """Fetches vulnerability data from OSV.dev (open, no key required).

    Returns (refs, severity_list, status). ``refs`` is a list of dicts
    {url, type, evidence_type, trust}. ``status`` follows SOURCE_* conventions.

    200 = ok (refs may be empty). 404 = notfound (silently continue).
    Other errors → error/ratelimited.
    """

    OSV_BASE = "https://api.osv.dev/v1/vulns"

    # OSV reference types → our evidence_type mapping
    _REF_TYPE_MAP = {
        "EVIDENCE": "poc",         # explicit PoC/test case
        "FIX": "reference",         # patch / fix commit
        "ADVISORY": "advisory",
        "WEB": "reference",         # generic web — advisory unless PoC host
        "REPORT": "reference",
        "PACKAGE": "reference",
        "ARTICLE": "advisory",
    }

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 offline: bool = False) -> None:
        self.cache = cache
        self.debug = debug
        self.offline = offline
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0 (security-research)",
            "Accept": "application/json",
        })

    def fetch(self, cve_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
        """Returns (refs, severity_list, status)."""
        cve_id = cve_id.upper()
        if self.offline:
            return [], [], SOURCE_SKIPPED
        cache_key = f"osv:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            refs, sev = cached if isinstance(cached, tuple) else (cached, [])
            if self.debug: self.debug.log("osv", cve_id, 0.0, SOURCE_OK)
            return refs, sev, SOURCE_OK
        t0 = time.time()
        try:
            resp = self.session.get(f"{self.OSV_BASE}/{cve_id}", timeout=15)
        except requests.RequestException:
            if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], [], SOURCE_ERROR
        if resp.status_code == 404:
            # Authoritative: OSV doesn't track this CVE — silent continue.
            if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_OK)
            return [], [], SOURCE_OK
        if resp.status_code in (403, 429):
            if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return [], [], SOURCE_RATELIMITED
        if resp.status_code != 200:
            if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], [], SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], [], SOURCE_ERROR

        refs: List[Dict[str, Any]] = []
        for ref in data.get("references", []) or []:
            url = ref.get("url") or ""
            rtype = (ref.get("type") or "WEB").upper()
            if not url: continue
            # OSV EVIDENCE refs are always PoCs; otherwise classify by host
            if rtype == "EVIDENCE":
                etype = "poc"; trust = "curated"
            elif _is_poc_url(url):
                etype = "poc" if rtype == "EVIDENCE" else "exploit"
                # GitHub repo URLs from OSV are curated (they're human-curated)
                trust = "curated"
            elif _is_advisory_url(url):
                etype = "advisory"; trust = "curated"
            else:
                etype = self._REF_TYPE_MAP.get(rtype, "reference")
                trust = "curated"
            refs.append({
                "url": url, "type": rtype,
                "evidence_type": etype, "trust": trust,
                "provenance": "osv",
            })

        severity = data.get("severity", []) or []
        try:
            self.cache.set(cache_key, (refs, severity))
        except (TypeError, ValueError):
            pass
        if self.debug: self.debug.log("osv", cve_id, time.time() - t0, SOURCE_OK)
        return refs, severity, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# GitHub Security Advisories (GHSA) — public, no key needed for read-only
# advisories endpoint. Returns GHSA records linked to the CVE.
# ════════════════════════════════════════════════════════════════════════════
class GitHubAdvisoryClient:
    """Fetches GitHub Security Advisories for a CVE.

    Returns (advisories, status). ``advisories`` is a list of dicts
    {ghsa_id, summary, severity, html_url, refs[], cvss} — refs are extracted
    and surfaced as curated evidence.

    NOTE: The advisories endpoint is rate-limited like all GitHub APIs.
    Without a token: 60 req/hour per IP. With a token: 5000 req/hour.
    Degrades cleanly with SOURCE_RATELIMITED or SOURCE_NEEDS_TOKEN.
    """

    GHSA_URL = "https://api.github.com/advisories"

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 offline: bool = False,
                 github_token: str = "") -> None:
        self.cache = cache
        self.debug = debug
        self.offline = offline
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0",
            "Accept": "application/vnd.github+json",
        })
        if github_token:
            self.session.headers["Authorization"] = f"Bearer {github_token}"
        self._has_token = bool(github_token)
        self._last_ts = 0.0

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_ts
        wait = 1.0 if self._has_token else 7.0
        if elapsed < wait: time.sleep(wait - elapsed)
        self._last_ts = time.time()

    def fetch(self, cve_id: str) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (advisories, status)."""
        cve_id = cve_id.upper()
        if self.offline:
            return [], SOURCE_SKIPPED
        cache_key = f"ghsa:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("ghsa", cve_id, 0.0, SOURCE_OK)
            return cached, SOURCE_OK
        t0 = time.time()
        self._rate_limit()
        try:
            resp = self.session.get(
                self.GHSA_URL,
                params={"cve_id": cve_id, "per_page": 10},
                timeout=15,
            )
        except requests.RequestException:
            if self.debug: self.debug.log("ghsa", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        if resp.status_code in (403, 429):
            # Rate-limited — likely no token, hit the 60/hour cap
            if self.debug:
                self.debug.log("ghsa", cve_id, time.time() - t0,
                               SOURCE_NEEDS_TOKEN if not self._has_token else SOURCE_RATELIMITED)
            return [], (SOURCE_NEEDS_TOKEN if not self._has_token else SOURCE_RATELIMITED)
        if resp.status_code != 200:
            if self.debug: self.debug.log("ghsa", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("ghsa", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        advisories: List[Dict[str, Any]] = []
        if isinstance(data, list):
            for a in data[:10]:
                if not isinstance(a, dict): continue
                refs_raw = a.get("references") or []
                refs: List[Dict[str, Any]] = []
                for r in refs_raw:
                    # GHSA references can be either:
                    #   - dicts: {"url": "...", "type": "..."}  (newer API)
                    #   - strings: "https://..."               (older API variant)
                    if isinstance(r, dict):
                        url = r.get("url") or r.get("href") or ""
                    elif isinstance(r, str):
                        url = r
                    else:
                        continue
                    if not url: continue
                    if _is_poc_url(url):
                        refs.append({"url": url, "evidence_type": "poc",
                                     "trust": "curated", "provenance": "ghsa"})
                    elif _is_advisory_url(url):
                        refs.append({"url": url, "evidence_type": "advisory",
                                     "trust": "curated", "provenance": "ghsa"})
                    else:
                        refs.append({"url": url, "evidence_type": "reference",
                                     "trust": "curated", "provenance": "ghsa"})
                cvss = a.get("cvss") or {}
                advisories.append({
                    "ghsa_id": a.get("ghsa_id") or a.get("id") or "",
                    "summary": a.get("summary") or "",
                    "severity": a.get("severity") or cvss.get("severity") or "",
                    "html_url": a.get("html_url") or "",
                    "cvss_score": cvss.get("score") or 0.0,
                    "cvss_vector": cvss.get("vector_string") or "",
                    "refs": refs,
                })
        try:
            self.cache.set(cache_key, advisories)
        except (TypeError, ValueError):
            pass
        if self.debug: self.debug.log("ghsa", cve_id, time.time() - t0, SOURCE_OK)
        return advisories, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Vulners — OPTIONAL key-gated exploit intelligence API.
# Collects exploit-family bulletins (exploitdb, metasploit, packetstorm, zdt,
# githubexploit) → curated evidence. Generic web refs → mention evidence.
# Skips cleanly with SOURCE_NO_KEY if no key configured.
# ════════════════════════════════════════════════════════════════════════════
class VulnersClient:
    """Fetches exploit bulletins from Vulners.com (requires API key).

    Returns (bulletins, status). ``bulletins`` is a list of dicts
    {id, title, type, href, source, cvss, trust}.

    If no key is configured, returns ([], SOURCE_NO_KEY) — silently skipped.
    """

    VULNERS_URL = "https://vulners.com/api/v3/search/id/"

    # Vulners bulletin families that count as exploit-family evidence
    _EXPLOIT_FAMILIES = {
        "exploitdb", "metasploit", "packetstorm", "zdt",
        "githubexploit", "exploitkit", "cxsecurity",
    }

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 offline: bool = False,
                 api_key: str = "") -> None:
        self.cache = cache
        self.debug = debug
        self.offline = offline
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0 (security-research)",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def fetch(self, cve_id: str) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (bulletins, status)."""
        cve_id = cve_id.upper()
        if self.offline:
            return [], SOURCE_SKIPPED
        if not self.api_key:
            if self.debug: self.debug.log("vulners", cve_id, 0.0, SOURCE_NO_KEY)
            return [], SOURCE_NO_KEY
        cache_key = f"vulners:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("vulners", cve_id, 0.0, SOURCE_OK)
            return cached, SOURCE_OK
        t0 = time.time()
        try:
            resp = self.session.post(
                self.VULNERS_URL,
                json={"id": cve_id, "references": True, "apiKey": self.api_key},
                timeout=20,
            )
        except requests.RequestException:
            if self.debug: self.debug.log("vulners", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        if resp.status_code in (403, 429):
            if self.debug: self.debug.log("vulners", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return [], SOURCE_RATELIMITED
        if resp.status_code != 200:
            if self.debug: self.debug.log("vulners", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("vulners", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR

        bulletins: List[Dict[str, Any]] = []
        # Vulners schema: data.documents (dict keyed by bulletin id) OR
        # data.references / data.items. Walk defensively.
        docs = (data.get("data") or {}).get("documents") or {}
        if isinstance(docs, dict):
            for bid, doc in docs.items():
                if not isinstance(doc, dict): continue
                family = (doc.get("type") or doc.get("bulletinFamily") or "").lower()
                href = doc.get("href") or doc.get("link") or ""
                title = doc.get("title") or ""
                cvss = doc.get("cvss") or {}
                if isinstance(cvss, dict):
                    cvss_score = cvss.get("score") or 0.0
                else:
                    cvss_score = float(cvss) if cvss else 0.0
                trust = "curated" if family in self._EXPLOIT_FAMILIES else "mention"
                etype = "exploit" if family in self._EXPLOIT_FAMILIES else "reference"
                bulletins.append({
                    "id": bid,
                    "title": title,
                    "type": family,
                    "href": href,
                    "source": "vulners",
                    "cvss": cvss_score,
                    "evidence_type": etype,
                    "trust": trust,
                    "provenance": "vulners",
                })
        # Also walk data.references if present (newer API variant)
        refs_data = (data.get("data") or {}).get("references") or []
        if isinstance(refs_data, list):
            for r in refs_data:
                if not isinstance(r, dict): continue
                url = r.get("link") or r.get("url") or ""
                if not url: continue
                family = (r.get("type") or r.get("source") or "").lower()
                if family in self._EXPLOIT_FAMILIES:
                    bulletins.append({
                        "id": r.get("id") or "",
                        "title": r.get("title") or "",
                        "type": family,
                        "href": url,
                        "source": "vulners",
                        "cvss": 0.0,
                        "evidence_type": "exploit",
                        "trust": "curated",
                        "provenance": "vulners",
                    })
        try:
            self.cache.set(cache_key, bulletins)
        except (TypeError, ValueError):
            pass
        if self.debug: self.debug.log("vulners", cve_id, time.time() - t0, SOURCE_OK)
        return bulletins, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Shodan — internet exposure count for CVEs (how many devices are vulnerable
# and reachable from the internet). Requires a Shodan API key (free tier works
# for the /shodan/host/count endpoint).
# ════════════════════════════════════════════════════════════════════════════
class ShodanClient:
    """Fetches internet exposure data from Shodan.

    Uses the /shodan/host/count endpoint to get the number of internet-facing
    devices matching a CVE. The query format is ``vuln:CVE-YYYY-NNNNN``.

    Returns (data, status):
      data = {"exposed_count": int, "query": str}
      status = SOURCE_OK / SOURCE_NO_KEY / SOURCE_RATELIMITED / SOURCE_ERROR
    """

    SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 offline: bool = False,
                 api_key: str = "") -> None:
        self.cache = cache
        self.debug = debug
        self.offline = offline
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0 (security-research)",
        })

    def check(self, cve_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (exposure_data, status)."""
        cve_id = cve_id.upper()
        if self.offline:
            return None, SOURCE_SKIPPED
        if not self.api_key:
            if self.debug: self.debug.log("shodan", cve_id, 0.0, SOURCE_NO_KEY)
            return None, SOURCE_NO_KEY
        cache_key = f"shodan:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("shodan", cve_id, 0.0, SOURCE_OK)
            return cached, SOURCE_OK
        t0 = time.time()
        query = f"vuln:{cve_id}"
        try:
            resp = self.session.get(
                self.SHODAN_COUNT_URL,
                params={"query": query, "key": self.api_key},
                timeout=15,
            )
        except requests.RequestException:
            if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code == 401:
            # Invalid API key
            if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code == 429:
            if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return None, SOURCE_RATELIMITED
        if resp.status_code != 200:
            if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        exposed_count = int(data.get("total", 0))
        result = {"exposed_count": exposed_count, "query": query}
        self.cache.set(cache_key, result)
        if self.debug: self.debug.log("shodan", cve_id, time.time() - t0, SOURCE_OK)
        return result, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# GreyNoise — checks if a CVE is being actively scanned/exploited on the
# internet RIGHT NOW. Requires a GreyNoise API key (Community tier is free).
# Uses the v3/community/{indicator} endpoint which supports CVE IDs.
# ════════════════════════════════════════════════════════════════════════════
class GreyNoiseClient:
    """Fetches active exploitation data from GreyNoise.

    Uses the /v3/community/{cve_id} endpoint to check if the CVE is being
    actively scanned. Returns noise=True if scanners are looking for it.

    Returns (data, status):
      data = {"noise": bool, "riot": bool, "last_seen": str, "link": str}
      status = SOURCE_OK / SOURCE_NO_KEY / SOURCE_RATELIMITED / SOURCE_ERROR
    """

    GREYNOISE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 offline: bool = False,
                 api_key: str = "") -> None:
        self.cache = cache
        self.debug = debug
        self.offline = offline
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Hunter/4.0 (security-research)",
        })

    def check(self, cve_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (activity_data, status)."""
        cve_id = cve_id.upper()
        if self.offline:
            return None, SOURCE_SKIPPED
        if not self.api_key:
            if self.debug: self.debug.log("greynoise", cve_id, 0.0, SOURCE_NO_KEY)
            return None, SOURCE_NO_KEY
        cache_key = f"greynoise:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("greynoise", cve_id, 0.0, SOURCE_OK)
            return cached, SOURCE_OK
        t0 = time.time()
        try:
            resp = self.session.get(
                f"{self.GREYNOISE_URL}/{cve_id}",
                headers={"key": self.api_key},
                timeout=15,
            )
        except requests.RequestException:
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code == 401:
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code == 429:
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return None, SOURCE_RATELIMITED
        if resp.status_code == 404:
            # Not in GreyNoise database — no activity detected (this is ok)
            result = {"noise": False, "riot": False, "last_seen": "", "link": "",
                      "message": "no activity detected"}
            self.cache.set(cache_key, result)
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_OK)
            return result, SOURCE_OK
        if resp.status_code != 200:
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        result = {
            "noise": bool(data.get("noise", False)),
            "riot": bool(data.get("riot", False)),
            "last_seen": data.get("last_seen", ""),
            "link": data.get("link", ""),
            "message": data.get("message", ""),
            "count": data.get("count", 0),
        }
        self.cache.set(cache_key, result)
        if self.debug: self.debug.log("greynoise", cve_id, time.time() - t0, SOURCE_OK)
        return result, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# trickest/cve — secondary curated PoC source (Phase 3 task 2)
# ════════════════════════════════════════════════════════════════════════════
class TrickestCVESearcher:
    """Searches the trickest/cve repo for curated PoC links.

    Local-mirror only: user clones the repo to a path. We read the per-CVE
    markdown file and extract PoC links (blacklist-filtered). Merged + deduped
    with PoC-in-GitHub by CVEHunter._build_exploit_evidence.
    """
    # Blacklist: non-PoC URLs that appear in trickest markdown
    URL_BLACKLIST = ("github.com/advisories", "github.com/issues",
                     "github.com/pull", "github.com/security",
                     "github.com/settings", "github.com/login",
                     "github.com/orgs", "github.com/sponsors")

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 local_path: Optional[Path] = None) -> None:
        self.cache = cache
        self.debug = debug
        self.local_path = local_path

    def search(self, cve_id: str, max_results: int = 10) -> Tuple[List[Dict[str, Any]], str]:
        cve_id = cve_id.upper()
        if not self.local_path:
            return [], SOURCE_SKIPPED
        cache_key = f"trickest:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached[:max_results], SOURCE_OK

        m = re.match(r"CVE-(\d{4})-", cve_id)
        if not m:
            return [], SOURCE_ERROR
        year = m.group(1)
        # trickest/cve structure: cves/YYYY/CVE-YYYY-NNNNN.md
        md_file = self.local_path / "cves" / year / f"{cve_id}.md"
        if not md_file.exists():
            self.cache.set(cache_key, [])
            return [], SOURCE_OK

        try:
            content = md_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return [], SOURCE_ERROR

        # Extract GitHub URLs from markdown
        urls = re.findall(r"https://github\.com/[^\s\)\]\"]+", content)
        # Blacklist filter
        filtered = [u for u in urls
                    if not any(b in u.lower() for b in self.URL_BLACKLIST)]
        # Dedupe
        filtered = list(dict.fromkeys(filtered))
        results = [{
            "name": "/".join(u.split("github.com/")[-1].split("/")[:2]) if "github.com/" in u else "",
            "url": u, "stars": 0, "description": "",
            "updated": "", "language": "",
        } for u in filtered[:max_results]]
        self.cache.set(cache_key, results)
        if self.debug: self.debug.log("trickest", cve_id, 0.0, SOURCE_OK)
        return results, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Nuclei templates (Phase 3 task 3) — offline-friendly detection signal
# ════════════════════════════════════════════════════════════════════════════
class NucleiTemplateSearcher:
    """Checks if a Nuclei template exists for a CVE.

    Local-mirror only: user clones projectdiscovery/nuclei-templates.
    Template presence = practical detection/exploit signal that feeds the
    exploit maturity model (counts as a POC-level signal).
    """

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 local_path: Optional[Path] = None) -> None:
        self.cache = cache
        self.debug = debug
        self.local_path = local_path

    def search(self, cve_id: str) -> Tuple[bool, str]:
        """Returns (has_template, status)."""
        cve_id = cve_id.upper()
        if not self.local_path:
            return False, SOURCE_SKIPPED
        cache_key = f"nuclei:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached, SOURCE_OK

        m = re.match(r"CVE-(\d{4})-", cve_id)
        if not m:
            return False, SOURCE_ERROR
        year = m.group(1)
        # nuclei-templates structure: http/cves/YYYY/CVE-YYYY-NNNNN.yaml
        template_file = self.local_path / "http" / "cves" / year / f"{cve_id}.yaml"
        has = template_file.exists()
        self.cache.set(cache_key, has)
        if self.debug: self.debug.log("nuclei", cve_id, 0.0, SOURCE_OK)
        return has, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# VulnCheck KEV (Phase 3 task 4) — optional KEV superset
# ════════════════════════════════════════════════════════════════════════════
class VulnCheckKEVChecker:
    """Optional KEV superset from VulnCheck (free community tier).

    Only active when an API key is configured (via --vulncheck-key or
    config.ini [vulncheck] api_key). Feeds IN_THE_WILD maturity alongside
    CISA KEV.
    """
    BASE_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"

    def __init__(self, cache: Cache,
                 debug: Optional[DebugLog] = None,
                 api_key: str = "",
                 offline: bool = False) -> None:
        self.cache = cache
        self.debug = debug
        self.api_key = api_key
        self.offline = offline
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CVE-Hunter/4.0"})
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and not self.offline

    def check(self, cve_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (entry, status). entry is None when not in VulnCheck KEV."""
        cve_id = cve_id.upper()
        if not self.enabled:
            return None, SOURCE_SKIPPED
        cache_key = f"vulncheck_kev:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached, SOURCE_OK

        t0 = time.time()
        try:
            resp = self.session.get(self.BASE_URL,
                                    params={"cve": cve_id}, timeout=20)
        except requests.RequestException:
            if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        if resp.status_code in (403, 429):
            if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_RATELIMITED)
            return None, SOURCE_RATELIMITED
        if resp.status_code != 200:
            if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        try:
            data = resp.json()
        except json.JSONDecodeError:
            if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_ERROR)
            return None, SOURCE_ERROR
        entries = data.get("data", [])
        if not entries:
            self.cache.set(cache_key, None)
            if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_OK)
            return None, SOURCE_OK
        entry = entries[0]
        result = {
            "vulncheck_kev": True,
            "date_added": entry.get("date_added", ""),
            "description": entry.get("description", ""),
        }
        self.cache.set(cache_key, result)
        if self.debug: self.debug.log("vulncheck_kev", cve_id, time.time() - t0, SOURCE_OK)
        return result, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# NVD snapshot importer (Phase 3 task 7) — for offline mode
# ════════════════════════════════════════════════════════════════════════════
class NVDSnapshotImporter:
    """Imports NVD JSON feed files into the SQLite cache for offline use.

    Supports BOTH NVD feed formats:
      - NVD 2.0 API format (current): top-level ``vulnerabilities[]``,
        each item has ``cve.descriptions``, ``cve.metrics.cvssMetricV31``,
        ``cve.configurations[].nodes[].cpeMatch``. Filename pattern:
        ``nvdcve-2.0-YYYY.json.gz`` (or any .json/.json.gz).
      - NVD 1.1 feed format (legacy): top-level ``CVE_Items[]``,
        each item has ``cve.CVE_data_meta.ID``, ``cve.problemtype.data``,
        ``configurations.nodes[].cpe_match[].cpe23Uri``,
        ``impact.baseMetricV3.cvssV3``. Filename pattern:
        ``nvdcve-1.1-YYYY.json.gz``.

    The format is auto-detected from the JSON structure, so any NVD feed
    file (1.1 or 2.0) will import correctly without manual configuration.

    Usage:
      # Import a single year's feed (1.1 or 2.0 — auto-detected):
      cve-hunter import-nvd nvdcve-1.1-2024.json.gz
      cve-hunter import-nvd nvdcve-2.0-2024.json.gz

      # Import all feeds from a directory:
      cve-hunter import-nvd /path/to/nvd/feeds/

    After importing, scanning with --offline will find CVEs in the local
    cache without any network calls.
    """

    @staticmethod
    def _normalize_v11(item: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single NVD 1.1 ``CVE_Items[]`` entry into the same
        dict shape returned by ``NVDClient._normalize`` (which only handles
        the 2.0 API format).

        NVD 1.1 schema reference:
          - cve.CVE_data_meta.ID — the CVE id
          - cve.description.description_data[].value (lang=en)
          - cve.problemtype.data[].description[].value — "CWE-xxx"
          - cve.references.reference_data[].url + .tags
          - configurations.nodes[].cpe_match[].cpe23Uri + version bounds
          - impact.baseMetricV3.cvssV3.{baseScore, vectorString, baseSeverity}
            + impact.baseMetricV3.{exploitabilityScore, impactScore}
          - impact.baseMetricV2.cvssV2.{baseScore, vectorString}
            + impact.baseMetricV2.{exploitabilityScore, impactScore}
          - publishedDate, lastModified
        """
        cve = safe_get(item, "cve", default={})
        meta = safe_get(cve, "CVE_data_meta", default={})
        cve_id = (meta.get("ID") or "").upper()

        # Description (lang=en)
        desc_data = safe_get(cve, "description", default={}).get("description_data", [])
        description = next(
            (d.get("value") for d in desc_data if d.get("lang") == "en"),
            (desc_data[0].get("value") if desc_data else ""),
        )

        # CVSS — translate 1.1 impact blocks into the 2.0 cvss_all shape
        impact = safe_get(item, "impact", default={})
        cvss_all: List[Dict[str, Any]] = []
        # CVSS v3.x (baseMetricV3 → cvssV3)
        bm3 = safe_get(impact, "baseMetricV3", default={})
        cvss3 = safe_get(bm3, "cvssV3", default={})
        if cvss3:
            cvss_all.append({
                "version": cvss3.get("version", "3.1"),
                "score": float(cvss3.get("baseScore", 0.0) or 0.0),
                "severity": (cvss3.get("baseSeverity") or "").title(),
                "vector": cvss3.get("vectorString", ""),
                "exploitability": bm3.get("exploitabilityScore"),
                "impact": bm3.get("impactScore"),
                "source_type": "Primary",
            })
        # CVSS v2 (baseMetricV2 → cvssV2)
        bm2 = safe_get(impact, "baseMetricV2", default={})
        cvss2 = safe_get(bm2, "cvssV2", default={})
        if cvss2:
            cvss_all.append({
                "version": "2.0",
                "score": float(cvss2.get("baseScore", 0.0) or 0.0),
                "severity": (bm2.get("severity") or "").title(),
                "vector": cvss2.get("vectorString", ""),
                "exploitability": bm2.get("exploitabilityScore"),
                "impact": bm2.get("impactScore"),
                "source_type": "Primary",
            })

        # CWE — translate problemtype.problemtype_data[].description[].value
        # FIX (critical-1a): NVD 1.1 schema uses "problemtype_data" (NOT "data").
        # The old code used .get("data", []) which always returned [] → all
        # CWEs were silently dropped, downgrading classification to keyword
        # matching only.
        cwe_entries: List[Dict[str, str]] = []
        seen_cwes: set = set()
        for pt in safe_get(cve, "problemtype", default={}).get("problemtype_data", []):
            for d in safe_get(pt, "description", default=[]):
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cid = d["value"]
                    if cid not in seen_cwes:
                        seen_cwes.add(cid)
                        cwe_entries.append({"cwe_id": cid, "source_type": "Primary"})

        # References
        refs_raw = safe_get(cve, "references", default={}).get("reference_data", [])
        references = [{"url": r.get("url"), "source": r.get("refsource", ""),
                       "tags": r.get("tags", [])} for r in refs_raw]

        # CPEs + version ranges (1.1 uses cpe_match + cpe23Uri + versionStart/EndIncluding/Excluding)
        # FIX (critical-1b): NVD 1.1 schema has configurations as a DICT
        # ({"CVE_data_version": "4.0", "nodes": [...]}), NOT a list. The old
        # code iterated configs as a list, so it walked the dict's string keys
        # ("CVE_data_version", "nodes") → safe_get(cfg, "nodes") failed →
        # 0 version ranges extracted. This made --check-version always return
        # "no version ranges → NOT AFFECTED" for offline-imported 1.1 CVEs.
        configs = safe_get(item, "configurations", default={})
        cpes: List[str] = []
        version_ranges: List[Dict[str, Any]] = []
        # Handle both shapes defensively: dict (NVD 1.1) or list (some variants)
        if isinstance(configs, dict):
            nodes_list = configs.get("nodes", [])
        elif isinstance(configs, list):
            # NVD 2.0-style: list of config dicts, each with its own "nodes"
            nodes_list = []
            for cfg in configs:
                nodes_list.extend(safe_get(cfg, "nodes", default=[]))
        else:
            nodes_list = []
        for node in nodes_list:
            for m in safe_get(node, "cpe_match", default=[]):
                if m.get("cpe23Uri"):
                    cpe = m["cpe23Uri"]
                    cpes.append(cpe)
                    version_ranges.append({
                        "cpe": cpe,
                        "vulnerable": m.get("vulnerable", True),
                        "version_start_including": m.get("versionStartIncluding", ""),
                        "version_start_excluding": m.get("versionStartExcluding", ""),
                        "version_end_including": m.get("versionEndIncluding", ""),
                            "version_end_excluding": m.get("versionEndExcluding", ""),
                        })
        cpes = list(dict.fromkeys(cpes))

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_all": cvss_all,
            "cwe_entries": cwe_entries,
            "references": references,
            "cpes": cpes,
            "version_ranges": version_ranges,
            "published": item.get("publishedDate", ""),
            "modified": item.get("lastModifiedDate", ""),
            "vuln_status": item.get("cve", {}).get("CVE_data_meta", {}).get("STATE", ""),
        }

    @staticmethod
    def import_file(path: Path, cache: Cache) -> int:
        """Import a single NVD JSON feed file. Returns count of CVEs imported.

        Auto-detects NVD 1.1 (``CVE_Items[]``) vs NVD 2.0
        (``vulnerabilities[]``) format from the JSON structure.
        """
        import gzip
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        count = 0
        # FIX (critical-1): auto-detect NVD 1.1 vs 2.0 format.
        # NVD 1.1 feeds use top-level CVE_Items[] (legacy schema with
        # cve.CVE_data_meta.ID, impact.baseMetricV3.cvssV3, etc.).
        # NVD 2.0 API uses top-level vulnerabilities[] (current schema).
        # Before this fix, the importer only read vulnerabilities[] — so
        # importing a real nvdcve-1.1-YYYY.json.gz feed silently imported
        # 0 CVEs despite printing "Import complete".
        if "CVE_Items" in data and isinstance(data["CVE_Items"], list):
            # NVD 1.1 legacy format
            for item in data["CVE_Items"]:
                record = NVDSnapshotImporter._normalize_v11(item)
                cve_id = record.get("cve_id", "").upper()
                if cve_id:
                    cache.set(f"nvd:{cve_id}", record)
                    count += 1
        else:
            # NVD 2.0 API format (current)
            for vuln in safe_get(data, "vulnerabilities", default=[]):
                record = NVDClient._normalize(vuln)
                cve_id = record.get("cve_id", "").upper()
                if cve_id:
                    cache.set(f"nvd:{cve_id}", record)
                    count += 1
        return count

    @staticmethod
    def import_dir(dir_path: Path, cache: Cache) -> int:
        """Import all NVD JSON files from a directory. Returns total count."""
        total = 0
        for path in sorted(dir_path.glob("nvdcve-*.json*")):
            try:
                count = NVDSnapshotImporter.import_file(path, cache)
                total += count
                print(f"  {path.name}: {count} CVEs imported")
            except Exception as e:
                print(f"  {path.name}: ERROR ({e})")
        return total


# ════════════════════════════════════════════════════════════════════════════
# CWE → CAPEC → ATT&CK mapping (Phase 3 task 6)
# ════════════════════════════════════════════════════════════════════════════
# Static subset from MITRE's published CWE→CAPEC and CAPEC→ATT&CK mappings.
# Used for reporting context only — NOT for attack generation.
CWE_CAPEC_ATTACK_MAP: Dict[str, Dict[str, List[str]]] = {
    "CWE-78":  {"capec": ["CAPEC-88: OS Command Injection"],
                "attack": ["T1059: Command and Scripting Interpreter", "T1059.004: Unix Shell"]},
    "CWE-89":  {"capec": ["CAPEC-66: SQL Injection"],
                "attack": ["T1190: Exploit Public-Facing Application"]},
    "CWE-79":  {"capec": ["CAPEC-18: XSS Targeting Scripts"],
                "attack": ["T1059.007: JavaScript", "T1185: Browser Session Hijacking"]},
    "CWE-94":  {"capec": ["CAPEC-242: Code Injection"],
                "attack": ["T1059: Command and Scripting Interpreter"]},
    "CWE-502": {"capec": ["CAPEC-586: Object Injection"],
                "attack": ["T1059: Command and Scripting Interpreter", "T1203: Exploitation for Client Execution"]},
    "CWE-22":  {"capec": ["CAPEC-126: Path Traversal"],
                "attack": ["T1083: File and Directory Discovery", "T1005: Data from Local System"]},
    "CWE-352": {"capec": ["CAPEC-111: Browser Session Hijacking"],
                "attack": ["T1185: Browser Session Hijacking"]},
    "CWE-918": {"capec": ["CAPEC-663: Server Side Request Forgery"],
                "attack": ["T1190: Exploit Public-Facing Application"]},
    # FIX (accuracy-5): corrected against MITRE CWE→CAPEC reference.
    # CWE-119 (Improper Restriction of Operations within the Bounds of a
    #   Memory Buffer) — primary CAPEC is CAPEC-100: Overflow Buffers
    #   (was wrongly CAPEC-92: Forced Integer Overflow, which is for CWE-190).
    "CWE-119": {"capec": ["CAPEC-100: Overflow Buffers"],
                "attack": ["T1203: Exploitation for Client Execution", "T1068: Exploitation for Privilege Escalation"]},
    "CWE-787": {"capec": ["CAPEC-100: Overflow Buffers"],
                "attack": ["T1203: Exploitation for Client Execution", "T1068: Exploitation for Privilege Escalation"]},
    # FIX (accuracy-5): CWE-416 (Use After Free) — CAPEC-123 is correct
    # (Remove Structures from Memory). The DUPLICATE was on CWE-269.
    "CWE-416": {"capec": ["CAPEC-123: Remove Structures from Memory"],
                "attack": ["T1203: Exploitation for Client Execution"]},
    "CWE-190": {"capec": ["CAPEC-92: Forced Integer Overflow"],
                "attack": ["T1203: Exploitation for Client Execution"]},
    "CWE-287": {"capec": ["CAPEC-114: Authentication Abuse"],
                "attack": ["T1078: Valid Accounts"]},
    "CWE-862": {"capec": ["CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs"],
                "attack": ["T1078: Valid Accounts"]},
    # FIX (accuracy-5): CWE-269 (Improper Privilege Management) — was wrongly
    # CAPEC-123 (Remove Structures from Memory, which is for memory bugs).
    # Correct CAPEC is CAPEC-122: Privilege Abuse (matches MITRE's mapping
    # for privilege-management weaknesses). ATT&CK stays T1068/T1548.
    "CWE-269": {"capec": ["CAPEC-122: Privilege Abuse"],
                "attack": ["T1068: Exploitation for Privilege Escalation", "T1548: Abuse Elevation Control Mechanism"]},
    "CWE-200": {"capec": ["CAPEC-118: Excavation"],
                "attack": ["T1087: Account Discovery", "T1082: System Information Discovery"]},
    "CWE-400": {"capec": ["CAPEC-125: Flooding"],
                "attack": ["T1499: Endpoint Denial of Service"]},
    "CWE-611": {"capec": ["CAPEC-201: Serialize Data"],
                "attack": ["T1190: Exploit Public-Facing Application"]},
    "CWE-434": {"capec": ["CAPEC-137: Splitting"],
                "attack": ["T1105: Ingress Tool Transfer", "T1059: Command and Scripting Interpreter"]},
    "CWE-77":  {"capec": ["CAPEC-88: OS Command Injection"],
                "attack": ["T1059: Command and Scripting Interpreter"]},
}


def get_capec_attack_mapping(cwe_ids: List[str]) -> Dict[str, List[str]]:
    """Return CAPEC + ATT&CK mappings for the given CWE IDs.

    For reporting/context only — never used for attack generation.
    """
    capec: List[str] = []
    attack: List[str] = []
    for cwe_id in cwe_ids:
        cwe_id = cwe_id.upper()
        if cwe_id in CWE_CAPEC_ATTACK_MAP:
            capec.extend(CWE_CAPEC_ATTACK_MAP[cwe_id]["capec"])
            attack.extend(CWE_CAPEC_ATTACK_MAP[cwe_id]["attack"])
    return {"capec": list(dict.fromkeys(capec)),
            "attack": list(dict.fromkeys(attack))}


# ════════════════════════════════════════════════════════════════════════════
# Searchsploit (Exploit-DB local database on Kali)
# ════════════════════════════════════════════════════════════════════════════
class SearchsploitSearcher:
    """Integrates with `searchsploit` (preinstalled on Kali Linux)."""

    def __init__(self, cache: Cache, debug: Optional[DebugLog] = None) -> None:
        self.cache = cache
        self.debug = debug
        self._available: Optional[bool] = None

    @property
    def available(self) -> bool:
        if self._available is None:
            from shutil import which
            self._available = which("searchsploit") is not None
        return self._available

    def search(self, cve_id: str, max_results: int = 10) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (results, status). status is `unavailable` if searchsploit
        is not installed; `ok` otherwise (results may still be empty)."""
        cve_id = cve_id.upper()
        if not self.available:
            if self.debug: self.debug.log("searchsploit", cve_id, 0.0, SOURCE_UNAVAILABLE)
            return [], SOURCE_UNAVAILABLE
        cache_key = f"searchsploit:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("searchsploit", cve_id, 0.0, SOURCE_OK)
            return cached[:max_results], SOURCE_OK
        import subprocess
        t0 = time.time()
        try:
            result = subprocess.run(
                ["searchsploit", "--json", "-q", cve_id],
                capture_output=True, text=True, timeout=30,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            if self.debug: self.debug.log("searchsploit", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        if result.returncode != 0:
            # searchsploit exits non-zero when no results — treat as ok.
            if self.debug: self.debug.log("searchsploit", cve_id, time.time() - t0, SOURCE_OK)
            return [], SOURCE_OK
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            if self.debug: self.debug.log("searchsploit", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        items = data.get("RESULTS_EXPLOIT", []) or []
        results: List[Dict[str, Any]] = []
        for it in items[:max_results]:
            results.append({
                "id": it.get("EDB-ID") or it.get("id"),
                "title": it.get("Title", ""),
                "path": it.get("Path", ""),
                "type": it.get("Type", ""),
                "platform": it.get("Platform", ""),
                "author": it.get("Author", ""),
                "date": it.get("Date", ""),
                "verified": it.get("Verified", False),
            })
        self.cache.set(cache_key, results)
        if self.debug: self.debug.log("searchsploit", cve_id, time.time() - t0, SOURCE_OK)
        return results, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Metasploit Module Search — local msf module lookup
# ════════════════════════════════════════════════════════════════════════════
# IMPORTANT: Metasploit is opt-in. MSFModuleSearcher is NOT instantiated by
# CVEHunter unless --use-msf is passed. This guarantees no msfconsole
# subprocess is ever spawned in the default code path.
class MSFModuleSearcher:
    """Searches Metasploit Framework for modules matching a CVE.

    Uses the local `msfconsole` command (preinstalled on Kali). Returns
    module names that can be used directly: `use exploit/windows/...`
    """

    def __init__(self, cache: Cache, debug: Optional[DebugLog] = None) -> None:
        self.cache = cache
        self.debug = debug
        self._available: Optional[bool] = None

    @property
    def available(self) -> bool:
        if self._available is None:
            from shutil import which
            self._available = which("msfconsole") is not None
        return self._available

    def search(self, cve_id: str, max_results: int = 10) -> Tuple[List[Dict[str, Any]], str]:
        """Returns (results, status). status is `unavailable` if msfconsole
        is not installed; `ok` otherwise (results may still be empty)."""
        cve_id = cve_id.upper()
        if not self.available:
            if self.debug: self.debug.log("msf", cve_id, 0.0, SOURCE_UNAVAILABLE)
            return [], SOURCE_UNAVAILABLE
        cache_key = f"msf:{cve_id}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            if self.debug: self.debug.log("msf", cve_id, 0.0, SOURCE_OK)
            return cached[:max_results], SOURCE_OK
        import subprocess
        # msfconsole -q -x "search CVE-XXXX-XXXX; exit" — terse output
        # We use -q (quiet) and exit immediately after the search.
        cmd = ["msfconsole", "-q", "-x", f"search {cve_id}; exit"]
        t0 = time.time()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=60, stdin=subprocess.DEVNULL)
        except (subprocess.SubprocessError, FileNotFoundError):
            if self.debug: self.debug.log("msf", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        # msfconsole may exit 0 even with no results — parse stdout regardless.
        try:
            data = result.stdout or ""
        except Exception:
            if self.debug: self.debug.log("msf", cve_id, time.time() - t0, SOURCE_ERROR)
            return [], SOURCE_ERROR
        # Parse the msfconsole search output. Format:
        #    exploit/windows/smb/ms17_010_eternalblue  2017-03-14   ...
        results: List[Dict[str, Any]] = []
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or line.startswith("="): continue
            if line.startswith("Matching") or "modules" in line and "total" in line: continue
            tokens = line.split()
            if not tokens: continue
            module_path = tokens[0]
            if "/" not in module_path: continue
            if module_path.lower() in ("name", "disclosure", "rank", "check", "description"):
                continue
            disclosure = tokens[1] if len(tokens) > 1 and re.match(r"\d{4}-\d{2}-\d{2}", tokens[1]) else ""
            rank = ""
            for r in ("manual", "low", "average", "normal", "good", "great", "excellent"):
                if r in line.lower():
                    rank = r
                    break
            results.append({
                "module": module_path,
                "disclosure": disclosure,
                "rank": rank,
            })
            if len(results) >= max_results: break
        self.cache.set(cache_key, results)
        if self.debug: self.debug.log("msf", cve_id, time.time() - t0, SOURCE_OK)
        return results, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Composite Risk Score (NEW in v3.1) — single number for prioritization
# ════════════════════════════════════════════════════════════════════════════
def compute_risk_score(result: "CVERecord") -> Risk:
    """Compute a dimensional, confidence-weighted risk score (Phase 2).

    Replaces the old additive model. The old model double-counted correlated
    signals (KEV, EPSS, exploit-existence all proxy "exploitedness") and
    ignored attacker accessibility. The new model uses three orthogonal axes:

      likelihood = MAX of {KEV, ExploitMaturity, EPSS} — a max-style combine,
                   NOT a sum. The strongest single piece of evidence wins.
                   Ransomware use bumps likelihood one tier.
      impact     = CVSS impact sub-score (C/I/A) normalized to 0..1.
                   Falls back to CVSS base score / 10 when impact sub-score
                   is unavailable (e.g. CVSS v2 sometimes omits it).
      accessibility = derived from AV / PR / UI:
                   network + no-priv + no-UI = 1.0 (max — easiest to reach)
                   each "harder" condition lowers it.

    Final score = round(100 * likelihood * impact * accessibility * confidence_factor)
    capped to [0, 100]. The confidence_factor discounts low-confidence
    classifications so a guess never produces a confident high score.

    Weights / thresholds (documented for review):
      likelihood tiers:
        1.00 — IN_THE_WILD (KEV) or known ransomware use
        0.85 — FUNCTIONAL exploit maturity
        0.70 — EPSS >= 0.36 OR FUNCTIONAL without EPSS confirmation
        0.55 — POC maturity
        0.30 — EPSS >= 0.05 (some exploitation signal)
        0.15 — UNPROVEN maturity + low EPSS
        0.00 — no data and a material source failed (evidence_incomplete)
      impact:  cvss.impact / 10  (or cvss.score / 10 as fallback)
      accessibility:
        AV:N=1.0  AV:A=0.7  AV:L=0.3  AV:P=0.1  (or 0.6 if unknown)
        PR:N=1.0  PR:L=0.9  PR:H=0.5  (multiply)
        UI:N=1.0  UI:R=0.8             (multiply)
      confidence_factor:
        high=1.0   medium=0.8   low=0.5
    """
    breakdown: List[str] = []

    # ---- likelihood (max-style) ----
    # CRITICAL: evidence_incomplete forces likelihood=0 regardless of maturity.
    # If a material source failed, we cannot trust IN_THE_WILD or FUNCTIONAL
    # verdicts — the evidence may be incomplete.
    likelihood = 0.0
    maturity = result.exploit_maturity
    epss = result.epss or {}
    epss_val = float(epss.get("epss", 0.0) or 0.0)
    kev = result.cisa_kev
    ransomware = (kev or {}).get("known_ransomware_use", "Unknown") if kev else "Unknown"

    if result.evidence_incomplete:
        likelihood = 0.0
        breakdown.append("likelihood=0.00 (evidence incomplete — a material source failed)")
    elif kev:
        likelihood = 1.0
        breakdown.append("likelihood=1.00 (CISA KEV — actively exploited)")
        if ransomware == "Known":
            breakdown.append("  + ransomware use confirmed (likelihood already maxed)")
    elif maturity == ExploitMaturity.FUNCTIONAL:
        likelihood = 0.85
        breakdown.append("likelihood=0.85 (FUNCTIONAL exploit maturity)")
    elif epss_val >= 0.36:
        likelihood = 0.70
        breakdown.append(f"likelihood=0.70 (EPSS={epss_val*100:.1f}% >= 36%)")
    elif maturity == ExploitMaturity.POC:
        likelihood = 0.55
        breakdown.append("likelihood=0.55 (POC exploit maturity)")
    elif epss_val >= 0.05:
        likelihood = 0.30
        breakdown.append(f"likelihood=0.30 (EPSS={epss_val*100:.1f}% >= 5%)")
    elif maturity == ExploitMaturity.UNPROVEN:
        likelihood = 0.15
        breakdown.append("likelihood=0.15 (UNPROVEN, sources ok)")

    # Ransomware bumps likelihood one tier (only if not already maxed
    # AND evidence is not incomplete — we can't trust KEV data if a
    # material source failed).
    if ransomware == "Known" and likelihood < 1.0 and not result.evidence_incomplete:
        old = likelihood
        likelihood = min(likelihood + 0.15, 1.0)
        breakdown.append(f"  + ransomware use: likelihood {old:.2f} → {likelihood:.2f}")

    # ---- impact ----
    # Use the HIGHER of: CVSS impact sub-score OR CVSS base score / 10.
    # Rationale: CVSS 3.1 Scope Changed (S:C) discounts the impact
    # sub-score (e.g. Log4Shell: base=10.0 but impact=5.9 because S:C).
    # For an attacker, the real-world impact is closer to the base score.
    # Using max(impact_sub, base/10) ensures S:C vulns don't get an
    # artificially low risk score that misleads the pentester.
    cvss = result.cvss_selected
    if cvss:
        impact_sub = (float(cvss.impact) / 10.0) if cvss.impact is not None else 0.0
        impact_base = cvss.score / 10.0
        impact = max(impact_sub, impact_base)
        if impact == impact_base and cvss.impact is not None and impact_sub < impact_base:
            breakdown.append(f"impact={impact:.2f} (using CVSS base {cvss.score}/10 — "
                             f"impact sub-score {cvss.impact} discounted by S:C)")
        elif cvss.impact is not None:
            breakdown.append(f"impact={impact:.2f} (CVSS impact sub-score {cvss.impact})")
        else:
            breakdown.append(f"impact={impact:.2f} (CVSS base {cvss.score}/10 fallback)")
    else:
        impact = 0.0
        breakdown.append("impact=0.00 (no CVSS data)")

    # ---- accessibility (AV / PR / UI) ----
    # Fix 1: Linearly remap the composite into [0.5, 1.0] so that local
    # privesc / AD vulns are not buried. Remote-unauth still reaches 1.0;
    # the floor of 0.5 ensures high-value local vulns remain visible.
    vector = cvss.vector if cvss else ""
    av = extract_attack_vector(vector)
    av_factor = {"N": 1.0, "A": 0.7, "L": 0.3, "P": 0.1}.get(av or "", 0.6)
    m_pr = re.search(r"PR:([NLH])", vector)
    pr_factor = {"N": 1.0, "L": 0.9, "H": 0.5}.get(m_pr.group(1) if m_pr else "", 0.9)
    m_ui = re.search(r"UI:([NR])", vector)
    ui_factor = {"N": 1.0, "R": 0.8}.get(m_ui.group(1) if m_ui else "", 0.9)
    raw_access = av_factor * pr_factor * ui_factor
    accessibility = 0.5 + 0.5 * raw_access
    breakdown.append(
        f"accessibility={accessibility:.2f} (remapped from raw={raw_access:.2f}: "
        f"AV={av or '?'}={av_factor}, "
        f"PR={m_pr.group(1) if m_pr else '?'}={pr_factor}, "
        f"UI={m_ui.group(1) if m_ui else '?'}={ui_factor})"
    )

    # ---- confidence factor ----
    # Fix 2: confidence_factor reflects CWE-tag quality (Primary vs Secondary),
    # NOT whether an exploit exists. A working exploit (FUNCTIONAL or
    # IN_THE_WILD) is confirmed evidence — the score should not be docked
    # for a weak CWE tag. Only POC / UNPROVEN tiers (which rest on weaker
    # evidence) are discounted.
    conf = result.classification.confidence
    if maturity in (ExploitMaturity.IN_THE_WILD, ExploitMaturity.FUNCTIONAL):
        confidence_factor = 1.0
        breakdown.append(f"confidence_factor=1.0 (classification: {conf} — "
                         f"overridden: {maturity.value} exploit confirmed)")
    else:
        confidence_factor = {"high": 1.0, "medium": 0.8, "low": 0.5}.get(conf, 0.5)
        breakdown.append(f"confidence_factor={confidence_factor} (classification: {conf})")

    # ---- final score ----
    raw = likelihood * impact * accessibility * confidence_factor
    score = int(round(raw * 100))
    score = max(0, min(100, score))

    if score >= 90: label = "CRITICAL — exploit immediately"
    elif score >= 70: label = "HIGH — strong candidate"
    elif score >= 40: label = "MEDIUM — assess context"
    elif score > 0: label = "LOW — likely theoretical"
    else: label = "NONE"

    breakdown.append(f"→ score = {likelihood:.2f} × {impact:.2f} × "
                     f"{accessibility:.2f} × {confidence_factor} × 100 = {score}")

    return Risk(
        score=score, label=label, breakdown=breakdown,
        likelihood=likelihood, impact=impact,
        accessibility=accessibility, confidence_factor=confidence_factor,
    )


def risk_color(score: int) -> str:
    if score >= 90: return "bright_red"
    if score >= 70: return "red"
    if score >= 40: return "yellow"
    if score > 0: return "green"
    return "dim"


# ════════════════════════════════════════════════════════════════════════════
# Patch version extraction (NEW in v3.1)
# ════════════════════════════════════════════════════════════════════════════
def extract_patch_versions(version_ranges: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """From NVD version_ranges, extract the first patched version per product.

    Logic:
      - versionEndExcluding=X → first patched = X
      - versionEndIncluding=X → first patched = X+1 (next version)
      - if no end bound → 'not yet patched' (still vulnerable in latest)
    """
    patches: List[Dict[str, str]] = []
    seen = set()
    for vr in version_ranges:
        if not vr.get("vulnerable", True): continue
        product = vr.get("human", vr.get("cpe", ""))
        # Parse product name (strip version info from "Apache log4j 2.14.0 (App)")
        # to dedupe — we only want one patch line per product family.
        # Use the vendor/product from CPE for dedup.
        cpe = vr.get("cpe", "")
        cpe_parts = cpe.split(":")
        if len(cpe_parts) >= 5:
            dedup_key = f"{cpe_parts[3]}:{cpe_parts[4]}"
        else:
            dedup_key = product
        if dedup_key in seen: continue
        seen.add(dedup_key)

        if vr.get("version_end_excluding"):
            patch_ver = vr["version_end_excluding"]
            patches.append({"product": product, "first_patched": patch_ver,
                            "note": f"upgrade to >= {patch_ver}"})
        elif vr.get("version_end_including"):
            # Including X means X is vulnerable; first patched is the next version
            patches.append({"product": product, "first_patched": f">{vr['version_end_including']}",
                            "note": f"upgrade past {vr['version_end_including']}"})
        else:
            patches.append({"product": product, "first_patched": "—",
                            "note": "no patched version listed (still vulnerable)"})
    return patches


# ════════════════════════════════════════════════════════════════════════════
# Version comparison + version-match confirmation (Phase 2 task 9)
# ════════════════════════════════════════════════════════════════════════════
def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for proper comparison.

    Handles common forms: "2.14.0", "2019-01". Returns empty tuple () for
    unparseable input — callers MUST treat empty tuple as "unknown version"
    and reject the comparison (safer than treating malformed input as
    version 0, which causes false-positive affected=True).

    Pre-release suffixes (beta, rc, M1, etc.) are STRIPPED — only the
    numeric prefix is returned. E.g. "2.0-beta9" → (2, 0), "9.0.0.M1" →
    (9, 0, 0). This means _parse_version("2.0-beta9") == _parse_version("2.0")
    numerically. Callers that need to distinguish pre-release from final
    MUST use ``_version_has_suffix()`` first, then decide:

      - If either side has a suffix → comparison is UNCERTAIN → return False
        from _version_lt/_le/_gt/_ge (conservative: don't guess).
      - If neither side has a suffix → numeric comparison is safe.

    This makes the code and docstring consistent: pre-release versions are
    NOT magically sorted before final releases (that would require full
    semver implementation, which NVD doesn't consistently apply). Instead,
    we explicitly refuse to compare them.
    """
    if not v or not isinstance(v, str): return ()
    # FIX (low-3): strip pre-release suffix BEFORE parsing. The old regex
    # `re.sub(r"[^0-9.]+", ".", v)` converted "2.0-beta9" to "2.0.beta9"
    # which then parsed as (2, 0, 9) — folding the suffix into the version
    # number. The new approach: cut at the first non-numeric separator
    # (dash, space, +, etc.) so only the numeric prefix remains.
    # "2.0-beta9" → "2.0" → (2, 0)
    # "9.0.0.M1"  → "9.0.0" → (9, 0, 0)
    # "2.14.0"    → "2.14.0" → (2, 14, 0)  (unchanged)
    v = v.strip()
    # Find the first character that is NOT a digit or dot, and cut there.
    cut_at = len(v)
    for i, ch in enumerate(v):
        if ch != "." and not ch.isdigit():
            cut_at = i
            break
    numeric_prefix = v[:cut_at].rstrip(".")
    parts: List[int] = []
    for p in numeric_prefix.split("."):
        p = p.strip()
        if p.isdigit():
            parts.append(int(p))
        # No "else: break" needed — we already cut at the suffix boundary.
    return tuple(parts) if parts else ()


def _version_has_suffix(v: str) -> bool:
    """True if the version string contains a non-numeric suffix (beta, rc,
    M1, dev, alpha, etc.) that makes a strict numeric comparison uncertain.

    NVD sometimes uses versionStartIncluding="2.0-beta9" literally, and the
    semver semantics of "2.0-beta9 < 2.0" are well-defined in spec but NVD
    does not consistently apply them. Treating such comparisons as
    "inconclusive" (returning False from _version_lt etc.) is safer than
    guessing wrong and silently producing a false affected/not-affected.
    """
    if not v or not isinstance(v, str): return False
    # After stripping digits and dots, if anything non-trivial remains → suffix
    stripped = re.sub(r"[0-9.]+", "", v.strip().lower())
    # Allow whitespace and leading "v" as non-suffix decoration
    stripped = stripped.replace("v", "").strip()
    return bool(stripped)


def _version_lt(a: str, b: str) -> bool:
    """Strict less-than using proper version comparison (not string compare).

    Returns False if EITHER version is unparseable OR if either version
    contains a non-numeric suffix (beta/rc/M1/etc.) that makes the
    comparison uncertain. This is a deliberate conservative bias: better
    to say "inconclusive" than to silently produce a wrong affected verdict.
    """
    if _version_has_suffix(a) or _version_has_suffix(b): return False
    pa, pb = _parse_version(a), _parse_version(b)
    if not pa or not pb: return False
    return pa < pb

def _version_le(a: str, b: str) -> bool:
    if _version_has_suffix(a) or _version_has_suffix(b): return False
    pa, pb = _parse_version(a), _parse_version(b)
    if not pa or not pb: return False
    return pa <= pb

def _version_gt(a: str, b: str) -> bool:
    if _version_has_suffix(a) or _version_has_suffix(b): return False
    pa, pb = _parse_version(a), _parse_version(b)
    if not pa or not pb: return False
    return pa > pb

def _version_ge(a: str, b: str) -> bool:
    if _version_has_suffix(a) or _version_has_suffix(b): return False
    pa, pb = _parse_version(a), _parse_version(b)
    if not pa or not pb: return False
    return pa >= pb


def check_version_affected(version_ranges: List[Dict[str, Any]],
                            product_version: str) -> Dict[str, Any]:
    """Definitive in/out-of-range verdict for a user-supplied version.

    Walks the NVD version_ranges and returns the first matching vulnerable
    range. ``product_version`` MUST be a value the user typed manually —
    the tool never obtains a version by scanning (Phase 2 guardrail).

    Returns:
      {"affected": bool, "matched_range": Optional[dict], "reason": str}
    """
    if not product_version or not version_ranges:
        return {"affected": False, "matched_range": None,
                "reason": "no version ranges or no input version"}
    pv = product_version.strip()
    # Reject malformed versions early — prevents false-positive affected=True
    # when the user types something like "not-a-version" or "v2.14!!!".
    # A valid version must contain at least one digit group.
    if not _parse_version(pv):
        return {"affected": False, "matched_range": None,
                "reason": f"invalid version format: {pv!r} (expected digits like '2.14.0')"}
    # Detect pre-release suffixes (beta/rc/M1/dev) that make comparison
    # uncertain. NVD does not consistently apply semver pre-release semantics,
    # so we surface this to the operator instead of guessing silently.
    if _version_has_suffix(pv):
        return {"affected": False, "matched_range": None,
                "reason": f"version {pv!r} has a pre-release suffix — comparison "
                          f"is uncertain, please verify manually against the advisory"}
    skipped_due_to_suffix = False
    wildcard_match = False
    wildcard_cpe = ""
    for vr in version_ranges:
        if not vr.get("vulnerable", True):
            continue
        # FIX (user-test): CPE-embedded version handling. NVD sometimes lists
        # CPE matches WITHOUT version_start/end bounds — the version is
        # embedded in the CPE URI itself (e.g. cpe:2.3:a:apache:log4j:2.0:...).
        # Before this fix, such entries were treated as "any version affected",
        # causing false-positive affected=True for patched versions like 2.15.0.
        cpe = vr.get("cpe", "")
        has_bounds = (vr.get("version_start_including") or
                      vr.get("version_start_excluding") or
                      vr.get("version_end_including") or
                      vr.get("version_end_excluding"))
        if not has_bounds and cpe:
            # Parse the version from the CPE URI.
            # CPE 2.3 format: cpe:2.3:type:vendor:product:version:update:...
            cpe_parts = cpe.split(":")
            if len(cpe_parts) >= 6:
                cpe_version = cpe_parts[5]
                if cpe_version and cpe_version != "*":
                    # This CPE is for a SPECIFIC version — exact match only.
                    if _parse_version(pv) == _parse_version(cpe_version) and \
                            not _version_has_suffix(pv) and \
                            not _version_has_suffix(cpe_version):
                        return {
                            "affected": True,
                            "matched_range": vr,
                            "reason": f"version {pv} matches CPE-specified version {cpe_version}",
                        }
                    # Version doesn't match this specific CPE — skip it.
                    continue
            # CPE has version="*" (wildcard) and no bounds — NVD is saying
            # "this entire product line is affected" but we can't verify the
            # user's specific version against it. Return affected=True but
            # with a clear reason so the operator knows it's a wildcard match,
            # not a precise version match.
            # However, for the common case of a user checking a specific
            # software version (e.g. Apache Log4j 2.15.0) against a CVE that
            # also lists unrelated products (e.g. Siemens firmware) as
            # wildcard-affected, this produces misleading results.
            # The safest behavior: treat wildcard CPEs as "possibly affected"
            # but continue checking other ranges for a more precise match.
            # If we find a precise non-match later, the overall verdict is
            # still "not affected" for the user's specific product/version.
            wildcard_match = True
            wildcard_cpe = cpe
            continue
        # FIX (accuracy-4 cont.): if ANY bound in this range has a pre-release
        # suffix (beta/rc/M1/dev), the comparison is uncertain — skip this
        # range rather than risk a false affected=True. The operator can
        # verify manually against the advisory.
        bounds_with_suffix = [
            vr.get("version_start_including", ""),
            vr.get("version_start_excluding", ""),
            vr.get("version_end_including", ""),
            vr.get("version_end_excluding", ""),
        ]
        if any(_version_has_suffix(b) for b in bounds_with_suffix):
            # Track that we skipped at least one range due to suffix
            # uncertainty — surfaced in the final reason if no clean range matches.
            skipped_due_to_suffix = True
            continue
        # Check lower bound
        in_range = True
        has_lower_bound = bool(vr.get("version_start_including") or vr.get("version_start_excluding"))
        has_upper_bound = bool(vr.get("version_end_including") or vr.get("version_end_excluding"))
        # FIX (user-test): ranges with ONLY an upper bound (no lower bound, no
        # CPE-embedded version) are too generic — they match almost any version
        # number and belong to a different product than what the user is likely
        # checking. E.g. CVE-2021-44228 lists Siemens Capital < 2019.1 as
        # affected, which would match Apache Log4j 2.15.0 (a patched version)
        # just because 2.15.0 < 2019.1 numerically. Skip such ranges.
        if has_upper_bound and not has_lower_bound:
            continue
        if vr.get("version_start_including") and \
                _version_lt(pv, vr["version_start_including"]):
            in_range = False
        if vr.get("version_start_excluding") and \
                _version_le(pv, vr["version_start_excluding"]):
            in_range = False
        # Check upper bound
        if vr.get("version_end_including") and \
                _version_gt(pv, vr["version_end_including"]):
            in_range = False
        if vr.get("version_end_excluding") and \
                _version_ge(pv, vr["version_end_excluding"]):
            in_range = False
        if in_range:
            # Build a human-readable range string for the verdict.
            parts = []
            if vr.get("version_start_including"): parts.append(f">= {vr['version_start_including']}")
            if vr.get("version_start_excluding"): parts.append(f"> {vr['version_start_excluding']}")
            if vr.get("version_end_including"): parts.append(f"<= {vr['version_end_including']}")
            if vr.get("version_end_excluding"): parts.append(f"< {vr['version_end_excluding']}")
            range_str = " ".join(parts) if parts else "any version"
            return {
                "affected": True,
                "matched_range": vr,
                "reason": f"version {pv} is in vulnerable range ({range_str})",
            }
    if skipped_due_to_suffix:
        return {"affected": False, "matched_range": None,
                "reason": f"version {pv} not in any clean vulnerable range; "
                          f"one or more ranges use pre-release suffix bounds "
                          f"(beta/rc/M1) — please verify manually against the advisory"}
    if wildcard_match:
        return {"affected": False, "matched_range": None,
                "reason": f"version {pv} not in any specific vulnerable range; "
                          f"a wildcard CPE ({wildcard_cpe[:40]}...) lists the entire "
                          f"product line as affected — verify manually if your product matches"}
    return {"affected": False, "matched_range": None,
            "reason": f"version {pv} not in any vulnerable range"}


# ════════════════════════════════════════════════════════════════════════════
# PoC quality scoring + exploit maturity decision tree (Phase 2 tasks 5/6)
# ════════════════════════════════════════════════════════════════════════════
# Quality thresholds (documented for review):
POC_MIN_STARS = 10            # below this, a repo is "low" quality
POC_RECENT_DAYS = 365         # a push within this window counts as "recent"
POC_HIGH_QUALITY_MIN = 2      # need this many high-quality signals for FUNCTIONAL


def _normalize_url(url: str) -> str:
    """Normalize a URL for dedup. Strips trailing slash, lowercases host."""
    if not url: return ""
    u = url.strip().lower()
    if u.endswith("/"): u = u[:-1]
    # Strip query string for dedup purposes (exploit-db URLs sometimes have ?)
    # Actually keep query for exploit-db IDs — they're meaningful. Just strip
    # trailing slash and lowercase.
    return u


def _score_github_poc(repo: Dict[str, Any]) -> str:
    """Score a GitHub PoC repo's quality: high / medium / low.

    Assumes the repo already passed ``_poc_is_excluded`` (forks and
    aggregators are dropped before this function is called). This function
    only evaluates stars + recency.
    """
    stars = int(repo.get("stars", 0) or 0)
    # Recent push check (parse ISO date)
    updated = repo.get("updated", "")
    is_recent = False
    if updated:
        try:
            from datetime import datetime, timedelta, timezone
            d = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            is_recent = (datetime.now(timezone.utc) - d).days <= POC_RECENT_DAYS
        except (ValueError, TypeError):
            pass
    if stars >= POC_MIN_STARS and is_recent:
        return "high"
    if stars >= POC_MIN_STARS or is_recent:
        return "medium"
    return "low"


def _score_exploitdb_entry(entry: Dict[str, Any]) -> str:
    """Score an ExploitDB entry: verified → high, else medium."""
    if entry.get("verified"):
        return "high"
    return "medium"


def _score_msf_module(module: Dict[str, Any]) -> str:
    """Score an MSF module by rank: excellent/great → high, else medium."""
    rank = (module.get("rank") or "").lower()
    if rank in ("excellent", "great"):
        return "high"
    if rank in ("good", "normal", "average"):
        return "medium"
    return "low"


def decide_exploit_maturity(
    cisa_kev: Optional[Dict[str, Any]],
    exploit_evidence: List["ExploitEvidence"],
    epss_value: float,
    sources_status: Dict[str, str],
    msf_enabled: bool = False,
    deep_mode: bool = True,
) -> Tuple[ExploitMaturity, bool]:
    """Decision tree for exploit maturity (Phase 2 task 6, Phase 4 B1/B2).

    Returns (maturity, evidence_incomplete).

    PART B1 — Curated drives automated maturity/verdict:
      Only ``trust=="curated"`` / VERIFIED evidence counts toward
      ``has_any_poc`` / ``high_quality_count`` / FUNCTIONAL / IN_THE_WILD.
      CANDIDATE/mention evidence is displayed but never raises automated
      maturity. Forks excluded from scoring. (No false "TRY FIRST".)

    PART B2 — Never floor a high-severity CVE to 0 because discovery was
      skipped/degraded. ``evidence_incomplete`` is now True ONLY when the
      NVD spine itself is missing. A skipped/degraded/unreachable
      PoC-discovery source (including ``deep=False`` fast mode) must NOT
      floor the score. With no curated exploit evidence, risk is computed
      from available signals (CVSS impact + accessibility + EPSS + KEV) at
      the right maturity tier.

    Decision tree (highest wins):
      1. IN_THE_WILD  — CISA KEV entry present (and KEV source ok).
      2. FUNCTIONAL   — high-rank MSF module (--use-msf only) OR verified
                        ExploitDB entry OR >=2 high-quality PoCs OR EPSS>=0.36
                        (with at least one curated PoC).
      3. POC          — >=1 PoC repo (any quality) OR single low-quality exploit.
      4. UNPROVEN     — no evidence AND no material source failed.
    """
    # ---- evidence_incomplete: PART B2 ----
    # Floor to 0 ONLY when the NVD spine is missing entirely.
    # A skipped/degraded PoC-discovery source (including deep=False fast
    # mode) must NOT floor the score — the CVE may still be a high-CVSS
    # critical that deserves attention.
    if not deep_mode:
        # Fast listing mode — we deliberately skipped discovery. The score
        # should reflect CVSS + EPSS + KEV, not be floored to 0.
        evidence_incomplete = False
    else:
        # Deep mode — only flag incomplete if NVD itself failed.
        # (NVD failure is the one true spine-missing case.)
        evidence_incomplete = sources_status.get("nvd") in ("error", "ratelimited")

    # ---- IN_THE_WILD ----
    # Only confident if the KEV source itself was ok.
    if cisa_kev and sources_status.get("cisa_kev") == "ok":
        return ExploitMaturity.IN_THE_WILD, evidence_incomplete

    # ---- Gather quality-tagged evidence (curated only) ----
    # PART B1: trust=="mention" evidence (raw GitHub search fallback) is
    # IGNORED by the maturity tree entirely — it can never produce POC or
    # FUNCTIONAL. CANDIDATE mentions are display-only.
    high_quality_count = 0
    has_any_poc = False
    has_verified_edb = False
    has_high_msf = False
    for ev in exploit_evidence:
        if ev.evidence_type not in ("exploit", "poc", "module"):
            continue
        if ev.trust != "curated":
            continue  # mention evidence — display only, never counts
        # Skip availability markers (url="") — they don't count as evidence.
        is_avail_marker = (not ev.url and (
            ev.extra.get("_searchsploit_available") or
            ev.extra.get("_msf_available")
        ))
        if is_avail_marker:
            continue
        has_any_poc = True
        if ev.source == "exploitdb" and ev.quality == "high":
            has_verified_edb = True
        if ev.source == "msf" and ev.quality == "high":
            has_high_msf = True
        if ev.quality == "high":
            high_quality_count += 1

    # ---- FUNCTIONAL ----
    # MSF high-rank only counts if --use-msf was passed (msf_enabled).
    # CRITICAL FIX: EPSS >= 0.36 only counts as a FUNCTIONAL signal when
    # there is at least ONE piece of curated exploit evidence (PoC, EDB,
    # MSF, NVD ref). EPSS predicts exploitation probability — it does NOT
    # mean a public exploit exists. Without this guard, a CVE with high
    # EPSS but zero exploit pointers would be labeled FUNCTIONAL → TRY
    # FIRST, misleading the pentester into thinking a ready exploit exists.
    functional_signals = 0
    if has_high_msf and msf_enabled:
        functional_signals += 1
    if has_verified_edb:
        functional_signals += 1
    if high_quality_count >= POC_HIGH_QUALITY_MIN:
        functional_signals += 1
    # EPSS only counts as a signal when there's at least some exploit evidence
    if epss_value >= 0.36 and has_any_poc:
        functional_signals += 1
    if functional_signals >= 1:
        return ExploitMaturity.FUNCTIONAL, evidence_incomplete

    # ---- POC ----
    if has_any_poc:
        return ExploitMaturity.POC, evidence_incomplete

    # ---- UNPROVEN ----
    # Note: even if EPSS is high, if there is zero exploit evidence,
    # maturity is UNPROVEN. The pentester sees "no exploit pointers" and
    # knows they need to search manually. Risk is still computed from
    # CVSS + EPSS + accessibility — never floored to 0 (PART B2).
    return ExploitMaturity.UNPROVEN, evidence_incomplete


# ════════════════════════════════════════════════════════════════════════════
# CISA KEV Catalog (Known Exploited Vulnerabilities)
# ════════════════════════════════════════════════════════════════════════════
class CISAKEVChecker:
    """Checks CVE against CISA's Known Exploited Vulnerabilities catalog.

    If a CVE appears here, it means CISA has confirmed it is being actively
    exploited in the wild.

    IMPORTANT: ``check()`` returns ``(entry, status)``. A *failed* catalog
    load (network error, 403, parse failure) returns status = `error` /
    `ratelimited`, and the entry is None. Callers MUST distinguish this
    from a successful "not in KEV" verdict (status = `ok`, entry = None) —
    silently treating a failed load as "not in KEV" is a real accuracy bug.
    """

    def __init__(self, settings: Settings, cache: Cache,
                 debug: Optional[DebugLog] = None) -> None:
        self.s = settings
        self.cache = cache
        self.debug = debug
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self._catalog: Optional[Dict[str, Dict[str, Any]]] = None
        self._catalog_status: str = SOURCE_OK

    def _load_catalog(self) -> str:
        """Load the full CISA KEV catalog (cached for 24h).

        Returns the catalog status: SOURCE_OK / SOURCE_RATELIMITED /
        SOURCE_ERROR. Populates self._catalog (empty dict on failure).
        """
        if self._catalog is not None:
            return self._catalog_status
        cached = self.cache.get("cisa_kev:catalog")
        if cached is not None:
            self._catalog = {k.upper(): v for k, v in cached.items()}
            self._catalog_status = SOURCE_OK
            return self._catalog_status
        t0 = time.time()
        # Try PRIMARY (cisagov/kev-data mirror) first; fall back to cisa.gov
        # direct feed if the mirror is unreachable. Many server IPs are now
        # Akamai-gated on cisa.gov (403) — the GitHub mirror avoids that.
        urls_to_try = [self.s.cisa_kev_url]
        if self.s.cisa_kev_url != CISA_KEV_URL:
            urls_to_try.append(CISA_KEV_URL)
        if CISA_KEV_URL_FALLBACK not in urls_to_try:
            urls_to_try.append(CISA_KEV_URL_FALLBACK)
        resp = None
        last_err: Optional[requests.RequestException] = None
        for url in urls_to_try:
            try:
                resp = self.session.get(url, timeout=120)
                if resp.status_code == 200:
                    break  # success — use this response
                # 403/429 on cisa.gov → try mirror; 404 on mirror → try cisa.gov
                # keep last non-200 response for status reporting
            except requests.RequestException as e:
                last_err = e
                resp = None
                continue
        if resp is None:
            self._catalog = {}
            self._catalog_status = SOURCE_ERROR
            if self.debug: self.debug.log("cisa_kev", "catalog", time.time() - t0, SOURCE_ERROR)
            return self._catalog_status
        if resp.status_code in (403, 429):
            self._catalog = {}
            self._catalog_status = SOURCE_RATELIMITED
            if self.debug: self.debug.log("cisa_kev", "catalog", time.time() - t0, SOURCE_RATELIMITED)
            return self._catalog_status
        if resp.status_code != 200:
            self._catalog = {}
            self._catalog_status = SOURCE_ERROR
            if self.debug: self.debug.log("cisa_kev", "catalog", time.time() - t0, SOURCE_ERROR)
            return self._catalog_status
        try:
            data = resp.json()
        except json.JSONDecodeError:
            self._catalog = {}
            self._catalog_status = SOURCE_ERROR
            if self.debug: self.debug.log("cisa_kev", "catalog", time.time() - t0, SOURCE_ERROR)
            return self._catalog_status
        catalog: Dict[str, Dict[str, Any]] = {}
        for entry in safe_get(data, "vulnerabilities", default=[]):
            cve_id = (entry.get("cveID") or "").upper()
            if not cve_id: continue
            catalog[cve_id] = {
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "description": entry.get("shortDescription", ""),
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "required_action": entry.get("requiredAction", ""),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
            }
        self.cache.set("cisa_kev:catalog", catalog)
        self._catalog = catalog
        self._catalog_status = SOURCE_OK
        if self.debug: self.debug.log("cisa_kev", "catalog", time.time() - t0, SOURCE_OK)
        return self._catalog_status

    def check(self, cve_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (entry, status). entry is None if not in KEV.

        status is one of: ok / ratelimited / error / skipped.
        A failed catalog load MUST NOT be reported as "not in KEV" —
        the status field tells the caller to lower confidence.
        """
        status = self._load_catalog()
        if status != SOURCE_OK:
            return None, status
        entry = self._catalog.get(cve_id.upper()) if self._catalog else None
        return entry, SOURCE_OK


# ════════════════════════════════════════════════════════════════════════════
# Classifier (rule-based, no AI)
# ════════════════════════════════════════════════════════════════════════════
def classify(cwes: List[str], description: str = "",
             cwe_entries: Optional[List[Dict[str, str]]] = None,
             provisional: bool = False) -> Classification:
    """Classify CVE based on CWE list (with provenance) and description keywords.

    Phase 2 changes:
      - Returns a ``Classification`` dataclass (not a dict).
      - Uses ``cwe_entries`` (list of {cwe_id, source_type}) when available
        to set confidence: Primary CWE → high, Secondary → medium.
      - If ``provisional`` (vuln_status is "Awaiting/Undergoing Analysis"),
        confidence is forced to "low" regardless of basis.
      - Builds a ``chain`` of all recognized CWE ids.

    Strategy:
      1. From recognized CWEs, pick non-generic ones; if any, choose best by
         priority. Confidence = high if Primary, medium if Secondary only.
      2. If only generic CWEs remain, try keyword fallback first.
      3. If keyword match succeeds, confidence = low.
      4. Otherwise, fall back to the first generic CWE (confidence = low).
      5. If no CWEs at all, use keyword fallback (confidence = low).
      6. Otherwise, return Unknown (confidence = low).
    """
    # Build (cwe_id, source_type) tuples. Prefer cwe_entries if provided;
    # fall back to plain list with empty source_type.
    if cwe_entries:
        entries = [(ce["cwe_id"].upper(), ce.get("source_type", ""))
                   for ce in cwe_entries]
    else:
        entries = [(c.upper(), "") for c in (cwes or [])]

    known = [(cid, st) for cid, st in entries if cid in CWE_MAP]
    known_ids = [cid for cid, _ in known]
    non_generic = [(cid, st) for cid, st in known if cid not in GENERIC_CWES]

    # Helper: build Classification, applying provisional override.
    def _build(primary: str, sub: str, chain: List[str],
               confidence: str, basis: str) -> Classification:
        if provisional and confidence != "low":
            confidence = "low"
        return Classification(primary=primary, subcategory=sub,
                              chain=chain, confidence=confidence, basis=basis)

    # Step 1: non-generic CWEs available — pick the most severe category.
    if non_generic:
        # Pick the CWE with the best (lowest) priority number.
        best_cid, best_st = min(
            non_generic,
            key=lambda cs: CATEGORY_PRIORITY.get(CWE_MAP[cs[0]]["cat"], 99),
        )
        best_map = CWE_MAP[best_cid]
        # Confidence: high if any Primary CWE exists among non_generic;
        # medium otherwise (Secondary only).
        has_primary = any(st == "Primary" for _, st in non_generic)
        confidence = "high" if has_primary else "medium"
        basis = "cwe_primary" if has_primary else "cwe_secondary"
        return _build(best_map["cat"], best_map["sub"], known_ids,
                      confidence, basis)

    # Step 2: only generic CWEs (or no CWEs) — try keyword fallback first.
    desc_lower = (description or "").lower()
    match = _keyword_match(desc_lower)
    if match is not None:
        return _build(match["cat"], match["sub"], known_ids, "low", "keyword")

    # Step 3: keyword failed, use the generic CWE if we have one.
    if known_ids:
        first = known_ids[0]
        first_map = CWE_MAP[first]
        return _build(first_map["cat"], first_map["sub"], known_ids,
                      "low", "generic")

    return _build("Unknown", "Unclassified", [], "low", "generic")


def is_remote_exploitable(category: str, cvss_vector: str = "") -> Optional[bool]:
    """Determine if the vuln is remotely exploitable.

    Priority:
      1. CVSS Attack Vector (AV:N → remote, AV:L → local)
      2. Category-based heuristic
    """
    if cvss_vector:
        m = re.search(r"AV:([NAPL])", cvss_vector)
        if m:
            av = m.group(1)
            if av == "N": return True
            if av == "L" or av == "P": return False
            if av == "A": return True  # Adjacent — usually network-reachable
    remote = {"RCE", "SQLi", "XSS", "SSRF", "XXE", "LFI", "RFI", "CSRF",
              "OpenRedirect", "AuthBypass", "Injection"}
    local = {"PrivEsc", "Race"}
    if category in remote: return True
    if category in local: return False
    return None


# ════════════════════════════════════════════════════════════════════════════
# Phase 4: Attacker-mindset verdicts, reach, outcome (pure functions)
# ════════════════════════════════════════════════════════════════════════════

# Verdict constants
VERDICT_TRY_FIRST = "TRY_FIRST"
VERDICT_WORTH_A_LOOK = "WORTH_A_LOOK"
VERDICT_PARK_IT = "PARK_IT"

VERDICT_LABELS = {
    VERDICT_TRY_FIRST: "▶ TRY FIRST",
    VERDICT_WORTH_A_LOOK: "◐ WORTH A LOOK",
    VERDICT_PARK_IT: "✓ PARK IT",
}

# Attacker-mindset palette: green = go/easy, yellow = assess, red = blocked
VERDICT_COLORS = {
    VERDICT_TRY_FIRST: "green",
    VERDICT_WORTH_A_LOOK: "yellow",
    VERDICT_PARK_IT: "red",
}

# Maturity display labels + colors (attacker mindset, not severity)
MATURITY_LABELS = {
    ExploitMaturity.IN_THE_WILD: "WEAPONIZED",
    ExploitMaturity.FUNCTIONAL: "READY",
    ExploitMaturity.POC: "POC",
    ExploitMaturity.UNPROVEN: "NONE",
}
MATURITY_COLORS = {
    ExploitMaturity.IN_THE_WILD: "green",
    ExploitMaturity.FUNCTIONAL: "green",
    ExploitMaturity.POC: "yellow",
    ExploitMaturity.UNPROVEN: "red",
}


def compute_reach(cvss_vector: str, category: str) -> str:
    """Compute the attacker 'reach' tag from CVSS AV/PR.

    Returns one of: 'UNAUTH·NETWORK', 'AUTH·NETWORK', 'LOCAL', 'ADJACENT', 'UNKNOWN'.

    UNAUTH·NETWORK = AV:N + PR:N (anyone, no login — easiest to reach).
    AUTH·NETWORK   = AV:N + PR:L/H (needs credentials).
    LOCAL          = AV:L or AV:P.
    ADJACENT       = AV:A.
    """
    av = extract_attack_vector(cvss_vector)
    m_pr = re.search(r"PR:([NLH])", cvss_vector)
    pr = m_pr.group(1) if m_pr else ""

    if av == "N":
        if pr == "N":
            return "UNAUTH·NETWORK"
        return "AUTH·NETWORK"
    if av == "A":
        return "ADJACENT"
    if av in ("L", "P"):
        return "LOCAL"
    # No CVSS vector — fall back to category heuristic
    remote_cats = {"RCE", "SQLi", "XSS", "SSRF", "XXE", "LFI", "RFI",
                   "CSRF", "OpenRedirect", "AuthBypass", "Injection"}
    local_cats = {"PrivEsc", "Race"}
    if category in remote_cats:
        return "UNAUTH·NETWORK"  # assume network-reachable for remote cats
    if category in local_cats:
        return "LOCAL"
    return "UNKNOWN"


def compute_outcome(category: str) -> str:
    """Compute the attacker 'outcome' tag from vuln category.

    Returns one of: 'FOOTHOLD', 'PRIV-ESC', 'LOOT', 'DENIAL', 'OTHER'.
    """
    if category in ("RCE", "AuthBypass"):
        return "FOOTHOLD"
    if category == "PrivEsc":
        return "PRIV-ESC"
    if category in ("InfoLeak", "XSS"):
        return "LOOT"
    if category == "DoS":
        return "DENIAL"
    # SQLi, SSRF, LFI, etc. can be foothold-adjacent but not guaranteed RCE
    if category in ("SQLi", "SSRF", "LFI", "RFI", "XXE", "Injection"):
        return "FOOTHOLD"
    return "OTHER"


def compute_verdict(reach: str, maturity: ExploitMaturity,
                    evidence_incomplete: bool, provisional: bool,
                    risk_score: int) -> str:
    """Compute the attacker verdict: TRY_FIRST / WORTH_A_LOOK / PARK_IT.

    Decision tree:
      1. PARK IT if evidence_incomplete (can't trust the data) or provisional.
      2. TRY FIRST if reachable (UNAUTH·NETWORK or AUTH·NETWORK) AND
         maturity is IN_THE_WILD or FUNCTIONAL.
      3. WORTH A LOOK if reachable AND (POC maturity OR risk_score >= 40).
      4. WORTH A LOOK if not reachable but has FUNCTIONAL or IN_THE_WILD maturity.
      5. PARK IT otherwise.
    """
    if evidence_incomplete or provisional:
        return VERDICT_PARK_IT
    reachable = reach in ("UNAUTH·NETWORK", "AUTH·NETWORK", "ADJACENT")
    has_working_exploit = maturity in (ExploitMaturity.IN_THE_WILD,
                                        ExploitMaturity.FUNCTIONAL)
    has_any_exploit = maturity in (ExploitMaturity.IN_THE_WILD,
                                    ExploitMaturity.FUNCTIONAL,
                                    ExploitMaturity.POC)

    if reachable and has_working_exploit:
        return VERDICT_TRY_FIRST
    if reachable and (maturity == ExploitMaturity.POC or risk_score >= 40):
        return VERDICT_WORTH_A_LOOK
    if not reachable and has_working_exploit:
        return VERDICT_WORTH_A_LOOK
    if has_any_exploit:
        return VERDICT_WORTH_A_LOOK
    return VERDICT_PARK_IT


def compute_why(reach: str, maturity: ExploitMaturity, kev: Optional[Dict],
                provisional: bool, evidence_incomplete: bool,
                confidence: str) -> str:
    """One-line human-readable 'why this verdict' explanation."""
    if evidence_incomplete:
        return "a material source failed — data may be incomplete"
    if provisional:
        return "CVE is awaiting NVD analysis — classification is provisional"
    parts = []
    if kev:
        parts.append("exploited in the wild (KEV)")
    if maturity == ExploitMaturity.IN_THE_WILD:
        if not kev:
            parts.append("actively exploited")
    elif maturity == ExploitMaturity.FUNCTIONAL:
        parts.append("reliable exploit available")
    elif maturity == ExploitMaturity.POC:
        parts.append("PoC available but needs work")
    elif maturity == ExploitMaturity.UNPROVEN:
        parts.append("no exploit evidence")
    if reach == "UNAUTH·NETWORK":
        parts.append("no auth required")
    elif reach == "AUTH·NETWORK":
        parts.append("needs credentials")
    elif reach == "LOCAL":
        parts.append("local access required")
    if confidence == "low":
        parts.append("classification uncertain")
    return " + ".join(parts) if parts else "insufficient data"


def is_data_incomplete(record: "CVERecord") -> bool:
    """True if the record's data is unreliable (provisional or failed source)."""
    return record.provisional or record.evidence_incomplete


# ════════════════════════════════════════════════════════════════════════════
# Discovery Engine — concurrent multi-source PoC/exploit aggregator (Phase 4).
# Runs every configured source in parallel via ThreadPoolExecutor; merges and
# dedups results into a single ranked candidate list with "also seen in" sets.
# One slow/failed source never blocks or aborts the run.
# ════════════════════════════════════════════════════════════════════════════
from concurrent.futures import ThreadPoolExecutor, as_completed

# Display tiers (PART A5 of the brief). Higher = more trustworthy.
TIER_VERIFIED = "VERIFIED"   # ExploitDB-verified, MSF module, KEV-linked, Vulners exploitdb/metasploit
TIER_CURATED  = "CURATED"    # nomi-sec/trickest/GHSA/OSV-evidence/Nuclei/NVD exploit-tagged ref
TIER_CANDIDATE = "CANDIDATE" # GitHub-search mention / generic web ref
TIER_NONE     = "—"          # no exploit evidence at all

# Trust weight for tier computation: VERIFIED > CURATED > CANDIDATE
_TIER_RANK = {TIER_VERIFIED: 3, TIER_CURATED: 2, TIER_CANDIDATE: 1, TIER_NONE: 0}


def _classify_lead_tier(source: str, trust: str, extra: Dict[str, Any],
                        cisa_kev: Optional[Dict[str, Any]] = None) -> str:
    """Compute the display tier (VERIFIED/CURATED/CANDIDATE) for a single lead.

    Rules:
      - VERIFIED: ExploitDB-verified entry, MSF module, or appears in CISA KEV
                  (exploited in the wild), or Vulners exploitdb/metasploit.
      - CURATED:  nomi-sec/trickest/GHSA/OSV-evidence/Nuclei/NVD exploit-tagged ref.
      - CANDIDATE: GitHub-search mention / generic web ref / unknown provenance.
    """
    if source == "exploitdb":
        # searchsploit's "verified" flag (Doc_File_Verified column) is the
        # classic ExploitDB verified-PoC signal.
        if extra.get("verified"):
            return TIER_VERIFIED
        return TIER_CURATED
    if source == "msf":
        # Any MSF module is a verified exploit (the framework ships it).
        return TIER_VERIFIED
    if source == "vulners":
        family = (extra.get("type") or "").lower()
        if family in ("exploitdb", "metasploit"):
            return TIER_VERIFIED
        return TIER_CURATED if trust == "curated" else TIER_CANDIDATE
    if source == "nvd_ref":
        # NVD-tagged exploit refs (e.g. exploit-db.com, packetstorm) — curated.
        # If the CVE is in KEV, treat nvd_ref as VERIFIED (active exploitation).
        if cisa_kev:
            return TIER_VERIFIED
        return TIER_CURATED
    if source in ("github",):
        # GitHub PoC: curated if from nomi-sec/trickest/mirror; candidate if
        # from raw search.
        return TIER_CURATED if trust == "curated" else TIER_CANDIDATE
    if source == "osv":
        # OSV EVIDENCE-typed refs are explicit PoCs; others are advisory/refs.
        if extra.get("evidence_type") == "poc":
            return TIER_CURATED
        return TIER_CURATED if trust == "curated" else TIER_CANDIDATE
    if source == "ghsa":
        # GHSA-curated refs are curated; PoC-host refs are VERIFIED if they
        # point at ExploitDB/MSF.
        url = (extra.get("url") or "").lower()
        if "exploit-db.com" in url:
            return TIER_VERIFIED
        return TIER_CURATED if trust == "curated" else TIER_CANDIDATE
    if source == "nuclei":
        # Nuclei templates are detection signatures — curated.
        return TIER_CURATED
    if source == "trickest":
        return TIER_CURATED
    # Unknown source — fall back to trust tier.
    return TIER_CURATED if trust == "curated" else TIER_CANDIDATE


def _github_owner_repo(url: str) -> Optional[str]:
    """Extract owner/repo from a github.com OR raw.githubusercontent.com URL
    for repo-level collapsing. Returns None for non-GitHub URLs or unparseable paths.

    Handles:
      - https://github.com/owner/repo
      - https://www.github.com/owner/repo
      - https://github.com/owner/repo/... (subpaths stripped)
      - https://github.com/owner/repo.git
      - https://raw.githubusercontent.com/owner/repo/main/file.py
      - https://raw.githubusercontent.com/owner/repo/refs/heads/main/file.py
    """
    if not url: return None
    # Match github.com/owner/repo (with optional www and any subpath)
    m = re.match(r"https?://(?:www\.)?github\.com/([^/]+/[^/]+)", url, re.IGNORECASE)
    if m:
        owner_repo = m.group(1).rstrip("/")
    else:
        # Match raw.githubusercontent.com/owner/repo/<branch>/...
        # The first two path segments after the host are always owner/repo.
        m = re.match(r"https?://raw\.githubusercontent\.com/([^/]+/[^/]+)", url, re.IGNORECASE)
        if not m: return None
        owner_repo = m.group(1).rstrip("/")
    # Strip trailing .git, /issues, /pulls, /releases etc. (only for github.com URLs;
    # raw URLs already only have owner/repo captured by the regex above)
    owner_repo = re.sub(r"\.git$|/(issues|pulls|releases|blob|tree|commits|wiki|actions|projects|settings|stargazers|forks|network|graphs).*$",
                        "", owner_repo, flags=re.IGNORECASE)
    return owner_repo.lower() if owner_repo else None


class DiscoveryEngine:
    """Concurrent multi-source PoC/exploit discovery (Phase 4).

    The engine runs every configured source concurrently via a thread pool,
    then merges + dedups results into a single ranked candidate list. Each
    candidate carries:
      - source: which source surfaced it
      - url: the canonical URL
      - quality: high/medium/low
      - trust: curated/mention
      - tier: VERIFIED/CURATED/CANDIDATE
      - extra: source-specific metadata (stars, language, etc.)
      - also_seen_in: set of source names that also referenced this URL

    A slow or failed source NEVER blocks or aborts the run; we collect
    partial results from whichever sources responded.

    Usage:
        engine = DiscoveryEngine(hunter, max_workers=6)
        leads, sources_status = engine.discover(cve_id, kev_entry=kev_dict)
    """

    def __init__(self, hunter: "CVEHunter", max_workers: int = 6,
                 max_pocs: int = 15) -> None:
        self.hunter = hunter
        self.max_workers = max_workers
        self.max_pocs = max_pocs

    def discover(self, cve_id: str,
                 ref_info: Dict[str, Any],
                 kev_entry: Optional[Dict[str, Any]] = None,
                 use_msf: bool = False,
                 search_local: bool = True) -> Tuple[List[ExploitEvidence], Dict[str, str]]:
        """Run all configured sources concurrently; return (leads, sources_status).

        ``leads`` is a deduplicated, ranked list of ExploitEvidence.
        ``sources_status`` maps each source name to its SOURCE_* status.
        """
        cve_id = cve_id.upper()
        sources_status: Dict[str, str] = {}
        # Each source contributes a list of raw candidate dicts in the form:
        #   {source, url, quality, evidence_type, trust, extra, also_seen_in}
        # We dedup at the end.
        raw_candidates: List[Dict[str, Any]] = []

        # ---- Define per-source fetch callables ----
        # Each returns (candidates_list, status). candidates_list is a list
        # of dicts with keys: {source, url, quality, evidence_type, trust, extra}.
        def _fetch_nvd_refs() -> Tuple[List[Dict[str, Any]], str]:
            # NVD refs tagged as exploit/PoC by detect_exploit_in_refs.
            out: List[Dict[str, Any]] = []
            for url in ref_info.get("exploit_refs", []):
                q = "high" if "exploit-db.com" in url.lower() else "medium"
                out.append({
                    "source": "nvd_ref", "url": url, "quality": q,
                    "evidence_type": "exploit", "trust": "curated",
                    "extra": {"source_tag": "nvd"},
                })
            return out, SOURCE_OK

        def _fetch_poc_in_github() -> Tuple[List[Dict[str, Any]], str]:
            repos, status = self.hunter.poc_searcher.search(cve_id, max_results=self.max_pocs)
            out: List[Dict[str, Any]] = []
            for r in repos:
                q = _score_github_poc(r)
                provenance = r.get("provenance", "curated")
                trust = "curated" if provenance == "curated" else "mention"
                extra = {
                    "name": r.get("name", ""),
                    "stars": r.get("stars", 0),
                    "description": r.get("description", ""),
                    "updated": r.get("updated", ""),
                    "language": r.get("language", ""),
                    "provenance": provenance,
                }
                if r.get("extra"):
                    extra.update(r["extra"])
                out.append({
                    "source": "github", "url": r.get("url", ""), "quality": q,
                    "evidence_type": "poc", "trust": trust, "extra": extra,
                })
            return out, status

        def _fetch_trickest() -> Tuple[List[Dict[str, Any]], str]:
            repos, status = self.hunter.trickest_searcher.search(cve_id, max_results=self.max_pocs)
            out: List[Dict[str, Any]] = []
            for r in repos:
                q = _score_github_poc(r)
                out.append({
                    "source": "trickest", "url": r.get("url", ""), "quality": q,
                    "evidence_type": "poc", "trust": "curated",
                    "extra": {"name": r.get("name", ""), "stars": r.get("stars", 0),
                              "description": r.get("description", ""),
                              "provenance": "curated"},
                })
            return out, status

        def _fetch_nuclei() -> Tuple[List[Dict[str, Any]], str]:
            has, status = self.hunter.nuclei_searcher.search(cve_id)
            if not has:
                return [], status
            return [{
                "source": "nuclei",
                "url": f"nuclei-template:{cve_id}",
                "quality": "medium",
                "evidence_type": "poc",
                "trust": "curated",
                "extra": {"template": True},
            }], status

        def _fetch_searchsploit() -> Tuple[List[Dict[str, Any]], str]:
            if not search_local:
                return [], SOURCE_SKIPPED
            entries, status = self.hunter.searchsploit.search(cve_id, max_results=self.max_pocs)
            out: List[Dict[str, Any]] = []
            for e in entries:
                q = _score_exploitdb_entry(e)
                url = f"https://www.exploit-db.com/exploits/{e.get('id','')}"
                out.append({
                    "source": "exploitdb", "url": url, "quality": q,
                    "evidence_type": "exploit", "trust": "curated",
                    "extra": {"id": e.get("id"), "title": e.get("title", ""),
                              "path": e.get("path", ""), "type": e.get("type", ""),
                              "platform": e.get("platform", ""),
                              "verified": e.get("verified", False)},
                })
            return out, status

        def _fetch_msf() -> Tuple[List[Dict[str, Any]], str]:
            if not use_msf or self.hunter.msf_searcher is None:
                return [], SOURCE_SKIPPED
            mods, status = self.hunter.msf_searcher.search(cve_id, max_results=self.max_pocs)
            out: List[Dict[str, Any]] = []
            for m in mods:
                q = _score_msf_module(m)
                out.append({
                    "source": "msf", "url": m.get("module", ""), "quality": q,
                    "evidence_type": "module", "trust": "curated",
                    "extra": {"module": m.get("module", ""),
                              "rank": m.get("rank", ""),
                              "disclosure": m.get("disclosure", "")},
                })
            return out, status

        def _fetch_osv() -> Tuple[List[Dict[str, Any]], str]:
            if self.hunter.osv_client is None:
                return [], SOURCE_SKIPPED
            refs, _sev, status = self.hunter.osv_client.fetch(cve_id)
            out: List[Dict[str, Any]] = []
            for r in refs:
                url = r.get("url", "")
                if not url: continue
                # Skip pure advisory hosts — we already surface those via NVD.
                # Surface only PoC/exploit-tier OSV refs.
                if r.get("evidence_type") not in ("poc", "exploit"):
                    continue
                out.append({
                    "source": "osv", "url": url, "quality": "medium",
                    "evidence_type": r.get("evidence_type", "poc"),
                    "trust": r.get("trust", "curated"),
                    "extra": {"osv_type": r.get("type", ""),
                              "evidence_type": r.get("evidence_type", "poc"),
                              "provenance": "osv"},
                })
            return out, status

        def _fetch_ghsa() -> Tuple[List[Dict[str, Any]], str]:
            if self.hunter.ghsa_client is None:
                return [], SOURCE_SKIPPED
            advisories, status = self.hunter.ghsa_client.fetch(cve_id)
            out: List[Dict[str, Any]] = []
            for a in advisories:
                # Surface PoC/exploit-tier refs from each advisory.
                for r in a.get("refs", []):
                    if r.get("evidence_type") not in ("poc", "exploit"):
                        continue
                    url = r.get("url", "")
                    if not url: continue
                    out.append({
                        "source": "ghsa", "url": url, "quality": "medium",
                        "evidence_type": r.get("evidence_type", "poc"),
                        "trust": r.get("trust", "curated"),
                        "extra": {"ghsa_id": a.get("ghsa_id", ""),
                                  "summary": a.get("summary", ""),
                                  "url": url,
                                  "provenance": "ghsa"},
                    })
            return out, status

        def _fetch_vulners() -> Tuple[List[Dict[str, Any]], str]:
            if self.hunter.vulners_client is None:
                return [], SOURCE_SKIPPED
            bulletins, status = self.hunter.vulners_client.fetch(cve_id)
            out: List[Dict[str, Any]] = []
            for b in bulletins:
                href = b.get("href", "")
                if not href: continue
                out.append({
                    "source": "vulners", "url": href, "quality": "medium",
                    "evidence_type": b.get("evidence_type", "reference"),
                    "trust": b.get("trust", "mention"),
                    "extra": {"id": b.get("id", ""), "title": b.get("title", ""),
                              "type": b.get("type", ""), "url": href,
                              "provenance": "vulners"},
                })
            return out, status

        # Map source key → (callable, label)
        source_specs = [
            ("nvd_ref",      _fetch_nvd_refs,    "nvd_ref"),
            ("poc_in_github", _fetch_poc_in_github, "poc_in_github"),
            ("trickest",     _fetch_trickest,    "trickest"),
            ("nuclei",       _fetch_nuclei,      "nuclei"),
            ("searchsploit", _fetch_searchsploit, "searchsploit"),
            ("msf",          _fetch_msf,         "msf"),
            ("osv",          _fetch_osv,         "osv"),
            ("ghsa",         _fetch_ghsa,        "ghsa"),
            ("vulners",      _fetch_vulners,     "vulners"),
        ]

        # ---- Run all sources concurrently ----
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_key = {
                pool.submit(fn): key for (key, fn, _label) in source_specs
            }
            for fut in as_completed(future_to_key):
                key = future_to_key[fut]
                try:
                    candidates, status = fut.result()
                except Exception as exc:
                    candidates, status = [], SOURCE_ERROR
                sources_status[key] = status
                raw_candidates.extend(candidates)

        # ---- Dedup + merge ----
        # Key by normalized URL; for GitHub URLs, also key by owner/repo so
        # the same repo surfaced via different URLs collapses to one entry.
        # Track "also seen in" set per dedup key.
        deduped: Dict[str, Dict[str, Any]] = {}
        for c in raw_candidates:
            url = c.get("url", "")
            if not url: continue
            norm = _normalize_url(url)
            if not norm: continue
            # Try repo-level collapsing for GitHub
            gh_key = _github_owner_repo(url)
            dedup_key = f"gh:{gh_key}" if gh_key else norm
            existing = deduped.get(dedup_key)
            if existing is None:
                c["also_seen_in"] = {c["source"]}
                c["dedup_key"] = dedup_key
                deduped[dedup_key] = c
            else:
                # Merge: keep highest-trust source; add to also_seen_in.
                existing_trust = existing.get("trust", "mention")
                new_trust = c.get("trust", "mention")
                if (new_trust == "curated" and existing_trust != "curated") or \
                   (new_trust == existing_trust and
                    c.get("source") in ("exploitdb", "msf", "vulners")):
                    # Newcomer wins on trust, or same tier but exploit-family source.
                    c["also_seen_in"] = existing["also_seen_in"] | {c["source"]}
                    c["dedup_key"] = dedup_key
                    deduped[dedup_key] = c
                else:
                    existing["also_seen_in"].add(c["source"])

        # ---- Compute display tier per lead, then sort ----
        for c in deduped.values():
            c["tier"] = _classify_lead_tier(
                c["source"], c.get("trust", "mention"),
                c.get("extra", {}), cisa_kev=kev_entry,
            )

        # Sort: VERIFIED > CURATED > CANDIDATE; within tier, by stars descending.
        def _sort_key(c: Dict[str, Any]) -> Tuple[int, int]:
            tier_rank = _TIER_RANK.get(c.get("tier", TIER_NONE), 0)
            stars = int((c.get("extra") or {}).get("stars", 0) or 0)
            return (-tier_rank, -stars)

        ranked = sorted(deduped.values(), key=_sort_key)

        # ---- Convert to ExploitEvidence objects ----
        # Keep all candidates (no max cap here — the presentation layer applies --max-pocs).
        leads: List[ExploitEvidence] = []
        seen_keys: set = set()
        for c in ranked:
            url = c.get("url", "")
            norm = _normalize_url(url) if url else ""
            if norm and norm in seen_keys:
                continue
            if norm:
                seen_keys.add(norm)
            extra = dict(c.get("extra") or {})
            extra["also_seen_in"] = sorted(c.get("also_seen_in", set()))
            extra["tier"] = c.get("tier", TIER_NONE)
            leads.append(ExploitEvidence(
                source=c["source"], url=url, quality=c.get("quality", "low"),
                evidence_type=c.get("evidence_type", "reference"),
                extra=extra,
                trust=c.get("trust", "mention"),
            ))

        return leads, sources_status


# ════════════════════════════════════════════════════════════════════════════
# Core Scanner
# ════════════════════════════════════════════════════════════════════════════
class CVEHunter:
    """Coordinates per-source enrichment for a single CVE or batch.

    Phase 2 changes:
      - ``scan()`` and ``search()`` return ``CVERecord`` instances (not dicts).
      - CVSS: captures all metric blocks (V40/V31/V30/V2) and picks
        ``cvss_selected`` per the policy: prefer Primary; if a non-primary
        source carries a higher CVSS version, use the higher version.
      - CWE: captures provenance (Primary vs Secondary) and passes it to
        ``classify()`` for confidence scoring.
      - vuln_status "Awaiting/Undergoing Analysis" → ``provisional=True``,
        which forces classification confidence to "low".
      - Exploit maturity: builds a deduplicated ``exploit_evidence`` list and
        runs ``decide_exploit_maturity()``.
      - Risk: dimensional model (likelihood × impact × accessibility ×
        confidence_factor), computed by ``compute_risk_score()``.
    """

    # ---- Phase 2 task 2: CVSS selection policy ----
    @staticmethod
    def _select_cvss(cvss_all: List[Dict[str, Any]]) -> Tuple[Optional[CVSSRecord], bool]:
        """Pick the best CVSS record per the Phase 2 policy.

        Policy:
          1. Among Primary entries, pick the one with the highest version.
          2. If a non-Primary (Secondary/Adp) entry has a strictly higher
             version than the best Primary, use the higher-version one.
          3. cvss_source_disagreement = True when Primary and non-Primary
             entries disagree on score (delta > 0.1) for the same version.

        Returns (selected_cvss_record_or_None, disagreement_bool).
        """
        if not cvss_all:
            return None, False
        # Build CVSSRecord objects
        records = [CVSSRecord(
            version=str(c.get("version", "")),
            score=float(c.get("score", 0.0) or 0.0),
            severity=str(c.get("severity", "")),
            vector=str(c.get("vector", "")),
            exploitability=c.get("exploitability"),
            impact=c.get("impact"),
            source_type=str(c.get("source_type", "")),
        ) for c in cvss_all]

        # Version ranking: 4.0 > 3.1 > 3.0 > 2.0
        version_rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
        def v_rank(r: CVSSRecord) -> int:
            return version_rank.get(r.version, 0)

        primary = [r for r in records if r.source_type == "Primary"]
        non_primary = [r for r in records if r.source_type != "Primary"]

        # Step 1: best Primary by version (then by highest score as tiebreaker)
        def sort_key(r: CVSSRecord) -> Tuple[int, float]:
            """Sort key: (version_rank, score) — higher version wins, then higher score."""
            return (version_rank.get(r.version, 0), r.score)

        best_primary = max(primary, key=sort_key) if primary else None

        # Step 2: if a non-primary has strictly higher version, use it.
        # FIX (CRITICAL — audit finding): when multiple non-Primary entries
        # share the same version (e.g. CVE-2020-1472 has TWO v3.1 Secondary
        # entries: score=5.5 and score=10.0), the old code used
        # max(non_primary, key=v_rank) which returned the FIRST one (5.5)
        # instead of the highest-scoring one (10.0). This caused Zerologon
        # to appear as Risk=35/100 (LOW) instead of ~98/100 (CRITICAL) —
        # a false PARK IT on a KEV+CVSS-10 vulnerability.
        # Fix: use (version_rank, score) as the sort key so the highest-
        # scoring entry wins among same-version entries.
        selected = best_primary
        if non_primary:
            best_non_primary = max(non_primary, key=sort_key)
            if best_primary is None or v_rank(best_non_primary) > v_rank(best_primary):
                selected = best_non_primary

        # Step 3: disagreement detection (Primary vs non-Primary, same version)
        disagreement = False
        if best_primary and non_primary:
            for r in non_primary:
                if r.version == best_primary.version and \
                        abs(r.score - best_primary.score) > 0.1:
                    disagreement = True
                    break

        return selected, disagreement

    # ---- Phase 2 task 6: build deduplicated exploit_evidence ----
    @staticmethod
    def _build_exploit_evidence(
        cve_id: str,
        ref_info: Dict[str, Any],
        github_pocs: List[Dict[str, Any]],
        searchsploit_results: List[Dict[str, Any]],
        msf_results: List[Dict[str, Any]],
        msf_available: bool,
        ss_available: bool,
    ) -> List[ExploitEvidence]:
        """Build a deduplicated, quality-scored exploit_evidence list.

        Dedup key: (cve_id, normalized_url). The same exploit mirrored on
        ExploitDB + GitHub + PacketStorm is counted once.
        """
        evidence: List[ExploitEvidence] = []
        seen: set = set()

        def _add(source: str, url: str, quality: str,
                 evidence_type: str, extra: Dict[str, Any],
                 trust: str = "curated") -> None:
            if not url: return
            norm = _normalize_url(url)
            key = (cve_id.upper(), norm)
            if key in seen: return
            seen.add(key)
            evidence.append(ExploitEvidence(
                source=source, url=url, quality=quality,
                evidence_type=evidence_type, extra=extra, trust=trust,
            ))

        # NVD references classified as exploits
        for url in ref_info.get("exploit_refs", []):
            # NVD ref quality: high if exploit-db (verified-ish), else medium
            q = "high" if "exploit-db.com" in url.lower() else "medium"
            _add("nvd_ref", url, q, "exploit", {"source_tag": "nvd"}, trust="curated")

        # GitHub PoCs — drop excluded repos, wire provenance → trust
        for repo in github_pocs:
            if _poc_is_excluded(repo):
                continue
            q = _score_github_poc(repo)
            provenance = repo.get("provenance", "curated")
            trust = "curated" if provenance == "curated" else "mention"
            _add("github", repo.get("url", ""), q, "poc",
                 {"name": repo.get("name", ""), "stars": repo.get("stars", 0),
                  "description": repo.get("description", ""),
                  "updated": repo.get("updated", ""),
                  "language": repo.get("language", ""),
                  "provenance": provenance},
                 trust=trust)

        # ExploitDB (searchsploit local)
        for entry in searchsploit_results:
            q = _score_exploitdb_entry(entry)
            url = f"https://www.exploit-db.com/exploits/{entry.get('id','')}"
            _add("exploitdb", url, q, "exploit",
                 {"id": entry.get("id"), "title": entry.get("title", ""),
                  "path": entry.get("path", ""), "type": entry.get("type", ""),
                  "platform": entry.get("platform", ""),
                  "verified": entry.get("verified", False)})

        # MSF modules (only if --use-msf and results present)
        for mod in msf_results:
            q = _score_msf_module(mod)
            _add("msf", mod.get("module", ""), q, "module",
                 {"module": mod.get("module", ""),
                  "rank": mod.get("rank", ""),
                  "disclosure": mod.get("disclosure", "")})

        # Availability markers (so render code can show "available but 0 hits")
        if ss_available and not searchsploit_results:
            evidence.append(ExploitEvidence(
                source="exploitdb", url="", quality="low",
                evidence_type="advisory", extra={"_searchsploit_available": True}))
        if msf_available and not msf_results:
            evidence.append(ExploitEvidence(
                source="msf", url="", quality="low",
                evidence_type="advisory", extra={"_msf_available": True}))

        return evidence

    def __init__(self, settings: Settings,
                 debug: Optional[DebugLog] = None,
                 use_msf: bool = False,
                 offline: bool = False) -> None:
        self.s = settings
        self.cache = Cache(settings.cache_dir, settings.cache_ttl_hours)
        self.debug = debug
        self.offline = offline

        # Offline mode: force MSF off, use offline NVDClient
        if offline:
            use_msf = False

        self.nvd = NVDClient(settings, self.cache, offline=offline)

        # Network sources — skipped in offline mode.
        # Note: ExploitSearcher (raw GitHub search) was replaced by
        # PoCInGitHubSearcher in Phase 3. It is kept as a class but no
        # longer instantiated — the curated PoC-in-GitHub index is strictly
        # better (less noise, supports local mirror).
        if not offline:
            self.epss = EPSSClient(settings, self.cache, debug=debug)
            self.kev_checker = CISAKEVChecker(settings, self.cache, debug=debug)
            self.vulncheck_kev = VulnCheckKEVChecker(
                self.cache, debug=debug,
                api_key=settings.vulncheck_api_key, offline=False)
        else:
            self.epss = None
            self.kev_checker = None
            self.vulncheck_kev = None

        # Phase 3: curated PoC sources (local mirror works offline)
        self.poc_searcher = PoCInGitHubSearcher(
            self.cache, debug=debug,
            local_path=settings.poc_in_github_path, offline=offline,
            github_token=settings.github_token)
        self.trickest_searcher = TrickestCVESearcher(
            self.cache, debug=debug, local_path=settings.trickest_path)
        self.nuclei_searcher = NucleiTemplateSearcher(
            self.cache, debug=debug, local_path=settings.nuclei_path)

        # Phase 4: new always-on discovery sources (OSV, GHSA) + optional
        # Vulners (key-gated). All degrade cleanly under SOURCE_SKIPPED /
        # SOURCE_NO_KEY / SOURCE_NEEDS_TOKEN.
        if not offline:
            self.osv_client = OSVClient(self.cache, debug=debug, offline=False)
            self.ghsa_client = GitHubAdvisoryClient(
                self.cache, debug=debug, offline=False,
                github_token=settings.github_token)
            self.vulners_client = VulnersClient(
                self.cache, debug=debug, offline=False,
                api_key=settings.vulners_api_key)
            self.shodan_client = ShodanClient(
                self.cache, debug=debug, offline=False,
                api_key=settings.shodan_api_key)
            self.greynoise_client = GreyNoiseClient(
                self.cache, debug=debug, offline=False,
                api_key=settings.greynoise_api_key)
        else:
            self.osv_client = None
            self.ghsa_client = None
            self.vulners_client = None
            self.shodan_client = None
            self.greynoise_client = None

        # searchsploit always works (local on Kali)
        self.searchsploit = SearchsploitSearcher(self.cache, debug=debug)

        # OPT-IN: only instantiate MSFModuleSearcher if explicitly requested.
        self.msf_searcher: Optional[MSFModuleSearcher] = (
            MSFModuleSearcher(self.cache, debug=debug) if use_msf else None
        )
        self._use_msf = use_msf

        # Phase 4: shared discovery engine — used by scan, batch, search --deep.
        self.discovery = DiscoveryEngine(
            self, max_workers=settings.discovery_workers,
            max_pocs=settings.max_pocs_default)

    def scan(self, cve_id: str, *, search_github: bool = True,
             search_local: bool = True, check_kev: bool = True) -> Optional[CVERecord]:
        """Enrich a single CVE. Returns None if NVD doesn't recognize it.

        Phase 4: ``scan`` is now a thin wrapper around ``enrich_one`` — the
        unified enrichment core shared by ``scan``, ``batch``, and
        ``search --deep``. Always runs in deep mode (full multi-source
        discovery engine).
        """
        rec = self.nvd.get_cve(cve_id)
        if rec is None: return None
        return self.enrich_one(
            rec, deep=True, use_msf=self._use_msf,
            search_local=search_local, check_kev=check_kev,
            search_github=search_github,
        )

    def enrich_one(self, base: Dict[str, Any], *, deep: bool,
                   use_msf: bool = False,
                   search_local: bool = True,
                   check_kev: bool = True,
                   search_github: bool = True) -> CVERecord:
        """Unified enrichment core — shared by scan, batch, and search --deep.

        Always computes: CVSS selection, CWE classification, version ranges,
        EPSS, KEV (when enabled), CISA KEV + VulnCheck KEV.

        When ``deep=True``: ALSO runs the full multi-source discovery engine
        (PoC-in-GitHub, trickest, nuclei, searchsploit, optional MSF, OSV,
        GHSA, Vulners, NVD exploit refs), builds ``exploit_evidence``, decides
        maturity, computes risk.

        When ``deep=False`` (fast listing mode): skips PoC discovery entirely.
        ``exploit_evidence=[]``, maturity from EPSS/KEV only. Risk is still
        computed sensibly — never floored to 0 just because discovery was
        skipped (PART B2 of the brief).
        """
        cve_id = (base.get("cve_id") or "").upper()

        # ---- Always-on enrichment (CVSS, CWE, version ranges, EPSS, KEV) ----
        vuln_status = base.get("vuln_status", "")
        provisional = vuln_status in ("Awaiting Analysis", "Undergoing Analysis",
                                      "Awaiting Vendor Analysis")

        cvss_all_raw = base.get("cvss_all", [])
        cvss_selected, cvss_disagreement = self._select_cvss(cvss_all_raw)

        cwe_entries_raw = base.get("cwe_entries", [])
        cwe_entries: List[CWEEntry] = [
            CWEEntry(cwe_id=ce["cwe_id"], source_type=ce.get("source_type", ""))
            for ce in cwe_entries_raw
        ]
        cls = classify(
            cwes=[ce.cwe_id for ce in cwe_entries],
            description=base.get("description", ""),
            cwe_entries=cwe_entries_raw,
            provisional=provisional,
        )

        ref_info = detect_exploit_in_refs(base.get("references", []))
        version_ranges = base.get("version_ranges", [])
        patches = extract_patch_versions(version_ranges)

        # ---- EPSS ----
        if self.epss is not None:
            epss_data, epss_status = self.epss.get(cve_id)
        else:
            epss_data, epss_status = None, SOURCE_SKIPPED

        # ---- CISA KEV + VulnCheck KEV ----
        if self.kev_checker is not None and check_kev:
            kev, kev_status = self.kev_checker.check(cve_id)
        else:
            kev, kev_status = None, SOURCE_SKIPPED

        if self.vulncheck_kev is not None:
            vc_kev, vc_kev_status = self.vulncheck_kev.check(cve_id)
            if vc_kev and not kev:
                kev = vc_kev
        else:
            vc_kev, vc_kev_status = None, SOURCE_SKIPPED

        # ---- Shodan (internet exposure count) ----
        if self.shodan_client is not None:
            shodan_data, shodan_status = self.shodan_client.check(cve_id)
        else:
            shodan_data, shodan_status = None, SOURCE_SKIPPED

        # ---- GreyNoise (active exploitation status) ----
        if self.greynoise_client is not None:
            greynoise_data, greynoise_status = self.greynoise_client.check(cve_id)
        else:
            greynoise_data, greynoise_status = None, SOURCE_SKIPPED

        # ---- Deep mode: full discovery engine ----
        if deep:
            # The DiscoveryEngine runs all sources concurrently via a thread
            # pool and returns a deduplicated, ranked ExploitEvidence list.
            leads, disc_status = self.discovery.discover(
                cve_id, ref_info=ref_info, kev_entry=kev,
                use_msf=use_msf, search_local=search_local,
            )
            # Merge discovery source statuses with the always-on statuses.
            sources_status: Dict[str, str] = {
                "nvd": SOURCE_OK,
                "epss": epss_status,
                "cisa_kev": kev_status,
                "vulncheck_kev": vc_kev_status,
                "shodan": shodan_status,
                "greynoise": greynoise_status,
            }
            sources_status.update(disc_status)

            exploit_evidence = leads
            nuclei_has = any(e.source == "nuclei" for e in leads)
            # Detect explicit availability markers for searchsploit/MSF when
            # the tool ran but found nothing.
            ss_available = self.searchsploit.available
            msf_available = self.msf_searcher.available if self.msf_searcher else False
            if ss_available and not any(e.source == "exploitdb" for e in leads):
                exploit_evidence.append(ExploitEvidence(
                    source="exploitdb", url="", quality="low",
                    evidence_type="advisory", extra={"_searchsploit_available": True}))
            if msf_available and not any(e.source == "msf" for e in leads):
                exploit_evidence.append(ExploitEvidence(
                    source="msf", url="", quality="low",
                    evidence_type="advisory", extra={"_msf_available": True}))
        else:
            # Fast listing mode — no discovery, no PoC evidence.
            sources_status = {
                "nvd": SOURCE_OK,
                "epss": epss_status,
                "cisa_kev": kev_status,
                "vulncheck_kev": vc_kev_status,
                "poc_in_github": SOURCE_SKIPPED,
                "trickest": SOURCE_SKIPPED,
                "nuclei": SOURCE_SKIPPED,
                "searchsploit": SOURCE_SKIPPED,
                "msf": SOURCE_SKIPPED,
                "osv": SOURCE_SKIPPED,
                "ghsa": SOURCE_SKIPPED,
                "vulners": SOURCE_SKIPPED,
                "nvd_ref": SOURCE_SKIPPED,
            }
            exploit_evidence: List[ExploitEvidence] = []
            nuclei_has = False

        # ---- Decide maturity + evidence_incomplete ----
        epss_val = float((epss_data or {}).get("epss", 0.0) or 0.0)
        maturity, evidence_incomplete = decide_exploit_maturity(
            cisa_kev=kev,
            exploit_evidence=exploit_evidence,
            epss_value=epss_val,
            sources_status=sources_status,
            msf_enabled=use_msf,
            deep_mode=deep,  # PART B2: deep=False never floors to 0
        )

        # ---- CAPEC → ATT&CK ----
        capec_attack = get_capec_attack_mapping([ce.cwe_id for ce in cwe_entries])

        # ---- Build the typed CVERecord ----
        vector = cvss_selected.vector if cvss_selected else ""
        record = CVERecord(
            cve_id=base["cve_id"],
            description=base.get("description", ""),
            cvss_all=[CVSSRecord(
                version=str(c.get("version", "")),
                score=float(c.get("score", 0.0) or 0.0),
                severity=str(c.get("severity", "")),
                vector=str(c.get("vector", "")),
                exploitability=c.get("exploitability"),
                impact=c.get("impact"),
                source_type=str(c.get("source_type", "")),
            ) for c in cvss_all_raw],
            cvss_selected=cvss_selected,
            cvss_source_disagreement=cvss_disagreement,
            cwes=cwe_entries,
            references=base.get("references", []),
            cpes=base.get("cpes", []),
            version_ranges=version_ranges,
            patch_versions=patches,
            published=base.get("published", ""),
            modified=base.get("modified", ""),
            vuln_status=vuln_status,
            provisional=provisional,
            epss=epss_data,
            classification=cls,
            remote_exploitable=is_remote_exploitable(cls.primary, vector),
            vector_category_conflict=detect_vector_category_conflict(cls.primary, vector),
            exploit_evidence=exploit_evidence,
            exploit_maturity=maturity,
            evidence_incomplete=evidence_incomplete,
            cisa_kev=kev,
            sources_status=sources_status,
            capec_attack=capec_attack,
            vulncheck_kev=vc_kev,
            nuclei_template=nuclei_has,
            shodan_exposure=shodan_data,
            greynoise_activity=greynoise_data,
        )
        record.risk = compute_risk_score(record)
        return record

    def search(self, *, keyword: Optional[str] = None, cpe_name: Optional[str] = None,
               pub_start: Optional[str] = None, pub_end: Optional[str] = None,
               max_results: int = 50, enrich: bool = True,
               deep: bool = False, deep_limit: int = 25,
               max_pocs: int = 15) -> List[CVERecord]:
        """Search NVD by keyword/CPE.

        Phase 4 changes:
          - New ``deep`` flag: when True, runs the FULL discovery engine on
            each result via ``enrich_one(..., deep=True)``. Default False
            (fast EPSS+KEV listing stays the default).
          - ``deep_limit`` caps how many results get full discovery
            (highest-CVSS / KEV-first ordering). When results exceed
            deep_limit, only the top N are deep-enriched; the rest are
            shallow-enriched with a warning.
          - ``max_pocs`` overrides the per-CVE PoC display cap.

        ``enrich`` controls EPSS + KEV (always on by default for fast mode).
        ``deep`` controls the full discovery engine (off by default).
        """
        records = self.nvd.search(keyword=keyword, cpe_name=cpe_name,
                                  pub_start=pub_start, pub_end=pub_end,
                                  max_results=max_results)

        # When --deep is requested, sort by CVSS desc + KEV-first so the
        # deep_limit cap prioritizes the most exploitable CVEs.
        if deep and records and len(records) > deep_limit:
            def _deep_sort_key(r: Dict[str, Any]) -> Tuple[int, float]:
                # KEV-first (we don't have KEV yet at this point, so use CVSS)
                cvss_list = r.get("cvss_all", []) or []
                best_cvss = 0.0
                for c in cvss_list:
                    try:
                        s = float(c.get("score", 0.0) or 0.0)
                        if s > best_cvss: best_cvss = s
                    except (TypeError, ValueError):
                        pass
                return (-int(best_cvss), -best_cvss)
            records.sort(key=_deep_sort_key)

        # Bulk EPSS prefetch for fast mode (1 request per 100 CVEs).
        epss_map: Dict[str, Dict[str, Any]] = {}
        epss_status = SOURCE_SKIPPED
        if enrich and records and not deep:
            epss_map, epss_status = self.epss.bulk([r["cve_id"] for r in records])

        # If --deep, adjust the discovery engine's max_pocs for this run.
        original_max_pocs = self.discovery.max_pocs
        if deep:
            self.discovery.max_pocs = max_pocs

        results: List[CVERecord] = []
        try:
            for i, r in enumerate(records):
                if deep and i >= deep_limit:
                    # Past the deep_limit — shallow-enrich the rest.
                    shallow = self.enrich_one(r, deep=False, use_msf=False,
                                              search_local=False, check_kev=enrich)
                    results.append(shallow)
                else:
                    if deep:
                        # Deep-enrich: full discovery engine runs per-CVE.
                        rec = self.enrich_one(r, deep=True, use_msf=False,
                                              search_local=True, check_kev=enrich)
                    else:
                        # Fast listing mode — EPSS + KEV only, no discovery.
                        rec = self.enrich_one(r, deep=False, use_msf=False,
                                              search_local=False, check_kev=enrich)
                    results.append(rec)
        finally:
            self.discovery.max_pocs = original_max_pocs

        return results

    def clear_cache(self) -> int:
        return self.cache.clear()


# ════════════════════════════════════════════════════════════════════════════
# Output Formatting
# ════════════════════════════════════════════════════════════════════════════
console = Console()
err_console = Console(stderr=True)


def _fmt_cvss(score: float, severity: str) -> Text:
    c = severity_color(severity)
    return Text.assemble((f"{score:.1f} ", f"bold {c}"), (f"({severity})", c))


def _fmt_epss(epss_data) -> Text:
    if not epss_data:
        return Text("N/A", "dim")
    pct = epss_data["epss"] * 100
    pc = epss_data["percentile"] * 100
    c = ("bright_red" if pct >= 50 else "red" if pct >= 20
          else "yellow" if pct >= 5 else "green")
    return Text.assemble(
        (f"{pct:.2f}%", f"bold {c}"),
        (" exploit probability  |  ", "dim"),
        (f"percentile {pc:.2f}%", c),
    )


def _get_verdict_data(record) -> Dict[str, Any]:
    """Compute all attacker-mindset tags for a CVERecord."""
    if hasattr(record, "to_dict"):
        r = record
    else:
        r = record
    cvss_vector = r.cvss_vector if hasattr(r, "cvss_vector") else (r.get("cvss",{}) or {}).get("vector","")
    category = r.category if hasattr(r, "category") else r.get("category","Unknown")
    maturity = r.exploit_maturity if hasattr(r, "exploit_maturity") else ExploitMaturity.UNPROVEN
    risk_score = (r.risk.score if r.risk else 0) if hasattr(r, "risk") else (r.get("risk") or {}).get("score",0)
    kev = r.cisa_kev if hasattr(r, "cisa_kev") else r.get("cisa_kev")
    provisional = r.provisional if hasattr(r, "provisional") else r.get("provisional", False)
    evidence_incomplete = r.evidence_incomplete if hasattr(r, "evidence_incomplete") else r.get("evidence_incomplete", False)
    confidence = r.classification.confidence if hasattr(r, "classification") else (r.get("classification") or {}).get("confidence","low")

    reach = compute_reach(cvss_vector, category)
    outcome = compute_outcome(category)
    verdict = compute_verdict(reach, maturity, evidence_incomplete, provisional, risk_score)
    why = compute_why(reach, maturity, kev, provisional, evidence_incomplete, confidence)
    data_incomplete = provisional or evidence_incomplete
    return {
        "verdict": verdict, "reach": reach, "outcome": outcome,
        "maturity_label": MATURITY_LABELS.get(maturity, "UNKNOWN"),
        "maturity_color": MATURITY_COLORS.get(maturity, "white"),
        "verdict_label": VERDICT_LABELS[verdict],
        "verdict_color": VERDICT_COLORS[verdict],
        "why": why, "data_incomplete": data_incomplete,
        "risk_score": risk_score,
    }


def _format_pointers(record) -> str:
    """Format exploit pointers (IDs/URLs/module names) — NOT commands.

    Phase 4: priority is now tier-driven. VERIFIED leads first (ExploitDB,
    MSF, Vulners exploit-family), then CURATED (GitHub curated PoCs, OSV,
    GHSA, Nuclei, NVD exploit refs), then CANDIDATES (GitHub mentions).
    Within each tier, sort by stars descending.
    """
    parts = []
    if hasattr(record, "exploit_evidence"):
        # Filter to actionable leads (has URL, not just an availability marker).
        leads = [e for e in record.exploit_evidence
                 if e.evidence_type in ("exploit", "poc", "module")
                 and e.url
                 and not (e.extra.get("_searchsploit_available") or
                          e.extra.get("_msf_available"))]
        # Compute tier per lead (defensive — DiscoveryEngine sets it).
        for e in leads:
            if "tier" not in e.extra:
                e.extra["tier"] = _classify_lead_tier(
                    e.source, e.trust, e.extra, cisa_kev=record.cisa_kev)
        # Sort by tier rank (desc), then stars (desc).
        leads.sort(key=lambda e: (
            -_TIER_RANK.get(e.extra.get("tier", TIER_NONE), 0),
            -int(e.extra.get("stars", 0) or 0),
        ))
        for e in leads:
            if e.source == "exploitdb" and e.extra.get("id"):
                parts.append(f"ExploitDB: {e.extra['id']}")
            elif e.source == "msf" and e.extra.get("module"):
                parts.append(f"MSF: {e.extra['module']}")
            elif e.source == "github" and e.url:
                parts.append(f"PoC: {e.url}")
            elif e.source == "nvd_ref" and e.url:
                parts.append(f"Ref: {e.url}")
            elif e.source == "osv" and e.url:
                parts.append(f"OSV: {e.url}")
            elif e.source == "ghsa" and e.url:
                parts.append(f"GHSA: {e.url}")
            elif e.source == "vulners" and e.url:
                parts.append(f"Vulners: {e.url}")
            elif e.source == "trickest" and e.url:
                parts.append(f"trickest: {e.url}")
            elif e.source == "nuclei":
                parts.append("Nuclei: template exists")
    if parts:
        return "  |  ".join(parts[:5])

    # No pointers found — explain why based on maturity + sources
    maturity = getattr(record, "exploit_maturity", None)
    sources = getattr(record, "sources_status", {})

    # FIX (secondary-9): distinguish "failed" (source tried and errored) from
    # "unavailable/not installed" (source couldn't run). Previously both were
    # mixed into failed_sources and printed as "... failed", which was
    # misleading — searchsploit being absent is not a failure.
    failed_sources = []      # sources that tried but errored / got rate-limited
    unavailable_sources = []  # sources that couldn't run (not installed / no key)
    if sources.get("poc_in_github") in ("error", "ratelimited"):
        failed_sources.append("PoC-in-GitHub")
    if sources.get("searchsploit") == "error":
        failed_sources.append("searchsploit")
    elif sources.get("searchsploit") == "unavailable":
        unavailable_sources.append("searchsploit (not installed)")
    if sources.get("cisa_kev") in ("error", "ratelimited"):
        failed_sources.append("CISA KEV")
    # Build a combined "why no pointers" suffix.
    notes = []
    if failed_sources:
        notes.append(f"{', '.join(failed_sources)} failed")
    if unavailable_sources:
        notes.append(f"{', '.join(unavailable_sources)} unavailable")
    note_str = "; ".join(notes)

    if maturity and maturity.value == "in_the_wild":
        if note_str:
            return f"(no public PoC found — {note_str}; " \
                   f"KEV indicates private/active exploitation — search manually)"
        return "(no public PoC — KEV indicates private exploitation — search manually)"
    elif maturity and maturity.value == "functional":
        if note_str:
            return f"(no pointers — {note_str} — search manually)"
        return "(no public exploit found — search manually)"
    elif note_str:
        return f"(no pointers — {note_str})"
    return "(no exploit pointers)"


def _print_single(result, verbose: bool = False,
                  exploit_mode: bool = False, report_mode: bool = False) -> None:
    """Phase 4: Attacker card with verdict, reach, maturity, outcome.

    Progressive disclosure:
      default  = decision card (verdict + tags + why)
      --exploit = + version-match result + exploit pointers
      --report  = + references + remediation + CAPEC/ATT&CK + risk breakdown
      --verbose = + CVSS vector decoded + all references (legacy compat)
    """
    vd = _get_verdict_data(result)

    # ---- Verdict header ----
    header = Text.assemble(
        (f"{result.cve_id}  ", "bold white"),
        ("·  ", "dim"),
        (vd["verdict_label"], f"bold {vd['verdict_color']}"),
    )
    # Data-honesty badge
    if vd["data_incomplete"]:
        header.append("  ⚠ DATA INCOMPLETE", "bold red")
    console.print(Panel(header, border_style=vd["verdict_color"], padding=(0, 2)))

    # ---- Compact card ----
    card = Table.grid(padding=(0, 2))
    card.add_column(justify="right", style="dim", no_wrap=True)
    card.add_column()
    card.add_row("Reach",
                 Text(vd["reach"], style=f"bold {vd['verdict_color']}"))
    card.add_row("Exploit",
                 Text(vd["maturity_label"], style=f"bold {vd['maturity_color']}"))
    card.add_row("Gives",
                 Text(f"{result.classification.subcategory} ({vd['outcome']})", "white"))
    # Affects (abbreviated)
    vr = result.version_ranges[:3] if result.version_ranges else []
    if vr:
        affects_parts = []
        for v in vr[:3]:
            p = v.get("human", v.get("cpe", ""))
            affects_parts.append(p)
        affects_str = ", ".join(affects_parts)
        if len(result.version_ranges) > 3:
            affects_str += f" (+{len(result.version_ranges)-3} more)"
        card.add_row("Affects", truncate(affects_str, 80))
    else:
        card.add_row("Affects", "—")
    # Risk score (compact)
    card.add_row("Risk",
                 Text(f"{vd['risk_score']}/100", style=f"bold {risk_color(vd['risk_score'])}"))
    # Pointers (NOT commands)
    pointers = _format_pointers(result)
    card.add_row("Next", Text(pointers, "cyan"))
    # Why
    card.add_row("why", Text(vd["why"], "dim"))
    console.print(card)

    # ---- CISA KEV banner ----
    if result.cisa_kev:
        kev = result.cisa_kev
        kev_text = Text.assemble(
            ("⚠  CISA KEV — ACTIVELY EXPLOITED\n", "bold bright_red"),
            (f"  Vendor/Product: {kev.get('vendor','')} / {kev.get('product','')}\n", "white"),
            (f"  Date Added: {kev.get('date_added','')}  |  Due: {kev.get('due_date','')}\n", "dim"),
            (f"  Ransomware: {kev.get('known_ransomware_use','')}", "bright_red"),
        )
        console.print(Panel(kev_text, border_style="bright_red"))

    # ---- Shodan exposure banner ----
    if result.shodan_exposure:
        count = result.shodan_exposure.get("exposed_count", 0)
        if count > 0:
            exposure_color = "bright_red" if count > 1000 else ("yellow" if count > 10 else "green")
            exposure_text = Text.assemble(
                ("🌐  SHODAN — INTERNET EXPOSURE\n", f"bold {exposure_color}"),
                (f"  Devices exposed: {count:,}\n", "white"),
                (f"  Query: {result.shodan_exposure.get('query', '')}\n", "dim"),
                (f"  → https://www.shodan.io/search?query={result.shodan_exposure.get('query', '')}",
                 f"link {exposure_color}"),
            )
            console.print(Panel(exposure_text, border_style=exposure_color))

    # ---- GreyNoise activity banner ----
    if result.greynoise_activity:
        noise = result.greynoise_activity.get("noise", False)
        last_seen = result.greynoise_activity.get("last_seen", "")
        msg = result.greynoise_activity.get("message", "")
        if noise:
            gn_text = Text.assemble(
                ("📡  GREYNOISE — ACTIVELY SCANNED NOW\n", "bold bright_red"),
                (f"  Status: {msg}\n", "white"),
                (f"  Last seen: {last_seen}\n", "dim"),
                (f"  → {result.greynoise_activity.get('link', 'https://viz.greynoise.io')}",
                 "link bright_red"),
            )
            console.print(Panel(gn_text, border_style="bright_red"))
        elif result.greynoise_activity.get("message") != "no activity detected":
            gn_text = Text.assemble(
                ("📡  GREYNOISE — NO ACTIVE SCANNING DETECTED\n", "bold green"),
                (f"  {msg}", "dim"),
            )
            console.print(Panel(gn_text, border_style="green"))

    # ---- Vector/category conflict warning ----
    if result.vector_category_conflict:
        console.print(Panel(
            Text(result.vector_category_conflict, "bold yellow"),
            title="[bold yellow]⚠ Vector/Category Conflict[/bold yellow]",
            border_style="yellow",
        ))

    # ---- --exploit mode: version-match + detailed pointers ----
    # Phase 4 fix: --report auto-includes --exploit content.
    if exploit_mode or report_mode or verbose:
        # Version ranges
        meaningful = [v for v in result.version_ranges
                      if v.get("version_start_including") or v.get("version_start_excluding")
                      or v.get("version_end_including") or v.get("version_end_excluding")]
        if meaningful:
            ct = Table(title="[bold]Affected Versions[/bold]",
                       show_lines=False, header_style="bold magenta")
            ct.add_column("#", style="dim", justify="right")
            ct.add_column("Product", overflow="fold")
            ct.add_column("Range", overflow="fold")
            for i, v in enumerate(meaningful[:15], 1):
                rp = []
                if v.get("version_start_including"): rp.append(f">= {v['version_start_including']}")
                if v.get("version_start_excluding"): rp.append(f"> {v['version_start_excluding']}")
                if v.get("version_end_including"): rp.append(f"<= {v['version_end_including']}")
                if v.get("version_end_excluding"): rp.append(f"< {v['version_end_excluding']}")
                ct.add_row(str(i), v.get("human", v.get("cpe", "")), " ".join(rp))
            console.print(ct)
        # ---- Phase 4 PART D1: PoC / Exploit Intelligence section ----
        # Ranked, clickable, grouped by display tier (VERIFIED → CURATED →
        # CANDIDATES). Each lead shows source, key metadata (stars/lang/
        # recency), the "also seen in" set, and the direct URL.
        # CANDIDATES labeled "unverified — review before use" but PROMINENT.
        if result.exploit_evidence:
            # Filter to actionable leads (exploit/poc/module; has URL).
            leads = [e for e in result.exploit_evidence
                     if e.evidence_type in ("exploit", "poc", "module")
                     and e.url
                     and not (e.extra.get("_searchsploit_available") or
                              e.extra.get("_msf_available"))]
            # Compute tier per lead (already set by DiscoveryEngine, but
            # recompute defensively for legacy records).
            for e in leads:
                if "tier" not in e.extra:
                    e.extra["tier"] = _classify_lead_tier(
                        e.source, e.trust, e.extra, cisa_kev=result.cisa_kev)

            verified = [e for e in leads if e.extra.get("tier") == TIER_VERIFIED]
            curated  = [e for e in leads if e.extra.get("tier") == TIER_CURATED]
            candidates = [e for e in leads if e.extra.get("tier") == TIER_CANDIDATE]

            console.print()
            console.print("[bold red]═══ PoC / Exploit Intelligence ═══[/bold red]")

            def _render_lead_row(et: Table, e: ExploitEvidence) -> None:
                """Add one lead to a tier table."""
                ptr = e.url
                meta_parts = []
                if e.source == "exploitdb" and e.extra.get("id"):
                    ptr = f"https://www.exploit-db.com/exploits/{e.extra['id']}"
                    if e.extra.get("verified"):
                        meta_parts.append("verified")
                    if e.extra.get("title"):
                        meta_parts.append(e.extra["title"][:40])
                elif e.source == "msf" and e.extra.get("module"):
                    ptr = e.extra["module"]
                    if e.extra.get("rank"):
                        meta_parts.append(f"rank:{e.extra['rank']}")
                elif e.source == "github":
                    stars = e.extra.get("stars", 0)
                    meta_parts.append(f"{stars}★")
                    if e.extra.get("language"):
                        meta_parts.append(e.extra["language"])
                    if e.extra.get("updated"):
                        # Recency check: push within POC_RECENT_DAYS = "recent"
                        try:
                            from datetime import datetime, timezone
                            updated = e.extra["updated"][:10]
                            d = datetime.fromisoformat(updated).replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            if (now - d).days <= POC_RECENT_DAYS:
                                meta_parts.append("recent")
                        except (ValueError, TypeError):
                            pass
                elif e.source == "nuclei":
                    ptr = f"nuclei-template:{result.cve_id}"
                    meta_parts.append("detection")
                elif e.source == "vulners":
                    if e.extra.get("type"):
                        meta_parts.append(e.extra["type"])
                elif e.source == "osv":
                    if e.extra.get("osv_type"):
                        meta_parts.append(f"osv:{e.extra['osv_type'].lower()}")
                elif e.source == "ghsa":
                    if e.extra.get("ghsa_id"):
                        meta_parts.append(e.extra["ghsa_id"])
                # "also seen in" set (excludes the lead's own source)
                also = e.extra.get("also_seen_in") or []
                also = [s for s in also if s != e.source]
                if also:
                    meta_parts.append(f"also: {','.join(also[:3])}")
                meta = "  ".join(meta_parts) if meta_parts else ""
                et.add_row(e.source, ptr, meta, e.quality)

            if verified:
                et = Table(title="[bold bright_red]VERIFIED ★ (ExploitDB-verified / MSF / KEV-linked / Vulners exploit-family)[/bold bright_red]",
                           show_lines=False, header_style="bold bright_red",
                           title_style="bold bright_red")
                et.add_column("Source", style="cyan", no_wrap=True)
                et.add_column("Pointer", overflow="fold")
                et.add_column("Metadata", overflow="fold")
                et.add_column("Quality", justify="right")
                for e in verified:
                    _render_lead_row(et, e)
                console.print(et)

            if curated:
                et = Table(title="[bold cyan]CURATED (nomi-sec / trickest / GHSA / OSV-evidence / Nuclei / NVD exploit-tagged)[/bold cyan]",
                           show_lines=False, header_style="bold cyan",
                           title_style="bold cyan")
                et.add_column("Source", style="cyan", no_wrap=True)
                et.add_column("Pointer", overflow="fold")
                et.add_column("Metadata", overflow="fold")
                et.add_column("Quality", justify="right")
                for e in curated:
                    _render_lead_row(et, e)
                console.print(et)

            if candidates:
                et = Table(title="[bold yellow]CANDIDATES (unverified — review before use)[/bold yellow]",
                           show_lines=False, header_style="bold yellow",
                           title_style="bold yellow")
                et.add_column("Source", style="dim cyan", no_wrap=True)
                et.add_column("Pointer", overflow="fold")
                et.add_column("Metadata", overflow="fold")
                et.add_column("Quality", justify="right")
                for e in candidates:
                    _render_lead_row(et, e)
                console.print(et)

            if not (verified or curated or candidates):
                # Only availability markers — no real leads.
                console.print("[dim]No public PoC/exploit pointers found.[/dim]")

        # ---- Phase 4 PART D2: per-source status footer (always visible) ----
        ss = result.sources_status or {}
        if ss:
            status_order = [
                ("nvd", "NVD"),
                ("epss", "EPSS"),
                ("cisa_kev", "CISA KEV"),
                ("vulncheck_kev", "VulnCheck KEV"),
                ("poc_in_github", "PoC-in-GitHub"),
                ("trickest", "trickest/cve"),
                ("nuclei", "Nuclei"),
                ("searchsploit", "searchsploit"),
                ("msf", "Metasploit"),
                ("osv", "OSV.dev"),
                ("ghsa", "GHSA"),
                ("vulners", "Vulners"),
                ("nvd_ref", "NVD refs"),
                ("shodan", "Shodan"),
                ("greynoise", "GreyNoise"),
            ]
            status_color = {
                SOURCE_OK: "green",
                SOURCE_SKIPPED: "dim",
                SOURCE_UNAVAILABLE: "yellow",
                SOURCE_NO_KEY: "yellow",
                SOURCE_NEEDS_TOKEN: "yellow",
                SOURCE_RATELIMITED: "bright_red",
                SOURCE_ERROR: "bright_red",
                SOURCE_NOTFOUND: "dim",
            }
            parts = []
            for key, label in status_order:
                if key not in ss: continue
                st = ss[key]
                c = status_color.get(st, "white")
                parts.append(f"[{c}]{label}: {st}[/{c}]")
            if parts:
                console.print()
                console.print(Panel(
                    Text.from_markup("  ·  ".join(parts)),
                    title="[bold]Per-source status[/bold]",
                    border_style="dim",
                    padding=(0, 1),
                ))

    # ---- --report mode: references + remediation + CAPEC ----
    if report_mode or verbose:
        # Risk breakdown
        if result.risk and result.risk.breakdown:
            rt = Table(title=f"[bold]Risk Score: {result.risk.score}/100 — {result.risk.label}[/bold]",
                       show_lines=False, header_style=f"bold {risk_color(result.risk.score)}")
            rt.add_column("Factor", style="dim")
            rt.add_column("Contribution")
            for factor in result.risk.breakdown:
                rt.add_row("•", factor)
            console.print(rt)

        # CVSS metrics
        t = Table.grid(padding=(0, 2))
        t.add_column(justify="right", style="dim", no_wrap=True)
        t.add_column()
        t.add_row("CVSS", str(_fmt_cvss(result.cvss_score, result.cvss_severity)))
        if result.cvss_vector:
            t.add_row("Vector", result.cvss_vector)
        t.add_row("EPSS", str(_fmt_epss(result.epss)))
        if result.cwe_ids:
            t.add_row("CWEs", "  ".join(result.cwe_ids))
        # CAPEC/ATT&CK
        if result.capec_attack and result.capec_attack.get("capec"):
            t.add_row("CAPEC", " | ".join(result.capec_attack["capec"][:5]))
        if result.capec_attack and result.capec_attack.get("attack"):
            t.add_row("ATT&CK", " | ".join(result.capec_attack["attack"][:5]))
        t.add_row("Published", result.published or "-")
        t.add_row("Status", result.vuln_status or "-")
        t.add_row("Confidence", f"{result.classification.confidence} ({result.classification.basis})")
        console.print(t)

        # Patch info
        if result.patch_versions:
            pt = Table(title="[bold]Patch Information[/bold]",
                       show_lines=False, header_style="bold green")
            pt.add_column("Product", overflow="fold")
            pt.add_column("First Patched", style="green")
            for p in result.patch_versions[:10]:
                pt.add_row(p.get("product", ""), p.get("first_patched", "—"))
            console.print(pt)

        # Description
        console.print(Panel(truncate(result.description, 1200),
                            title="[bold]Description[/bold]", border_style="cyan"))

        # References (split)
        if result.exploit_refs:
            console.print(f"[bold red]Exploit refs ({len(result.exploit_refs)}):[/bold red]")
            for url in result.exploit_refs[:10]:
                console.print(f"  {url}")
        if result.advisory_refs:
            console.print(f"[bold yellow]Advisories ({len(result.advisory_refs)}):[/bold yellow]")
            for url in result.advisory_refs[:10]:
                console.print(f"  {url}")

    # ---- CVSS Vector Decoded (only in verbose) ----
    if verbose and result.cvss_vector_decoded:
        vt = Table(title="[bold]CVSS Vector Decoded[/bold]",
                   show_lines=False, header_style="bold blue")
        vt.add_column("Metric", style="cyan")
        vt.add_column("Raw", style="dim")
        vt.add_column("Value")
        for metric_label, raw, value_label in result.cvss_vector_decoded:
            vt.add_row(metric_label, raw, value_label)
        console.print(vt)


def _top_exploit_tier(record) -> str:
    """Return the highest display tier across the record's exploit_evidence.

    Used by the summary table to surface "which CVEs actually have exploits"
    at a glance (PART C3). Returns TIER_NONE ('—') if no evidence.
    """
    if not record.exploit_evidence:
        return TIER_NONE
    best = TIER_NONE
    best_rank = 0
    for e in record.exploit_evidence:
        # Skip availability markers (no URL, just _available flags)
        if not e.url and (e.extra.get("_searchsploit_available") or
                          e.extra.get("_msf_available")):
            continue
        tier = e.extra.get("tier") or _classify_lead_tier(
            e.source, e.trust, e.extra, cisa_kev=record.cisa_kev)
        rank = _TIER_RANK.get(tier, 0)
        if rank > best_rank:
            best_rank = rank
            best = tier
    return best


def _exploit_lead_count(record) -> int:
    """Count of PoC/exploit leads (excludes availability markers)."""
    return sum(1 for e in record.exploit_evidence
               if e.url and not (e.extra.get("_searchsploit_available") or
                                 e.extra.get("_msf_available")))


def _tier_badge(tier: str) -> Text:
    """Render a tier as a colored badge for the summary table."""
    if tier == TIER_VERIFIED:
        return Text("VERIFIED ★", style="bold bright_red")
    if tier == TIER_CURATED:
        return Text("curated", style="cyan")
    if tier == TIER_CANDIDATE:
        return Text("candidate", style="dim yellow")
    return Text("—", style="dim")


def _print_summary(results) -> None:
    """Phase 4: Triage board — bucket by verdict, sort within each bucket.

    Phase 4 PART C3: each row now shows the top exploit tier per CVE
    (VERIFIED ★ / curated / candidate / —) and the lead count. Within each
    verdict bucket, rows are sorted by (has verified) → (has curated) →
    risk score → CVSS so CVEs with real exploits float to the top.
    """
    items = []
    for r in results:
        vd = _get_verdict_data(r)
        tier = _top_exploit_tier(r)
        lead_count = _exploit_lead_count(r)
        items.append((r, vd, tier, lead_count))

    # Bucket by verdict
    for verdict_key, verdict_label in [("TRY_FIRST", "▶ TRY FIRST"),
                                        ("WORTH_A_LOOK", "◐ WORTH A LOOK"),
                                        ("PARK_IT", "✓ PARK IT")]:
        bucket = [(r, vd, tier, lc) for (r, vd, tier, lc) in items
                  if vd["verdict"] == verdict_key]
        if not bucket:
            continue
        # PART C3: sort by exploit outcome first, then risk, then CVSS.
        # VERIFIED > CURATED > CANDIDATE > none; higher rank floats up.
        bucket.sort(key=lambda x: (
            -_TIER_RANK.get(x[2], 0),
            -x[1]["risk_score"],
            -getattr(x[0], "cvss_score", 0.0),
        ))
        color = VERDICT_COLORS[verdict_key]
        console.print(f"\n[bold {color}]{verdict_label} ({len(bucket)})[/bold {color}]")

        t = Table(show_header=True, header_style=f"bold {color}", show_lines=False)
        t.add_column("CVE ID", style="bold")
        t.add_column("Reach")
        t.add_column("Exploit")
        t.add_column("Gives")
        t.add_column("Tier", no_wrap=True)
        t.add_column("Leads", justify="right")
        t.add_column("Risk", justify="right")
        t.add_column("Next", overflow="fold")
        for r, vd, tier, lc in bucket:
            pointers = _format_pointers(r)
            t.add_row(
                r.cve_id,
                Text(vd["reach"], style=color),
                Text(vd["maturity_label"], style=vd["maturity_color"]),
                Text(vd["outcome"], "white"),
                _tier_badge(tier),
                Text(str(lc) if lc else "—",
                     style="bold" if lc else "dim"),
                Text(f"{vd['risk_score']}", style=f"bold {risk_color(vd['risk_score'])}"),
                Text(pointers, "cyan"),
            )
        console.print(t)

    # Data-honesty summary
    incomplete = [r for (r, vd, _t, _l) in items if vd["data_incomplete"]]
    if incomplete:
        console.print(f"\n[bold red]⚠ {len(incomplete)} CVE(s) have incomplete data "
                      f"(provisional or source failure).[/bold red]")


def _print_plain(results) -> None:
    """Phase 4: Pipe-friendly one-line-per-CVE output (no tables, no color)."""
    for r in results:
        vd = _get_verdict_data(r)
        pointers = _format_pointers(r)
        # One line: CVE|verdict|reach|maturity|outcome|category|cvss|risk|pointers
        epss_val = ""
        if r.epss:
            epss_val = f"{r.epss.get('epss',0)*100:.1f}%"
        print(f"{r.cve_id}|{vd['verdict']}|{vd['reach']}|{vd['maturity_label']}|"
              f"{vd['outcome']}|{r.category}|{r.cvss_score:.1f}|{epss_val}|"
              f"{vd['risk_score']}|{pointers}")


# ════════════════════════════════════════════════════════════════════════════
# Export
# ════════════════════════════════════════════════════════════════════════════
def export_json(results, path: Path) -> Path:
    # Phase 2: convert CVERecord objects to dicts.
    results = [r.to_dict() if hasattr(r, "to_dict") else r for r in results]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    return path


def export_csv(results, path: Path) -> Path:
    results = [r.to_dict() if hasattr(r, "to_dict") else r for r in results]
    path.parent.mkdir(parents=True, exist_ok=True)
    if not results:
        with open(path, "w", newline="", encoding="utf-8") as f: f.write("")
        return path
    headers = ["cve_id", "risk_score", "risk_label", "category", "subcategory",
               "cvss_score", "cvss_severity", "cvss_version", "cvss_vector",
               "cvss_source", "cvss_source_disagreement",
               "epss", "epss_percentile", "has_exploit", "exploit_count",
               "exploit_maturity", "top_exploit_tier", "verified_leads",
               "curated_leads", "candidate_leads",
               "classification_confidence", "classification_basis",
               "cwe_chain", "provisional", "reach", "outcome",
               "cisa_kev", "cisa_kev_date_added", "ransomware_use",
               "vulncheck_kev", "nuclei_template", "version_match",
               "msf_modules", "published", "modified", "vuln_status",
               "remote_exploitable", "vector_conflict", "sources_status",
               "affected_products", "first_patches", "description"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        for r in results:
            row = dict(r)
            risk = r.get("risk") or {}
            cls = r.get("classification") or {}
            cvss_sel = r.get("cvss_selected") or {}
            kev = r.get("cisa_kev") or {}
            row["risk_score"] = risk.get("score", 0)
            row["risk_label"] = risk.get("label", "")
            row["exploit_maturity"] = r.get("exploit_maturity", "")
            # Phase 4: per-CVE tier summary columns
            ev_list = r.get("exploit_evidence") or []
            actionable = [e for e in ev_list
                          if e.get("type") in ("exploit", "poc", "module")
                          and e.get("url")
                          and not (e.get("_searchsploit_available") or
                                   e.get("_msf_available"))]
            tiers = [e.get("tier", "") for e in actionable]
            row["top_exploit_tier"] = (max(tiers, key=lambda t: _TIER_RANK.get(t, 0))
                                       if tiers else TIER_NONE)
            row["verified_leads"] = sum(1 for t in tiers if t == TIER_VERIFIED)
            row["curated_leads"] = sum(1 for t in tiers if t == TIER_CURATED)
            row["candidate_leads"] = sum(1 for t in tiers if t == TIER_CANDIDATE)
            row["classification_confidence"] = cls.get("confidence", "")
            row["classification_basis"] = cls.get("basis", "")
            row["cwe_chain"] = " | ".join(cls.get("chain", []))
            row["provisional"] = "YES" if r.get("provisional") else "NO"
            row["cvss_source"] = cvss_sel.get("source_type", "")
            row["cvss_source_disagreement"] = "YES" if r.get("cvss_source_disagreement") else "NO"
            row["reach"] = compute_reach(r.get("cvss_vector", ""), r.get("category", ""))
            row["outcome"] = compute_outcome(r.get("category", ""))
            row["ransomware_use"] = kev.get("known_ransomware_use", "")
            row["vulncheck_kev"] = "YES" if r.get("vulncheck_kev") else "NO"
            row["nuclei_template"] = "YES" if r.get("nuclei_template") else "NO"
            row["version_match"] = ""  # filled only when --check-version was used
            row["cwes"] = " | ".join(r.get("cwes", []))
            row["affected_products"] = " | ".join(
                vr.get("human", vr.get("cpe", ""))
                for vr in r.get("version_ranges", [])[:5]
            ) or " | ".join(r.get("cpes", [])[:5])
            row["first_patches"] = " | ".join(
                f"{p.get('product','')}: {p.get('first_patched','')}"
                for p in r.get("patch_versions", [])[:5]
            )
            row["epss"] = (r.get("epss") or {}).get("epss", "")
            row["epss_percentile"] = (r.get("epss") or {}).get("percentile", "")
            row["cvss_score"] = cvss_sel.get("score", "")
            row["cvss_severity"] = cvss_sel.get("severity", "")
            row["cvss_version"] = cvss_sel.get("version", "")
            row["cvss_vector"] = cvss_sel.get("vector", "")
            row["cisa_kev"] = "YES" if kev else "NO"
            row["cisa_kev_date_added"] = kev.get("date_added", "")
            msf = r.get("msf_modules") or []
            row["msf_modules"] = " | ".join(m.get("module", "") for m in msf[:5])
            row["remote_exploitable"] = ("Yes" if r.get("remote_exploitable")
                                          else "No" if r.get("remote_exploitable") is False
                                          else "Unknown")
            row["vector_conflict"] = "YES" if r.get("vector_category_conflict") else "NO"
            row["sources_status"] = json.dumps(r.get("sources_status", {}))
            w.writerow(row)
    return path


def export_markdown(results, path: Path) -> Path:
    """Phase 4: Markdown report — paste-ready finding blocks for Obsidian."""
    results = [r if hasattr(r, "to_dict") else r for r in results]
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# CVE-Hunter Report", ""]
    for r in results:
        vd = _get_verdict_data(r)
        lines.append(f"## {r.cve_id} — {vd['verdict_label']}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Verdict | {vd['verdict_label']} |")
        lines.append(f"| Reach | {vd['reach']} |")
        lines.append(f"| Exploit Maturity | {vd['maturity_label']} |")
        lines.append(f"| Outcome | {vd['outcome']} |")
        lines.append(f"| Category | {r.category} ({r.classification.subcategory}) |")
        lines.append(f"| CVSS | {r.cvss_score:.1f} ({r.cvss_severity}) |")
        lines.append(f"| Risk Score | {vd['risk_score']}/100 |")
        lines.append(f"| Confidence | {r.classification.confidence} ({r.classification.basis}) |")
        if r.cvss_vector:
            lines.append(f"| CVSS Vector | `{r.cvss_vector}` |")
        epss_val = r.epss or {}
        if epss_val:
            lines.append(f"| EPSS | {epss_val.get('epss',0)*100:.2f}% |")
        if r.cisa_kev:
            lines.append(f"| CISA KEV | YES (added: {r.cisa_kev.get('date_added','')}) |")
            lines.append(f"| Ransomware | {r.cisa_kev.get('known_ransomware_use','')} |")
        if r.provisional:
            lines.append(f"| Provisional | YES |")
        if r.evidence_incomplete:
            lines.append(f"| Data Incomplete | YES |")
        if r.cwe_ids:
            lines.append(f"| CWEs | {' '.join(r.cwe_ids)} |")
        if r.capec_attack.get("capec"):
            lines.append(f"| CAPEC | {' '.join(r.capec_attack['capec'][:3])} |")
        if r.capec_attack.get("attack"):
            lines.append(f"| ATT&CK | {' '.join(r.capec_attack['attack'][:3])} |")
        lines.append(f"| Why | {vd['why']} |")
        lines.append("")
        # PoC / Exploit Intelligence (Phase 4 tier-grouped)
        if r.exploit_evidence:
            # Filter to actionable leads
            leads = [e for e in r.exploit_evidence
                     if e.evidence_type in ("exploit", "poc", "module")
                     and e.url
                     and not (e.extra.get("_searchsploit_available") or
                              e.extra.get("_msf_available"))]
            # Compute tier defensively
            for e in leads:
                if "tier" not in e.extra:
                    e.extra["tier"] = _classify_lead_tier(
                        e.source, e.trust, e.extra, cisa_kev=r.cisa_kev)
            verified = [e for e in leads if e.extra.get("tier") == TIER_VERIFIED]
            curated  = [e for e in leads if e.extra.get("tier") == TIER_CURATED]
            candidates = [e for e in leads if e.extra.get("tier") == TIER_CANDIDATE]
            if leads:
                lines.append("### PoC / Exploit Intelligence")
                lines.append("")
                if verified:
                    lines.append("#### VERIFIED ★ (ExploitDB-verified / MSF / KEV-linked / Vulners exploit-family)")
                    for e in verified:
                        # FIX (secondary-8): exclude the lead's own source from
                        # the "also seen in" list (no self-reference).
                        also = [s for s in (e.extra.get("also_seen_in") or []) if s != e.source]
                        also_str = f" _(also seen in: {', '.join(also)})_" if also else ""
                        lines.append(f"- `{e.source}`: [{e.url}]({e.url}){also_str}")
                    lines.append("")
                if curated:
                    lines.append("#### CURATED (nomi-sec / trickest / GHSA / OSV-evidence / Nuclei / NVD exploit-tagged)")
                    for e in curated:
                        stars = e.extra.get("stars", 0)
                        star_str = f" ({stars}★)" if stars else ""
                        # FIX (secondary-8): exclude self-source.
                        also = [s for s in (e.extra.get("also_seen_in") or []) if s != e.source]
                        also_str = f" _(also seen in: {', '.join(also)})_" if also else ""
                        lines.append(f"- `{e.source}`: [{e.url}]({e.url}){star_str}{also_str}")
                    lines.append("")
                if candidates:
                    lines.append("#### CANDIDATES (unverified — review before use)")
                    for e in candidates:
                        stars = e.extra.get("stars", 0)
                        star_str = f" ({stars}★)" if stars else ""
                        lines.append(f"- `{e.source}`: [{e.url}]({e.url}){star_str}")
                    lines.append("")
                if not (verified or curated or candidates):
                    lines.append("_No public PoC/exploit pointers found._")
                    lines.append("")
        # Per-source status
        ss = r.sources_status or {}
        if ss:
            lines.append("### Per-source status")
            lines.append("")
            for key, label in [("nvd", "NVD"), ("epss", "EPSS"),
                               ("cisa_kev", "CISA KEV"), ("vulncheck_kev", "VulnCheck KEV"),
                               ("poc_in_github", "PoC-in-GitHub"), ("trickest", "trickest/cve"),
                               ("nuclei", "Nuclei"), ("searchsploit", "searchsploit"),
                               ("msf", "Metasploit"), ("osv", "OSV.dev"),
                               ("ghsa", "GHSA"), ("vulners", "Vulners"), ("nvd_ref", "NVD refs")]:
                if key in ss:
                    lines.append(f"- {label}: `{ss[key]}`")
            lines.append("")
        # Patch info
        if r.patch_versions:
            lines.append("### Remediation")
            lines.append("")
            for p in r.patch_versions[:5]:
                lines.append(f"- {p.get('product','')}: upgrade to {p.get('first_patched','—')}")
            lines.append("")
        lines.append("---")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


# ════════════════════════════════════════════════════════════════════════════
# CLI Commands
# ════════════════════════════════════════════════════════════════════════════
def cmd_scan(args, settings: Settings) -> int:
    if not validate_cve(args.cve_id):
        err_console.print(f"[red]✗ Invalid CVE format:[/red] {args.cve_id}")
        err_console.print("[dim]Expected: CVE-2021-44228[/dim]")
        return 2
    debug = DebugLog() if args.debug else None
    offline = getattr(args, "offline", False)
    hunter = CVEHunter(settings, debug=debug, use_msf=args.use_msf, offline=offline)
    # Honor --max-pocs for the scan's discovery engine.
    max_pocs = getattr(args, "max_pocs", settings.max_pocs_default)
    hunter.discovery.max_pocs = max_pocs
    if offline:
        err_console.print("[cyan]⚡ Offline mode — using local mirrors only, zero network calls.[/cyan]")
        err_console.print("[yellow]  Note: EPSS, CISA KEV, and PoC-in-GitHub API are unavailable offline. "
                          "Risk scores and verdicts may be lower than online mode.[/yellow]")
    if args.use_msf and not offline:
        err_console.print(
            "[yellow]⚠ Metasploit is enabled (--use-msf). Invoking msfconsole "
            "may be restricted in some exam / engagement contexts. You are "
            "responsible for compliance with the rules of your environment.[/yellow]"
        )
    with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning {task.description}..."),
                  transient=True, console=err_console) as prog:
        task = prog.add_task(description=args.cve_id.upper(), total=None)
        result = hunter.scan(args.cve_id,
                             search_github=not args.no_github,
                             search_local=not args.no_local,
                             check_kev=not args.no_kev)
        prog.update(task, completed=1)
    if result is None:
        err_console.print(f"[red]✗ CVE not found:[/red] {args.cve_id}")
        if debug: debug.dump(console)
        return 1
    # P0 fix: --plain on scan should produce pipe-friendly output.
    if getattr(args, "plain", False):
        _print_plain([result])
    else:
        _print_single(result, verbose=args.verbose,
                      exploit_mode=getattr(args, "exploit", False),
                      report_mode=getattr(args, "report", False))
    # Phase 2 task 9: version-match confirmation (MANUAL INPUT ONLY).
    if getattr(args, "check_version", None):
        verdict = check_version_affected(result.version_ranges, args.check_version)
        affected = verdict["affected"]
        color = "bright_red" if affected else "green"
        icon = "✗ AFFECTED" if affected else "✓ NOT AFFECTED"
        console.print()
        console.print(Panel(
            Text.assemble(
                (f"{icon}\n", f"bold {color}"),
                (f"  Version: {args.check_version}\n", "white"),
                (f"  {verdict['reason']}", "dim"),
            ),
            title=f"[bold {color}]Version Match Confirmation[/bold {color}]",
            border_style=color,
        ))
    if debug: debug.dump(console)
    if args.export:
        _export([result], args.export, settings)
    return 0


def cmd_batch(args, settings: Settings) -> int:
    file_path = Path(args.file)
    if not file_path.exists():
        err_console.print(f"[red]✗ File not found:[/red] {file_path}")
        return 2
    raw = file_path.read_text(encoding="utf-8", errors="ignore")
    # FIX (secondary-7): deduplicate CVE ids while preserving first-occurrence
    # order. Previously a file with the same CVE on two lines produced two
    # identical rows in the output AND corrupted order_map (which used the
    # last index, breaking the original-file ordering).
    cve_ids: List[str] = []
    seen_cves: set = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        token = line.split(",", 1)[0].strip()
        if validate_cve(token) and token not in seen_cves:
            seen_cves.add(token)
            cve_ids.append(token)
    if not cve_ids:
        err_console.print("[red]✗ No valid CVE IDs found in file[/red]")
        return 2
    debug = DebugLog() if args.debug else None
    offline = getattr(args, "offline", False)
    is_plain = getattr(args, "plain", False)
    if not is_plain:
        console.print(f"[cyan]Scanning {len(cve_ids)} CVE(s) with deep enrichment...[/cyan]")
    hunter = CVEHunter(settings, debug=debug, use_msf=args.use_msf, offline=offline)
    if offline and not is_plain:
        err_console.print("[cyan]⚡ Offline mode — using local mirrors only, zero network calls.[/cyan]")
        err_console.print("[yellow]  Note: EPSS, CISA KEV, and PoC-in-GitHub API are unavailable offline. "
                          "Risk scores and verdicts may be lower than online mode.[/yellow]")
    if args.use_msf and not offline and not is_plain:
        err_console.print(
            "[yellow]⚠ Metasploit is enabled (--use-msf). Invoking msfconsole "
            "may be restricted in some exam / engagement contexts. You are "
            "responsible for compliance with the rules of your environment.[/yellow]"
        )

    # Bulk-fetch EPSS ONCE for the whole batch (1 request per 100 CVEs).
    if not args.no_kev and not args.no_enrich and not offline:
        try:
            hunter.epss.bulk(cve_ids)
        except Exception as exc:
            err_console.print(f"[yellow]⚠ EPSS bulk fetch failed: {exc}[/yellow]")

    # Phase 4 PART C2 + C4: deep-enrich each CVE via enrich_one() in a
    # bounded thread pool (4-8 workers). Per-CVE caching prevents
    # re-fetching. One slow/failed CVE never blocks or aborts the set.
    max_workers = min(settings.discovery_workers, max(1, len(cve_ids)))
    results: List[CVERecord] = []
    results_lock = __import__("threading").Lock()
    failed: List[Tuple[str, str]] = []

    def _enrich_one_safe(cid: str) -> None:
        try:
            rec = hunter.nvd.get_cve(cid)
            if rec is None:
                with results_lock:
                    failed.append((cid, "NVD not found"))
                return
            r = hunter.enrich_one(
                rec, deep=True, use_msf=args.use_msf,
                search_local=not args.no_local,
                check_kev=not args.no_kev,
                search_github=not args.no_github,
            )
            with results_lock:
                results.append(r)
        except Exception as exc:
            with results_lock:
                failed.append((cid, str(exc)[:120]))

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  console=err_console) as prog:
        task = prog.add_task(description="", total=len(cve_ids))
        completed_count = [0]
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_enrich_one_safe, cid): cid for cid in cve_ids}
            for fut in as_completed(futures):
                cid = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    with results_lock:
                        failed.append((cid, str(exc)[:120]))
                completed_count[0] += 1
                prog.update(task, description=f"({completed_count[0]}/{len(cve_ids)})",
                            completed=completed_count[0])
        prog.update(task, completed=len(cve_ids))

    # Preserve the original CVE order from the input file.
    order_map = {cid: i for i, cid in enumerate(cve_ids)}
    results.sort(key=lambda r: order_map.get(r.cve_id, 9999))

    if failed and not is_plain:
        for cid, msg in failed[:5]:
            err_console.print(f"[red]✗ Failed {cid}:[/red] {msg}")
        if len(failed) > 5:
            err_console.print(f"[dim]...and {len(failed) - 5} more failure(s).[/dim]")

    # Phase 4 fix: --filter-outcome lens
    filter_outcome = getattr(args, "filter_outcome", None)
    if filter_outcome:
        filter_outcome = filter_outcome.upper().replace("-", "_")
        results = [r for r in results
                   if compute_outcome(r.category) == filter_outcome]
        if not is_plain:
            console.print(f"[dim]Filtered to {len(results)} CVE(s) with outcome={filter_outcome}[/dim]")
    if getattr(args, "plain", False):
        _print_plain(results)
    else:
        _print_summary(results)
    if debug: debug.dump(console)
    if args.export:
        _export(results, args.export, settings)
    return 0


def cmd_search(args, settings: Settings) -> int:
    if not (args.keyword or args.cpe):
        err_console.print("[red]✗ Provide --keyword or --cpe[/red]")
        return 2
    if args.cpe and not validate_cpe(args.cpe):
        err_console.print(f"[red]✗ Invalid CPE format:[/red] {args.cpe}")
        err_console.print("[dim]Expected: cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*[/dim]")
        return 2
    # Phase 4 usability fix: if the user passed a CVE ID as --keyword,
    # redirect them to `scan` automatically. NVD's keyword search does NOT
    # match CVE IDs — it only searches the description text. So
    # `search --keyword CVE-2021-44228` always returns "No results found",
    # which is confusing. Detect the pattern and run scan instead.
    if args.keyword:
        kw = args.keyword.strip()
        if validate_cve(kw):
            err_console.print(
                f"[yellow]⚠ '{kw}' looks like a CVE ID.[/yellow] "
                f"[dim]Auto-redirecting to `scan` (NVD keyword search does not match CVE IDs).[/dim]"
            )
            args.cve_id = kw
            return cmd_scan(args, settings)
    debug = DebugLog() if args.debug else None
    offline = getattr(args, "offline", False)
    is_plain = getattr(args, "plain", False)
    deep = getattr(args, "deep", False)
    deep_limit = getattr(args, "deep_limit", settings.deep_default_limit)
    max_pocs = getattr(args, "max_pocs", settings.max_pocs_default)
    hunter = CVEHunter(settings, debug=debug, use_msf=getattr(args, "use_msf", False), offline=offline)
    if offline and not is_plain:
        err_console.print("[cyan]⚡ Offline mode — keyword/CPE search is not available offline.[/cyan]")
    if deep and not is_plain:
        err_console.print(f"[cyan]Deep mode: full discovery on top {deep_limit} result(s) "
                          f"(max {max_pocs} PoCs per CVE).[/cyan]")
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  transient=False, console=err_console) as prog:
        task = prog.add_task(description="Searching NVD...", total=None)
        results = hunter.search(keyword=args.keyword, cpe_name=args.cpe,
                                pub_start=args.pub_start, pub_end=args.pub_end,
                                max_results=args.limit,
                                enrich=not args.no_enrich,
                                deep=deep, deep_limit=deep_limit,
                                max_pocs=max_pocs)
        prog.update(task, completed=1)
    if not results:
        console.print("[yellow]No results found.[/yellow]")
        # Helpful diagnostic: explain the likely causes so the user knows
        # what to do next. NVD's keyword search silently returns 0 results
        # when rate-limited (no error, just empty list), which is confusing.
        console.print()
        console.print("[dim]Possible causes:[/dim]")
        console.print("[dim]  • NVD rate limit hit (5 requests/30s without API key)[/dim]")
        console.print("[dim]  • Keyword too short or doesn't match any CVE description[/dim]")
        console.print("[dim]  • NVD's keyword search only searches CVE descriptions, not CVE IDs[/dim]")
        console.print()
        console.print("[dim]Tips:[/dim]")
        console.print("[dim]  • If you have a CVE ID, use:  cve-hunter scan CVE-2021-44228[/dim]")
        console.print("[dim]  • Wait 30s and retry (NVD rate limit resets)[/dim]")
        console.print("[dim]  • Get a free NVD API key for higher rate limits:[/dim]")
        console.print("[dim]    https://nvd.nist.gov/developers/request-an-api-key[/dim]")
        console.print("[dim]  • Use --debug to see per-source HTTP status[/dim]")
        if debug: debug.dump(console)
        return 0
    # Phase 4 PART C3: ranked summary — when --deep was used, the summary
    # table now shows the exploit tier per CVE and sorts CVEs with real
    # exploits to the top.
    if deep and not is_plain:
        deep_count = sum(1 for r in results if r.exploit_evidence)
        shallow_count = len(results) - deep_count
        if shallow_count > 0:
            console.print(f"[dim]Deep-enriched: {deep_count} CVE(s); "
                          f"shallow (past --deep-limit): {shallow_count} CVE(s).[/dim]")
    _print_summary(results)
    if debug: debug.dump(console)
    if args.export:
        _export(results, args.export, settings)
    return 0


def cmd_import_nvd(args, settings: Settings) -> int:
    """Import NVD JSON feed(s) into the local cache for offline use."""
    path = Path(args.path)
    if not path.exists():
        err_console.print(f"[red]✗ Path not found:[/red] {path}")
        return 2
    cache = Cache(settings.cache_dir, settings.cache_ttl_hours)
    console.print(f"[cyan]Importing NVD feeds from {path}...[/cyan]")
    if path.is_dir():
        total = NVDSnapshotImporter.import_dir(path, cache)
    else:
        try:
            total = NVDSnapshotImporter.import_file(path, cache)
            console.print(f"  {path.name}: {total} CVEs imported")
        except Exception as e:
            err_console.print(f"[red]✗ Import failed:[/red] {e}")
            return 1
    console.print(f"\n[green]✓ Import complete: {total} CVE(s) cached.[/green]")
    console.print(f"[dim]  You can now use --offline to scan without network.[/dim]")
    return 0


def cmd_config(args, settings: Settings) -> int:
    if args.action == "show":
        console.print("[bold]Current Configuration[/bold]")
        console.print(f"  Config file : {DEFAULT_CONFIG_FILE}")
        console.print(f"  Cache dir   : {settings.cache_dir}")
        console.print(f"  Cache TTL   : {settings.cache_ttl_hours} hours")
        console.print(f"  NVD API key : {'[green]set[/green]' if settings.nvd_api_key else '[yellow]not set[/yellow]'}")
        console.print(f"  GitHub token: {'[green]set[/green]' if settings.github_token else '[yellow]not set[/yellow]'}")
        console.print(f"  VulnCheck key: {'[green]set[/green]' if settings.vulncheck_api_key else '[yellow]not set[/yellow]'}")
        console.print(f"  Vulners key : {'[green]set[/green]' if settings.vulners_api_key else '[yellow]not set[/yellow]'}")
        console.print(f"  Shodan key  : {'[green]set[/green]' if settings.shodan_api_key else '[yellow]not set[/yellow]'}")
        console.print(f"  GreyNoise   : {'[green]set[/green]' if settings.greynoise_api_key else '[yellow]not set[/yellow]'}")
        console.print(f"  NVD interval: {settings.nvd_request_interval}s")
        console.print(f"  PoC-in-GitHub: {settings.poc_in_github_path or '[yellow]not set[/yellow]'}")
        console.print(f"  trickest/cve : {settings.trickest_path or '[yellow]not set[/yellow]'}")
        console.print(f"  nuclei-templates: {settings.nuclei_path or '[yellow]not set[/yellow]'}")
        from shutil import which as _which
        ss_available = _which("searchsploit") is not None
        msf_available = _which("msfconsole") is not None
        console.print(f"  searchsploit: {'[green]available[/green]' if ss_available else '[yellow]not installed[/yellow]'}")
        console.print(f"  msfconsole  : {'[green]available[/green]' if msf_available else '[yellow]not installed[/yellow]'} [dim](opt-in via --use-msf)[/dim]")
    elif args.action == "set-key":
        path = save_config(
            nvd_key=args.nvd_key or "",
            github_token=args.github_token or "",
            poc_in_github_path=args.poc_in_github_path or "",
            trickest_path=args.trickest_path or "",
            nuclei_path=args.nuclei_path or "",
            vulncheck_key=args.vulncheck_key or "",
            vulners_key=getattr(args, "vulners_key", "") or "",
            shodan_key=getattr(args, "shodan_key", "") or "",
            greynoise_key=getattr(args, "greynoise_key", "") or "",
        )
        console.print(f"[green]✓ Saved to[/green] {path} [dim](mode 0600)[/dim]")
    elif args.action == "clear-cache":
        n = CVEHunter(settings).clear_cache()
        console.print(f"[green]✓ Cleared {n} cached entries[/green]")
    return 0


def _export(results, fmt: str, settings: Settings) -> None:
    out_dir = settings.default_export_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    if fmt.lower() == "json":
        path = out_dir / "cve_hunter_results.json"
        export_json(results, path)
    elif fmt.lower() == "csv":
        path = out_dir / "cve_hunter_results.csv"
        export_csv(results, path)
    elif fmt.lower() == "markdown":
        path = out_dir / "cve_hunter_results.md"
        export_markdown(results, path)
    else:
        err_console.print(f"[red]Unknown format: {fmt}[/red]")
        return
    console.print(f"\n[green]✓ Results exported to[/green] {path}")


# ════════════════════════════════════════════════════════════════════════════
# Argument Parser
# ════════════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve-hunter",
        description="CVE analysis & prioritization tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cve-hunter scan CVE-2021-44228
  cve-hunter scan CVE-2021-44228 --verbose
  cve-hunter scan CVE-2021-44228 --offline              # offline mode
  cve-hunter scan CVE-2023-23397 --export json
  cve-hunter scan CVE-2017-0144 --use-msf
  cve-hunter scan CVE-2017-5638 --check-version 2.3.32  # version-match
  cve-hunter batch cves.txt --export csv
  cve-hunter search --keyword "log4j" --limit 20
  cve-hunter import-nvd /path/to/nvd/feeds/              # offline setup
  cve-hunter config set-key --nvd-key YOUR_KEY
  cve-hunter config set-key --poc-in-github-path /path/to/PoC-in-GitHub
  cve-hunter config set-key --nuclei-path /path/to/nuclei-templates

Note: Metasploit is OPT-IN (--use-msf). By default no msfconsole subprocess
is ever spawned. Use --debug to print per-source status/timing.
Use --offline for exam/air-gapped mode (local mirrors only, zero network,
MSF forced off). Import NVD feeds first with `import-nvd`.
        """,
    )
    p.add_argument("--version", action="version", version=f"cve-hunter {__version__}")
    # FIX (critical-2): global flags must be accepted BOTH before AND after the
    # subcommand. The epilog shows `scan CVE --offline` which previously failed
    # with "unrecognized arguments: --offline". The cleanest fix is a parent
    # parser that every subparser inherits via parents=[...].
    #
    # We add the flags to BOTH the main parser `p` AND the parent parser that
    # subparsers inherit. argparse's quirk: when a flag is set BEFORE the
    # subcommand, the subparser's default (False) shadows it. To work around
    # this, we use a TWO-PASS approach in main(): first parse with the main
    # parser to capture pre-subcommand flags, then the subparser captures
    # post-subcommand flags. We OR the two in main() via a custom action.
    #
    # Simpler workaround that works: use `argparse.SUPPRESS` on the main
    # parser so it doesn't set a default, AND use a custom dest prefix on
    # the parent parser. But the cleanest is to just handle it in main()
    # by checking sys.argv directly for the global flags.
    p.add_argument("--debug", action="store_true",
                   help="Print per-source success/failure/timing")
    p.add_argument("--offline", action="store_true",
                   help="Offline mode: local mirrors + searchsploit only, "
                        "zero network calls, MSF forced off. Requires NVD "
                        "snapshot imported via `import-nvd`.")
    p.add_argument("-q", "--plain", action="store_true",
                   help="Pipe-friendly one-line-per-CVE output (no tables/color). "
                        "Suppresses banner and all rich formatting.")
    sub = p.add_subparsers(dest="command", required=True)

    # Parent parser with the global flags — inherited by every subparser so
    # `cve-hunter scan CVE --offline`, `cve-hunter scan CVE --debug`, and
    # `cve-hunter scan CVE -q` all work (matching the epilog examples).
    global_parent = argparse.ArgumentParser(add_help=False)
    global_parent.add_argument("--debug", action="store_true",
                               help="Print per-source success/failure/timing")
    global_parent.add_argument("--offline", action="store_true",
                               help="Offline mode: local mirrors + searchsploit only, "
                                    "zero network calls, MSF forced off.")
    global_parent.add_argument("-q", "--plain", action="store_true",
                               help="Pipe-friendly one-line-per-CVE output.")

    sp = sub.add_parser("scan", help="Scan a single CVE", parents=[global_parent])
    sp.add_argument("cve_id", help="CVE identifier, e.g. CVE-2021-44228")
    sp.add_argument("--verbose", "-v", action="store_true",
                    help="Show CVSS vector decoded + all references")
    sp.add_argument("--no-github", action="store_true", help="Skip GitHub PoC search")
    sp.add_argument("--no-local", action="store_true",
                    help="Skip searchsploit (Exploit-DB local)")
    sp.add_argument("--use-msf", action="store_true",
                    help="Enable Metasploit module search (opt-in; off by default)")
    sp.add_argument("--no-kev", action="store_true",
                    help="Skip CISA KEV catalog check")
    sp.add_argument("--check-version", metavar="VERSION",
                    help="Check if a manually-supplied version is affected "
                         "(e.g. --check-version 2.14.0). You MUST type the "
                         "version yourself — the tool never scans for it.")
    sp.add_argument("--exploit", action="store_true",
                    help="Show version-match details + exploit pointers (progressive disclosure)")
    sp.add_argument("--report", action="store_true",
                    help="Show references + remediation + CAPEC/ATT&CK (full report mode)")
    sp.add_argument("--max-pocs", type=int, default=15,
                    help="Maximum PoC/exploit leads to display per CVE "
                         "(default 15). All leads are still exported to JSON/CSV/MD.")
    sp.add_argument("--export", choices=["json", "csv", "markdown"], help="Export results")
    sp.set_defaults(func=cmd_scan)

    bp = sub.add_parser("batch", help="Scan CVEs from a file", parents=[global_parent])
    bp.add_argument("file", help="File with one CVE ID per line")
    bp.add_argument("--no-github", action="store_true", help="Skip GitHub PoC search")
    bp.add_argument("--no-local", action="store_true",
                    help="Skip searchsploit (Exploit-DB local)")
    bp.add_argument("--use-msf", action="store_true",
                    help="Enable Metasploit module search (opt-in; off by default)")
    bp.add_argument("--no-kev", action="store_true",
                    help="Skip CISA KEV catalog check")
    bp.add_argument("--no-enrich", action="store_true",
                    help="Skip EPSS bulk pre-fetch (per-CVE fallback still used)")
    bp.add_argument("--filter-outcome", metavar="OUTCOME",
                    help="Filter results by outcome: FOOTHOLD, PRIV-ESC, LOOT, DENIAL, OTHER")
    bp.add_argument("--export", choices=["json", "csv", "markdown"], help="Export results")
    bp.set_defaults(func=cmd_batch)

    srp = sub.add_parser("search", help="Search CVEs by keyword or CPE", parents=[global_parent])
    srp.add_argument("--keyword", help="Keyword search (e.g. 'log4j')")
    srp.add_argument("--cpe", help="CPE name (e.g. cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*)")
    srp.add_argument("--pub-start", help="Publish start date (ISO 8601: 2021-01-01T00:00:00.000)")
    srp.add_argument("--pub-end", help="Publish end date (ISO 8601)")
    srp.add_argument("--limit", type=int, default=50, help="Max results (default 50)")
    srp.add_argument("--no-enrich", action="store_true",
                    help="Skip EPSS + CISA KEV enrichment (faster but less info)")
    # Phase 4 PART C1: deep discovery on search results
    srp.add_argument("--deep", "--with-pocs", dest="deep", action="store_true",
                    help="Run the FULL discovery engine (PoC-in-GitHub, OSV, GHSA, "
                         "Vulners, searchsploit, etc.) on each result. Default off "
                         "(fast EPSS+KEV listing stays the default).")
    srp.add_argument("--deep-limit", type=int, default=25,
                    help="When --deep, cap how many results get full discovery "
                         "(highest-CVSS first). Default 25. Results past this "
                         "limit are shallow-enriched with a note.")
    srp.add_argument("--max-pocs", type=int, default=15,
                    help="Maximum PoC/exploit leads to display per CVE in deep mode "
                         "(default 15). All leads are still exported to JSON/CSV/MD.")
    srp.add_argument("--use-msf", action="store_true",
                    help="Enable Metasploit module search (opt-in; off by default). "
                         "Forced off in --offline mode.")
    srp.add_argument("--export", choices=["json", "csv", "markdown"], help="Export results")
    srp.set_defaults(func=cmd_search)

    # Phase 3: import-nvd subcommand
    imp = sub.add_parser("import-nvd",
                         help="Import NVD JSON feed(s) into local cache for offline use",
                         parents=[global_parent])
    imp.add_argument("path", help="Path to an NVD JSON feed file (e.g. nvdcve-1.1-2024.json.gz) "
                                  "or a directory containing multiple feed files")
    imp.set_defaults(func=cmd_import_nvd)

    cp = sub.add_parser("config", help="Configuration", parents=[global_parent])
    cps = cp.add_subparsers(dest="action", required=True)
    # FIX (secondary-2): inherit global_parent so `config show --debug`,
    # `config set-key --offline`, etc. work the same as other subcommands.
    cps.add_parser("show", help="Show current configuration", parents=[global_parent])
    sk = cps.add_parser("set-key", help="Save API keys + local mirror paths (file is chmod 600)",
                        parents=[global_parent])
    sk.add_argument("--nvd-key", help="NVD API key (https://nvd.nist.gov/developers/request-an-api-key)")
    sk.add_argument("--github-token", help="GitHub personal access token")
    sk.add_argument("--poc-in-github-path", help="Path to local clone of nomi-sec/PoC-in-GitHub")
    sk.add_argument("--trickest-path", help="Path to local clone of trickest/cve")
    sk.add_argument("--nuclei-path", help="Path to local clone of projectdiscovery/nuclei-templates")
    sk.add_argument("--vulncheck-key", help="VulnCheck KEV API key (optional)")
    sk.add_argument("--vulners-key", help="Vulners API key (optional — enables exploit-family bulletins: exploitdb, metasploit, packetstorm, 0day.today, etc.)")
    sk.add_argument("--shodan-key", help="Shodan API key (free — https://account.shodan.io/register)")
    sk.add_argument("--greynoise-key", help="GreyNoise API key (free Community — https://www.greynoise.io/signup)")
    cps.add_parser("clear-cache", help="Clear local cache", parents=[global_parent])
    cp.set_defaults(func=cmd_config)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    # FIX (critical-2 cont.): argparse quirk — when a global flag (like
    # --offline) is set BEFORE the subcommand, the subparser's default
    # (False) shadows it in `args`. We detect pre-subcommand flags by
    # scanning sys.argv for them before the subcommand name, and OR them
    # into the parsed args. This makes `cve-hunter --offline scan CVE`
    # behave identically to `cve-hunter scan CVE --offline`.
    subcommand_names = ("scan", "batch", "search", "import-nvd", "config")
    pre_sub_flags = {"debug": False, "offline": False, "plain": False}
    for tok in sys.argv[1:]:
        if tok in subcommand_names:
            break  # stop at first subcommand name
        if tok in ("--debug",):
            pre_sub_flags["debug"] = True
        elif tok in ("--offline",):
            pre_sub_flags["offline"] = True
        elif tok in ("-q", "--plain"):
            pre_sub_flags["plain"] = True
    # OR the pre-subcommand flags into args (True wins over False).
    for flag, value in pre_sub_flags.items():
        if value:
            setattr(args, flag, True)
    settings = load_settings()
    # Phase 4 fix: suppress banner in --plain mode so output is pipe-clean.
    is_plain = getattr(args, "plain", False)
    if args.command in ("scan", "batch", "search") and not is_plain:
        console.print(BANNER.format(version=__version__))
    try:
        return args.func(args, settings)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        return 130
    except Exception as exc:
        err_console.print(f"[red]✗ Error:[/red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
