"""Indicator-of-Compromise extraction for the article drawer.

Deliberately conservative patterns — this feeds a copy-to-clipboard UI, not a
sink list: valid-octet IPv4 (0.0.0.0 / 255.255.255.255 excluded), bare domain
names (publisher's own host excluded per article), CVE IDs, and SHA-256
hex strings. MD5/SHA-1 are skipped on purpose: 32/40-hex strings match too
much unrelated text in news copy.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

MAX_PER_KIND = 50

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b([a-f0-9]{64})\b", re.IGNORECASE)

# lookalike domains that appear in ordinary news copy and are never IOCs
_DOMAIN_DENYLIST = frozenset({
    "example.com", "example.org", "example.net", "domain.com",
    "yourdomain.com", "localhost", "localhost.localdomain",
    "w3.org", "schema.org", "json-schema.org", "google.com",
    "github.com", "twitter.com", "x.com", "youtube.com",
    "apple.com", "microsoft.com", "wikipedia.org",
})


def _valid_ipv4(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    if any(not p.isdigit() or int(p) > 255 for p in parts):
        return False
    return candidate not in ("0.0.0.0", "255.255.255.255")


def extract_iocs(text: str, exclude_domains: frozenset[str] = frozenset()) -> dict[str, list[str]]:
    """Extract IOCs from article text.

    exclude_domains: hosts that must never be reported (typically the
    publisher's own domain) — matched case-insensitively, with or without
    a leading "www.".
    """
    if not text:
        return {"ips": [], "domains": [], "cves": [], "sha256": []}

    def _excluded(host: str) -> bool:
        bare = host.lower().removeprefix("www.")
        return bare in exclude_domains or host.lower() in _DOMAIN_DENYLIST

    seen: dict[str, set[str]] = {"ips": set(), "domains": set(), "cves": set(), "sha256": set()}
    for m in _IPV4_RE.finditer(text):
        if _valid_ipv4(m.group(1)):
            seen["ips"].add(m.group(1))
    for m in _DOMAIN_RE.finditer(text):
        # normalize to the bare form — "www.evil-c2.example" is stored as
        # "evil-c2.example", and exclusion checks run on the bare form too
        bare = m.group(1).lower().removeprefix("www.")
        if bare in seen["domains"] or _excluded(bare):
            continue
        seen["domains"].add(bare)
    for m in _CVE_RE.finditer(text):
        seen["cves"].add(m.group(1).upper())
    for m in _SHA256_RE.finditer(text):
        seen["sha256"].add(m.group(1).lower())

    return {
        kind: sorted(values)[:MAX_PER_KIND]
        for kind, values in seen.items()
    }


def source_domain(url: str) -> str:
    """The publisher host of a feed URL, for per-article exclusion."""
    return (urlparse(url).hostname or "").lower()
