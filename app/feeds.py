"""RSS aggregation for the Cyber Threats Intelligence dashboard.

Sources are curated from two hand-maintained indexes of threat-intelligence
publishers, merged into one group taxonomy:

- https://github.com/NewBee119/threat-intelligence — General / Cloud / ICS /
  Endpoint / Mobile / Threat Intel / Traditional sections
- https://github.com/zer0yu/CyberSecurityRSS — contributes the Research and
  Gov / CERT groups plus many of the publishers slotted into the groups above

Every entry was liveness-probed (HTTP 200 + XML body) before inclusion;
candidates behind bot-walls or with invalid TLS were dropped. Feeds that
moved hosts (rebrands, www/non-www shifts) were re-pointed at their verified
final URLs; retired publishers (Cybereason, AlienVault Labs, Bugtraq, …)
were removed rather than left dark.

All outbound fetching is guarded: http(s) only, domain allowlist, and a
DNS-resolution check that rejects loopback / private / reserved targets.
"""

from __future__ import annotations

import concurrent.futures as futures
import hashlib
import html as html_mod
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser
import httpx

log = logging.getLogger("cti.feeds")

MAX_REDIRECTS = 4
MAX_BYTES = 3_000_000  # vendor feeds with embedded HTML (e.g. Squarespace) run ~2-3 MB
FETCH_TIMEOUT = 12.0
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def _ip_allowed(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def assert_public_url(url: str) -> str:
    """Validate an outbound URL. Returns the canonical URL or raises ValueError.

    http/https only, hostname required, and every DNS-resolved address must be
    public (rejects loopback, private, link-local, reserved, multicast).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"scheme not allowed: {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"DNS resolution failed for {host}: {exc}") from exc
    if not infos:
        raise ValueError(f"no DNS records for {host}")
    for info in infos:
        ip = str(info[4][0])
        if not _ip_allowed(ip):
            raise ValueError(f"blocked non-public address {ip} for {host}")
    return url


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    group: str  # section name from the NewBee119/threat-intelligence README


# Curated from NewBee119/threat-intelligence + zer0yu/CyberSecurityRSS
# (every entry liveness-probed), regrouped into the dashboard's five
# threat-news categories: news media & intel firms -> Threat Intel,
# established AV/platform vendors -> Traditional, EDR + mobile -> Endpoint,
# research labs & personal blogs -> Research, advisories -> Gov / CERT.
SOURCES: tuple[Source, ...] = (
    # 威胁情报类 — threat-news media & threat-intel firms
    Source("Hackread", "https://hackread.com/feed/", "Threat Intel"),
    Source("Security Affairs", "https://securityaffairs.com/feed", "Threat Intel"),
    Source("Krebs on Security", "https://krebsonsecurity.com/feed/", "Threat Intel"),
    Source("SecurityWeek", "https://www.securityweek.com/feed/", "Threat Intel"),
    Source("Dark Reading", "https://www.darkreading.com/rss.xml", "Threat Intel"),
    Source("The Hacker News", "https://thehackernews.com/feeds/posts/default", "Threat Intel"),
    Source("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "Threat Intel"),
    Source("Schneier on Security", "https://www.schneier.com/feed/", "Threat Intel"),
    Source("Ars Technica Security", "https://arstechnica.com/security/feed/", "Threat Intel"),
    Source("Dataminr Blog", "https://www.dataminr.com/feed/", "Threat Intel"),  # ex-ThreatConnect
    Source("ClearSky", "https://www.clearskysec.com/feed/", "Threat Intel"),
    Source("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "Threat Intel"),
    Source("The DFIR Report", "https://thedfirreport.com/feed/", "Threat Intel"),
    Source("Exploit-DB", "https://www.exploit-db.com/rss.xml", "Threat Intel"),
    Source("Zero Day Initiative", "https://www.zerodayinitiative.com/blog/atom.xml", "Threat Intel"),
    Source("GreyNoise", "https://www.greynoise.io/blog/rss.xml", "Threat Intel"),
    # 传统安全类 — established AV / platform vendors
    Source("Securelist", "https://securelist.com/feed/", "Traditional"),
    Source("Kaspersky Blog", "https://www.kaspersky.com/blog/feed/", "Traditional"),
    Source("Talos Intelligence", "https://blog.talosintelligence.com/rss/", "Traditional"),
    Source("Check Point Blog", "https://blog.checkpoint.com/feed/", "Traditional"),
    Source("Heimdal Security", "https://heimdalsecurity.com/blog/feed/", "Traditional"),
    Source("Imperva Blog", "https://www.imperva.com/blog/feed/", "Traditional"),
    Source("Rapid7 Blog", "https://www.rapid7.com/blog/rss/", "Traditional"),
    Source("Qualys Blog", "https://blog.qualys.com/feed", "Traditional"),
    Source("Tenable Blog", "https://feeds.feedburner.com/tenable/qaXL", "Traditional"),
    Source("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed", "Traditional"),
    Source("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "Traditional"),
    Source("AWS Security Blog", "https://aws.amazon.com/blogs/security/feed/", "Traditional"),
    Source("Google Security Blog", "https://security.googleblog.com/feeds/posts/default", "Traditional"),
    # 终端安全类 — endpoint & mobile vendors
    Source("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/", "Endpoint"),
    Source("Sophos News", "https://www.sophos.com/en-gb/blog/feed", "Endpoint"),
    Source("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/", "Endpoint"),
    Source("NowSecure", "https://www.nowsecure.com/feed/", "Endpoint"),
    Source("Android Explorations", "https://nelenkov.blogspot.com/feeds/posts/default", "Endpoint"),
    # 研究类 — research labs & personal research blogs
    Source("Project Zero", "https://projectzero.google/feed.xml", "Research"),
    Source("Tencent Xuanwu Lab", "https://xlab.tencent.com/cn/feed/", "Research"),
    Source("Tencent Keen Lab", "https://keenlab.tencent.com/zh/atom.xml", "Research"),
    Source("Anquanke", "https://api.anquanke.com/data/v1/rss", "Research"),
    Source("Xianzhi Community", "https://xz.aliyun.com/feed", "Research"),
    Source("lcamtuf's things", "https://blog.coredump.cx/feed", "Research"),
    Source("Claroty Team82", "https://claroty.com/team82/disclosure-dashboard/feed/atom", "Research"),
    Source("Citizen Lab", "https://citizenlab.ca/feed/", "Research"),
    # 政府与 CERT — government advisories & CERTs
    Source("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "Gov / CERT"),
    Source("CERT/CC Vul Notes", "https://www.kb.cert.org/vulfeed", "Gov / CERT"),
    Source("Huawei PSIRT", "https://www.huawei.com/cn/rss-feeds/psirt/rss", "Gov / CERT"),
)

# Display order for the dashboard's chips, sources panel and category strip.
GROUPS: tuple[str, ...] = (
    "Traditional", "Research", "Gov / CERT", "Endpoint", "Threat Intel",
)

ALLOWED_HOSTS: frozenset[str] = frozenset(urlparse(s.url).hostname or "" for s in SOURCES)


@dataclass
class Article:
    id: str
    title: str
    url: str
    source: str
    source_group: str
    category: str  # Cyber / Global / Business keyword bucket
    published: float  # epoch seconds; fetch time when the feed has none
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "source": self.source,
            "source_group": self.source_group,
            "category": self.category,
            "published": self.published,
            "summary": self.summary,
        }


def _clean(text: str | None, limit: int = 240) -> str:
    if not text:
        return ""
    text = html_mod.unescape(TAG_RE.sub(" ", text))
    return WS_RE.sub(" ", text).strip()[:limit]


_ACRONYM_RE = re.compile(r"\b(ssh|siem|soc|mdr|edr|xdr|cve|apt|iot|vpngw)\b", re.IGNORECASE)


def _bucket(title: str) -> str:
    t = title.lower()
    cyber = (
        "malware", "ransomware", "breach", "exploit", "vulnerabilit", "cve",
        "botnet", "phishing", "hack", "cyber", "ddos", "spyware",
        "backdoor", "stealer", "threat", "ioc", "ransom", "zero-day",
        "zero day", "security", "data leak", "infostealer", "credential",
        "patch", "firewall", "password", "encrypt", "malicious", "attack",
        "leak", "trojan", "rootkit", "keylogger", "stalkerware", "espionage",
        "fraud", "scam", "incident response", "forensic",
        # Chinese-language feeds (zer0yu Research / Gov / CERT sources)
        "勒索", "漏洞", "攻击", "恶意", "后门", "钓鱼", "木马", "病毒",
        "挖矿", "数据泄露", "安全通告", "情报",
    )
    business = (
        "market", "stocks", "revenue", "ipo", "merger", "acquisition",
        "funding", "profit", "economy", "tariff", "inflation",
    )
    if _ACRONYM_RE.search(title) or any(k in t for k in cyber):
        return "Cyber"
    if any(k in t for k in business):
        return "Business"
    return "Global"


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def fetch_url(url: str, client: httpx.Client) -> bytes:
    """SSRF-guarded GET with manual redirect validation and a byte cap.

    Redirect hops may keep the same site under a www/non-www variant of the
    source's own host (publishers move between them often); anything else off
    the allowlist is rejected. Every hop still passes assert_public_url.
    """
    source_host = _strip_www(urlparse(url).hostname or "")
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        hop = urlparse(current).hostname or ""
        # entry URL must be strictly allowlisted; redirect hops may keep the
        # same site under a www/non-www variant of the source's own host
        allowed = hop in ALLOWED_HOSTS or (current != url and _strip_www(hop) == source_host)
        if not allowed:
            raise ValueError(f"host not in allowlist: {current}")
        assert_public_url(current)
        with client.stream("GET", current) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                current = str(resp.next_request.url) if resp.next_request else loc
                if not loc:
                    raise ValueError("redirect without location")
                continue
            resp.raise_for_status()
            chunks, total = [], 0
            for chunk in resp.iter_bytes(64_000):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError("response exceeds byte cap")
                chunks.append(chunk)
            return b"".join(chunks)
    raise ValueError("too many redirects")


def _parse_feed(source: Source, payload: bytes) -> list[Article]:
    parsed = feedparser.parse(payload)
    articles: list[Article] = []
    now = time.time()
    for entry in parsed.entries[:40]:
        title = _clean(entry.get("title"), 180)
        link = entry.get("link", "")
        if not title or not link:
            continue
        stamp = entry.get("published_parsed") or entry.get("updated_parsed")
        epoch = (
            datetime(*stamp[:6], tzinfo=timezone.utc).timestamp()
            if stamp
            else now
        )
        articles.append(
            Article(
                id=hashlib.blake2b(link.encode(), digest_size=10).hexdigest(),
                title=title,
                url=link,
                source=source.name,
                source_group=source.group,
                category=_bucket(title),
                published=epoch,
                summary=_clean(entry.get("summary") or entry.get("description")),
            )
        )
    return articles


@dataclass
class FeedReport:
    source: Source
    ok: bool
    count: int = 0
    error: str = ""
    articles: list[Article] = field(default_factory=list)


def fetch_source(source: Source, client: httpx.Client) -> FeedReport:
    try:
        payload = fetch_url(source.url, client)
        articles = _parse_feed(source, payload)
        if not articles:
            return FeedReport(source, False, error="feed returned no entries")
        return FeedReport(source, True, len(articles), articles=articles)
    except Exception as exc:  # noqa: BLE001 — one bad feed must not kill the sweep
        log.warning("feed %s failed: %s", source.name, exc)
        return FeedReport(source, False, error=str(exc)[:200])


def fetch_all(timeout: float = FETCH_TIMEOUT) -> tuple[list[Article], list[FeedReport]]:
    """Fetch every source concurrently. Returns (articles, per-source reports)."""
    headers = {
        "User-Agent": "CyberThreatIntelDashboard/1.0 (+local demo; contact: none)",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    }
    reports: list[FeedReport] = []
    with httpx.Client(headers=headers, timeout=timeout, follow_redirects=False) as client:
        with futures.ThreadPoolExecutor(max_workers=12) as pool:
            reports = list(pool.map(lambda s: fetch_source(s, client), SOURCES))
    articles = [a for r in reports for a in r.articles]
    # newest first, de-duplicated by id
    seen: set[str] = set()
    unique: list[Article] = []
    for a in sorted(articles, key=lambda x: x.published, reverse=True):
        if a.id not in seen:
            seen.add(a.id)
            unique.append(a)
    return unique, reports
