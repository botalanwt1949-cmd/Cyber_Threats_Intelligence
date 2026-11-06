"""Unit tests: SSRF guard, feed parsing, simulation determinism, API contracts."""

from __future__ import annotations

import socket
import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import feeds, main, sim


# ---------- SSRF guard ----------

@pytest.mark.parametrize("url", [
    "ftp://example.com/feed",
    "file:///etc/passwd",
    "http://127.0.0.1/x",
    "http://localhost/x",
    "http://10.0.0.5/x",
    "http://192.168.1.1/x",
    "http://172.16.0.9/x",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]/x",
    "http://0.0.0.0/x",
])
def test_assert_public_url_rejects(url, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ValueError):
        feeds.assert_public_url(url)


def test_assert_public_url_allows_public(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, None, 6, "", ("93.184.216.34", 443))])
    assert feeds.assert_public_url("https://securelist.com/feed/") == "https://securelist.com/feed/"


def test_fetch_url_rejects_off_allowlist_host():
    with pytest.raises(ValueError, match="allowlist"):
        with feeds.httpx.Client() as client:
            feeds.fetch_url("https://evil.example.com/feed", client)


def test_sources_are_https_and_unique():
    hosts = [s.url.split("/")[2] for s in feeds.SOURCES]
    assert all(s.url.startswith("https://") for s in feeds.SOURCES)
    assert len(hosts) == len(set(hosts))


# ---------- classification / parsing ----------

def test_bucket_classification():
    assert feeds._bucket("New Ransomware Campaign Hits Hospitals") == "Cyber"
    assert feeds._bucket("Chip Maker Sees Record Revenue") == "Business"
    assert feeds._bucket("Election Results Announced") == "Global"


def test_parse_feed_extracts_articles():
    rss = b"""<?xml version="1.0"?><rss version="2.0"><channel>
      <title>T</title><item>
        <title>Zero-Day Exploit Sold &amp; Traded</title>
        <link>https://securelist.com/post-1</link>
        <pubDate>Tue, 03 Jun 2025 09:39:21 +0000</pubDate>
        <description>&lt;p&gt;body text&lt;/p&gt;</description>
      </item></channel></rss>"""
    src = feeds.Source("Securelist", "https://securelist.com/feed/", "Traditional")
    arts = feeds._parse_feed(src, rss)
    assert len(arts) == 1
    a = arts[0]
    assert a.category == "Cyber"
    assert a.title == "Zero-Day Exploit Sold & Traded"
    assert a.summary == "body text"
    assert a.published == datetime(2025, 6, 3, 9, 39, 21, tzinfo=timezone.utc).timestamp()


# ---------- simulation ----------

def test_market_snapshot_deterministic():
    now = time.time()
    a = sim.market_snapshot(now)
    b = sim.market_snapshot(now)
    assert a == b
    btc = next(q for q in a["crypto"] if q["symbol"] == "BTC")
    assert btc["prefix"] == "$"
    assert len(btc["spark"]) == sim.WINDOW_MINUTES


def test_map_events_shape():
    events = sim.map_events(1_900_000_000, heat=1.0)
    assert 8 <= len(events) <= 21
    for e in events:
        assert e.severity in (0, 1, 2)
        assert e.a != e.b
        assert e.kind in ("arc", "pulse")
        d = e.to_dict()
        assert d["from"]["name"] != d["to"]["name"]


def test_moon_phase_bounds():
    m = sim.moon_phase(1_900_000_000)
    assert m["name"] in ("New Moon", "Waxing Crescent", "First Quarter", "Waxing Gibbous",
                         "Full Moon", "Waning Gibbous", "Last Quarter", "Waning Crescent")
    assert 0 <= m["percent"] <= 100


# ---------- API contracts (offline: fetch_all is stubbed) ----------

def _seed_articles():
    now = time.time()
    return [
        feeds.Article(id=f"a{i}", title="Ransomware Attack on Utility Firm",
                      url="https://example.com/x", source="Securelist",
                      source_group="Traditional", category="Cyber",
                      published=now - 3600 * i, summary="cyber detail")
        for i in range(6)
    ]


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main.feeds, "fetch_all", lambda *a, **k: (_seed_articles(), []))
    main.state["articles"] = _seed_articles()
    main.state["reports"] = []
    main.state["last_fetch"] = time.time()
    main.state["ready"] = True
    with TestClient(main.app) as c:
        yield c


def test_api_news_contract(client):
    data = client.get("/api/news").json()
    assert data["ready"] is True
    assert len(data["articles"]) == 6
    art = data["articles"][0]
    for key in ("id", "title", "url", "source", "category", "published"):
        assert key in art


def test_api_threats_contract(client):
    data = client.get("/api/threats").json()
    names = [lv["name"] for lv in data["levels"]]
    assert names == ["Global", "Cyber", "Business"]
    for lv in data["levels"]:
        assert lv["badge"] in ("HIGH", "MEDIUM", "LOW", "—")
        assert len(lv["spark"]) == 24


def test_api_markets_contract(client):
    data = client.get("/api/markets").json()
    assert {g["symbol"] for g in data["indices"]} == {"SPY", "QQQ", "DIA"}
    assert len(data["vectors"]) == 6


def test_api_status_and_health(client):
    status = client.get("/api/status").json()
    assert status["online"] is True
    assert status["uptime_s"] >= 0
    assert client.get("/api/healthz").json() == {"ok": True}


def test_bucket_security_vocabulary():
    assert feeds._bucket("A Critical SSH Password Bypass Hits musl-Based Linux") == "Cyber"
    assert feeds._bucket("Virtualization security: attack layers and misconfiguration") == "Cyber"
    assert feeds._bucket("How to navigate the SIEM correlation rule set") == "Cyber"
    assert feeds._bucket("Bring a tent, I've got the coffee: Lessons from it-sa") == "Global"
