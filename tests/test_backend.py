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


def test_sources_groups_known():
    # every source's group must appear in the dashboard chip taxonomy,
    # and GROUPS must not drift away from the roster
    assert set(s.group for s in feeds.SOURCES) == set(feeds.GROUPS)


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


def test_api_vectors_contract(client):
    data = client.get("/api/vectors").json()
    assert len(data["vectors"]) == 6
    for v in data["vectors"]:
        assert v["name"] in ("PHISHING", "RANSOMWARE", "DDOS", "MALWARE", "CVE", "APT")
        assert len(v["spark"]) == 24


def test_api_status_and_health(client):
    status = client.get("/api/status").json()
    assert status["online"] is True
    assert status["uptime_s"] >= 0
    assert client.get("/api/healthz").json() == {"ok": True}


def _seed_reports():
    by_name = {s.name: s for s in feeds.SOURCES}
    return [
        feeds.FeedReport(by_name["Securelist"], True, 5),
        feeds.FeedReport(by_name["CrowdStrike Blog"], False, 0, error="boom"),
    ]


@pytest.fixture()
def client_reports(monkeypatch):
    # the stub must return the seeded reports too: startup fires refresh_loop
    # immediately, and refresh() overwrites state["reports"] with the stub's
    # second element
    monkeypatch.setattr(
        main.feeds, "fetch_all", lambda *a, **k: (_seed_articles(), _seed_reports())
    )
    main.state["articles"] = _seed_articles()
    main.state["reports"] = _seed_reports()
    main.state["last_fetch"] = time.time()
    main.state["ready"] = True
    with TestClient(main.app) as c:
        yield c


def test_api_sources_contract(client):
    data = client.get("/api/sources").json()
    assert data["sources_total"] == len(feeds.SOURCES)
    assert len(data["sources"]) == len(feeds.SOURCES)
    for src in data["sources"]:
        for key in ("name", "group", "ok", "count", "error", "articles"):
            assert key in src
    # group rollup must reconcile with the roster and keep the display order
    assert [g["name"] for g in data["groups"]] == list(feeds.GROUPS)
    assert sum(g["total"] for g in data["groups"]) == len(feeds.SOURCES)
    assert data["sources_active"] == 0  # no sweep reports in this fixture
    # every group carries a latest-headlines list (full corpus, any age)
    assert all(isinstance(g["latest"], list) for g in data["groups"])
    trad = next(g for g in data["groups"] if g["name"] == "Traditional")
    assert trad["latest"] and trad["latest"][0]["source"] == "Securelist"


def test_api_sources_reports_join(client_reports):
    data = client_reports.get("/api/sources").json()
    by_name = {s["name"]: s for s in data["sources"]}
    assert by_name["Securelist"]["ok"] is True
    assert by_name["Securelist"]["count"] == 5
    assert by_name["Securelist"]["error"] == ""
    assert by_name["CrowdStrike Blog"]["ok"] is False
    assert by_name["CrowdStrike Blog"]["error"] == "boom"
    assert by_name["Talos Intelligence"]["ok"] is None  # absent from this sweep
    # Securelist articles come from the seeded corpus, not the report count
    assert by_name["Securelist"]["articles"] == 6


def test_bucket_security_vocabulary():
    assert feeds._bucket("A Critical SSH Password Bypass Hits musl-Based Linux") == "Cyber"
    assert feeds._bucket("Virtualization security: attack layers and misconfiguration") == "Cyber"
    assert feeds._bucket("How to navigate the SIEM correlation rule set") == "Cyber"
    assert feeds._bucket("Bring a tent, I've got the coffee: Lessons from it-sa") == "Global"


def test_bucket_chinese_vocabulary():
    # Chinese-language sources (zer0yu Research / Gov / CERT) must classify too
    assert feeds._bucket("新型勒索软件针对制造业企业发起攻击") == "Cyber"
    assert feeds._bucket("Xuanwu Lab 发布本周安全漏洞情报") == "Cyber"
    assert feeds._bucket("团队发布年度技术总结文章") == "Global"


def test_severity_chinese_words():
    # 勒索(2.5) + 攻击(1.0) must clear the ransomware-level floor
    assert main._score_severity("新型勒索软件攻击") >= 3.0


# ---------- threat-map clone (Check Point style, /api/threatmap) ----------

def test_daily_attack_total_deterministic_and_ticking():
    ts = 1_900_000_000
    assert sim.daily_attack_total(ts) == sim.daily_attack_total(ts)
    day = sim.daily_attack_total(ts)
    assert day["total"] > 0
    assert 200 <= day["rate_per_min"] <= 400
    assert sim.daily_attack_total(ts + 60)["total"] >= day["total"]


def test_daily_series_shape():
    series = sim.daily_series(1_900_000_000, days=7)
    assert len(series) == 7
    assert all(v > 10_000_000 for v in series)


def test_attack_stream_shape_and_determinism():
    ts = 1_900_000_000.0
    s1, s2 = sim.attack_stream(ts), sim.attack_stream(ts)
    assert s1 == s2
    assert 1 <= len(s1) <= 20
    for item in s1:
        assert item["category"] in ("malware", "phishing", "exploit")
        assert item["name"]
        assert item["from"] != item["to"]
        assert item["ts"] <= ts


def test_country_ranking_shape():
    rows = sim.country_ranking(1_900_000_000)
    assert len(rows) == 5
    assert len({r["name"] for r in rows}) == 5
    rates = [r["rate"] for r in rows]
    assert rates == sorted(rates, reverse=True)


def test_legend_counts():
    stream = sim.attack_stream(1_900_000_000)
    counts = sim.legend_counts(stream)
    assert set(counts) == {"malware", "phishing", "exploit"}
    assert sum(counts.values()) == len(stream)


def test_map_events_carry_category():
    for e in sim.map_events(1_900_000_000, heat=1.0):
        d = e.to_dict()
        assert d["category"] in ("malware", "phishing", "exploit")
        assert d["from_country"] and d["to_country"]


def test_api_threatmap_contract(client):
    data = client.get("/api/threatmap").json()
    assert data["total_today"] > 0
    assert len(data["daily_series"]) == 7
    assert 1 <= len(data["attacks"]) <= 20
    assert len(data["top_countries"]) == 5
    assert set(data["legend"]) == {"malware", "phishing", "exploit"}
    attack = data["attacks"][0]
    for key in ("id", "name", "category", "from", "to", "ts"):
        assert key in attack
