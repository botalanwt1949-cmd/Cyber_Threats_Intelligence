"""FastAPI backend for the Cyber Threats Intelligence dashboard.

Serves the static frontend and a small JSON API:
  /api/news    — aggregated RSS corpus (NewBee119/threat-intelligence sources)
  /api/threats — threat-level cards computed from the live corpus
  /api/vectors — 24h corpus keyword counts (real data, see vector_snapshot)
  /api/map-events — simulated global threat events for the map layer
  /api/threatmap — Check Point-style counter, attack feed, top countries
  /api/status  — health/uptime counters for the footer bar
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import feeds, sim

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("cti.main")

REFRESH_SECONDS = 300
DATA_DIR = Path(os.environ.get("CTI_DATA_DIR", "/app/data"))
CACHE_FILE = DATA_DIR / "cache.json"

SEVERITY_WORDS: dict[str, float] = {
    "critical": 3.0, "zero-day": 3.0, "actively exploited": 3.0, "ransomware": 2.5,
    "breach": 2.0, "backdoor": 2.0, "data leak": 2.0, "cve-": 2.0, "apt": 2.0,
    "malware": 1.5, "phishing": 1.5, "exploit": 1.5, "botnet": 1.5, "ddos": 1.2,
    "hack": 1.0, "vulnerability": 1.0, "spyware": 1.5, "stealer": 1.5, "patch": 0.5,
    # Chinese-language feeds (zer0yu Research / Gov / CERT sources)
    "勒索": 2.5, "后门": 2.0, "数据泄露": 2.0,
    "恶意": 1.5, "钓鱼": 1.5, "木马": 1.5, "病毒": 1.5, "挖矿": 1.5,
    "漏洞": 1.0, "攻击": 1.0,
}

BUCKETS = ("Global", "Cyber", "Business")

state: dict = {
    "articles": [],
    "reports": [],
    "last_fetch": 0.0,
    "started": time.time(),
    "ready": False,
}


def _score_severity(text: str) -> float:
    t = text.lower()
    return sum(w for k, w in SEVERITY_WORDS.items() if k in t)


def _save_cache() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps(
                {
                    "saved": time.time(),
                    "articles": [a.to_dict() for a in state["articles"]],
                    "last_fetch": state["last_fetch"],
                }
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        log.warning("cache write failed: %s", exc)


def _load_cache() -> None:
    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        state["articles"] = [feeds.Article(**a) for a in payload.get("articles", [])]
        state["last_fetch"] = float(payload.get("last_fetch", 0.0))
        state["ready"] = bool(state["articles"])
        log.info("cache loaded: %d articles", len(state["articles"]))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        log.info("no usable cache: %s", exc)


def refresh() -> None:
    """Blocking sweep of every source; swaps the corpus atomically."""
    articles, reports = feeds.fetch_all()
    if articles:
        state["articles"] = articles
        state["reports"] = reports
        state["last_fetch"] = time.time()
        state["ready"] = True
        _save_cache()
    else:
        log.warning("sweep produced no articles; keeping previous corpus")
    active = sum(1 for r in reports if r.ok)
    log.info("sweep done: %d articles from %d/%d sources",
             len(articles), active, len(feeds.SOURCES))


async def refresh_loop() -> None:
    while True:
        try:
            await asyncio.to_thread(refresh)
        except Exception as exc:  # noqa: BLE001
            log.error("refresh failed: %s", exc)
        await asyncio.sleep(REFRESH_SECONDS)


def build_threat_levels() -> list[dict]:
    now = time.time()
    levels = []
    for bucket in BUCKETS:
        arts = [a for a in state["articles"] if a.category == bucket and now - a.published < 86400]
        hourly = [0] * 24
        for a in arts:
            hourly[min(23, int((now - a.published) // 3600))] += 1
        spark = list(reversed(hourly))
        prev = [a for a in state["articles"] if a.category == bucket
                and 86400 <= now - a.published < 172800]
        delta = ((len(arts) - len(prev)) / len(prev) * 100.0) if prev else (100.0 if arts else 0.0)
        score = sum(_score_severity(a.title + " " + a.summary) for a in arts)
        density = score / max(1, len(arts))
        badge = "HIGH" if (density >= 1.8 and arts) or len(arts) >= 12 else (
            "MEDIUM" if density >= 0.9 and arts else ("LOW" if arts else "—"))
        latest = max(arts, key=lambda a: a.published, default=None)
        levels.append(
            {
                "name": bucket,
                "badge": badge,
                "count_24h": len(arts),
                "delta_pct": round(delta),
                "spark": spark,
                "severity_score": round(score, 1),
                "latest": (
                    {"title": latest.title, "age_s": int(now - latest.published), "source": latest.source}
                    if latest
                    else None
                ),
            }
        )
    return levels


def vector_snapshot() -> list[dict]:
    """Bottom-strip 'threat vector' mini-cards, from real keyword counts."""
    now = time.time()
    terms = ("phishing", "ransomware", "ddos", "malware", "cve", "apt")
    out = []
    for term in terms:
        hourly = [0] * 24
        for a in state["articles"]:
            if now - a.published > 86400:
                continue
            blob = (a.title + " " + a.summary).lower()
            if term in blob or (term == "cve" and "cve-" in blob):
                hourly[min(23, int((now - a.published) // 3600))] += 1
        spark = list(reversed(hourly))
        total = sum(spark)
        out.append({"name": term.upper(), "value": total, "spark": spark})
    return out


app = FastAPI(title="Cyber Threats Intelligence Dashboard", version="1.0.0")


@app.on_event("startup")
async def on_startup() -> None:
    _load_cache()
    asyncio.create_task(refresh_loop())


@app.get("/api/news")
async def api_news() -> JSONResponse:
    arts = state["articles"][:80]
    today = sum(1 for a in state["articles"] if time.time() - a.published < 86400)
    return JSONResponse(
        {
            "articles": [a.to_dict() for a in arts],
            "articles_today": today,
            "sources_active": sum(1 for r in state["reports"] if r.ok),
            "sources_total": len(feeds.SOURCES),
            "last_fetch": state["last_fetch"],
            "ready": state["ready"],
            "generated_at": time.time(),
        }
    )


@app.get("/api/threats")
async def api_threats() -> JSONResponse:
    return JSONResponse({"levels": build_threat_levels(), "generated_at": time.time()})


@app.get("/api/vectors")
async def api_vectors() -> JSONResponse:
    now = time.time()
    return JSONResponse({"vectors": vector_snapshot(), "generated_at": now})


@app.get("/api/map-events")
async def api_map_events() -> JSONResponse:
    now = time.time()
    cyber = sum(1 for a in state["articles"] if a.category == "Cyber")
    heat = 0.8 + min(1.7, cyber / 25.0)
    return JSONResponse(
        {
            "events": [e.to_dict() for e in sim.map_events(now, heat)],
            "moon": sim.moon_phase(now),
            "generated_at": now,
        }
    )


@app.get("/api/threatmap")
async def api_threatmap() -> JSONResponse:
    """Check Point-style threat-map payload: ticking daily counter, per-second
    attack feed, top targeted countries, daily series and legend counts.

    The counter/feed/ranking are deterministic simulations (see sim.py);
    the footer and README disclose this."""
    now = time.time()
    daily = sim.daily_attack_total(now)
    stream = sim.attack_stream(now)
    return JSONResponse(
        {
            "total_today": daily["total"],
            "rate_per_min": daily["rate_per_min"],
            "daily_series": sim.daily_series(now, 7),
            "attacks": stream,
            "top_countries": sim.country_ranking(now),
            "legend": sim.legend_counts(stream),
            "generated_at": now,
        }
    )


@app.get("/api/sources")
async def api_sources() -> JSONResponse:
    """Per-source and per-group health for the dashboard's SOURCES panel.

    Roster comes from feeds.SOURCES (stable even before the first sweep);
    ok/count/error join from the latest sweep reports by source name. Group
    article counts use the current corpus within a 24h window.
    """
    now = time.time()
    reports = {r.source.name: r for r in state["reports"]}
    articles_by_source: dict[str, int] = {}
    for a in state["articles"]:
        if now - a.published < 86400:
            articles_by_source[a.source] = articles_by_source.get(a.source, 0) + 1

    sources = []
    for src in feeds.SOURCES:
        rep = reports.get(src.name)
        sources.append(
            {
                "name": src.name,
                "group": src.group,
                "ok": bool(rep.ok) if rep else None,
                "count": rep.count if rep else 0,
                "error": "" if (rep and rep.ok) else (rep.error if rep else ""),
                "articles": articles_by_source.get(src.name, 0),
            }
        )

    groups = []
    for group in feeds.GROUPS:
        members = [s for s in sources if s["group"] == group]
        groups.append(
            {
                "name": group,
                "active": sum(1 for m in members if m["ok"]),
                "total": len(members),
                "articles": sum(m["articles"] for m in members),
            }
        )

    return JSONResponse(
        {
            "sources": sources,
            "groups": groups,
            "sources_active": sum(1 for s in sources if s["ok"]),
            "sources_total": len(feeds.SOURCES),
            "last_fetch": state["last_fetch"],
            "generated_at": now,
        }
    )


@app.get("/api/status")
async def api_status() -> JSONResponse:
    now = time.time()
    return JSONResponse(
        {
            "online": state["ready"],
            "articles_today": sum(1 for a in state["articles"] if now - a.published < 86400),
            "sources_active": sum(1 for r in state["reports"] if r.ok),
            "uptime_s": int(now - state["started"]),
            "last_fetch": state["last_fetch"],
            "version": app.version,
        }
    )


STATIC_DIR = Path(__file__).resolve().parent / "static"


@app.get("/")
async def index() -> FileResponse:
    # the HTML shell must always revalidate: it carries the versioned asset URLs
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/healthz")
async def healthz() -> dict:
    return {"ok": True}
