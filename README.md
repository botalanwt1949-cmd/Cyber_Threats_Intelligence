# Cyber Threats Intelligence — Command Desk

A single-screen, dark command-center dashboard for cyber threat intelligence.
The **layout is cloned from the "STRATSIGHT AI" reference** (demo video:
<https://youtu.be/Zl-vqITIeqU>) — header with news ticker and world clocks,
left intel feed, center live world map, right market/threat panels, bottom
stat strip, footer status bar — re-purposed for cyber threat intel.

![layout parity](docs/evidence/S_full_layout.png)

## What it does

| Region | Content |
|---|---|
| Header | Brand, scrolling latest-headlines ticker, 5 zone clocks (UTC/LON/MOW/BEI/TYO), LIVE badge |
| Left | **INTEL FEED** — live RSS aggregation from the sources curated in [NewBee119/threat-intelligence](https://github.com/NewBee119/threat-intelligence) (general / ICS / endpoint / mobile / threat-intel / traditional-security sections) + WORLD CLOCKS |
| Center | Global threat-event map: animated attack arcs & pulses (cyan = low, orange = medium, red = critical), terminator dome, city labels, **FLAT / 3D / HYBRID / GLOBE** views, ATTACKS toggle, +EVENTS burst, moon phase |
| Right | MARKETS & CRYPTO tickers (simulated), **THREAT LEVELS** (Global / Cyber / Business — computed from the live article corpus: 24h counts, delta, hourly sparkline, severity badge, latest headline) |
| Bottom | MARKETS / SECURITY STOCKS / THREAT VECTORS / CRYPTO mini-cards with sparklines (vectors are real keyword counts from the corpus) |
| Footer | ● ONLINE, ARTICLES TODAY, SOURCES ACTIVE, UPTIME, LAST FETCH |

**Honesty note:** the intel feed, threat levels and threat vectors are real
(derived from the aggregated RSS corpus). The map events and market tickers are
**deterministic simulations** (seeded, reproducible) — the footer says
`EVENTS: SIMULATED · FEEDS: LIVE`.

## Run (Docker)

```bash
docker compose up -d --build
# → http://127.0.0.1:8092   (loopback-only binding)
```

Health: `curl http://127.0.0.1:8092/api/healthz`

## Tests

```bash
docker run --rm -v "$PWD:/src:ro" -w /src -e PYTHONDONTWRITEBYTECODE=1 \
  python:3.12 sh -c "pip install -q -r requirements.txt -r requirements-dev.txt && \
                     python -m pytest tests/ -q -p no:cacheprovider"
```

23 tests: SSRF guard (scheme/host/DNS checks), feed parsing & classification,
simulation determinism, and API contracts — all run inside a container.

## Security posture

- **SSRF guard** on every outbound fetch: http/https only, domain allowlist
  (the curated source list), DNS resolution checked against loopback / private /
  link-local / reserved addresses, manual redirect validation, 2 MB byte cap.
- Container runs as **non-root** (uid 10001), `no-new-privileges`, host port
  bound to **127.0.0.1** only.
- No secrets in code; no runtime CDN dependencies — d3, topojson-client,
  Natural Earth 110m TopoJSON and JetBrains Mono are vendored in
  `app/static/vendor/` (pinned versions, ISC/OFL-licensed).

## API

`/api/news` · `/api/threats` · `/api/markets` · `/api/map-events` ·
`/api/status` · `/api/healthz` — plain JSON, no auth (loopback demo).

## Layout parity evidence

`docs/evidence/verify.jsonl` is the verification ledger; composites live in
`docs/evidence/` (SRC = reference frame @4.8s/18.6s, REP = live dashboard
screenshot at 1920×1080).
