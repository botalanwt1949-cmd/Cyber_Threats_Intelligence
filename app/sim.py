"""Deterministic market / threat-event simulation for the dashboard.

Nothing here calls the network. Prices are an Ornstein–Uhlenbeck-style walk
seeded per (symbol, minute) so every client sees the same series and restarts
are reproducible. Threat events are seeded per 10-second tick and weighted by
live article severity counts passed in from the feed corpus.

The reference layout (STRATSIGHT AI demo) showed live ships/flights and
markets; this clone's event layer is an honest simulation — the footer and
README say so. Feed-driven panels (intel feed, threat levels, vectors) are
real, derived from the aggregated RSS corpus.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass

EPOCH = 1767225600  # 2026-01-01T00:00:00Z — fixed anchor for reproducibility


def _u01(key: str) -> float:
    """Deterministic uniform [0,1) from a blake2b digest of the key."""
    digest = hashlib.blake2b(key.encode(), digest_size=8).digest()
    return struct.unpack("<Q", digest)[0] / 2**64


# group, symbol, base price, display decimals, prefix
MARKETS: tuple[tuple[str, str, float, int, str], ...] = (
    ("indices", "SPY", 778.57, 2, ""),
    ("indices", "QQQ", 751.27, 2, ""),
    ("indices", "DIA", 516.11, 2, ""),
    ("stocks", "AAPL", 336.64, 2, ""),
    ("stocks", "GOOGL", 351.66, 2, ""),
    ("stocks", "MSFT", 534.82, 2, ""),
    ("security", "CRWD", 512.40, 2, ""),
    ("security", "PANW", 402.70, 2, ""),
    ("security", "FTNT", 96.42, 2, ""),
    ("security", "ZS", 208.35, 2, ""),
    ("security", "OKTA", 88.91, 2, ""),
    ("crypto", "BTC", 83712.0, 0, "$"),
    ("crypto", "ETH", 2547.0, 0, "$"),
    ("crypto", "SOL", 111.66, 2, "$"),
    ("crypto", "XRP", 1.40, 2, "$"),
)

WINDOW_MINUTES = 30  # sparkline depth
OU_DECAY = 0.96
OU_VOL = 0.006
OU_STEPS = 240


def _log_offset(symbol: str, minute_index: int) -> float:
    """Bounded OU accumulation over a fixed window ending at minute_index."""
    total = 0.0
    for j in range(min(OU_STEPS, minute_index + 1)):
        m = minute_index - j
        noise = (_u01(f"{symbol}:{m}") * 2.0 - 1.0)
        total += (OU_DECAY**j) * noise
    return total * OU_VOL


def _minute_index(now_ts: float) -> int:
    return int((now_ts - EPOCH) // 60)


def series(symbol: str, base: float, now_ts: float, points: int = WINDOW_MINUTES) -> list[float]:
    mi = _minute_index(now_ts)
    return [round(base * math.exp(_log_offset(symbol, mi - (points - 1 - i))), 6) for i in range(points)]


def market_snapshot(now_ts: float) -> dict:
    groups: dict[str, list[dict]] = {}
    for group, symbol, base, decimals, prefix in MARKETS:
        s = series(symbol, base, now_ts)
        price, prev = s[-1], s[0]
        change = (price / prev - 1.0) * 100.0 if prev else 0.0
        groups.setdefault(group, []).append(
            {
                "symbol": symbol,
                "price": round(price, decimals),
                "prefix": prefix,
                "change_pct": round(change, 2),
                "spark": [round(v, decimals) for v in s],
            }
        )
    return groups


# ---- map threat events -----------------------------------------------------

CITIES: tuple[tuple[str, float, float], ...] = (
    ("Washington D.C.", -77.04, 38.91), ("New York", -74.0, 40.71),
    ("Bogotá", -74.07, 4.71), ("São Paulo", -46.63, -23.55), ("Mexico City", -99.13, 19.43),
    ("London", -0.13, 51.51), ("Paris", 2.35, 48.86), ("Berlin", 13.40, 52.52),
    ("Madrid", -3.70, 40.42), ("Rome", 12.50, 41.90), ("Stockholm", 18.07, 59.33),
    ("Kyiv", 30.52, 50.45), ("Moscow", 37.62, 55.75), ("Istanbul", 28.98, 41.01),
    ("Tel Aviv", 34.78, 32.08), ("Dubai", 55.27, 25.20), ("Lagos", 3.38, 6.52),
    ("Nairobi", 36.82, -1.29), ("Johannesburg", 28.05, -26.20), ("New Delhi", 77.21, 28.61),
    ("Beijing", 116.41, 39.90), ("Hong Kong", 114.17, 22.32), ("Taipei", 121.56, 25.03),
    ("Seoul", 126.98, 37.57), ("Tokyo", 139.69, 35.69), ("Singapore", 103.82, 1.35),
    ("Jakarta", 106.85, -6.21), ("Sydney", 151.21, -33.87), ("Auckland", 174.76, -36.85),
    ("San Juan", -66.11, 18.47), ("Toronto", -79.38, 43.65), ("Amsterdam", 4.90, 52.37),
    ("Zurich", 8.54, 47.38), ("Warsaw", 21.01, 52.23), ("Hanoi", 105.85, 21.03),
)

TECHNIQUES: tuple[tuple[str, float], ...] = (  # label, weight
    ("SCAN", 0.26), ("PHISHING", 0.18), ("BRUTE FORCE", 0.14),
    ("MALWARE C2", 0.14), ("RANSOMWARE", 0.09), ("DDOS", 0.09),
    ("EXFIL", 0.06), ("ZERO-DAY", 0.04),
)


def _weighted_pick(r: float) -> str:
    acc = 0.0
    for label, weight in TECHNIQUES:
        acc += weight
        if r <= acc:
            return label
    return TECHNIQUES[0][0]


@dataclass(frozen=True)
class MapEvent:
    id: str
    kind: str  # "arc" or "pulse"
    a: int  # city index A (origin for arcs, site for pulses)
    b: int  # city index B (target for arcs)
    technique: str
    severity: int  # 0 low(cyan) 1 medium(orange) 2 high(red)

    def to_dict(self) -> dict:
        (name_a, lon_a, lat_a), (name_b, lon_b, lat_b) = CITIES[self.a], CITIES[self.b]
        return {
            "id": self.id,
            "kind": self.kind,
            "from": {"name": name_a, "lon": lon_a, "lat": lat_a},
            "to": {"name": name_b, "lon": lon_b, "lat": lat_b},
            "technique": self.technique,
            "severity": self.severity,
        }


def map_events(now_ts: float, heat: float = 1.0, window: int = 6) -> list[MapEvent]:
    """Events for one 10s window. heat scales the count with live feed volume."""
    tick = int(now_ts // 10)
    base = 8 + int(math.ceil(6 * min(max(heat, 0.2), 2.5)))
    count = base + int(_u01(f"n:{tick}") * 5)
    events: list[MapEvent] = []
    for i in range(count):
        tick_i = tick - (i % window)  # stagger events over the window for smooth arrival
        a = int(_u01(f"a:{tick_i}:{i}") * len(CITIES)) % len(CITIES)
        b = int(_u01(f"b:{tick_i}:{i}") * len(CITIES)) % len(CITIES)
        if a == b:
            b = (b + 1 + int(_u01(f"bb:{tick_i}:{i}") * (len(CITIES) - 1))) % len(CITIES)
        sev_r = _u01(f"s:{tick_i}:{i}")
        severity = 0 if sev_r < 0.68 else (1 if sev_r < 0.92 else 2)
        kind = "arc" if _u01(f"k:{tick_i}:{i}") < 0.72 else "pulse"
        technique = _weighted_pick(_u01(f"t:{tick_i}:{i}"))
        events.append(MapEvent(f"{tick_i}-{i}", kind, a, b, technique, severity))
    return events


def moon_phase(now_ts: float) -> dict:
    """Cosmetic moon phase, synodic approximation from a known new moon."""
    synodic = 29.530588853
    known_new_moon = 1737667200  # 2025-01-23T00:00:00Z-ish new moon anchor
    age = ((now_ts - known_new_moon) % (synodic * 86400)) / 86400
    frac = age / synodic
    names = ("New Moon", "Waxing Crescent", "First Quarter", "Waxing Gibbous",
             "Full Moon", "Waning Gibbous", "Last Quarter", "Waning Crescent")
    idx = int(frac * 8) % 8
    glyphs = ("🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘")
    return {"name": names[idx], "glyph": glyphs[idx], "percent": round(frac * 100)}
