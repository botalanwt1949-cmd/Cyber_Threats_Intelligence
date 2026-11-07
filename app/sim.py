"""Deterministic threat-event simulation for the dashboard.

Nothing here calls the network. Threat events are seeded per 10-second tick
and weighted by live article severity counts passed in from the feed corpus.

The reference layout (STRATSIGHT AI demo) showed live ships/flights and
markets; this clone keeps only the honest event layer — the footer and
README say so. Feed-driven panels (intel feed, threat levels, vectors,
category cards) are real, derived from the aggregated RSS corpus.
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
            "category": TECH_CATEGORY.get(self.technique, "exploit"),
            "from_country": _country(self.a)[0],
            "to_country": _country(self.b)[0],
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


# ---- Check Point-style threat-map layer ------------------------------------
# Cloned vocabulary/behaviour from the reference threat map (REA capture,
# 2026-11-06): per-second attack feed with CVE-style names, a ticking daily
# attack counter, a top-targeted-countries ranking and a 3-category legend
# (Malware / Phishing / Exploit). All values are deterministic simulations.

COUNTRY_OF: tuple[tuple[str, str], ...] = (  # parallel to CITIES: (country, iso2)
    ("United States", "US"), ("United States", "US"), ("Colombia", "CO"),
    ("Brazil", "BR"), ("Mexico", "MX"), ("United Kingdom", "GB"),
    ("France", "FR"), ("Germany", "DE"), ("Spain", "ES"), ("Italy", "IT"),
    ("Sweden", "SE"), ("Ukraine", "UA"), ("Russia", "RU"), ("Türkiye", "TR"),
    ("Israel", "IL"), ("United Arab Emirates", "AE"), ("Nigeria", "NG"),
    ("Kenya", "KE"), ("South Africa", "ZA"), ("India", "IN"), ("China", "CN"),
    ("Hong Kong", "HK"), ("Taiwan", "TW"), ("South Korea", "KR"), ("Japan", "JP"),
    ("Singapore", "SG"), ("Indonesia", "ID"), ("Australia", "AU"),
    ("New Zealand", "NZ"), ("Puerto Rico", "PR"), ("Canada", "CA"),
    ("Netherlands", "NL"), ("Switzerland", "CH"), ("Poland", "PL"),
    ("Vietnam", "VN"),
)

ATTACK_NAMES: tuple[str, ...] = (
    "OpenSSL TLS Protocol Downgrade", "Suspicious Payloads Over HTTP Headers",
    "Python Server-Side Template Injection", "Multiple SSH Initial Connection Requests",
    "GIMP Integer Overflow (CVE-2025-54239)", "Microsoft Windows RDP Brute Force",
    "Fortinet SSL VPN Heap Overflow", "Ivanti Connect Secure Auth Bypass",
    "Apache Struts OGNL Injection", "Confluence OGNL Query Injection",
    "Log4j JNDI Remote Code Execution", "SMBv1 EternalBlue Exploit Attempt",
    "Exchange ProxyLogon SSRF Chain", "Citrix Bleed Session Token Leak",
    "WordPress Plugin SQL Injection", "Redis Unauthenticated RCE Probe",
    "DNS Amplification Reflection Flood", "Credential Stuffing Burst on OWA",
    "Cobalt Strike Beacon C2 Callback", "Emotet Loader Download Attempt",
    "Phishing Kit Credential Harvest", "Maldoc Macro Dropper Delivery",
    "Kernel Driver Privilege Escalation", "Zerologon Netlogon Elevation",
    "GoAnywhere MFT Deserialization", "PaperCut Print Server RCE Probe",
)

TECH_CATEGORY: dict[str, str] = {
    "RANSOMWARE": "malware", "MALWARE C2": "malware", "EXFIL": "malware",
    "PHISHING": "phishing",
    "SCAN": "exploit", "BRUTE FORCE": "exploit", "DDOS": "exploit",
    "ZERO-DAY": "exploit",
}

RANK_POOL: tuple[tuple[str, str], ...] = (  # (country, iso2) candidates for daily ranking
    ("Ethiopia", "ET"), ("Nigeria", "NG"), ("Mongolia", "MN"), ("Uzbekistan", "UZ"),
    ("Indonesia", "ID"), ("United States", "US"), ("India", "IN"), ("Brazil", "BR"),
    ("United Kingdom", "GB"), ("Türkiye", "TR"), ("Vietnam", "VN"),
    ("South Africa", "ZA"), ("Ukraine", "UA"), ("Spain", "ES"), ("Mexico", "MX"),
)


def _country(i: int) -> tuple[str, str]:
    return COUNTRY_OF[i % len(COUNTRY_OF)]


def daily_attack_total(now_ts: float) -> dict:
    """Ticking 'attacks on this day' counter: deterministic per UTC day."""
    day = int(now_ts // 86400)
    base = 11_500_000 + int(_u01(f"day:{day}") * 2_500_000)      # 11.5M–14M per day
    rate = 3.5 + _u01(f"rate:{day}") * 2.5                        # 3.5–6.0 attacks/s
    sod = max(0.0, now_ts - day * 86400)
    return {
        "total": base + int(sod * rate),
        "base": base,
        "rate_per_min": round(rate * 60.0),
    }


def daily_series(now_ts: float, days: int = 7) -> list[int]:
    """Recent daily totals, oldest → newest (today is partial)."""
    day = int(now_ts // 86400)
    out = []
    for d in range(day - days + 1, day + 1):
        base = 11_500_000 + int(_u01(f"day:{d}") * 2_500_000)
        if d == day:
            base += int(max(0.0, now_ts - d * 86400) * (3.5 + _u01(f"rate:{d}") * 2.5))
        out.append(base)
    return out


def attack_stream(now_ts: float, count: int = 14) -> list[dict]:
    """Per-second attack feed, newest first: CVE-style name + country route."""
    sec = int(now_ts)
    out = []
    for i in range(count):
        s = sec - i
        name = ATTACK_NAMES[int(_u01(f"asn:{s}:{i}") * len(ATTACK_NAMES)) % len(ATTACK_NAMES)]
        technique = _weighted_pick(_u01(f"ast:{s}:{i}"))
        a = int(_u01(f"asa:{s}:{i}") * len(CITIES)) % len(CITIES)
        b = int(_u01(f"asb:{s}:{i}") * len(CITIES)) % len(CITIES)
        if a == b:
            b = (b + 1) % len(CITIES)
        out.append({
            "id": f"atk-{s}-{i}",
            "ts": float(s),
            "name": name,
            "technique": technique,
            "category": TECH_CATEGORY.get(technique, "exploit"),
            "from": _country(a)[0],
            "to": _country(b)[0],
        })
    return out


def country_ranking(now_ts: float, top: int = 5) -> list[dict]:
    """Top targeted countries for the current UTC day (deterministic order)."""
    day = int(now_ts // 86400)
    scored = sorted(
        RANK_POOL,
        key=lambda c: (_u01(f"rank:{day}:{c[1]}"), c[1]),
        reverse=True,
    )[:top]
    return [
        {"name": name, "code": code, "rate": round(96.0 - i * 9.0
         + _u01(f"rr:{day}:{code}") * 6.0, 1)}
        for i, (name, code) in enumerate(scored)
    ]


def legend_counts(stream: list[dict]) -> dict[str, int]:
    counts = {"malware": 0, "phishing": 0, "exploit": 0}
    for item in stream:
        cat = item.get("category", "exploit")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


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
