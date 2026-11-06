/* Dashboard controller: polls the API, renders panels, drives the map layer. */
/* global CTIMap */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const ZONES = [
    { lbl: 'UTC', tz: 'UTC' },
    { lbl: 'LON', tz: 'Europe/London' },
    { lbl: 'MOW', tz: 'Europe/Moscow' },
    { lbl: 'BEI', tz: 'Asia/Shanghai' },
    { lbl: 'TYO', tz: 'Asia/Tokyo' },
  ];
  const WCLOCKS = [
    { lbl: 'SYDNEY', tz: 'Australia/Sydney', gmt: 'GMT+11' },
    { lbl: 'TOKYO', tz: 'Asia/Tokyo', gmt: 'GMT+9' },
    { lbl: 'BEIJING', tz: 'Asia/Shanghai', gmt: 'GMT+8' },
  ];

  function fmtClock(tz) {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).format(new Date());
  }
  function fmtTime(ts) {
    if (!ts) return '--:--:--';
    return new Date(ts * 1000).toLocaleTimeString('en-GB', { hour12: false });
  }
  function ageLabel(seconds) {
    if (seconds < 60) return 'now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    return Math.floor(seconds / 86400) + 'd ago';
  }
  function sparkPath(values, w, h, color, pad = 1.5) {
    if (!values || values.length < 2) return '';
    const min = Math.min(...values), max = Math.max(...values);
    const span = (max - min) || 1;
    const pts = values.map((v, i) => {
      const x = pad + (i / (values.length - 1)) * (w - pad * 2);
      const y = h - pad - ((v - min) / span) * (h - pad * 2);
      return x.toFixed(1) + ',' + y.toFixed(1);
    });
    return `<svg class="mini-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">` +
      `<polyline points="${pts.join(' ')}" fill="none" stroke="${color}" stroke-width="1.4"/></svg>`;
  }
  function quoteSpark(values, color) {
    return `<svg class="quote-spark" viewBox="0 0 74 18" preserveAspectRatio="none">` +
      `<polyline fill="none" stroke="${color}" stroke-width="1.3" points="${sparkPoints(values, 74, 18)}"/></svg>`;
  }
  function sparkPoints(values, w, h) {
    const min = Math.min(...values), max = Math.max(...values), span = (max - min) || 1;
    return values.map((v, i) =>
      `${(1 + (i / (values.length - 1)) * (w - 2)).toFixed(1)},` +
      `${(h - 2 - ((v - min) / span) * (h - 4)).toFixed(1)}`).join(' ');
  }

  // ---------- header ----------
  function renderHeaderClocks() {
    $('hdr-clocks').innerHTML = ZONES.map((z) =>
      `<div class="hdr-clock"><span class="lbl">${z.lbl}</span><span class="val">${fmtClock(z.tz)}</span></div>`
    ).join('');
  }
  function renderWorldClocks() {
    const d = new Date();
    $('world-clocks').innerHTML = WCLOCKS.map((z) => {
      const gmt = 'GMT' + (d.toLocaleString('en-US', { timeZone: z.tz, timeZoneName: 'shortOffset' })
        .match(/GMT[+-]\d+/)?.[0]?.replace('GMT', '') || z.gmt.replace('GMT', ''));
      return `<div class="wclock"><div class="lbl">${z.lbl}</div>` +
        `<div class="val">${fmtClock(z.tz)}</div><div class="sub">${d.toLocaleDateString('en-GB', { timeZone: z.tz, weekday: 'short', day: '2-digit', month: 'short' })} · ${gmt}</div></div>`;
    }).join('');
  }
  let tickerItems = [];
  function renderTicker() {
    if (!tickerItems.length) return;
    const line = tickerItems.slice(0, 6).map((a) =>
      `<span class="tick-text">[<span class="tick-time">${fmtTime(a.published)}</span>] ${esc(a.title)} <span class="tick-src">— ${esc(a.source)}</span></span>`
    ).join(' &nbsp;·&nbsp; ');
    $('ticker').innerHTML = line + ' &nbsp;·&nbsp; ' + line; // duplicated for seamless marquee
  }

  // ---------- left: news ----------
  let knownIds = new Set();
  function renderNews(payload) {
    $('feed-count').textContent = `${payload.articles_today || payload.articles.length} ARTICLES`;
    const fresh = payload.articles.filter((a) => !knownIds.has(a.id)).slice(0, 3).map((a) => a.id);
    payload.articles.forEach((a) => knownIds.add(a.id));
    $('news-list').innerHTML = payload.articles.slice(0, 40).map((a) => {
      const t = new Date(a.published * 1000);
      return `<li class="news-item ${fresh.includes(a.id) ? 'fresh' : ''}" data-url="${esc(a.url)}">` +
        `<div class="news-meta"><span class="news-cat">${esc(a.category.toUpperCase())}</span>` +
        `<span class="news-time">${t.toLocaleTimeString('en-GB', { hour12: false })}</span></div>` +
        `<div class="news-title">${esc(a.title)}</div>` +
        `<div class="news-src">${esc(a.source)} · ${esc(a.source_group)}</div></li>`;
    }).join('');
    tickerItems = payload.articles.slice(0, 6);
    renderTicker();
  }

  // ---------- right: quotes + threats ----------
  function quoteRow(q) {
    const up = q.change_pct >= 0;
    return `<li class="quote-row"><span class="quote-sym">${esc(q.symbol)}</span>` +
      `<span class="quote-price">${q.prefix || ''}${q.price.toLocaleString('en-US', { minimumFractionDigits: 0 })} ` +
      `<span class="${up ? 'quote-up' : 'quote-down'}">${up ? '+' : ''}${q.change_pct.toFixed(2)}%</span></span>` +
      `${quoteSpark(q.spark, up ? '#2fd575' : '#ff5d5d')}</li>`;
  }
  function renderMarkets(payload) {
    $('markets-list').innerHTML = (payload.indices || []).concat(payload.stocks || []).slice(0, 6).map(quoteRow).join('');
    $('crypto-list').innerHTML = (payload.crypto || []).map(quoteRow).join('');
    renderMiniStrip(payload);
  }
  const GROUPS = [
    { key: 'indices', title: 'MARKETS' },
    { key: 'security', title: 'SECURITY STOCKS' },
    { key: 'vectors', title: 'THREAT VECTORS' },
    { key: 'cryptoMini', title: 'CRYPTO' },
  ];
  function renderMiniStrip(payload) {
    const miniCrypto = (payload.crypto || []).slice(0, 4);
    $('ministrip').innerHTML = GROUPS.map((g) => {
      let cells = '';
      if (g.key === 'vectors') {
        cells = (payload.vectors || []).map((v) => {
          const vals = v.spark.length ? v.spark : [0, 0];
          const trend = vals[vals.length - 1] >= vals[0];
          return `<div class="mini-cell"><span class="mini-name">${esc(v.name)}</span>` +
            `<span class="mini-val">${v.value}</span>` +
            sparkPath(vals, 86, 16, trend ? '#2fd575' : '#ff9f1a') + '</div>';
        }).join('');
      } else {
        const list = g.key === 'cryptoMini' ? miniCrypto : (payload[g.key] || []);
        cells = list.map((q) => {
          const up = q.change_pct >= 0;
          return `<div class="mini-cell"><span class="mini-name">${esc(q.symbol)}</span>` +
            `<span class="mini-val ${up ? 'up' : 'down'}">${q.prefix || ''}${q.price.toLocaleString('en-US')}</span>` +
            sparkPath(q.spark, 86, 16, up ? '#2fd575' : '#ff5d5d') + '</div>';
        }).join('');
      }
      return `<div class="mini-group"><div class="mini-title">${g.title}</div><div class="mini-rows">${cells}</div></div>`;
    }).join('');
  }
  function renderThreats(payload) {
    $('threat-levels').innerHTML = (payload.levels || []).map((lv) => {
      const cls = lv.badge === 'HIGH' ? '' : `lv-${lv.badge.toLowerCase()}`;
      const delta = lv.delta_pct >= 0 ? `+${lv.delta_pct}%` : `${lv.delta_pct}%`;
      return `<div class="tl-card ${cls}">` +
        `<div class="tl-head"><span class="tl-name">${esc(lv.name)}</span><span class="tl-badge">${esc(lv.badge)}</span></div>` +
        `<span class="tl-pill">AI · ${esc(lv.badge)}</span>` +
        `<div class="tl-nums"><b>${lv.count_24h}</b> / 24h &nbsp; <b>${delta}</b></div>` +
        `<svg class="tl-spark" viewBox="0 0 240 30" preserveAspectRatio="none">` +
        `<polyline fill="none" stroke="#ff9f1a" stroke-width="1.6" points="${sparkPoints(lv.spark, 240, 30)}"/></svg>` +
        (lv.latest ? `<div class="tl-latest"><span>${esc(lv.latest.title.slice(0, 90))}</span>` +
          `<span class="age">${ageLabel(lv.latest.age_s)}</span></div>` : '') +
        '</div>';
    }).join('');
  }

  // ---------- footer ----------
  function renderStatus(s) {
    $('status-dot').className = 'dot' + (s.online ? '' : ' off');
    $('status-text').textContent = s.online ? 'ONLINE' : 'SYNCING';
    $('st-articles').textContent = s.articles_today ?? 0;
    $('st-sources').textContent = `${s.sources_active ?? 0}`;
    $('st-uptime').textContent = uptimeLabel(s.uptime_s || 0);
    $('st-fetch').textContent = fmtTime(s.last_fetch);
  }
  function uptimeLabel(sec) {
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    return [h, m, s].map((v) => String(v).padStart(2, '0')).join(':');
  }

  // ---------- polling ----------
  async function getJSON(url) {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error(`${url} → ${res.status}`);
    return res.json();
  }

  async function pollNews() { try { renderNews(await getJSON('/api/news')); } catch (e) { console.warn(e); } }
  async function pollMarkets() { try { renderMarkets(await getJSON('/api/markets')); } catch (e) { console.warn(e); } }
  async function pollThreats() { try { renderThreats(await getJSON('/api/threats')); } catch (e) { console.warn(e); } }
  async function pollStatus() { try { renderStatus(await getJSON('/api/status')); } catch (e) { console.warn(e); } }
  async function pollEvents() {
    try { CTIMap.setEvents(await getJSON('/api/map-events')); } catch (e) { console.warn(e); }
  }

  // ---------- controls ----------
  document.querySelectorAll('.map-tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.map-tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      CTIMap.setView(btn.dataset.view);
    });
  });
  $('btn-arcs').addEventListener('click', (e) => {
    const on = !e.currentTarget.classList.contains('active');
    e.currentTarget.classList.toggle('active', on);
    CTIMap.toggleArcs(on);
  });
  $('btn-burst').addEventListener('click', async () => {
    try { CTIMap.burst(await getJSON('/api/map-events')); } catch (e) { console.warn(e); }
  });
  $('btn-snd').addEventListener('click', (e) => {
    const muted = e.currentTarget.textContent === '🔇';
    e.currentTarget.textContent = muted ? '🔊' : '🔇';
  });
  $('btn-theme').addEventListener('click', () => {
    document.body.style.filter = document.body.style.filter ? '' : 'invert(0.92) hue-rotate(180deg)';
  });
  $('news-list').addEventListener('click', (e) => {
    const item = e.target.closest('.news-item');
    if (item && item.dataset.url) window.open(item.dataset.url, '_blank', 'noopener');
  });

  // expose cities to the map module (from sim data via a tiny endpoint-free path:
  // the map labels come with the first events payload)
  function primeCities(payload) {
    if (!window.__CTI_CITIES__ && payload.events && payload.events.length) {
      window.__CTI_CITIES__ = [...new Map(payload.events.flatMap((e) => [e.from, e.to])
        .map((c) => [c.name, c])).values()];
    }
  }

  function boot() {
    renderHeaderClocks();
    renderWorldClocks();
    setInterval(() => { renderHeaderClocks(); renderWorldClocks(); }, 1000);
    pollNews(); pollMarkets(); pollThreats(); pollStatus(); pollEvents();
    setInterval(pollNews, 60000);
    setInterval(pollMarkets, 60000);
    setInterval(pollThreats, 60000);
    setInterval(pollStatus, 5000);
    setInterval(pollEvents, 10000);
    // map labels need city data; events payload carries it
    const origSetEvents = CTIMap.setEvents.bind(CTIMap);
    CTIMap.setEvents = (p) => { primeCities(p); origSetEvents(p); };
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
