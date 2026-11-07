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
  // ---------- main-thread rollers ----------
  // This host's GPU compositor stalls CSS transform animations AND gates
  // requestAnimationFrame (vsync never fires), so the ticker and the
  // intel-feed roll are driven from a setInterval loop instead. Speed is
  // dt-based, so timer jitter only pauses the roll, never distorts it.
  const rollers = new Map();
  function registerRoller(el, axis, speed, mode = 'loop', onWrap = null) {
    const r = { axis, speed, mode, onWrap, half: 0, offset: 0, paused: false };
    rollers.set(el, r);
    el.addEventListener('pointerenter', () => { r.paused = true; });
    el.addEventListener('pointerleave', () => { r.paused = false; });
  }
  function resetRoller(el) {
    const r = rollers.get(el);
    if (!r) return;
    r.offset = 0;
    const full = r.axis === 'y' ? el.scrollHeight : el.scrollWidth;
    // 'loop': duplicated track, one loop = half the scroll size (seamless);
    // 'end': single track, loop when the end of the content is reached
    r.half = r.mode === 'end'
      ? Math.max(0, full - (r.axis === 'y' ? el.parentElement.clientHeight : el.parentElement.clientWidth))
      : full / 2;
    el.style.transform = r.axis === 'y' ? 'translateY(0)' : 'translateX(0)';
  }
  function stopRoller(el) {
    const r = rollers.get(el);
    if (!r) return;
    r.half = 0;
    el.style.transform = '';
  }
  let rollLast = 0;
  function rollStep() {
    const now = performance.now();
    const dt = Math.min(2000, rollLast ? now - rollLast : 0);
    rollLast = now;
    for (const [el, r] of rollers) {
      if (r.paused || !r.half) continue;
      r.offset += (r.speed * dt) / 1000;
      if (r.offset >= r.half) {
        r.offset -= r.half;
        if (r.mode === 'end' && r.onWrap) {
          r.onWrap();          // re-renders the track with fresh content + resetRoller
          continue;            // resetRoller already wrote the reset transform
        }
      }
      el.style.transform = r.axis === 'y'
        ? `translateY(${-r.offset.toFixed(1)}px)`
        : `translateX(${-r.offset.toFixed(1)}px)`;
    }
  }
  // This environment: compositor stalls CSS animations, rAF never fires and
  // page timers are throttled to 1 Hz — but Web Worker timers run unthrottled
  // (~30 Hz verified), so the roll ticks arrive from a Blob worker. If Worker
  // is unavailable, fall back to the (chunky) 1 Hz page timer.
  function startRollClock() {
    try {
      const src = 'setInterval(() => postMessage(0), 33);';
      const url = URL.createObjectURL(new Blob([src], { type: 'application/javascript' }));
      const w = new Worker(url);
      w.onmessage = rollStep;
      w.onerror = () => { w.terminate(); setInterval(rollStep, 1000); };
    } catch (e) {
      setInterval(rollStep, 1000);
    }
  }

  let tickerItems = [];
  function renderTicker() {
    if (!tickerItems.length) return;
    const line = tickerItems.slice(0, 6).map((a) =>
      `<span class="tick-text">[<span class="tick-time">${fmtTime(a.published)}</span>] ${esc(a.title)} <span class="tick-src">— ${esc(a.source)}</span></span>`
    ).join(' &nbsp;·&nbsp; ');
    const el = $('ticker');
    el.innerHTML = line + ' &nbsp;·&nbsp; ' + line; // duplicated for seamless loop
    resetRoller(el);
  }

  // ---------- left: news ----------
  let knownIds = new Set();
  let activeGroup = 'ALL';
  let lastNews = null;
  let lastListSig = '';
  let lastSourcesSig = '';
  let sourcesState = { sources: [], groups: [] };
  function feedArticles(payload) {
    return activeGroup === 'ALL'
      ? payload.articles
      : payload.articles.filter((a) => a.source_group === activeGroup);
  }
  function renderNews(payload, force = false) {
    lastNews = payload;
    const pool = feedArticles(payload);
    $('feed-count').textContent =
      `${activeGroup === 'ALL' ? (payload.articles_today || payload.articles.length) : pool.length} ARTICLES`;
    const fresh = payload.articles.filter((a) => !knownIds.has(a.id)).slice(0, 3).map((a) => a.id);
    payload.articles.forEach((a) => knownIds.add(a.id));
    const items = pool.slice(0, 40);
    // re-render (and restart the roll) only when the visible content changed —
    // unchanged polls must not reset the rolling animation
    const sig = items.map((a) => a.id).join(',');
    if (force || sig !== lastListSig) {
      lastListSig = sig;
      const html = items.map((a) => {
        const t = new Date(a.published * 1000);
        return `<li class="news-item ${fresh.includes(a.id) ? 'fresh' : ''}" data-url="${esc(a.url)}">` +
          `<div class="news-meta"><span class="news-cat">${esc(a.category.toUpperCase())}</span>` +
          `<span class="news-time">${t.toLocaleTimeString('en-GB', { hour12: false })}</span></div>` +
          `<div class="news-title">${esc(a.title)}</div>` +
          `<div class="news-src">${esc(a.source)} · ${esc(a.source_group)}</div></li>`;
      }).join('');
      const list = $('news-list');
      // duplicate the track; the roller wraps at half its height → seamless loop
      list.innerHTML = html + html;
      const overflows = list.scrollHeight / 2 > list.parentElement.clientHeight + 8;
      if (overflows) resetRoller(list);
      else stopRoller(list);
    }
    tickerItems = payload.articles.slice(0, 6);
    renderTicker();
    renderCatStrip();
  }

  // ---------- right: threat vectors (real 24h corpus keyword counts) ----------
  function renderVectors(payload) {
    $('vectors-list').innerHTML = (payload.vectors || []).map((v) => {
      const vals = v.spark.length ? v.spark : [0, 0];
      return `<li class="vec-row"><span class="vec-name">${esc(v.name)}</span>` +
        `<span class="vec-val">${v.value}</span>` +
        sparkPath(vals, 74, 16, '#ff9f1a') + '</li>';
    }).join('');
  }

  // ---------- bottom: one rolling card per threat-news category ----------
  let catScaffoldBuilt = false;
  const catCards = new Map();  // group name -> {dot, n, h, track, sig}
  function renderCatStrip() {
    const groups = sourcesState.groups || [];
    if (!groups.length) return;
    // build the card shells once so track elements keep their roller registration
    if (!catScaffoldBuilt) {
      const strip = $('catstrip');
      strip.innerHTML = '';
      groups.forEach((g) => {
        const card = document.createElement('div');
        card.className = 'cat-card';
        card.innerHTML =
          `<div class="cat-top"><i class="chip-dot idle" data-role="dot"></i>` +
          `<span class="cat-name">${esc(g.name)}</span>` +
          `<span class="cat-n" data-role="n">0/24h</span>` +
          `<span class="cat-health" data-role="h">0/0</span></div>` +
          `<div class="cat-roll"><div class="cat-track" data-role="track"></div></div>`;
        strip.appendChild(card);
        catCards.set(g.name, {
          dot: card.querySelector('[data-role="dot"]'),
          n: card.querySelector('[data-role="n"]'),
          h: card.querySelector('[data-role="h"]'),
          track: card.querySelector('[data-role="track"]'),
          sig: '',
        });
        registerRoller(card.querySelector('[data-role="track"]'), 'y', 8);
      });
      catScaffoldBuilt = true;
    }
    const arts = lastNews ? lastNews.articles : [];
    for (const g of groups) {
      const ui = catCards.get(g.name);
      if (!ui) continue;
      ui.dot.className = `chip-dot ${chipDot(g.active, g.total)}`;
      ui.n.textContent = `${g.articles}/24h`;
      ui.h.textContent = `${g.active}/${g.total}`;
      const items = arts
        .filter((a) => a.source_group === g.name)
        .sort((a, b) => b.published - a.published)
        .slice(0, 8);
      const sig = items.map((a) => a.id).join(',');
      if (sig === ui.sig) continue;   // unchanged → keep rolling
      ui.sig = sig;
      const item = (a) =>
        `<div class="cat-item"><div class="cat-headline" title="${esc(a.title)}">${esc(a.title)}</div>` +
        `<div class="cat-src">${esc(a.source)} · ${ageLabel(Date.now() / 1000 - a.published)}</div></div>`;
      if (!items.length) {
        ui.track.innerHTML = '<div class="cat-headline dim">— no articles in the current corpus —</div>';
        stopRoller(ui.track);
        continue;
      }
      const html = items.map(item).join('');
      ui.track.innerHTML = html;
      // roll only when several headlines overflow the card; a lone headline stays static
      if (items.length > 1 && ui.track.scrollHeight > ui.track.parentElement.clientHeight + 4) {
        ui.track.innerHTML = html + html;   // duplicated for the seamless loop
        resetRoller(ui.track);
      } else {
        stopRoller(ui.track);
      }
    }
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

  // ---------- sources panel + feed group chips ----------
  function chipDot(active, total) {
    if (active >= total && total > 0) return 'ok';
    if (active > 0) return 'part';
    return 'bad';
  }
  function chipHtml(key, active, total, articles) {
    return `<button class="feed-chip ${activeGroup === key ? 'active' : ''}" data-group="${esc(key)}">` +
      `<i class="chip-dot ${chipDot(active, total)}"></i>${esc(key)}` +
      `<span class="chip-n">${active}/${total}</span></button>`;
  }
  function renderChips() {
    const groups = sourcesState.groups || [];
    if (!groups.length) return;
    const act = groups.reduce((n, g) => n + g.active, 0);
    const tot = groups.reduce((n, g) => n + g.total, 0);
    $('feed-chips').innerHTML =
      chipHtml('ALL', act, tot, 0) + groups.map((g) => chipHtml(g.name, g.active, g.total, g.articles)).join('');
  }
  function renderSources(payload) {
    sourcesState = payload;
    $('sources-count').textContent = `${payload.sources_active ?? 0}/${payload.sources_total ?? 0} ACTIVE`;
    const cells = payload.sources || [];
    // re-render (and restart the roll) only when health actually changed
    const sig = cells.map((s) => `${s.ok}|${s.articles}`).join(',');
    if (sig !== lastSourcesSig) {
      lastSourcesSig = sig;
      const html = cells.map((s) => {
        const cls = s.ok === true ? 'ok' : (s.ok === false ? 'bad' : 'idle');
        const tip = s.ok === false && s.error ? ` — ${esc(s.error)}` : '';
        return `<div class="src-cell" title="${esc(s.name)} · ${esc(s.group)}${tip}">` +
          `<i class="src-dot ${cls}"></i><span class="src-name">${esc(s.name)}</span>` +
          `<span class="src-n">${s.articles ? s.articles : ''}</span></div>`;
      }).join('');
      const grid = $('sources-grid');
      // duplicate the track for a seamless loop (44 sources = even row pairs)
      grid.innerHTML = html + html;
      resetRoller(grid);
    }
    renderChips();
    renderCatStrip();
  }

  // ---------- threat map clone (Check Point style) ----------
  let shownTotal = null;
  function tweenCounter(target) {
    const el = $('tm-counter');
    if (!el) return;
    const from = shownTotal === null ? Math.max(0, target - 40000) : shownTotal;
    shownTotal = target;
    const t0 = performance.now(), dur = 900;
    function step(t) {
      const k = Math.min(1, (t - t0) / dur);
      const eased = 1 - Math.pow(1 - k, 3);
      el.textContent = Math.round(from + (target - from) * eased).toLocaleString('en-US');
      if (k < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  const seenAttacks = new Set();
  const attacksState = [];  // newest first, capped — the rolling window
  function atkRow(a) {
    return `<li class="atk-item fresh"><i class="atk-ring cat-${esc(a.category)}"></i>` +
      `<div class="atk-body"><div class="atk-name" title="${esc(a.name)}">${esc(a.name)}</div>` +
      `<div class="atk-meta"><span class="atk-time">${fmtTime(a.ts)}</span>` +
      `<span class="atk-route">${esc(a.from)} <span class="arr">➜</span> ${esc(a.to)}</span></div></div></li>`;
  }
  function renderAttacksTrack() {
    const list = $('attack-list');
    list.innerHTML = attacksState.map(atkRow).join('');
    resetRoller(list);
  }
  function renderAttacks(payload) {
    $('atk-rate').textContent = `${payload.rate_per_min ?? '—'} /MIN`;
    const fresh = (payload.attacks || []).filter((a) => !seenAttacks.has(a.id)).slice(0, 6);
    (payload.attacks || []).forEach((a) => seenAttacks.add(a.id));
    if (seenAttacks.size > 2000) seenAttacks.clear();
    if (fresh.length) {
      attacksState.unshift(...fresh);
      if (attacksState.length > 16) attacksState.length = 16;
      // the track only re-renders here for the initial fill; afterwards it
      // refreshes at each roller wrap (onWrap), so the roll never restarts
      // just because new attacks streamed in
      if (!rollers.get($('attack-list')).half) renderAttacksTrack();
    }
  }
  function renderTargets(payload) {
    const rows = payload.top_countries || [];
    const max = Math.max(...rows.map((c) => c.rate), 1);
    $('top-countries').innerHTML = rows.map((c) => {
      const hue = (c.code.charCodeAt(0) * 31 + c.code.charCodeAt(1) * 17) % 360;
      return `<li class="target-row"><i class="flag" style="--h:${hue}">${esc(c.code)}</i>` +
        `<span class="t-name" title="${esc(c.name)}">${esc(c.name)}</span>` +
        `<span class="t-bar"><span style="width:${Math.round((c.rate / max) * 100)}%"></span></span>` +
        `<span class="t-rate">${c.rate.toFixed(1)}</span></li>`;
    }).join('');
  }
  async function pollThreatmap() {
    try {
      const d = await getJSON('/api/threatmap');
      tweenCounter(d.total_today || 0);
      renderAttacks(d);
      renderTargets(d);
      CTIMap.setLegend(d.legend || {});
    } catch (e) { console.warn(e); }
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
  async function pollSources() { try { renderSources(await getJSON('/api/sources')); } catch (e) { console.warn(e); } }
  async function pollVectors() { try { renderVectors(await getJSON('/api/vectors')); } catch (e) { console.warn(e); } }
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
  $('feed-chips').addEventListener('click', (e) => {
    const chip = e.target.closest('.feed-chip');
    if (!chip || chip.dataset.group === activeGroup) return;
    activeGroup = chip.dataset.group;
    renderChips();
    if (lastNews) renderNews(lastNews, true);
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
    setInterval(renderHeaderClocks, 1000);
    registerRoller($('ticker'), 'x', 22);      // px/s — calmer headline crawl
    registerRoller($('news-list'), 'y', 12);   // px/s, ≈3.7s per headline
    registerRoller($('attack-list'), 'y', 10, 'end', renderAttacksTrack);
    registerRoller($('sources-grid'), 'y', 8);
    startRollClock();
    pollNews(); pollVectors(); pollThreats(); pollStatus(); pollEvents(); pollThreatmap(); pollSources();
    setInterval(pollNews, 60000);
    setInterval(pollSources, 60000);
    setInterval(pollVectors, 60000);
    setInterval(pollThreats, 60000);
    setInterval(pollStatus, 5000);
    setInterval(pollEvents, 10000);
    setInterval(pollThreatmap, 2000);
    // map labels need city data; events payload carries it
    const origSetEvents = CTIMap.setEvents.bind(CTIMap);
    CTIMap.setEvents = (p) => { primeCities(p); origSetEvents(p); };
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
