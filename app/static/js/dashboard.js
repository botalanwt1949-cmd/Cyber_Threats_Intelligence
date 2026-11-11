/* Dashboard controller: polls the API, renders panels, drives the map layer.
   Motion discipline: every animated thing runs on the shared CTIMotion worker
   clock (motion.js) because this host stalls CSS transforms and never fires
   rAF; reduced-motion parks the rollers and turns the rolling lists into
   plain scrollable lists. Wiki-stack rules applied: tabular numerals,
   token-driven theme, aria-live announcements, keyboard-reachable rows. */
/* global CTIMap, CTIMotion, CTIDrawer */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const reduced = () => window.CTIMotion && CTIMotion.reduced;

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

  // ---------- a11y announcements (throttled) + audio tick ----------
  let lastAnnounce = 0;
  function announce(msg) {
    const now = performance.now();
    if (now - lastAnnounce < 4000) return;
    lastAnnounce = now;
    const el = $('aria-live');
    if (el) el.textContent = msg;
  }

  // soft WebAudio tick for new attacks — opt-in (off by default, persisted),
  // never plays under reduced motion, rate-capped to one per 2 s
  let audioCtx = null;
  let lastTickAt = 0;
  function playTick() {
    if ($('btn-snd').getAttribute('aria-pressed') !== 'true') return;
    if (reduced()) return;
    const now = performance.now();
    if (now - lastTickAt < 2000) return;
    lastTickAt = now;
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.frequency.value = 880;
      gain.gain.setValueAtTime(0.02, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.06);
      osc.connect(gain).connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.07);
    } catch (e) { /* audio unavailable — stay silent */ }
  }

  // ---------- header ----------
  function renderHeaderClocks() {
    $('hdr-clocks').innerHTML = ZONES.map((z) =>
      `<div class="hdr-clock"><span class="lbl">${z.lbl}</span><span class="val">${fmtClock(z.tz)}</span></div>`
    ).join('');
  }

  // ---------- theme (real token theme, persisted; no filter hacks) ----------
  function initTheme() {
    const stored = localStorage.getItem('cti-theme');
    const prefersLight = window.matchMedia
      && window.matchMedia('(prefers-color-scheme: light)').matches;
    applyTheme(stored || (prefersLight ? 'light' : 'dark'));
  }
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $('btn-theme').setAttribute('aria-pressed', String(theme === 'light'));
    $('btn-theme').textContent = theme === 'light' ? '☀' : '◐';
    localStorage.setItem('cti-theme', theme);
    // the map recolors its SVG paint from the CSS custom properties
    document.dispatchEvent(new CustomEvent('cti-theme', { detail: { theme } }));
  }

  // ---------- rollers (worker-clock driven; see motion.js) ----------
  const rollers = new Map();
  const canHover = window.matchMedia
    ? window.matchMedia('(hover: hover)').matches : true;
  function registerRoller(el, axis, speed, mode = 'loop', onWrap = null) {
    const r = { axis, speed, mode, onWrap, half: 0, offset: 0, paused: false };
    rollers.set(el, r);
    if (canHover) {
      // hover pause only for real pointers — on touch, pointerenter fires and
      // never leaves, which used to freeze the roll permanently (hover-stick)
      el.addEventListener('pointerenter', () => { r.paused = true; });
      el.addEventListener('pointerleave', () => { r.paused = false; });
    } else {
      el.addEventListener('pointerdown', () => { r.paused = true; });
      const release = () => { r.paused = false; };
      el.addEventListener('pointerup', release);
      el.addEventListener('pointercancel', release);
      el.addEventListener('pointerleave', release);
    }
  }
  function resetRoller(el, period) {
    const r = rollers.get(el);
    if (!r || reduced()) { stopRoller(el); return; }
    r.offset = 0;
    // loop length = one copy of the content; for a duplicated track that is
    // half the scroll size, for an N-copies track pass the period explicitly
    const full = r.axis === 'y' ? el.scrollHeight : el.scrollWidth;
    r.half = r.mode === 'end'
      ? Math.max(0, full - (r.axis === 'y' ? el.parentElement.clientHeight : el.parentElement.clientWidth))
      : (period !== undefined ? period : full / 2);
    el.style.transform = r.axis === 'y' ? 'translateY(0)' : 'translateX(0)';
  }
  function stopRoller(el) {
    const r = rollers.get(el);
    if (!r) return;
    r.half = 0;
    el.style.transform = '';
  }
  function rollStep(dt) {
    // dt comes from the shared CTIMotion worker clock — the compositor stalls
    // CSS transform animations here and rAF never fires
    for (const [el, r] of rollers) {
      if (r.paused || !r.half || reduced()) continue;
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

  let tickerItems = [];
  function renderTicker() {
    if (!tickerItems.length) return;
    const line = tickerItems.slice(0, 6).map((a) =>
      `<span class="tick-text">[<span class="tick-time">${fmtTime(a.published)}</span>] ${esc(a.title)} <span class="tick-src">— ${esc(a.source)}</span></span>`
    ).join(' &nbsp;·&nbsp; ');
    const el = $('ticker');
    // duplicated for a seamless loop; single copy under reduced motion
    el.innerHTML = reduced() ? line : line + ' &nbsp;·&nbsp; ' + line;
    resetRoller(el);
  }

  // ---------- left: news ----------
  let knownIds = new Set();
  let activeGroup = 'ALL';
  let activeCategory = null;      // threat-level card click → category filter
  let lastNews = null;
  let lastListSig = '';
  let lastSourcesSig = '';
  let sourcesState = { sources: [], groups: [] };

  function feedArticles(payload) {
    let pool = payload.articles;
    if (activeGroup !== 'ALL') pool = pool.filter((a) => a.source_group === activeGroup);
    if (activeCategory) pool = pool.filter((a) => a.category === activeCategory);
    return pool;
  }
  function newsRow(a, staggerMs) {
    const t = new Date(a.published * 1000);
    const style = staggerMs ? ` style="--stagger:${staggerMs}ms"` : '';
    return `<li class="news-item${staggerMs ? ' fresh' : ''}" role="button" tabindex="0"` +
      ` data-id="${esc(a.id)}" data-url="${esc(a.url)}"` +
      ` aria-label="${esc(a.title)} — open article"${style}>` +
      `<div class="news-meta"><span class="news-cat">${esc(a.category.toUpperCase())}</span>` +
      `<span class="news-time">${t.toLocaleTimeString('en-GB', { hour12: false })}</span></div>` +
      `<div class="news-title">${esc(a.title)}</div>` +
      `<div class="news-src">${esc(a.source)} · ${esc(a.source_group)}</div></li>`;
  }
  function renderNews(payload, force = false) {
    lastNews = payload;
    const pool = feedArticles(payload);
    $('feed-count').textContent =
      `${activeGroup === 'ALL' && !activeCategory
        ? (payload.articles_today || payload.articles.length)
        : pool.length} ARTICLES`;
    const fresh = payload.articles.filter((a) => !knownIds.has(a.id)).slice(0, 3).map((a) => a.id);
    payload.articles.forEach((a) => knownIds.add(a.id));
    const items = pool.slice(0, 40);
    // re-render (and restart the roll) only when the visible content changed —
    // unchanged polls must not reset the rolling animation
    const sig = `${activeGroup}|${activeCategory}|` + items.map((a) => a.id).join(',');
    if (force || sig !== lastListSig) {
      lastListSig = sig;
      const list = $('news-list');
      if (!items.length) {
        list.innerHTML = '<li class="news-empty">— no articles for this filter —</li>';
        stopRoller(list);
      } else {
        const html = items.map((a) =>
          newsRow(a, fresh.includes(a.id) ? fresh.indexOf(a.id) * 150 : 0)).join('');
        // duplicate the track for a seamless loop; single copy under reduced
        // motion (the duplicate would be visible while scrolling)
        list.innerHTML = reduced() ? html : html + html;
        const overflows = list.scrollHeight / 2 > list.parentElement.clientHeight + 8;
        if (overflows) resetRoller(list);
        else stopRoller(list);
      }
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

  // ---------- category cards: Research + Threat Intel live beside ATTACKS /
  // INTEL FEED in the left region; Traditional / Gov & CERT / Endpoint stay in
  // the bottom strip ----------
  let catScaffoldBuilt = false;
  const catCards = new Map();  // group name -> {dot, n, h, track, sig}
  function panelUi(panelId, trackId) {
    const p = document.getElementById(panelId);
    return {
      dot: null, n: p.querySelector('[data-role="n"]'), h: null,
      track: document.getElementById(trackId), sig: '',
    };
  }
  function catItem(a) {
    return `<div class="cat-item" role="button" tabindex="0" data-id="${esc(a.id)}"` +
      ` aria-label="${esc(a.title)} — open article">` +
      `<div class="cat-headline" title="${esc(a.title)}">${esc(a.title)}</div>` +
      `<div class="cat-src">${esc(a.source)} · ${ageLabel(Date.now() / 1000 - a.published)}</div></div>`;
  }
  function renderCatStrip(force = false) {
    const groups = sourcesState.groups || [];
    if (!groups.length) return;
    // build the strip shells once so track elements keep their roller
    // registration; Research / Threat Intel tracks are static panel elements
    if (!catScaffoldBuilt) {
      catCards.set('Research', panelUi('research-panel', 'research-track'));
      catCards.set('Threat Intel', panelUi('tintel-panel', 'tintel-track'));
      registerRoller($('research-track'), 'y', 8);
      registerRoller($('tintel-track'), 'y', 8);
      const strip = $('catstrip');
      strip.innerHTML = '';
      ['Traditional', 'Gov / CERT', 'Endpoint'].forEach((name) => {
        const card = document.createElement('div');
        card.className = 'cat-card';
        card.innerHTML =
          `<div class="cat-top"><i class="chip-dot idle" data-role="dot"></i>` +
          `<span class="cat-name">${esc(name)}</span>` +
          `<span class="cat-n" data-role="n">0/24h</span>` +
          `<span class="cat-health" data-role="h">0/0</span></div>` +
          `<div class="cat-roll"><div class="cat-track" data-role="track"></div></div>`;
        strip.appendChild(card);
        catCards.set(name, {
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
    // headlines come from /api/sources per-group `latest` (full corpus, any
    // age) — slow-cadence categories stay populated between publications
    for (const g of groups) {
      const ui = catCards.get(g.name);
      if (!ui) continue;
      if (force) ui.sig = '';
      if (ui.dot) ui.dot.className = `chip-dot ${chipDot(g.active, g.total)}`;
      ui.n.textContent = `${g.articles}/24h`;
      if (ui.h) ui.h.textContent = `${g.active}/${g.total}`;
      const items = (g.latest || []).slice(0, 8);
      const sig = items.map((a) => a.id).join(',');
      if (sig === ui.sig) continue;   // unchanged → keep rolling
      ui.sig = sig;
      if (!items.length) {
        ui.track.innerHTML = '<div class="cat-headline dim">— no articles in the current corpus —</div>';
        stopRoller(ui.track);
        continue;
      }
      const html = items.map(catItem).join('');
      // always roll when several headlines exist: repeat the track enough
      // times that the loop never exposes a gap, even in tall cards
      if (items.length > 1 && !reduced()) {
        ui.track.innerHTML = html;
        const contentH = Math.max(60, ui.track.scrollHeight);
        const viewH = ui.track.parentElement.clientHeight;
        const copies = Math.max(2, Math.ceil((viewH + contentH) / contentH) + 1);
        ui.track.innerHTML = html.repeat(copies);
        resetRoller(ui.track, contentH);
      } else {
        ui.track.innerHTML = html;
        stopRoller(ui.track);
      }
    }
  }

  const prevBadges = new Map();
  function renderThreats(payload) {
    let badgeMsg = null;
    $('threat-levels').innerHTML = (payload.levels || []).map((lv) => {
      const cls = lv.badge === 'HIGH' ? '' : `lv-${lv.badge.toLowerCase()}`;
      const delta = lv.delta_pct >= 0 ? `+${lv.delta_pct}%` : `${lv.delta_pct}%`;
      if (prevBadges.has(lv.name) && prevBadges.get(lv.name) !== lv.badge) {
        badgeMsg = `${lv.name} threat level ${lv.badge}`;
      }
      prevBadges.set(lv.name, lv.badge);
      // the card is a filter toggle: click → intel feed filtered to this bucket
      const active = activeCategory === lv.name;
      return `<div class="tl-card ${cls}" role="button" tabindex="0"` +
        ` data-category="${esc(lv.name)}" aria-pressed="${active}"` +
        ` aria-label="${esc(lv.name)} threat level ${esc(lv.badge)} — filter feed">` +
        `<div class="tl-head"><span class="tl-name">${esc(lv.name)}</span><span class="tl-badge">${esc(lv.badge)}</span></div>` +
        `<span class="tl-pill">AI · ${esc(lv.badge)}</span>` +
        `<div class="tl-nums"><b>${lv.count_24h}</b> / 24h &nbsp; <b>${delta}</b></div>` +
        `<svg class="tl-spark" viewBox="0 0 240 30" preserveAspectRatio="none">` +
        `<polyline fill="none" stroke="#ff9f1a" stroke-width="1.6" points="${sparkPoints(lv.spark, 240, 30)}"/></svg>` +
        (lv.latest ? `<div class="tl-latest"><span class="txt" title="${esc(lv.latest.title)}">${esc(lv.latest.title)}</span>` +
          `<span class="age">${ageLabel(lv.latest.age_s)}</span></div>` : '') +
        '</div>';
    }).join('');
    if (badgeMsg) announce(badgeMsg);
  }

  // ---------- sources panel + feed group chips ----------
  function chipDot(active, total) {
    if (active >= total && total > 0) return 'ok';
    if (active > 0) return 'part';
    return 'bad';
  }
  function chipHtml(key, active, total) {
    return `<button class="feed-chip ${activeGroup === key && !activeCategory ? 'active' : ''}" data-group="${esc(key)}">` +
      `<i class="chip-dot ${chipDot(active, total)}"></i>${esc(key)}` +
      `<span class="chip-n">${active}/${total}</span></button>`;
  }
  function renderChips() {
    const groups = sourcesState.groups || [];
    if (!groups.length) return;
    const act = groups.reduce((n, g) => n + g.active, 0);
    const tot = groups.reduce((n, g) => n + g.total, 0);
    $('feed-chips').innerHTML =
      chipHtml('ALL', act, tot) + groups.map((g) => chipHtml(g.name, g.active, g.total)).join('');
  }
  function renderSources(payload, force = false) {
    sourcesState = payload;
    $('sources-count').textContent = `${payload.sources_active ?? 0}/${payload.sources_total ?? 0} ACTIVE`;
    const cells = payload.sources || [];
    // re-render (and restart the roll) only when health actually changed
    const sig = cells.map((s) => `${s.ok}|${s.articles}`).join(',');
    if (force || sig !== lastSourcesSig) {
      lastSourcesSig = sig;
      const html = cells.map((s) => {
        const cls = s.ok === true ? 'ok' : (s.ok === false ? 'bad' : 'idle');
        const tip = s.ok === false && s.error ? ` — ${esc(s.error)}` : '';
        return `<div class="src-cell" title="${esc(s.name)} · ${esc(s.group)}${tip}">` +
          `<i class="src-dot ${cls}"></i><span class="src-name">${esc(s.name)}</span>` +
          `<span class="src-n">${s.articles ? s.articles : ''}</span></div>`;
      }).join('');
      const grid = $('sources-grid');
      grid.innerHTML = reduced() ? html : html + html;
      resetRoller(grid);
    }
    renderChips();
    renderCatStrip();
  }

  // ---------- threat map clone (Check Point style) ----------
  function tweenCounter(target) {
    // eased on the shared worker clock via CTIMotion.tween (motion.js) —
    // rAF never fires on this host; reduced-motion jumps straight to the value
    const el = $('tm-counter');
    if (!el) return;
    tweenCounter._shown = tweenCounter._shown === undefined ? null : tweenCounter._shown;
    const from = tweenCounter._shown === null ? Math.max(0, target - 40000) : tweenCounter._shown;
    tweenCounter._shown = target;
    CTIMotion.tween({
      from, to: target, duration: 900, ease: 'cubicOut',
      onUpdate: (v) => { el.textContent = Math.round(v).toLocaleString('en-US'); },
    });
  }

  const seenAttacks = new Set();
  const attacksState = [];  // newest first, capped — the rolling window
  function atkRow(a, staggerMs) {
    return `<li class="atk-item${staggerMs ? ' fresh' : ''}"${staggerMs ? ` style="--stagger:${staggerMs}ms"` : ''}>` +
      `<i class="atk-ring cat-${esc(a.category)}"></i>` +
      `<div class="atk-body"><div class="atk-name" title="${esc(a.name)}">${esc(a.name)}</div>` +
      `<div class="atk-meta"><span class="atk-time">${fmtTime(a.ts)}</span>` +
      `<span class="atk-route">${esc(a.from)} <span class="arr">➜</span> ${esc(a.to)}</span></div></div></li>`;
  }
  function renderAttacksTrack() {
    const list = $('attack-list');
    const html = attacksState.map((a) => atkRow(a, 0)).join('');
    list.innerHTML = reduced() ? html : html + html;
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
      announce(`${fresh.length} new attack${fresh.length > 1 ? 's' : ''}`);
      playTick();
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
  async function pollStatus() { try { renderStatus(await getJSON('/api/status')); } catch (e) { console.warn(e); } }
  async function pollEvents() {
    try { CTIMap.setEvents(await getJSON('/api/map-events')); } catch (e) { console.warn(e); }
  }
  // threats keeps its last payload so threat-card clicks can re-render
  // aria-pressed state without a refetch
  let threatsLast = null;
  async function pollThreats() {
    try {
      const payload = await getJSON('/api/threats');
      threatsLast = payload;
      renderThreats(payload);
    } catch (e) { console.warn(e); }
  }
  function renderThreatsLast() {
    if (threatsLast) renderThreats(threatsLast);
  }

  // ---------- controls ----------
  function setFilter({ group, category }) {
    if (group !== undefined) activeGroup = group;
    if (category !== undefined) activeCategory = category;
    renderChips();
    if (lastNews) renderNews(lastNews, true);
  }

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
  $('zoom-in').addEventListener('click', () => CTIMap.zoomIn());
  $('zoom-out').addEventListener('click', () => CTIMap.zoomOut());
  $('zoom-reset').addEventListener('click', () => CTIMap.zoomReset());

  $('btn-snd').addEventListener('click', (e) => {
    const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
    e.currentTarget.setAttribute('aria-pressed', String(on));
    e.currentTarget.textContent = on ? '🔊' : '🔇';
    localStorage.setItem('cti-sound', on ? '1' : '0');
    if (on) playTick();
  });

  $('btn-theme').addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
  });

  // feed rows: click/Enter opens the article drawer, Shift+click/Shift+Enter
  // opens the source site directly
  function activateRow(el, shiftKey) {
    if (!el || !el.dataset.id) return;
    if (shiftKey && el.dataset.url) {
      window.open(el.dataset.url, '_blank', 'noopener');
    } else {
      CTIDrawer.openById(el.dataset.id);
    }
  }
  $('news-list').addEventListener('click', (e) => {
    const item = e.target.closest('.news-item');
    activateRow(item, e.shiftKey);
  });
  $('news-list').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const item = e.target.closest('.news-item');
    if (item) { e.preventDefault(); activateRow(item, e.shiftKey); }
  });
  // category headlines open the same drawer (they carry article ids)
  document.body.addEventListener('click', (e) => {
    const cat = e.target.closest('.cat-item');
    if (cat) { CTIDrawer.openById(cat.dataset.id); return; }
    const tl = e.target.closest('.tl-card[data-category]');
    if (tl) {
      const name = tl.dataset.category;
      setFilter({ category: activeCategory === name ? null : name });
      renderThreatsLast();
      return;
    }
  });
  document.body.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const cat = e.target.closest('.cat-item');
    if (cat) { e.preventDefault(); CTIDrawer.openById(cat.dataset.id); return; }
    const tl = e.target.closest('.tl-card[data-category]');
    if (tl) { e.preventDefault(); setFilter({ category: activeCategory === tl.dataset.category ? null : tl.dataset.category }); renderThreatsLast(); }
  });

  $('feed-chips').addEventListener('click', (e) => {
    const chip = e.target.closest('.feed-chip');
    if (!chip) return;
    const group = chip.dataset.group;
    if ((group === activeGroup && !activeCategory)) return;
    // choosing a group chip clears any threat-card category filter
    setFilter({ group, category: null });
  });

  // single-column tab strip (≤767px)
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      $('main').dataset.tab = btn.dataset.tab;
    });
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
    initTheme();
    // sound preference persists; control starts honest (off, aria-pressed)
    const soundOn = localStorage.getItem('cti-sound') === '1';
    $('btn-snd').setAttribute('aria-pressed', String(soundOn));
    $('btn-snd').textContent = soundOn ? '🔊' : '🔇';

    registerRoller($('ticker'), 'x', 22);      // px/s — calmer headline crawl
    registerRoller($('news-list'), 'y', 12);   // px/s, ≈3.7s per headline
    registerRoller($('attack-list'), 'y', 10, 'end', renderAttacksTrack);
    registerRoller($('sources-grid'), 'y', 8);
    CTIMotion.frame(rollStep);                 // single shared worker clock
    CTIMotion.onReducedChange((isReduced) => {
      // reduced motion: park every roller and strip duplicated track copies
      // (the duplicate would be visible while scrolling); leaving reduced
      // re-measures and resumes the rolls
      for (const [el] of rollers) {
        if (isReduced) stopRoller(el);
        else resetRoller(el);
      }
      renderTicker();
      if (lastNews) renderNews(lastNews, true);
      renderSources(sourcesState, true);
      renderAttacksTrack();
      renderCatStrip(true);
    });

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
