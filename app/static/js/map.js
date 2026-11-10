/* Global threat-activity map layer — Check Point ThreatCloud-style clone.
   d3-geo over vendored Natural Earth 110m TopoJSON; equirectangular (FLAT),
   CSS-tilted 3D, HYBRID (graticule glow), and GLOBE (orthographic spin) views.
   Threat events arrive from /api/map-events; the visual language (dot-matrix
   continents, draw-on category arcs, impact rings, event labels, category
   legend) is cloned from threatmap.checkpoint.com (REA capture, 2026-11-06):
   Malware = red, Phishing = purple, Exploit = gold. */
/* global d3, topojson */
(function () {
  'use strict';

  const SVG = d3.select('#map');
  const wrap = document.getElementById('map-wrap');
  const tip = document.getElementById('map-tip');
  const moonEl = document.getElementById('map-moon');
  const legendEl = document.getElementById('map-legend');

  let width = 0, height = 0;
  let projection = null, path = null, land = null, borders = null;
  let currentView = 'flat';
  let arcsOn = true;
  let globeRotation = 0;
  let lastEvents = [];
  let rafHandle = null;
  let lastLegend = {};

  const CAT_COLOR = { malware: '#ff4d5e', phishing: '#a24bff', exploit: '#f2b230' };
  const CATS = ['malware', 'phishing', 'exploit'];
  const catFilter = { malware: true, phishing: true, exploit: true };
  const SEV_NAME = ['LOW', 'MEDIUM', 'CRITICAL'];

  const gRoot = SVG.append('g').attr('class', 'map-root');
  const gBack = gRoot.append('g');
  // everything zoomable lives in gZoom; the background grid stays fixed so
  // panning never exposes empty edges
  const gZoom = gRoot.append('g').attr('class', 'map-zoom');
  const gCountries = gZoom.append('g');
  const gGraticule = gZoom.append('g');
  const gLabels = gZoom.append('g');
  const gEvents = gZoom.append('g');

  // wheel / drag / double-click zoom+pan; buttons drive zoomBy()/zoomReset()
  let zoomK = 1;
  const zoomBehavior = d3.zoom()
    .scaleExtent([1, 12])
    .on('zoom', (ev) => {
      zoomK = ev.transform.k;
      gZoom.attr('transform', ev.transform);
      // counter-scale strokes and labels so they stay crisp when zoomed in
      gZoom.style('--k', zoomK);
      const hint = document.getElementById('map-hint');
      if (hint) hint.style.opacity = '0';   // first interaction hides the hint
    });
  SVG.call(zoomBehavior);

  const CITY_LABELS = ['Washington D.C.', 'São Paulo', 'London', 'Moscow', 'New Delhi',
    'Beijing', 'Tokyo', 'Sydney', 'Nairobi', 'Bogotá', 'San Juan', 'Dubai'];

  addDefs();

  function addDefs() {
    // Halftone continent fill + faint background grid, matching the reference.
    const defs = SVG.append('defs');
    const dots = defs.append('pattern').attr('id', 'dotgrid')
      .attr('width', 7).attr('height', 7).attr('patternUnits', 'userSpaceOnUse');
    dots.append('circle').attr('cx', 2).attr('cy', 2).attr('r', 1.15)
      .attr('fill', '#4c4553');
    const grid = defs.append('pattern').attr('id', 'gridbg')
      .attr('width', 56).attr('height', 56).attr('patternUnits', 'userSpaceOnUse');
    grid.append('path').attr('d', 'M56 0H0V56').attr('fill', 'none')
      .attr('stroke', 'rgba(130,120,150,0.07)').attr('stroke-width', 1);
  }

  function catOf(ev) {
    return CAT_COLOR[ev.category] ? ev.category : 'exploit';
  }

  function resize() {
    const rect = wrap.getBoundingClientRect();
    width = Math.max(320, rect.width);
    height = Math.max(240, rect.height);
    SVG.attr('viewBox', `0 0 ${width} ${height}`);
    // allow panning immediately at 1x: 35% slack outside the fitted map, so
    // drag feels alive instead of being locked until the first zoom-in
    zoomBehavior.translateExtent(
      [[-width * 0.35, -height * 0.35], [width * 1.35, height * 1.35]]);
    gBack.selectAll('rect').data([1]).join('rect')
      .attr('class', 'grid-bg').attr('width', width).attr('height', height)
      .attr('fill', 'url(#gridbg)');
    applyProjection();
  }

  function zoomBy(factor) {
    // d3 transitions are rAF-driven and this host's compositor stalls them —
    // apply the new transform synchronously, zooming toward the map centre
    const target = Math.min(12, Math.max(1, zoomK * factor));
    const cx = width / 2, cy = height / 2;
    SVG.call(zoomBehavior.transform,
      d3.zoomIdentity.translate(cx, cy).scale(target).translate(-cx, -cy));
  }

  function zoomReset() {
    SVG.call(zoomBehavior.transform, d3.zoomIdentity);
  }

  function applyProjection() {
    if (currentView === 'globe') {
      projection = d3.geoOrthographic().rotate([globeRotation, -18, 0])
        .fitExtent([[8, 8], [width - 8, height - 8]], { type: 'Sphere' });
    } else {
      projection = d3.geoEquirectangular()
        .fitExtent([[6, 6], [width - 6, height - 6]], land || { type: 'Sphere' });
    }
    path = d3.geoPath(projection);
    if (land) {
      // re-project BOTH the land fill and the border mesh — the borders used
      // to keep their flat-equirectangular d and float off the globe
      gCountries.selectAll('path').attr('d', path);
      gGraticule.selectAll('path').attr('d', path);
      drawLabels();
      redrawEvents();
    }
  }

  function drawLabels() {
    const cities = window.__CTI_CITIES__ || [];
    const subset = cities.filter((c) => CITY_LABELS.includes(c.name));
    gLabels.selectAll('text').data(subset, (d) => d.name).join('text')
      .attr('class', 'city-label')
      .attr('x', (d) => projection([d.lon, d.lat])[0] + 5)
      .attr('y', (d) => projection([d.lon, d.lat])[1] - 3)
      .text((d) => d.name);
  }

  function arcPath(from, to) {
    const a = projection([from.lon, from.lat]);
    const b = projection([to.lon, to.lat]);
    if (!a || !b) return null;
    if (currentView === 'globe') {
      const geo = { type: 'LineString', coordinates: [[from.lon, from.lat], [to.lon, to.lat]] };
      return path(geo);
    }
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
    const dx = b[0] - a[0], dy = b[1] - a[1];
    const dist = Math.sqrt(dx * dx + dy * dy);
    const lift = Math.min(90, 18 + dist * 0.28);
    return `M${a[0]},${a[1]} Q${mx - dy * 0.12},${my - lift} ${b[0]},${b[1]}`;
  }

  function eventVisible(ev) {
    if (currentView !== 'globe') return true;
    return d3.geoDistance([ev.to.lon, ev.to.lat], [-globeRotation, 18]) < Math.PI / 2 - 0.05;
  }

  function redrawEvents() {
    gEvents.selectAll('*').remove();
    if (!arcsOn) { lastEvents.forEach(addMarker); return; }
    lastEvents.forEach((ev) => {
      if (!catFilter[catOf(ev)]) return;
      if (ev.kind === 'arc') addArc(ev); else addPulse(ev);
      addMarker(ev);
    });
  }

  function addArc(ev) {
    const d = arcPath(ev.from, ev.to);
    if (!d || !eventVisible(ev)) return;
    const color = CAT_COLOR[catOf(ev)];
    const p = gEvents.append('path')
      .attr('class', `arc cat-${catOf(ev)}`)
      .attr('d', d)
      .attr('stroke', color)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip);
    let len = 600;
    try { len = p.node().getTotalLength(); } catch (err) { /* detached node */ }
    p.attr('fill', 'none')
      .attr('stroke-dasharray', `${len} ${len}`)
      .attr('stroke-dashoffset', len)
      .attr('opacity', 0.9)
      .transition().duration(1500).ease(d3.easeCubicOut)
      .attr('stroke-dashoffset', 0)
      .transition().delay(5000).duration(13500)
      .attr('opacity', 0).remove();
    addEventLabel(ev);
  }

  function addEventLabel(ev) {
    const xy = projection([ev.to.lon, ev.to.lat]);
    if (!xy || !eventVisible(ev)) return;
    gEvents.append('text')
      .attr('class', 'arc-label')
      .attr('x', xy[0] + 9)
      .attr('y', xy[1] + 3)
      .text(ev.to_country || ev.to.name)
      .transition().delay(6000).duration(13000)
      .attr('opacity', 0).remove();
  }

  function addPulse(ev) {
    const xy = projection([ev.to.lon, ev.to.lat]);
    if (!xy || !eventVisible(ev)) return;
    const color = CAT_COLOR[catOf(ev)];
    const g = gEvents.append('g').attr('transform', `translate(${xy[0]},${xy[1]})`)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip);
    g.append('circle').attr('r', 8).attr('fill', 'none')
      .attr('stroke', color).attr('stroke-width', 1)
      .attr('class', 'pulse-ring');
    g.append('circle').attr('r', 2.4).attr('fill', color);
    g.transition().duration(20000).attr('opacity', 0).remove();
  }

  function addMarker(ev) {
    const xy = projection([ev.to.lon, ev.to.lat]);
    if (!xy || !eventVisible(ev)) return;
    const color = CAT_COLOR[catOf(ev)];
    const g = gEvents.append('g').attr('transform', `translate(${xy[0]},${xy[1]})`)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip);
    g.append('circle').attr('r', 4.6).attr('fill', 'none')
      .attr('stroke', color).attr('stroke-width', 1);
    g.append('circle').attr('r', 1.8).attr('fill', color);
    g.transition().duration(20000).attr('opacity', 0).remove();
  }

  function showTip(evt, ev) {
    const rect = wrap.getBoundingClientRect();
    tip.classList.remove('hidden');
    tip.style.left = Math.min(evt.clientX - rect.left + 12, rect.width - 240) + 'px';
    tip.style.top = Math.max(evt.clientY - rect.top - 40, 4) + 'px';
    tip.innerHTML = `<div class="t-tech">${(ev.category || '').toUpperCase()} · ${ev.technique} · ${SEV_NAME[ev.severity]}</div>` +
      `<div>${ev.from_country || ev.from.name} → ${ev.to_country || ev.to.name}</div>`;
  }

  function hideTip() { tip.classList.add('hidden'); }

  function spin() {
    globeRotation = (globeRotation + 0.12) % 360;
    applyProjection();
    rafHandle = requestAnimationFrame(spin);
  }

  function setView(view) {
    currentView = view;
    if (rafHandle) { cancelAnimationFrame(rafHandle); rafHandle = null; }
    wrap.classList.toggle('tilt', view === 'tilt');
    wrap.classList.toggle('glow', view === 'grid');
    gGraticule.selectAll('path').data(view === 'grid' || view === 'globe'
      ? [d3.geoGraticule10()] : []).join('path').attr('class', 'graticule');
    if (view === 'globe') spin();
    applyProjection();
  }

  function loadWorld() {
    d3.json('/static/vendor/countries-110m.json').then((world) => {
      land = topojson.feature(world, world.objects.countries);
      borders = topojson.mesh(world, world.objects.countries, (a, b) => a !== b);
      gCountries.append('path').datum(land).attr('class', 'country').attr('d', path);
      gCountries.append('path').datum(borders).attr('class', 'country-border').attr('fill', 'none')
        .attr('stroke', 'rgba(150,140,170,0.14)').attr('d', path);
      applyProjection();
    }).catch((err) => console.error('world load failed', err));
  }

  function setEvents(payload) {
    lastEvents = payload.events || [];
    if (payload.moon) {
      moonEl.textContent = `${payload.moon.glyph} ${payload.moon.name} ${payload.moon.percent}%`;
    }
    redrawEvents();
  }

  function toggleArcs(on) { arcsOn = on; redrawEvents(); }

  function burst(payload) {
    lastEvents = (payload.events || []).concat(lastEvents).slice(0, 90);
    redrawEvents();
  }

  function renderLegend() {
    if (!legendEl) return;
    legendEl.innerHTML =
      `<span class="legend-note" title="Simulated attack events — see footer: MAP + ATTACKS: SIMULATED">SIM</span>` +
      CATS.map((c) =>
      `<button class="legend-chip${catFilter[c] ? '' : ' off'}" data-cat="${c}" title="Toggle simulated ${c} attacks">` +
      `<i class="legend-dot" style="--c:${CAT_COLOR[c]}"></i>` +
      `${c.charAt(0).toUpperCase() + c.slice(1)}<b>${lastLegend[c] ?? 0}</b></button>`).join('');
  }

  function setLegend(counts) {
    lastLegend = counts || {};
    renderLegend();
  }

  function toggleCategory(cat) {
    if (!(cat in catFilter)) return;
    catFilter[cat] = !catFilter[cat];
    renderLegend();
    redrawEvents();
  }

  legendEl.addEventListener('click', (e) => {
    const chip = e.target.closest('.legend-chip');
    if (chip) toggleCategory(chip.dataset.cat);
  });
  renderLegend();

  window.addEventListener('resize', resize);
  resize();
  loadWorld();

  window.CTIMap = { setEvents, setView, toggleArcs, burst, setLegend,
    zoomIn: () => zoomBy(1.6), zoomOut: () => zoomBy(1 / 1.6), zoomReset };
})();
