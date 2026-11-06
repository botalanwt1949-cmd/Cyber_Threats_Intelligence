/* Global threat-activity map layer.
   d3-geo over vendored Natural Earth 110m TopoJSON; equirectangular (FLAT),
   CSS-tilted 3D, HYBRID (graticule glow), and GLOBE (orthographic spin) views.
   Threat events (arcs + pulses) arrive from /api/map-events. */
/* global d3, topojson */
(function () {
  'use strict';

  const SVG = d3.select('#map');
  const wrap = document.getElementById('map-wrap');
  const tip = document.getElementById('map-tip');
  const moonEl = document.getElementById('map-moon');

  let width = 0, height = 0;
  let projection = null, path = null, land = null, borders = null;
  let currentView = 'flat';
  let arcsOn = true;
  let globeRotation = 0;
  let lastEvents = [];
  let rafHandle = null;

  const SEV_COLOR = ['#3fb8ea', '#ff9f1a', '#ff5d5d'];
  const SEV_NAME = ['LOW', 'MEDIUM', 'CRITICAL'];

  const gRoot = SVG.append('g').attr('class', 'map-root');
  const gTerminator = gRoot.append('g');
  const gCountries = gRoot.append('g');
  const gGraticule = gRoot.append('g');
  const gLabels = gRoot.append('g');
  const gEvents = gRoot.append('g');

  const CITY_LABELS = ['Washington D.C.', 'São Paulo', 'London', 'Moscow', 'New Delhi',
    'Beijing', 'Tokyo', 'Sydney', 'Nairobi', 'Bogotá', 'San Juan', 'Dubai'];

  function resize() {
    const rect = wrap.getBoundingClientRect();
    width = Math.max(320, rect.width);
    height = Math.max(240, rect.height);
    SVG.attr('viewBox', `0 0 ${width} ${height}`);
    applyProjection();
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
      gCountries.selectAll('path.country').attr('d', path);
      gGraticule.selectAll('path').attr('d', path);
      drawTerminator();
      drawLabels();
      redrawEvents();
    }
  }

  function drawTerminator() {
    // Big decorative day-side dome, matching the reference's translucent ellipse.
    const rx = width * 0.34, ry = height * 0.92;
    gTerminator.selectAll('ellipse').data([1]).join('ellipse')
      .attr('class', 'terminator')
      .attr('cx', width * 0.42).attr('cy', height * 1.02)
      .attr('rx', rx).attr('ry', ry);
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
      if (ev.kind === 'arc') addArc(ev); else addPulse(ev);
      addMarker(ev);
    });
  }

  function addArc(ev) {
    const d = arcPath(ev.from, ev.to);
    if (!d || !eventVisible(ev)) return;
    gEvents.append('path').attr('class', `arc sev${ev.severity}`)
      .attr('d', d).attr('opacity', 0.85)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip)
      .transition().duration(20000).ease(d3.easeLinear)
      .attr('opacity', 0).remove();
  }

  function addPulse(ev) {
    const xy = projection([ev.to.lon, ev.to.lat]);
    if (!xy || !eventVisible(ev)) return;
    const g = gEvents.append('g').attr('transform', `translate(${xy[0]},${xy[1]})`)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip);
    g.append('circle').attr('r', 7).attr('class', `pulse-ring sev${ev.severity}`)
      .attr('fill', 'none').attr('stroke-width', 1.4);
    g.append('circle').attr('r', 2.2).attr('class', `sev${ev.severity} marker`);
    g.transition().duration(20000).attr('opacity', 0).remove();
  }

  function addMarker(ev) {
    const xy = projection([ev.to.lon, ev.to.lat]);
    if (!xy || !eventVisible(ev)) return;
    const size = ev.severity === 2 ? 4.5 : 3.4;
    gEvents.append('path')
      .attr('d', `M0,${-size} L${size * 0.85},${size * 0.6} L${-size * 0.85},${size * 0.6} Z`)
      .attr('transform', `translate(${xy[0]},${xy[1]})`)
      .attr('class', `sev${ev.severity} marker`).attr('opacity', 0.95)
      .on('mousemove', (mouseEvent) => showTip(mouseEvent, ev))
      .on('mouseleave', hideTip)
      .transition().duration(20000).attr('opacity', 0).remove();
  }

  function showTip(evt, ev) {
    const rect = wrap.getBoundingClientRect();
    tip.classList.remove('hidden');
    tip.style.left = Math.min(evt.clientX - rect.left + 12, rect.width - 240) + 'px';
    tip.style.top = Math.max(evt.clientY - rect.top - 40, 4) + 'px';
    tip.innerHTML = `<div class="t-tech">${ev.technique} · ${SEV_NAME[ev.severity]}</div>` +
      `<div>${ev.from.name} → ${ev.to.name}</div>`;
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
      gCountries.append('path').datum(borders).attr('class', 'country').attr('fill', 'none')
        .attr('stroke', 'rgba(160,185,215,0.10)').attr('d', path);
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

  window.addEventListener('resize', resize);
  resize();
  loadWorld();

  window.CTIMap = { setEvents, setView, toggleArcs, burst };
})();
