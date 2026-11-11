/* CTIMotion — the dashboard's single motion core.
   This host's GPU compositor stalls CSS transform animations and never fires
   requestAnimationFrame, while Web Worker timers run unthrottled (~30 Hz,
   verified 2026-11-07). So ALL motion here — rollers, number tweens, the globe
   spin — is driven from one shared Blob-worker clock instead of rAF/CSS.

   Also owns the reduced-motion contract (wiki stack universal rule):
   prefers-reduced-motion is honoured automatically; tests can force it via
   CTIMotion.setReduced(true). Consumers:
     CTIMotion.frame(cb)                — per-tick callback(dtMs), returns un()
     CTIMotion.tween({from,to,...})     — eased number tween, returns {cancel}
     CTIMotion.reduced                  — current boolean
     CTIMotion.onReducedChange(cb)      — notified when the mode flips
     CTIMotion.setReduced(bool|null)    — manual override; null = media query
*/
/* global CTIMotion:true */
(function () {
  'use strict';

  const subs = new Set();
  let lastTick = 0;
  let worker = null;
  let fallbackTimer = null;

  function tick() {
    const now = performance.now();
    const dt = Math.min(2000, lastTick ? now - lastTick : 0);
    lastTick = now;
    for (const cb of [...subs]) cb(dt);
  }

  function startClock() {
    try {
      const src = 'setInterval(() => postMessage(0), 33);';
      const url = URL.createObjectURL(new Blob([src], { type: 'application/javascript' }));
      worker = new Worker(url);
      worker.onmessage = tick;
      worker.onerror = () => {
        worker.terminate(); worker = null;
        if (!fallbackTimer) fallbackTimer = setInterval(tick, 1000);
      };
    } catch (e) {
      fallbackTimer = setInterval(tick, 1000);
    }
  }

  // ---------- reduced-motion manager ----------
  const mql = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  let override = null;               // true/false forces; null follows media
  const reducedSubs = new Set();

  function computeReduced() {
    return override !== null ? override : Boolean(mql && mql.matches);
  }
  function applyReduced() {
    const value = computeReduced();
    if (value !== api.reduced) {
      api.reduced = value;
      document.body.classList.toggle('static-motion', value);
      reducedSubs.forEach((cb) => { try { cb(value); } catch (e) { /* consumer bug */ } });
    }
  }
  if (mql) {
    if (mql.addEventListener) mql.addEventListener('change', applyReduced);
    else if (mql.addListener) mql.addListener(applyReduced);   // legacy Safari
  }

  const EASE = {
    linear: (k) => k,
    cubicOut: (k) => 1 - Math.pow(1 - k, 3),
    quartOut: (k) => 1 - Math.pow(1 - k, 4),
  };

  const api = {
    reduced: false,
    EASE,
    frame(cb) {
      subs.add(cb);
      return () => subs.delete(cb);
    },
    tween({ from = 0, to = 0, duration = 600, ease = 'cubicOut', onUpdate, onDone }) {
      const fn = EASE[ease] || EASE.cubicOut;
      if (api.reduced) {                    // reduced motion: jump to end state
        if (onUpdate) onUpdate(to);
        if (onDone) onDone();
        return { cancel() {} };
      }
      const t0 = performance.now();
      let un = null;
      const step = (dt) => {
        const k = Math.min(1, (performance.now() - t0) / duration);
        if (onUpdate) onUpdate(from + (to - from) * fn(k));
        if (k >= 1) { un(); if (onDone) onDone(); }
      };
      un = api.frame(step);
      return { cancel: un };
    },
    onReducedChange(cb) {
      reducedSubs.add(cb);
      return () => reducedSubs.delete(cb);
    },
    setReduced(v) {
      override = v === null ? null : Boolean(v);
      applyReduced();
    },
  };

  // publish before the first applyReduced() so subscribers see the real flag
  window.CTIMotion = api;
  startClock();
  applyReduced();
})();
