/* Article detail drawer (P3) — native <dialog> so Esc, focus trapping and
   the top layer are the platform's job, not ours. Opens from feed rows,
   category headlines, and threat-level cards. IOC chips are server-extracted
   (app/ioc.py via /api/article/{id}) and copy to the clipboard on click. */
/* global CTIDrawer:true */
(function () {
  'use strict';

  const dlg = document.getElementById('article-drawer');
  const body = document.getElementById('drw-body');
  const closeBtn = document.getElementById('drw-close');

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function ageLabel(seconds) {
    if (seconds < 60) return 'now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    return Math.floor(seconds / 86400) + 'd ago';
  }

  function iocLabel(kind) {
    return { ips: 'IP', domains: 'DOMAIN', cves: 'CVE', sha256: 'SHA256' }[kind] || kind;
  }

  function render(article) {
    const t = new Date(article.published * 1000);
    const kinds = Object.keys(article.iocs || {});
    const iocCount = kinds.reduce((n, k) => n + (article.iocs[k] || []).length, 0);
    body.innerHTML =
      `<div class="drw-cat">${esc(article.category.toUpperCase())} · ${esc(article.source_group || '')}</div>` +
      `<div class="drw-headline">${esc(article.title)}</div>` +
      `<div class="drw-meta"><span>${esc(article.source)}</span>` +
      `<span class="age">${t.toLocaleTimeString('en-GB', { hour12: false })} · ${ageLabel(Date.now() / 1000 - article.published)}</span></div>` +
      `<div class="drw-summary">${article.summary ? esc(article.summary) : '<span class="drw-empty">No summary text in this feed entry.</span>'}</div>` +
      `<div class="drw-section-title">INDICATORS ${iocCount ? `(${iocCount})` : ''}</div>` +
      (iocCount
        ? `<div class="ioc-grid">${kinds.flatMap((k) => (article.iocs[k] || []).map((v) =>
            `<button class="ioc-chip" data-ioc="${esc(v)}" title="Copy ${esc(v)}">` +
            `${iocLabel(k)} · ${esc(v)}</button>`)).join('')}</div>`
        : '<div class="ioc-none">— no indicators surfaced in this article —</div>') +
      `<button class="drw-open" data-url="${esc(article.url)}">OPEN SOURCE ↗</button>`;
  }

  function renderError(id) {
    body.innerHTML = '<div class="drw-empty">Article details unavailable — ' +
      'the corpus may have rotated. Close and reopen from the feed.</div>' +
      `<div class="drw-meta"><span>id: ${esc(id)}</span></div>`;
  }

  async function openById(id) {
    if (typeof dlg.showModal !== 'function') return;   // ancient engine guard
    if (!dlg.open) dlg.showModal();
    body.innerHTML = '<div class="drw-empty">Loading…</div>';
    try {
      const res = await fetch(`/api/article/${encodeURIComponent(id)}`, { cache: 'no-store' });
      if (!res.ok) throw new Error(`article ${res.status}`);
      render(await res.json());
    } catch (e) {
      renderError(id);
    }
  }

  // copy-to-clipboard with a fallback for non-secure contexts (loopback http
  // without a secure context is not guaranteed to expose the async API)
  async function copyText(text, chip) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
      ta.remove();
    }
    if (ok) {
      chip.classList.add('copied');
      setTimeout(() => chip.classList.remove('copied'), 1200);
    }
  }

  body.addEventListener('click', (e) => {
    const chip = e.target.closest('.ioc-chip');
    if (chip) { copyText(chip.dataset.ioc, chip); return; }
    const open = e.target.closest('.drw-open');
    if (open && open.dataset.url) {
      window.open(open.dataset.url, '_blank', 'noopener');
    }
  });
  closeBtn.addEventListener('click', () => dlg.close());
  // click on the backdrop (the dialog element itself) closes too
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });

  window.CTIDrawer = { openById };
})();
