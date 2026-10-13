/* pcap-diff browser UI: file inputs -> PcapDiffCore.parseCapture -> compareSessions -> render.
 * Offline, no CDN, no deps. Load via file:// with core.js first (classic scripts, no modules).
 */
'use strict';
(function () {
  const $ = (id) => document.getElementById(id);
  let bufA = null, bufB = null;

  function readAsU8(file) {
    return file.arrayBuffer().then((ab) => new Uint8Array(ab));
  }

  function fmt(n) { return n === null || n === undefined ? '—' : String(n); }

  async function onFile(side, file) {
    const err = $('error');
    err.textContent = '';
    try {
      const u8 = await readAsU8(file);
      const parsed = window.PcapDiffCore.parseCapture(u8);
      if (side === 'A') { bufA = parsed; $('metaA').textContent = file.name + ' — ' + parsed.format + ', ' + parsed.records.length + ' records'; }
      else { bufB = parsed; $('metaB').textContent = file.name + ' — ' + parsed.format + ', ' + parsed.records.length + ' records'; }
    } catch (e) {
      if (side === 'A') bufA = null; else bufB = null;
      err.textContent = 'Could not parse ' + file.name + ': ' + (e && e.message ? e.message : e);
    }
    $('compareBtn').disabled = !(bufA && bufB);
  }

  function render(cmp) {
    $('results').hidden = false;
    $('counts').textContent =
      'A: ' + cmp.counts.a + ' records\nB: ' + cmp.counts.b + ' records\ndelta (B−A): ' + cmp.counts.delta;
    $('endpoints').textContent =
      'common (' + cmp.endpoints.common.length + '): ' + (cmp.endpoints.common.join(', ') || '—') +
      '\nonly in A / lost (' + cmp.endpoints.aOnly.length + '): ' + (cmp.endpoints.aOnly.join(', ') || '—') +
      '\nonly in B / new (' + cmp.endpoints.bOnly.length + '): ' + (cmp.endpoints.bOnly.join(', ') || '—') +
      '\n(heuristic: payload[0]=dev, payload[1]=ep)';
    const C = window.PcapDiffCore;
    $('timing').textContent =
      'A first: ' + (cmp.timing.aFirst === null ? '—' : C.formatTsUs(BigInt(cmp.timing.aFirst))) +
      '\nA last:  ' + (cmp.timing.aLast === null ? '—' : C.formatTsUs(BigInt(cmp.timing.aLast))) +
      '\nB first: ' + (cmp.timing.bFirst === null ? '—' : C.formatTsUs(BigInt(cmp.timing.bFirst))) +
      '\nB last:  ' + (cmp.timing.bLast === null ? '—' : C.formatTsUs(BigInt(cmp.timing.bLast))) +
      '\nfirst-delta (B−A): ' + cmp.timing.firstDeltaUs + ' µs' +
      '\nduration-delta (B−A): ' + cmp.timing.durDeltaUs + ' µs';
    function histStr(h) {
      const keys = Object.keys(h).map(Number).sort((x, y) => x - y);
      return keys.map((k) => {
        const bar = '#'.repeat(Math.min(40, h[String(k)]));
        return String(k).padStart(5) + 'B: ' + String(h[String(k)]).padStart(4) + ' ' + bar;
      }).join('\n') || '—';
    }
    $('hist').textContent = 'A:\n' + histStr(cmp.lengthHist.a) + '\n\nB:\n' + histStr(cmp.lengthHist.b);
    const tb = $('diffs').querySelector('tbody');
    tb.textContent = '';
    for (const d of cmp.payloadDiffs) {
      const tr = document.createElement('tr');
      [d.index, d.kind, fmt(d.aLen), fmt(d.bLen), d.firstByteOffset, d.aPreview || '', d.bPreview || ''].forEach((v) => {
        const td = document.createElement('td');
        td.textContent = String(v);
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    }
    if (!cmp.payloadDiffs.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7; td.textContent = 'No differing windows in overlap; counts equal.';
      tr.appendChild(td); tb.appendChild(tr);
    }
    $('warnings').textContent =
      'A: ' + (cmp.warnings.a.length ? cmp.warnings.a.join('\n') : 'none') +
      '\nB: ' + (cmp.warnings.b.length ? cmp.warnings.b.join('\n') : 'none');
  }

  function init() {
    $('fileA').addEventListener('change', (e) => { if (e.target.files[0]) onFile('A', e.target.files[0]); });
    $('fileB').addEventListener('change', (e) => { if (e.target.files[0]) onFile('B', e.target.files[0]); });
    $('compareBtn').addEventListener('click', () => {
      const err = $('error');
      err.textContent = '';
      try {
        const cmp = window.PcapDiffCore.compareSessions(bufA, bufB);
        render(cmp);
      } catch (e) { err.textContent = 'Compare failed: ' + (e && e.message ? e.message : e); }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
