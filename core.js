/* pcap-diff core: offline classic-pcap + pcapng-EPB parser and session compare.
 * Pure logic, no DOM. Works in browser (window.PcapDiffCore) and Node (module.exports).
 * Timestamps kept as BigInt microseconds until display.
 * USB endpoint heuristic (synthetic fixtures): payload[0]=dev, payload[1]=ep.
 */
'use strict';

(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.PcapDiffCore = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {

  function u8(view) {
    if (view instanceof Uint8Array) return view;
    throw new Error('invalid input: expected Uint8Array');
  }

  function dv(buf) {
    return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  function endpointOf(payload) {
    if (payload.length >= 2) return { dev: payload[0], ep: payload[1] };
    return { dev: null, ep: null };
  }

  function endpointKey(dev, ep) {
    if (dev === null || dev === undefined || ep === null || ep === undefined) return 'unknown';
    return 'dev=' + dev + ' ep=0x' + ep.toString(16).padStart(2, '0');
  }

  function hexPreview(payload, n) {
    n = n || 16;
    const m = Math.min(n, payload.length);
    let out = '';
    for (let i = 0; i < m; i++) out += payload[i].toString(16).padStart(2, '0') + (i + 1 < m ? ' ' : '');
    if (payload.length > m) out += ' …';
    return out;
  }

  // ---------- classic pcap ----------
  function parsePcap(buf) {
    buf = u8(buf);
    if (buf.length === 0) throw new Error('invalid file: empty (malformed)');
    if (buf.length < 24) throw new Error('invalid file: short global header (malformed)');
    const d = dv(buf);
    const b0 = buf[0], b1 = buf[1], b2 = buf[2], b3 = buf[3];
    let le, nano;
    if (b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1) { le = true; nano = false; }
    else if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0xc3 && b3 === 0xd4) { le = false; nano = false; }
    else if (b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1) { le = true; nano = true; }
    else if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0x3c && b3 === 0x4d) { le = false; nano = true; }
    else throw new Error('invalid file: bad magic, not pcap/pcapng (malformed)');
    const snaplen = d.getUint32(16, le);
    const linktype = d.getUint32(20, le);
    const records = [];
    const warnings = [];
    let off = 24;
    let idx = 0;
    while (off < buf.length) {
      if (buf.length - off < 16) throw new Error('malformed file: short packet header at record ' + idx);
      const sec = d.getUint32(off, le);
      const usec = d.getUint32(off + 4, le);
      const incl = d.getUint32(off + 8, le);
      const orig = d.getUint32(off + 12, le);
      const remain = buf.length - off - 16;
      if (incl > remain) {
        throw new Error('malformed file: truncated packet data at record ' + idx + ' (incl=' + incl + ' > remaining=' + remain + ')');
      }
      if (snaplen !== 0 && incl > snaplen) {
        warnings.push('record ' + idx + ': incl_len ' + incl + ' exceeds snaplen ' + snaplen + ' (snaplen-aware bounds)');
      }
      if (incl > 100 * 1024 * 1024) throw new Error('malformed file: implausible incl_len at record ' + idx);
      const payload = buf.slice(off + 16, off + 16 + incl);
      const tsUs = BigInt(sec) * 1000000n + (nano ? BigInt(Math.floor(usec / 1000)) : BigInt(usec));
      const truncated = orig > incl;
      if (truncated) warnings.push('record ' + idx + ': snaplen truncation (capLen=' + incl + ' < origLen=' + orig + ')');
      const { dev, ep } = endpointOf(payload);
      records.push({ index: idx, tsUs, capLen: incl, origLen: orig, truncated, payload, dev, ep });
      off += 16 + incl;
      idx++;
    }
    return { format: 'pcap', linktype, snaplen, nano, records, warnings };
  }

  // ---------- pcapng (LE, EPB) ----------
  function parsePcapng(buf) {
    buf = u8(buf);
    if (buf.length < 12) throw new Error('invalid file: short pcapng (malformed)');
    const d = dv(buf);
    const records = [];
    const warnings = [];
    const ifaces = []; // { snaplen }
    let off = 0;
    let seenSHB = false;
    let le = true;
    let idx = 0;
    while (off + 12 <= buf.length) {
      const type = d.getUint32(off, true); // block type reads same both orders for SHB/IDB/EPB small values? read LE then fix
      // Detect BE by checking swapped type for known blocks
      let btype = type;
      const swapped = ((type & 0xff) << 24) | (((type >> 8) & 0xff) << 16) | (((type >> 16) & 0xff) << 8) | ((type >>> 24) & 0xff);
      if (type !== 0x0a0d0d0a && type !== 1 && type !== 6 && (swapped === 0x0a0d0d0a || swapped === 1 || swapped === 6)) {
        throw new Error('unsupported file: big-endian pcapng not supported in prototype');
      }
      btype = type;
      let total = d.getUint32(off + 4, le);
      if (total < 12) throw new Error('malformed file: bad pcapng block length at offset ' + off);
      if (off + total > buf.length) throw new Error('malformed file: truncated pcapng block at offset ' + off + ' (bounds)');
      if (d.getUint32(off + total - 4, le) !== total) throw new Error('malformed file: pcapng block trailer mismatch at offset ' + off);
      const bodyOff = off + 8;
      const bodyLen = total - 12;
      if (btype === 0x0a0d0d0a) {
        // SHB: byte-order magic at body+0
        if (bodyLen < 20) throw new Error('malformed file: short SHB');
        const magic = d.getUint32(bodyOff, true);
        if (magic === 0x1a2b3c4d) { le = true; }
        else if (magic === 0x4d3c2b1a) { throw new Error('unsupported file: big-endian pcapng not supported in prototype'); }
        else throw new Error('malformed file: bad SHB byte-order magic');
        seenSHB = true;
      } else if (btype === 1) {
        // IDB
        if (bodyLen < 8) throw new Error('malformed file: short IDB');
        const linktype = d.getUint16(bodyOff, le);
        const snaplen = d.getUint32(bodyOff + 4, le);
        ifaces.push({ linktype, snaplen });
      } else if (btype === 6) {
        // EPB: interface_id, ts_high, ts_low, caplen, len (spec order)
        if (bodyLen < 20) throw new Error('malformed file: short EPB');
        const ifId = d.getUint32(bodyOff, le);
        const tsHigh = d.getUint32(bodyOff + 4, le);
        const tsLow = d.getUint32(bodyOff + 8, le);
        const caplen = d.getUint32(bodyOff + 12, le);
        const origlen = d.getUint32(bodyOff + 16, le);
        const iface = ifaces[ifId];
        const snaplen = iface ? iface.snaplen : 0;
        if (snaplen !== 0 && caplen > snaplen) {
          warnings.push('record ' + idx + ': caplen ' + caplen + ' exceeds snaplen ' + snaplen + ' (snaplen-aware bounds)');
        }
        const pad = (4 - (caplen % 4)) % 4;
        if (20 + caplen + pad > bodyLen) {
          throw new Error('malformed file: truncated EPB packet data at record ' + idx + ' (bounds)');
        }
        const payload = buf.slice(bodyOff + 20, bodyOff + 20 + caplen);
        const tsUs = (BigInt(tsHigh) << 32n) | BigInt(tsLow); // microsecond resolution (prototype)
        const truncated = origlen > caplen;
        if (truncated) warnings.push('record ' + idx + ': snaplen truncation (capLen=' + caplen + ' < origLen=' + origlen + ')');
        const { dev, ep } = endpointOf(payload);
        records.push({ index: idx, tsUs, capLen: caplen, origLen: origlen, truncated, payload, dev, ep });
        idx++;
      }
      // else: ignore other blocks (ISB, options, etc.)
      off += total;
    }
    if (!seenSHB) throw new Error('invalid file: bad magic, not pcap/pcapng (malformed)');
    return { format: 'pcapng', linktype: ifaces.length ? ifaces[0].linktype : null, records, warnings };
  }

  function parseCapture(buf) {
    const b = u8(buf instanceof Uint8Array ? buf : new Uint8Array(buf));
    if (b.length === 0) throw new Error('invalid file: empty (malformed)');
    if (b.length >= 4 && b[0] === 0x0a && b[1] === 0x0d && b[2] === 0x0d && b[3] === 0x0a) {
      return parsePcapng(b);
    }
    // classic magic check first for a clean error on garbage
    return parsePcap(b);
  }

  // ---------- compare ----------
  function lengthHistogram(records) {
    const h = {};
    for (const r of records) {
      const k = String(r.capLen);
      h[k] = (h[k] || 0) + 1;
    }
    return h;
  }

  function firstByteDiff(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
    if (a.length !== b.length) return n;
    return -1;
  }

  function compareSessions(a, b) {
    const ra = a.records, rb = b.records;
    const setA = new Set(ra.map((r) => endpointKey(r.dev, r.ep)));
    const setB = new Set(rb.map((r) => endpointKey(r.dev, r.ep)));
    const aOnly = [...setA].filter((k) => !setB.has(k)).sort();
    const bOnly = [...setB].filter((k) => !setA.has(k)).sort();
    const common = [...setA].filter((k) => setB.has(k)).sort();

    function extent(r) {
      if (!r.length) return { first: null, last: null, dur: 0n };
      let first = r[0].tsUs, last = r[0].tsUs;
      for (const rec of r) {
        if (rec.tsUs < first) first = rec.tsUs;
        if (rec.tsUs > last) last = rec.tsUs;
      }
      return { first, last, dur: last - first };
    }
    const ea = extent(ra), eb = extent(rb);
    const timing = {
      aFirst: ea.first === null ? null : String(ea.first),
      aLast: ea.last === null ? null : String(ea.last),
      aDurUs: String(ea.dur),
      bFirst: eb.first === null ? null : String(eb.first),
      bLast: eb.last === null ? null : String(eb.last),
      bDurUs: String(eb.dur),
      firstDeltaUs: (ea.first === null || eb.first === null) ? '0' : String(eb.first - ea.first),
      durDeltaUs: String(eb.dur - ea.dur),
    };

    const payloadDiffs = [];
    const n = Math.min(ra.length, rb.length);
    for (let i = 0; i < n && payloadDiffs.length < 20; i++) {
      const pa = ra[i].payload, pb = rb[i].payload;
      const off = firstByteDiff(pa, pb);
      if (off >= 0) {
        payloadDiffs.push({
          index: i,
          kind: pa.length !== pb.length ? 'len' : 'bytes',
          aLen: pa.length, bLen: pb.length,
          firstByteOffset: off,
          aByte: off < pa.length ? pa[off] : null,
          bByte: off < pb.length ? pb[off] : null,
          aPreview: hexPreview(pa),
          bPreview: hexPreview(pb),
        });
      }
    }
    // tail extras
    if (ra.length !== rb.length && payloadDiffs.length < 20) {
      const longerIsB = rb.length > ra.length;
      for (let i = n; i < Math.max(ra.length, rb.length) && payloadDiffs.length < 20; i++) {
        const rec = longerIsB ? rb[i] : ra[i];
        payloadDiffs.push({
          index: i,
          kind: longerIsB ? 'extra-in-b' : 'extra-in-a',
          aLen: longerIsB ? null : rec.payload.length,
          bLen: longerIsB ? rec.payload.length : null,
          firstByteOffset: 0,
          aByte: null, bByte: null,
          aPreview: longerIsB ? '' : hexPreview(rec.payload),
          bPreview: longerIsB ? hexPreview(rec.payload) : '',
        });
      }
    }

    return {
      counts: { a: ra.length, b: rb.length, delta: rb.length - ra.length },
      endpoints: { aOnly, bOnly, common },
      timing,
      lengthHist: { a: lengthHistogram(ra), b: lengthHistogram(rb) },
      payloadDiffs,
      warnings: { a: a.warnings || [], b: b.warnings || [] },
    };
  }

  function formatTsUs(tsBig) {
    // BigInt microseconds -> "123.456789 s" style; keep BigInt until display.
    const v = BigInt(tsBig);
    const sec = v / 1000000n;
    const us = v % 1000000n;
    return sec.toString() + '.' + us.toString().padStart(6, '0') + 's';
  }

  return { parseCapture, parsePcap, parsePcapng, compareSessions, endpointKey, formatTsUs };
});
