// pcap-diff TDD tests (node:test). Must run with: node tests/*.test.cjs
// RED phase: imports ../core.js which does not exist yet -> fails.
// GREEN phase: core.js implements parseCapture/compareSessions.
'use strict';
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const corePath = path.join(__dirname, '..', 'core.js');
const { parseCapture, compareSessions } = require(corePath);

// ---- minimal in-test builders (independent of implementation) ----

function buildClassicPcap(records, { snaplen = 65535, linktype = 220 } = {}) {
  // records: [{ sec, usec, payload: Uint8Array }]
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0); // LE magic
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(snaplen, 16);
  header.writeUInt32LE(linktype, 20);
  const parts = [header];
  for (const r of records) {
    const h = Buffer.alloc(16);
    h.writeUInt32LE(r.sec >>> 0, 0);
    h.writeUInt32LE(r.usec >>> 0, 4);
    h.writeUInt32LE(r.payload.length, 8); // incl_len
    h.writeUInt32LE(r.origLen ?? r.payload.length, 12); // orig_len
    parts.push(h, Buffer.from(r.payload));
  }
  return Buffer.concat(parts);
}

function usbPayload(dev, ep, fill, len = 16) {
  const b = Buffer.alloc(len);
  b[0] = dev;
  b[1] = ep;
  for (let i = 2; i < len; i++) b[i] = (fill + i) & 0xff;
  return b;
}

function buildPcapngEPB(records) {
  // Minimal LE pcapng: SHB + IDB(snaplen 0) + EPBs, ts in microseconds.
  function block(type, body) {
    const total = 12 + body.length;
    const b = Buffer.alloc(total);
    b.writeUInt32LE(type, 0);
    b.writeUInt32LE(total, 4);
    Buffer.from(body).copy(b, 8);
    b.writeUInt32LE(total, 8 + body.length);
    return b;
  }
  const shbBody = Buffer.alloc(28);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0); // byte-order magic (LE read)
  shbBody.writeUInt16LE(1, 4);
  shbBody.writeUInt16LE(0, 6);
  shbBody.writeBigInt64LE(BigInt(-1), 8);
  // options none; pad to 28 total body? SHB body must be 20 min; use 28 with trailing zeros
  const shb = block(0x0a0d0d0a, shbBody);
  const idbBody = Buffer.alloc(20);
  idbBody.writeUInt16LE(220, 0); // linktype
  idbBody.writeUInt16LE(0, 2);
  idbBody.writeUInt32LE(0, 4); // snaplen 0 = unlimited
  const idb = block(0x00000001, idbBody);
  const epbs = records.map((r) => {
    const body = Buffer.alloc(20 + r.payload.length + ((4 - (r.payload.length % 4)) % 4));
    body.writeUInt32LE(0, 0); // interface_id
    const ts = BigInt(r.tsUs);
    body.writeUInt32LE(Number((ts >> 32n) & 0xffffffffn), 4); // ts high (spec order)
    body.writeUInt32LE(Number(ts & 0xffffffffn), 8); // ts low
    body.writeUInt32LE(r.payload.length, 12);
    body.writeUInt32LE(r.origLen ?? r.payload.length, 16);
    Buffer.from(r.payload).copy(body, 20);
    return block(0x00000006, body);
  });
  return Buffer.concat([shb, idb, ...epbs]);
}

describe('pcap-diff core', () => {
  test('detects known planted diff: 3 extra frames + 1 changed byte', () => {
    const base = [];
    for (let i = 0; i < 10; i++) {
      base.push({ sec: 1 + i, usec: i * 1000, payload: usbPayload(3, i % 2 ? 0x81 : 0x01, i) });
    }
    const aBuf = buildClassicPcap(base);
    const bRecs = base.map((r, idx) => {
      if (idx === 2) {
        const p = Buffer.from(r.payload);
        p[5] ^= 0xff; // 1 changed byte
        return { ...r, payload: p };
      }
      return r;
    });
    for (let k = 0; k < 3; k++) {
      bRecs.push({ sec: 2, usec: 50000 + k * 1000, payload: usbPayload(3, 0x02, 100 + k, 32) });
    }
    const bBuf = buildClassicPcap(bRecs);
    const a = parseCapture(new Uint8Array(aBuf));
    const b = parseCapture(new Uint8Array(bBuf));
    assert.equal(a.records.length, 10);
    assert.equal(b.records.length, 13);
    const cmp = compareSessions(a, b);
    assert.equal(cmp.counts.a, 10);
    assert.equal(cmp.counts.b, 13);
    assert.equal(cmp.counts.delta, 3);
    // differing payload windows must include index 2 with byte-level detail
    const idxs = cmp.payloadDiffs.map((d) => d.index);
    assert.ok(idxs.includes(2), 'expected diff window at index 2, got ' + JSON.stringify(idxs));
    // new endpoint 0x02 only on B side
    assert.ok(cmp.endpoints.bOnly.some((e) => e.includes('2') || e.toLowerCase().includes('02')), 'expected new endpoint on B side: ' + JSON.stringify(cmp.endpoints));
  });

  test('snaplen truncation is flagged (origLen > capLen, snaplen-aware bounds)', () => {
    // incl_len=8 but orig_len=64 -> truncated
    const payload = usbPayload(5, 0x81, 7, 8);
    const full = buildClassicPcap([{ sec: 1, usec: 0, payload, origLen: 64 }]);
    const parsed = parseCapture(new Uint8Array(full));
    assert.equal(parsed.records.length, 1);
    assert.equal(parsed.records[0].truncated, true);
    assert.equal(parsed.records[0].origLen, 64);
    assert.equal(parsed.records[0].capLen, 8);
  });

  test('malformed file is rejected (bad magic / truncated header)', () => {
    assert.throws(() => parseCapture(new Uint8Array([1, 2, 3, 4, 5])), /magic|short|malformed|invalid/i);
    assert.throws(() => parseCapture(new Uint8Array(0)), /empty|short|magic|malformed|invalid/i);
    // classic header claims a packet but buffer ends
    const hdr = Buffer.alloc(24);
    hdr.writeUInt32LE(0xa1b2c3d4, 0);
    hdr.writeUInt16LE(2, 4); hdr.writeUInt16LE(4, 6);
    hdr.writeUInt32LE(65535, 16); hdr.writeUInt32LE(220, 20);
    const pktHdr = Buffer.alloc(16);
    pktHdr.writeUInt32LE(1, 0); pktHdr.writeUInt32LE(0, 4);
    pktHdr.writeUInt32LE(100, 8); pktHdr.writeUInt32LE(100, 12);
    assert.throws(() => parseCapture(new Uint8Array(Buffer.concat([hdr, pktHdr]))), /trunc|short|bounds|malformed/i);
  });

  test('pcapng EPB parses with BigInt timestamps until display', () => {
    const recs = [
      { tsUs: 1_000_000n, payload: usbPayload(4, 0x81, 1) },
      { tsUs: 1_002_500n, payload: usbPayload(4, 0x01, 2) },
    ];
    const buf = buildPcapngEPB(recs);
    const parsed = parseCapture(new Uint8Array(buf));
    assert.equal(parsed.format, 'pcapng');
    assert.equal(parsed.records.length, 2);
    assert.equal(typeof parsed.records[0].tsUs, 'bigint');
    assert.equal(parsed.records[0].tsUs, 1_000_000n);
    const cmp = compareSessions(parsed, parsed);
    assert.equal(cmp.counts.delta, 0);
    assert.equal(cmp.payloadDiffs.length, 0);
  });

  test('record counts, endpoints, timing drift and histograms exist', () => {
    const aBuf = buildClassicPcap([
      { sec: 10, usec: 0, payload: usbPayload(2, 0x81, 1, 16) },
      { sec: 10, usec: 1000, payload: usbPayload(2, 0x81, 2, 64) },
    ]);
    const bBuf = buildClassicPcap([
      { sec: 10, usec: 500, payload: usbPayload(9, 0x02, 1, 16) },
      { sec: 10, usec: 3000, payload: usbPayload(9, 0x02, 2, 64) },
    ]);
    const a = parseCapture(new Uint8Array(aBuf));
    const b = parseCapture(new Uint8Array(bBuf));
    const cmp = compareSessions(a, b);
    assert.ok(cmp.counts && typeof cmp.counts.a === 'number');
    assert.ok(cmp.endpoints && Array.isArray(cmp.endpoints.aOnly) && Array.isArray(cmp.endpoints.bOnly));
    assert.ok(cmp.endpoints.aOnly.length > 0 && cmp.endpoints.bOnly.length > 0, 'expected lost+new endpoints');
    assert.ok(cmp.timing && typeof cmp.timing.firstDeltaUs === 'string', 'timing drift as string BigInt');
    assert.ok(cmp.lengthHist && cmp.lengthHist.a && cmp.lengthHist.b, 'histograms present');
  });

  test('generated fixtures (if present) show the documented known diff', () => {
    const fa = path.join(__dirname, '..', 'fixtures', 'a.pcap');
    const fb = path.join(__dirname, '..', 'fixtures', 'b.pcap');
    if (!fs.existsSync(fa) || !fs.existsSync(fb)) return; // generator not run yet
    const a = parseCapture(new Uint8Array(fs.readFileSync(fa)));
    const b = parseCapture(new Uint8Array(fs.readFileSync(fb)));
    const cmp = compareSessions(a, b);
    assert.equal(cmp.counts.b - cmp.counts.a, 3, 'fixtures must differ by exactly 3 frames');
    assert.ok(cmp.payloadDiffs.length >= 1, 'fixtures must contain >=1 changed-byte window');
  });
});
