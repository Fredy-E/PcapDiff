// Synthetic deterministic fixture generator (node). No real captures, no personal paths.
// Produces fixtures/a.pcap (10 frames) and fixtures/b.pcap (13 frames):
//   KNOWN planted diff = 3 extra bulk frames at the end + 1 changed byte in record #2.
// Usage: node tools/gen-fixtures.cjs
'use strict';
const fs = require('node:fs');
const path = require('node:path');

function usbPayload(dev, ep, fill, len) {
  const b = Buffer.alloc(len);
  b[0] = dev; b[1] = ep;
  for (let i = 2; i < len; i++) b[i] = (fill + i) & 0xff;
  return b;
}

function buildClassicPcap(records, snaplen = 65535, linktype = 220) {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0);
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
    h.writeUInt32LE(r.payload.length, 8);
    h.writeUInt32LE(r.payload.length, 12);
    parts.push(h, Buffer.from(r.payload));
  }
  return Buffer.concat(parts);
}

function main() {
  const dir = path.join(__dirname, '..', 'fixtures');
  fs.mkdirSync(dir, { recursive: true });
  const base = [];
  for (let i = 0; i < 10; i++) {
    base.push({ sec: 1 + i, usec: i * 1000, payload: usbPayload(3, i % 2 ? 0x81 : 0x01, i, 16) });
  }
  const aBuf = buildClassicPcap(base);
  const bRecs = base.map((r, idx) => {
    if (idx === 2) {
      const p = Buffer.from(r.payload);
      p[5] ^= 0xff; // the 1 planted changed byte
      return { ...r, payload: p };
    }
    return r;
  });
  for (let k = 0; k < 3; k++) {
    bRecs.push({ sec: 20 + k, usec: 50000 + k * 1000, payload: usbPayload(3, 0x02, 100 + k, 32) });
  }
  const bBuf = buildClassicPcap(bRecs);
  fs.writeFileSync(path.join(dir, 'a.pcap'), aBuf);
  fs.writeFileSync(path.join(dir, 'b.pcap'), bBuf);
  console.log('wrote fixtures/a.pcap (' + aBuf.length + ' bytes, 10 records)');
  console.log('wrote fixtures/b.pcap (' + bBuf.length + ' bytes, 13 records)');
  console.log('known diff: +3 extra bulk frames (dev=3 ep=0x02, 32B) in b + 1 changed byte at record #2 offset 5');
}

if (require.main === module) main();
