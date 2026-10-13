# pcap-diff — offline USB session-compare prototype

**Experimental concept prototype — idea exploration only.**

Offline browser page that loads TWO pcap/pcapng files locally and shows a session
comparison: record counts, new/lost endpoints, timing drift, payload-length
histograms, and differing payload windows. Nothing is uploaded; parsing runs
entirely in-page. Synthetic fixtures only.

## Open (no build, no server, no CDN)

1. In your file manager go to this folder (`pcap-diff/`).
2. Double-click `index.html` — or in a browser use File → Open File → `index.html`
   (`file://` is enough; no localhost needed).
3. Choose Capture A and Capture B (e.g. `fixtures/a.pcap`, `fixtures/b.pcap`
   after generating them), then click **Compare sessions**.

## Fixtures (synthetic, deterministic)

```sh
node tools/gen-fixtures.cjs   # writes fixtures/a.pcap + fixtures/b.pcap
```

Known planted diff: `b.pcap` = `a.pcap` (10 frames) **+ 3 extra bulk frames**
(dev=3, ep=0x02, 32 B each) **+ 1 changed byte** (record #2, payload offset 5
flipped with `^ 0xFF`). No real captures are shipped.

## Tests (TDD RED → GREEN)

```sh
node tests/pcap-diff.test.cjs
```

Covers: planted-diff detection, snaplen-truncation flag, malformed rejection,
pcapng EPB with BigInt timestamps, counts/endpoints/drift/histograms, and the
generated fixtures when present.

## How parsing works

- Classic pcap: LE/BE + micro/nanosec magic; per-packet `incl_len`/`orig_len`
  with snaplen-aware bounds (`orig > incl` → `truncated: true` + warning;
  `incl > remaining` → malformed error).
- pcapng: LE Section Header + Interface Description (snaplen) + Enhanced Packet
  Blocks; `caplen < len` → truncated; `caplen > snaplen` → warning.
- Timestamps stay `BigInt` microseconds until display (`formatTsUs`).
- USB endpoint identity is a documented prototype heuristic:
  `payload[0]` = device, `payload[1]` = endpoint. Real USB dissect (Linux
  usbmon/DDL 220 headers, descriptors, transfers) is out of scope.

## Honest limits

- Fixtures only; no hardware/USB capture or live-device claims.
- Heuristic endpoints, not a real USB dissector.
- pcapng: little-endian + microsecond resolution only; big-endian and custom
  `tsresol` rejected/assumed; other block types ignored.
- No fuzzing/security review; do not feed untrusted captures in production.
- Offline single-page prototype: no persistence, no workers, large files may be slow.
