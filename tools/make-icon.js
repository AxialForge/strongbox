'use strict';
// Generates every icon with no dependencies: a rounded dark tile, the blue bracket shared by all
// Bracket apps, and the app's glyph inside it. The design is rectangles on a 256-unit grid,
// rendered at each size with 4× supersampling. Change GLYPH for your app (keep the bracket).
//
//   node tools/make-icon.js
//
// Writes app/renderer/{favicon.ico, favicon-32.png, apple-touch-icon.png, icon-192.png, icon-512.png, logo.svg},
// docs/logo.png and build/{icon.png, icon.ico} (for electron-builder).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const TILE = [23, 26, 33], BLUE = [90, 169, 255], GREEN = [126, 231, 135], WHITE = [230, 232, 238];
// [x0, y0, x1, y1, colour, radius] on the 256 grid, painted in order.
const BRACKET = [
  [8, 8, 248, 248, TILE, 48],
  [56, 56, 200, 72, BLUE], [56, 184, 200, 200, BLUE], [56, 56, 72, 200, BLUE], [184, 56, 200, 200, BLUE],
];
// The app's glyph: a padlock (shackle, body, keyhole) inside the bracket.
const GLYPH = [
  [104, 84, 152, 96, WHITE], [104, 84, 116, 120, WHITE], [140, 84, 152, 120, WHITE],
  [90, 112, 166, 172, WHITE, 8],
  [121, 127, 135, 141, TILE, 7], [125, 136, 131, 156, TILE],
];
const SHAPES = [...BRACKET, ...GLYPH];

function inside(x, y, [x0, y0, x1, y1, , r = 0]) {
  if (x < x0 || x >= x1 || y < y0 || y >= y1) return false;
  if (!r) return true;
  const dx = Math.max(x0 + r - x, 0, x - (x1 - r)), dy = Math.max(y0 + r - y, 0, y - (y1 - r));
  return dx * dx + dy * dy <= r * r;
}
function render(S) {
  const px = Buffer.alloc(S * S * 4);
  const SS = 4, k = 256 / S;
  for (let y = 0; y < S; y++) for (let x = 0; x < S; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
      const gx = (x + (sx + 0.5) / SS) * k, gy = (y + (sy + 0.5) / SS) * k;
      let c = null;
      for (const s of SHAPES) if (inside(gx, gy, s)) c = s[4];
      if (c) { r += c[0]; g += c[1]; b += c[2]; a++; }
    }
    const i = (y * S + x) * 4, n = SS * SS;
    if (a) { px[i] = Math.round(r / a); px[i + 1] = Math.round(g / a); px[i + 2] = Math.round(b / a); }
    px[i + 3] = Math.round(255 * a / n);
  }
  return png(S, px);
}
// ---- PNG encode ----
const crcTable = new Int32Array(256).map((_, n) => { let c = n; for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c; });
const crc32 = buf => { let c = -1; for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ -1) >>> 0; };
const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, crc]); };
function png(S, px) {
  const raw = Buffer.alloc((S * 4 + 1) * S);
  for (let y = 0; y < S; y++) { raw[y * (S * 4 + 1)] = 0; px.copy(raw, y * (S * 4 + 1) + 1, y * S * 4, (y + 1) * S * 4); }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}
function ico(pngs) { // PNG-in-ICO, one entry per size
  const header = Buffer.alloc(6); header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(pngs.length, 4);
  let offset = 6 + 16 * pngs.length; const entries = [];
  for (const [S, data] of pngs) { const e = Buffer.alloc(16); e[0] = S >= 256 ? 0 : S; e[1] = S >= 256 ? 0 : S; e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6); e.writeUInt32LE(data.length, 8); e.writeUInt32LE(offset, 12); offset += data.length; entries.push(e); }
  return Buffer.concat([header, ...entries, ...pngs.map(p => p[1])]);
}
const svg = () => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">${SHAPES.map(([x0, y0, x1, y1, c, r]) => `<rect x="${x0}" y="${y0}" width="${x1 - x0}" height="${y1 - y0}"${r ? ` rx="${r}"` : ''} fill="rgb(${c.join(',')})"/>`).join('')}</svg>\n`;

const root = path.join(__dirname, '..');
const out = (rel, data) => { const p = path.join(root, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, data); console.log('wrote', rel); };
const p32 = render(32), p16 = render(16), p48 = render(48), p256 = render(256);
out('app/renderer/favicon-32.png', p32);
out('app/renderer/favicon.ico', ico([[16, p16], [32, p32], [48, p48]]));
out('app/renderer/apple-touch-icon.png', render(180));
out('app/renderer/icon-192.png', render(192));
out('app/renderer/icon-512.png', render(512));
out('app/renderer/logo.svg', svg());
out('docs/logo.png', p256);
out('build/icon.png', p256);
out('build/icon.ico', ico([[16, p16], [32, p32], [48, p48], [256, p256]]));
