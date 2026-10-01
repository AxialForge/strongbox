const vm = require('vm'), fs = require('fs'), assert = require('assert');
const store = { get: (k, d) => d, set() {} };
const ctx = { window: { UI: { $: () => null, $$: () => [], esc: String, toast() {}, store, api: () => ({}) } }, crypto: require('crypto').webcrypto, navigator: {}, document: {}, setTimeout, clearTimeout, console };
ctx.window.window = ctx.window; ctx.self = ctx.window;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(require('path').join(__dirname, '..', 'renderer', 'strength.js'), 'utf8'), ctx);
vm.runInContext(fs.readFileSync(require('path').join(__dirname, '..', 'renderer', 'util.js'), 'utf8'), ctx);
const SB = ctx.window.SB;
for (let i = 0; i < 300; i++) {
  const a = SB.generate({ length: 16, symbolSet: '!@#', minUpper: 2, minDigits: 3, minSymbols: 2, startLetter: true, exclude: 'abc' }).value;
  assert.strictEqual(a.length, 16); assert.ok(/^[A-Za-z]/.test(a)); assert.ok((a.match(/[A-Z]/g) || []).length >= 2); assert.ok((a.match(/\d/g) || []).length >= 3); assert.ok((a.match(/[!@#]/g) || []).length >= 2);
  assert.ok(!/[abcO0oIl1|]/.test(a) && !/[^A-Za-z0-9!@#]/.test(a) && !/(.)\1\1/.test(a), a);
}
assert.ok(!/[^A-Za-z0-9]/.test(SB.generate({ symbols: false }).value));
assert.ok(/^\d{6}$/.test(SB.generate({ mode: 'pin', length: 6 }).value));
assert.ok(/^[0-9a-f]{32}$/.test(SB.generate({ mode: 'hex', length: 32 }).value));
const ph = SB.generate({ mode: 'phrase', words: 4 }); assert.ok(/^([A-Z][a-z]{5}-){4}\d\d[^a-z]$/.test(ph.value), ph.value); assert.ok(ph.bits > 70);
assert.strictEqual(SB.generate({ length: 4, minUpper: 3, minDigits: 3, minSymbols: 3 }).value.length, 10, 'length grows to fit the minimums');
assert.throws(() => SB.generate({ lower: false, upper: false, digits: false, symbols: false }));
console.log('generator tests passed');
