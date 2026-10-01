// Rough password entropy in bits, shared by the server (weak-password report) and the browser (strength meter).
// Loaded as a plain script in the page and with require() on the server.
(function (root, fn) {
  if (typeof module !== 'undefined' && module.exports) module.exports = { strengthBits: fn };
  else root.strengthBits = fn;
})(typeof self !== 'undefined' ? self : this, function strengthBits(pw) {
  const s = String(pw || '');
  if (!s) return 0;
  let pool = 0;
  // A class used by a single character (the capital at the start, the digit at the end, one dash) adds little.
  const n = (re) => (s.match(re) || []).length;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += n(/[A-Z]/g) > 1 ? 26 : 8;
  if (/\d/.test(s)) pool += n(/\d/g) > 1 ? 10 : 5;
  if (/[^A-Za-z0-9]/.test(s)) pool += n(/[^A-Za-z0-9]/g) > 1 ? 32 : 8;
  const unique = new Set(s).size;
  const runs = (s.match(/(.)\1{2,}/g) || []).join('').length + (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv)/i.test(s) ? 6 : 0);
  const effective = Math.max(1, Math.min(s.length, unique * 2) - runs);
  let bits = effective * Math.log2(Math.max(pool, 2));
  if (/^(password|letmein|admin|welcome|qwerty|changeme|default)/i.test(s)) bits = Math.min(bits, 20);
  return Math.round(bits);
});
