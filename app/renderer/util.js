'use strict';
/* Small browser helpers the pages share: clipboard (with auto-clear), the password generator, downloads,
   the strength meter and the reveal/copy buttons. Everything secret is fetched at the moment of use and
   dropped from the page again after a few seconds. */
(function () {
  const { $, $$, esc, toast, store } = window.UI;
  const api = () => window.UI.api();
  const SB = (window.SB = { status: null, settings: null });

  // ---------- clipboard ----------------------------------------------------------------------------
  let clearTimer = null;
  async function writeClipboard(text) {
    try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; } } catch { /* fall through */ }
    const t = document.createElement('textarea'); // plain-HTTP pages have no async clipboard
    t.value = text; t.setAttribute('readonly', ''); t.style.cssText = 'position:fixed;top:-100px;opacity:0';
    document.body.append(t); t.select();
    let ok = false; try { ok = document.execCommand('copy'); } catch { /* blocked */ }
    t.remove();
    return ok;
  }
  /** Copies `text`; after the configured number of seconds the clipboard is overwritten with nothing. */
  async function copy(text, what = 'Copied', sensitive = true) {
    if (!(await writeClipboard(text))) return toast('The browser blocked copying. Use Show and copy it by hand.', true);
    const secs = sensitive ? Number((SB.settings || {}).clipboardClearSeconds) || 0 : 0;
    clearTimeout(clearTimer);
    if (secs) clearTimer = setTimeout(() => { writeClipboard(' '); }, secs * 1000);
    toast(secs ? `${what}. The clipboard clears in ${secs} s.` : what);
  }

  // ---------- downloads ----------------------------------------------------------------------------
  function download(name, data, type = 'text/plain', base64 = false) {
    const bytes = base64 ? Uint8Array.from(atob(data), c => c.charCodeAt(0)) : data;
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  // ---------- generator ----------------------------------------------------------------------------
  const CLASSES = { lower: 'abcdefghijklmnopqrstuvwxyz', upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits: '0123456789', symbols: '!@#$%^&*()-_=+[]{};:,.?/~' };
  const AMBIGUOUS = /[O0oIl1|]/g;
  const randInt = (n) => { const max = Math.floor(0x100000000 / n) * n; const b = new Uint32Array(1); do crypto.getRandomValues(b); while (b[0] >= max); return b[0] % n; };
  function generate({ length = 20, lower = true, upper = true, digits = true, symbols = true, ambiguous = false } = {}) {
    const sets = Object.entries({ lower, upper, digits, symbols }).filter(([, on]) => on).map(([k]) => (ambiguous ? CLASSES[k] : CLASSES[k].replace(AMBIGUOUS, '')));
    if (!sets.length) sets.push(CLASSES.lower);
    const all = sets.join(''), out = sets.map(s => s[randInt(s.length)]);
    while (out.length < length) out.push(all[randInt(all.length)]);
    for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
    return out.slice(0, Math.max(length, sets.length)).join('');
  }
  const strengthLabel = (bits) => (bits >= 90 ? ['Excellent', ''] : bits >= 70 ? ['Strong', ''] : bits >= 50 ? ['Fair', 'warn'] : ['Weak', 'bad']);
  const meterHtml = (bits) => { const [label, cls] = strengthLabel(bits); return `<div class="meter ${cls}"><div style="width:${Math.min(100, Math.round(bits / 1.2))}%"></div></div><span class="tiny ${cls}">${label} · ~${bits} bits</span>`; };

  /** A small dialog: pick options, get a password; calls onUse(password). */
  function generatorModal(onUse) {
    const saved = JSON.parse(store.get('gen', '{}') || '{}');
    const o = { length: 20, lower: true, upper: true, digits: true, symbols: true, ambiguous: false, ...saved };
    const card = window.UI.openModal(`<h2>Password generator</h2>
      <div class="field"><label>Length</label><div class="inline"><input type="range" id="gLen" min="8" max="64" value="${o.length}" style="flex:1"><b id="gLenN">${o.length}</b></div></div>
      <div class="field"><label>Include</label><div class="inline">${['lower', 'upper', 'digits', 'symbols'].map(k => `<label class="inline small"><input type="checkbox" class="gC" data-k="${k}" ${o[k] ? 'checked' : ''}> ${k}</label>`).join('')}<label class="inline small"><input type="checkbox" id="gAmb" ${o.ambiguous ? 'checked' : ''}> ambiguous (O 0 l 1)</label></div></div>
      <div class="secret" id="gOut" style="margin:10px 0;word-break:break-all"></div><div id="gMeter"></div>
      <div class="actions"><button id="gAgain">Another</button><span class="grow"></span><button id="gCancel">Cancel</button><button class="primary" id="gUse">Use this</button></div>`);
    let pw = '';
    const draw = () => {
      o.length = Number($('#gLen', card).value); $('#gLenN', card).textContent = o.length; o.ambiguous = $('#gAmb', card).checked;
      $$('.gC', card).forEach(c => { o[c.dataset.k] = c.checked; });
      pw = generate(o); $('#gOut', card).textContent = pw; $('#gMeter', card).innerHTML = meterHtml(window.strengthBits(pw));
      store.set('gen', JSON.stringify(o));
    };
    $$('input', card).forEach(i => { i.oninput = draw; i.onchange = draw; });
    $('#gAgain', card).onclick = draw; $('#gCancel', card).onclick = window.UI.closeModal;
    $('#gUse', card).onclick = () => { window.UI.closeModal(); onUse(pw); };
    draw();
  }

  // ---------- reveal / copy buttons ------------------------------------------------------------------
  /** Fetches one secret and runs fn(value); the error (e.g. the vault locked meanwhile) becomes a toast. */
  async function withSecret(id, ref, fn) {
    try { return fn(await api().entries.reveal(id, ref)); } catch (e) { toast(e.message, true); }
  }
  /** Wires every [data-reveal] / [data-copy] button under `root`: data-id, data-ref and a sibling .val to show into. */
  function wireSecrets(root, id) {
    const secs = Number((SB.settings || {}).revealSeconds) || 20;
    $$('[data-copy]', root).forEach(b => { b.onclick = () => withSecret(id, b.dataset.copy, v => copy(v, b.dataset.what || 'Copied')); });
    $$('[data-reveal]', root).forEach(b => {
      b.onclick = async () => {
        const out = b.closest('.srow').querySelector('.val');
        if (out.dataset.shown) { out.textContent = out.dataset.mask; delete out.dataset.shown; b.textContent = 'Show'; return; }
        await withSecret(id, b.dataset.reveal, v => {
          out.textContent = v; out.dataset.shown = '1'; b.textContent = 'Hide';
          const hide = () => { if (out.dataset.shown) { out.textContent = out.dataset.mask; delete out.dataset.shown; b.textContent = 'Show'; } };
          setTimeout(hide, secs * 1000);
        });
      };
    });
  }
  const MASK = '••••••••••';

  Object.assign(SB, { copy, download, generate, generatorModal, meterHtml, strengthLabel, withSecret, wireSecrets, MASK, writeClipboard });
})();
