'use strict';
/* Small browser helpers the pages share: clipboard (with auto-clear), the password generator (presets and
   requirements), downloads, the strength meter, tag badges and the reveal/copy buttons. Everything secret is
   fetched at the moment of use and dropped from the page again after a few seconds. */
(function () {
  const { $, $$, esc, toast, store } = window.UI;
  const api = () => window.UI.api();
  const SB = (window.SB = { status: null, settings: null, tagColors: {} });

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

  // ---------- generator engine ----------------------------------------------------------------------
  // Options: { mode: 'chars' | 'phrase' | 'pin' | 'hex', length, lower, upper, digits, symbols (booleans),
  //   minUpper, minDigits, minSymbols (how many of each it must contain), symbolSet, exclude (characters never used),
  //   ambiguous (allow O 0 l 1 |), startLetter, words, capitalize, addNumber }
  const CLASSES = { lower: 'abcdefghijklmnopqrstuvwxyz', upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits: '0123456789', symbols: '!@#$%^&*()-_=+[]{};:,.?/~' };
  const AMBIGUOUS = 'O0oIl1|';
  const CONS = 'bcdfghjklmnprstvz', VOW = 'aeiou';
  const DEFAULT_OPTS = { mode: 'chars', length: 20, lower: true, upper: true, digits: true, symbols: true, minUpper: 1, minDigits: 1, minSymbols: 1, symbolSet: CLASSES.symbols, exclude: '', ambiguous: false, startLetter: false, words: 4, capitalize: true, addNumber: true };
  const randInt = (n) => { const max = Math.floor(0x100000000 / n) * n; const b = new Uint32Array(1); do crypto.getRandomValues(b); while (b[0] >= max); return b[0] % n; };
  const pick = (s) => s[randInt(s.length)];
  const shuffle = (a) => { for (let i = a.length - 1; i > 0; i--) { const j = randInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  const unique = (s) => [...new Set(s)].join('');

  /** → { value, bits, note }. Always satisfies every requirement it was given (the length grows if the minimums need it). */
  function generate(input = {}) {
    const o = { ...DEFAULT_OPTS, ...input };
    if (o.mode === 'phrase') {
      const words = Math.min(10, Math.max(2, Number(o.words) || 4)), out = [];
      for (let w = 0; w < words; w++) { let s = ''; for (let i = 0; i < 3; i++) s += pick(CONS) + pick(VOW); out.push(o.capitalize ? s[0].toUpperCase() + s.slice(1) : s); }
      let value = out.join('-'), bits = words * 3 * Math.log2(CONS.length * VOW.length);
      if (o.addNumber) { value += '-' + randInt(100).toString().padStart(2, '0') + pick('!@#$%&*?'); bits += 6.6 + 3; }
      return { value, bits: Math.round(bits), note: `${words} pronounceable words` };
    }
    if (o.mode === 'pin') { const n = Math.min(32, Math.max(3, Number(o.length) || 6)); let v = ''; for (let i = 0; i < n; i++) v += randInt(10); return { value: v, bits: Math.round(n * 3.32), note: 'digits only' }; }
    if (o.mode === 'hex') { const n = Math.min(128, Math.max(4, Number(o.length) || 32)); let v = ''; for (let i = 0; i < n; i++) v += pick('0123456789abcdef'); return { value: v, bits: n * 4, note: 'hexadecimal' }; }
    const bad = new Set(String(o.exclude || '') + (o.ambiguous ? '' : AMBIGUOUS));
    const clean = (s) => [...s].filter(c => !bad.has(c)).join('');
    const pools = {
      lower: o.lower ? clean(CLASSES.lower) : '', upper: o.upper ? clean(CLASSES.upper) : '', digits: o.digits ? clean(CLASSES.digits) : '',
      symbols: o.symbols ? clean(unique((o.symbolSet || CLASSES.symbols).replace(/\s/g, ''))) : '',
    };
    const all = Object.values(pools).join('');
    if (!all) throw new Error('Nothing is left to choose from: relax the requirements');
    const need = { lower: pools.lower ? 1 : 0, upper: pools.upper ? Math.max(1, Number(o.minUpper) || 0) : 0, digits: pools.digits ? Math.max(1, Number(o.minDigits) || 0) : 0, symbols: pools.symbols ? Math.max(1, Number(o.minSymbols) || 0) : 0 };
    const required = Object.values(need).reduce((a, b) => a + b, 0);
    const length = Math.min(128, Math.max(Number(o.length) || 20, required, 4));
    for (let attempt = 0; attempt < 200; attempt++) {
      const chars = [];
      for (const [k, n] of Object.entries(need)) for (let i = 0; i < n; i++) chars.push(pick(pools[k]));
      while (chars.length < length) chars.push(pick(all));
      shuffle(chars);
      if (o.startLetter && !/[A-Za-z]/.test(chars[0])) { const i = chars.findIndex(c => /[A-Za-z]/.test(c)); if (i < 0) continue; [chars[0], chars[i]] = [chars[i], chars[0]]; }
      const v = chars.join('');
      if (/(.)\1\1/.test(v)) continue; // never three of the same character in a row
      return { value: v, bits: Math.round(length * Math.log2(all.length)), note: length > (Number(o.length) || 20) ? `length raised to ${length} to fit the minimums` : '' };
    }
    throw new Error('Could not satisfy those requirements');
  }
  const GEN_PRESETS = [
    { id: 'strong', name: 'Strong', note: '20 characters, every kind', o: { mode: 'chars', length: 20 } },
    { id: 'long', name: 'Very long', note: '32 characters, every kind', o: { mode: 'chars', length: 32 } },
    { id: 'alnum', name: 'Letters and digits only', note: 'for sites and devices that reject symbols', o: { mode: 'chars', length: 20, symbols: false } },
    { id: 'device', name: 'Router / device admin', note: '16 characters, a few safe symbols', o: { mode: 'chars', length: 16, symbolSet: '!@#$%^&*', startLetter: true } },
    { id: 'wifi', name: 'Wi-Fi key (WPA2 / WPA3)', note: '24 characters, easy to type in', o: { mode: 'chars', length: 24, symbols: false } },
    { id: 'phrase', name: 'Passphrase', note: 'four pronounceable words, easy to read out', o: { mode: 'phrase', words: 4 } },
    { id: 'pin4', name: 'PIN, 4 digits', note: '', o: { mode: 'pin', length: 4 } },
    { id: 'pin6', name: 'PIN, 6 digits', note: '', o: { mode: 'pin', length: 6 } },
    { id: 'hex', name: 'Hex key, 32', note: 'API tokens, encryption keys', o: { mode: 'hex', length: 32 } },
  ];
  const allPresets = () => [...GEN_PRESETS.map(p => ({ ...p, builtin: true })), ...(((SB.settings || {}).genPresets) || []).map(p => ({ ...p, builtin: false }))];
  const strengthLabel = (bits) => (bits >= 90 ? ['Excellent', ''] : bits >= 70 ? ['Strong', ''] : bits >= 50 ? ['Fair', 'warn'] : ['Weak', 'bad']);
  const meterHtml = (bits) => { const [label, cls] = strengthLabel(bits); return `<div class="meter ${cls}"><div style="width:${Math.min(100, Math.round(bits / 1.2))}%"></div></div><span class="tiny ${cls}">${label} · ~${bits} bits</span>`; };

  /** The generator UI: presets plus the requirements it can satisfy. onUse(password) shows a "Use this" button. */
  function generatorPanel(box, { presetId = null, onUse = null } = {}) {
    const last = (() => { try { return JSON.parse(store.get('gen2', '{}') || '{}'); } catch { return {}; } })();
    let pid = presetId || last.preset || 'strong';
    const find = (id) => allPresets().find(p => p.id === id) || allPresets()[0];
    let o = { ...DEFAULT_OPTS, ...find(pid).o, ...(presetId ? {} : last.o && last.preset === pid ? last.o : {}) };
    let result = null;
    const isAdmin = window.UI.isAdmin();
    const run = () => { try { result = generate(o); $('#gOut', box).textContent = result.value; $('#gMeter', box).innerHTML = meterHtml(result.bits) + (result.note ? ` <span class="tiny muted">· ${esc(result.note)}</span>` : ''); $('#gErr', box).textContent = ''; } catch (e) { result = null; $('#gOut', box).textContent = ''; $('#gMeter', box).innerHTML = ''; $('#gErr', box).textContent = e.message; } store.set('gen2', JSON.stringify({ preset: pid, o })); };
    const draw = () => {
      const p = find(pid), chars = o.mode === 'chars';
      box.innerHTML = `<div class="field"><label>Preset</label><div><select id="gPreset">${allPresets().map(x => `<option value="${esc(x.id)}" ${x.id === pid ? 'selected' : ''}>${esc(x.name)}${x.builtin ? '' : ' (yours)'}</option>`).join('')}</select><div class="hint tiny muted">${esc(p.note || '')}</div></div></div>
        <div class="field"><label>Type</label><select id="gMode">${[['chars', 'Characters (letters, digits, symbols)'], ['phrase', 'Passphrase (pronounceable words)'], ['pin', 'PIN (digits)'], ['hex', 'Hex key']].map(([k, l]) => `<option value="${k}" ${o.mode === k ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
        ${o.mode === 'phrase' ? `<div class="field"><label>Words</label><div class="inline"><input type="range" id="gWords" min="2" max="8" value="${o.words}" style="flex:1"><b id="gWordsN">${o.words}</b></div></div>
          <div class="field"><label>Also</label><div class="inline"><label class="inline small"><input type="checkbox" id="gCap" ${o.capitalize ? 'checked' : ''}> Capitalize each word</label><label class="inline small"><input type="checkbox" id="gNum" ${o.addNumber ? 'checked' : ''}> end with a number and a symbol</label></div></div>`
          : `<div class="field"><label>Length</label><div class="inline"><input type="range" id="gLen" min="${chars ? 8 : 3}" max="${chars ? 64 : o.mode === 'pin' ? 12 : 64}" value="${Math.min(o.length, chars ? 64 : 64)}" style="flex:1"><b id="gLenN">${o.length}</b></div></div>`}
        ${chars ? `<div class="field"><label>Must contain</label><div class="genreq">
            <label class="inline small"><input type="checkbox" id="gLower" ${o.lower ? 'checked' : ''}> lower-case</label>
            <label class="inline small"><input type="checkbox" id="gUpper" ${o.upper ? 'checked' : ''}> upper-case, at least <input type="number" id="gMinU" min="1" max="20" value="${o.minUpper}"></label>
            <label class="inline small"><input type="checkbox" id="gDigits" ${o.digits ? 'checked' : ''}> digits, at least <input type="number" id="gMinD" min="1" max="20" value="${o.minDigits}"></label>
            <label class="inline small"><input type="checkbox" id="gSym" ${o.symbols ? 'checked' : ''}> symbols, at least <input type="number" id="gMinS" min="1" max="20" value="${o.minSymbols}"></label></div></div>
          <div class="field"><label>Allowed symbols</label><input type="text" id="gSet" value="${esc(o.symbolSet)}" autocomplete="off" spellcheck="false"><div class="hint tiny muted">Devices often accept only some. Trim this list to match what the device allows.</div></div>
          <div class="field"><label>Never use</label><input type="text" id="gEx" value="${esc(o.exclude)}" placeholder="characters to leave out, e.g. \\ ' &quot;" autocomplete="off" spellcheck="false"></div>
          <div class="field"><label>Also</label><div class="inline"><label class="inline small"><input type="checkbox" id="gStart" ${o.startLetter ? 'checked' : ''}> start with a letter</label><label class="inline small"><input type="checkbox" id="gAmb" ${o.ambiguous ? 'checked' : ''}> allow look-alikes (O 0 l 1 |)</label></div></div>` : ''}
        <div class="genout"><div class="secret" id="gOut"></div><div id="gMeter"></div><div class="bad small" id="gErr"></div></div>
        <div class="inline" style="margin-top:10px"><button id="gAgain">Another</button><button id="gCopy">Copy</button>${onUse ? '<button class="primary" id="gUse">Use this</button>' : ''}<span class="grow"></span>${isAdmin ? `<button class="small" id="gSave">Save as preset…</button>${p.builtin ? '' : '<button class="small danger" id="gDel">Delete preset</button>'}` : ''}</div>`;
      const num = (id) => Number($(id, box).value);
      const on = (id, fn) => { const el = $(id, box); if (el) { el.oninput = fn; el.onchange = fn; } };
      $('#gPreset', box).onchange = (e) => { pid = e.target.value; o = { ...DEFAULT_OPTS, ...find(pid).o }; draw(); };
      $('#gMode', box).onchange = (e) => { o.mode = e.target.value; if (o.mode === 'pin') o.length = 6; else if (o.mode === 'hex') o.length = 32; else if (o.mode === 'chars' && o.length < 8) o.length = 20; draw(); };
      on('#gLen', () => { o.length = num('#gLen'); $('#gLenN', box).textContent = o.length; run(); });
      on('#gWords', () => { o.words = num('#gWords'); $('#gWordsN', box).textContent = o.words; run(); });
      on('#gCap', () => { o.capitalize = $('#gCap', box).checked; run(); }); on('#gNum', () => { o.addNumber = $('#gNum', box).checked; run(); });
      for (const [id, k] of [['#gLower', 'lower'], ['#gUpper', 'upper'], ['#gDigits', 'digits'], ['#gSym', 'symbols'], ['#gStart', 'startLetter'], ['#gAmb', 'ambiguous']]) on(id, () => { o[k] = $(id, box).checked; run(); });
      for (const [id, k] of [['#gMinU', 'minUpper'], ['#gMinD', 'minDigits'], ['#gMinS', 'minSymbols']]) on(id, () => { o[k] = num(id); run(); });
      on('#gSet', () => { o.symbolSet = $('#gSet', box).value; run(); }); on('#gEx', () => { o.exclude = $('#gEx', box).value; run(); });
      $('#gAgain', box).onclick = run;
      $('#gCopy', box).onclick = () => { if (result) copy(result.value, 'Copied', true); };
      if ($('#gUse', box)) $('#gUse', box).onclick = () => { if (result) onUse(result.value); };
      if ($('#gSave', box)) $('#gSave', box).onclick = async () => {
        const name = prompt('Name this preset (for example "Cisco switch" or "Bank, 12-16 chars, no symbols"):'); if (!name || !name.trim()) return;
        const mine = ((SB.settings || {}).genPresets || []).slice(); const id = 'c:' + Math.random().toString(36).slice(2, 8);
        mine.push({ id, name: name.trim().slice(0, 50), note: 'your own', o: { ...o } });
        try { const s = await api().settings.set({ vault: { genPresets: mine } }); SB.settings = s.vault; pid = id; toast('Preset saved'); draw(); } catch (e) { toast(e.message, true); }
      };
      if ($('#gDel', box)) $('#gDel', box).onclick = async () => {
        if (!confirm('Delete this preset?')) return;
        try { const s = await api().settings.set({ vault: { genPresets: ((SB.settings || {}).genPresets || []).filter(x => x.id !== pid) } }); SB.settings = s.vault; pid = 'strong'; o = { ...DEFAULT_OPTS, ...find(pid).o }; draw(); toast('Preset deleted'); } catch (e) { toast(e.message, true); }
      };
      run();
    };
    draw();
  }
  /** A dialog around the panel; onUse(password) is called with the chosen password. */
  function generatorModal(onUse, presetId = null) {
    const card = window.UI.openModal('<h2>Password generator</h2><div id="genBox"></div><div class="actions"><span class="grow"></span><button id="gClose">Close</button></div>');
    $('#gClose', card).onclick = window.UI.closeModal;
    generatorPanel($('#genBox', card), { presetId, onUse: (pw) => { window.UI.closeModal(); onUse(pw); } });
  }

  // ---------- tags ----------------------------------------------------------------------------------
  const tagBadge = (name) => { const c = SB.tagColors[name]; return `<span class="badge tag ${c ? 'tc-' + c : ''}">${esc(name)}</span>`; };
  async function loadTags() { try { SB.tagColors = Object.fromEntries((await api().tags.list()).map(t => [t.name, t.color])); } catch { /* locked */ } return SB.tagColors; }

  // ---------- reveal / copy buttons ------------------------------------------------------------------
  /** Fetches one secret and runs fn(value); the error (e.g. the vault locked meanwhile) becomes a toast. */
  async function withSecret(id, ref, fn) {
    try { return fn(await api().entries.reveal(id, ref)); } catch (e) { toast(e.message, true); }
  }
  /** Wires every [data-reveal] / [data-copy] button under `root`: data-ref and a sibling .val to show into. */
  function wireSecrets(root, id) {
    const secs = Number((SB.settings || {}).revealSeconds) || 20;
    $$('[data-copy]', root).forEach(b => { b.onclick = () => withSecret(id, b.dataset.copy, v => copy(v, b.dataset.what || 'Copied')); });
    $$('[data-reveal]', root).forEach(b => {
      b.onclick = async () => {
        const out = b.closest('.srow').querySelector('.val');
        if (out.dataset.shown) { out.textContent = out.dataset.mask; delete out.dataset.shown; b.textContent = 'Show'; return; }
        await withSecret(id, b.dataset.reveal, v => {
          out.textContent = v; out.dataset.shown = '1'; b.textContent = 'Hide';
          setTimeout(() => { if (out.dataset.shown) { out.textContent = out.dataset.mask; delete out.dataset.shown; b.textContent = 'Show'; } }, secs * 1000);
        });
      };
    });
  }
  const MASK = '••••••••••';

  Object.assign(SB, { copy, download, generate, generatorPanel, generatorModal, GEN_PRESETS, meterHtml, strengthLabel, withSecret, wireSecrets, MASK, writeClipboard, tagBadge, loadTags });
})();
