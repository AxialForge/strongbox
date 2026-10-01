'use strict';
/* Everything about opening the vault: the first-run setup, the unlock screen, the "change unlock
   method" dialog and the lock box in the sidebar. */
(function () {
  const { $, $$, esc, toast, fmtDate } = window.UI;
  const api = () => window.UI.api();
  const SB = window.SB;

  const MODE_TEXT = {
    'password+keyfile': ['Passphrase + key file', 'Recommended. Opening the vault needs something you know and something you hold, like a Synology volume with a key file. A stolen Pi, SD card or backup is useless without both.'],
    password: ['Passphrase only', 'One long passphrase. Simple, and fine if it is truly long and unique. Nothing to lose but nothing to hold either.'],
    keyfile: ['Key file only', 'A file you keep off the Pi (a USB stick). Anyone who gets the file can open the vault, so protect it like a physical key.'],
    'password+securitykey': ['Passphrase + hardware security key (experimental)', 'A YubiKey or similar: you touch the key to unlock. Needs HTTPS and a key with the hmac-secret (WebAuthn PRF) feature. The key is tied to the web address you set it up on, so keep the recovery key safe.'],
  };
  const modeName = (m) => (MODE_TEXT[m] || [m])[0];
  const needsPw = (m) => m !== 'keyfile', needsKf = (m) => m === 'password+keyfile' || m === 'keyfile', needsSk = (m) => m === 'password+securitykey';

  // ---------- the setup / change wizard --------------------------------------------------------------
  /** Draws the wizard into `box`. opts: { change, hasRecovery, run(opts) → { keyFile, keyFileId, recoveryKey }, done() } */
  function wizard(box, opts) {
    let mode = 'password+keyfile', recovery = opts.rotate ? 'new' : opts.change ? (opts.hasRecovery ? 'keep' : 'none') : 'new';
    // While the wizard is up, vault events must not re-draw the page: the key file and recovery key are shown once, on step 3.
    SB.wizardActive = true;
    const finish = () => { SB.wizardActive = false; };
    const step1 = () => {
      box.innerHTML = `<h2>${opts.rotate ? 'Rotate the encryption key' : opts.change ? 'Change how the vault unlocks' : 'Set up your vault'}</h2>
        <p class="muted">${opts.rotate ? 'A new encryption key is made and every entry, attachment and setting is re-encrypted with it. Choose how the vault unlocks from now on; the old recovery key stops working and a new one is made.' : opts.change ? 'The entries are not re-encrypted; only the lock around the key changes. The current method stops working at once.' : 'Choose what it takes to open it. Everything inside is encrypted with a random key that this lock protects; the Pi never stores it in the clear.'}</p>
        <div class="modecards">${Object.entries(MODE_TEXT).map(([k, [t, d]]) => `<label class="modecard ${k === mode ? 'on' : ''}" ${k === 'password+securitykey' && !SB.securityKey.supported() ? 'style="opacity:.5" title="Needs HTTPS and a browser with security-key support"' : ''}><input type="radio" name="mode" value="${k}" ${k === mode ? 'checked' : ''} ${k === 'password+securitykey' && !SB.securityKey.supported() ? 'disabled' : ''}><div><b>${t}</b><span>${d}${k === 'password+securitykey' && !SB.securityKey.supported() ? ' <b>Not available here: open Strongbox over HTTPS first.</b>' : ''}</span></div></label>`).join('')}</div>
        <div class="field"><label>Recovery key</label><select id="wRec">
          ${opts.change && opts.hasRecovery && !opts.rotate ? `<option value="keep" ${recovery === 'keep' ? 'selected' : ''}>Keep the current one</option>` : ''}
          <option value="new" ${recovery === 'new' ? 'selected' : ''}>Make a new one (recommended)</option>
          <option value="none" ${recovery === 'none' ? 'selected' : ''}>None: lose the factors and the data is gone</option></select>
          <div class="hint">A 40-character code you print or write down and keep somewhere safe. It opens the vault if the passphrase or the key file is lost.</div></div>
        <div class="actions"><span class="grow"></span>${opts.cancel ? '<button id="wCancel">Cancel</button>' : ''}<button class="primary" id="wNext">Next</button></div>`;
      $$('input[name=mode]', box).forEach(r => { r.onchange = () => { mode = r.value; $$('.modecard', box).forEach(c => c.classList.toggle('on', c.querySelector('input').checked)); }; });
      $('#wRec', box).onchange = (e) => { recovery = e.target.value; };
      if ($('#wCancel', box)) $('#wCancel', box).onclick = () => { finish(); opts.cancel(); };
      $('#wNext', box).onclick = () => { recovery = $('#wRec', box).value; step2(); };
    };
    const step2 = () => {
      box.innerHTML = `<h2>${needsPw(mode) ? 'Choose a passphrase' : 'Create the key file'}</h2>
        <p class="muted">${needsPw(mode) ? 'At least 12 characters. A few random words is better than a clever short one. There is no way to reset it; the recovery key and your key file are the only ways back.' : 'The next screen gives you a key file to download and keep away from the Pi.'}</p>
        ${needsPw(mode) ? `<div class="field"><label>Passphrase</label><div><input type="password" id="wPw" autocomplete="new-password"><div id="wMeter" class="tiny muted" style="margin-top:4px"></div></div></div>
        <div class="field"><label>Repeat</label><input type="password" id="wPw2" autocomplete="new-password"></div>` : ''}
        <div class="actions"><button id="wBack">Back</button><span class="grow"></span><button class="primary" id="wGo">${opts.change ? 'Change it' : 'Create the vault'}</button></div><div class="bad small" id="wErr"></div>`;
      if (needsPw(mode)) $('#wPw', box).oninput = (e) => { $('#wMeter', box).innerHTML = e.target.value ? SB.meterHtml(window.strengthBits(e.target.value)) : ''; };
      $('#wBack', box).onclick = step1;
      $('#wGo', box).onclick = async () => {
        const pw = needsPw(mode) ? $('#wPw', box).value : '';
        if (needsPw(mode) && pw !== $('#wPw2', box).value) return ($('#wErr', box).textContent = 'The two passphrases differ');
        if (needsPw(mode) && pw.length < 12) return ($('#wErr', box).textContent = 'The passphrase needs at least 12 characters');
        $('#wGo', box).disabled = true; $('#wErr', box).textContent = 'Working… (the key derivation takes a second or two)';
        try {
          let securityKey;
          if (needsSk(mode)) { $('#wErr', box).textContent = 'Touch your security key when it lights up (it asks twice)…'; securityKey = await SB.securityKey.register(); recovery = 'new'; }
          $('#wErr', box).textContent = 'Working… (the key derivation takes a second or two)';
          step3(await opts.run({ mode, password: pw, recovery, securityKey }));
        } catch (e) { $('#wGo', box).disabled = false; $('#wErr', box).textContent = e.message; }
      };
    };
    const step3 = (r) => {
      const needKf = !!r.keyFile, needRec = !!r.recoveryKey, got = { kf: !needKf, rec: !needRec };
      box.innerHTML = `<h2>Save these now</h2>
        <p class="warnbox">They are shown once. Strongbox keeps neither the key file nor the recovery key.</p>
        ${needKf ? `<div class="card" style="margin-bottom:10px"><h3>Key file <span class="right mono">${esc(r.keyFileId)}</span></h3><p class="muted small">Keep it on a USB stick or another computer, <b>not on the Pi</b>. You pick it each time you unlock.</p><button class="primary" id="wKf">Download the key file</button> <span id="wKfOk" class="ok small" hidden>downloaded ✓</span></div>` : ''}
        ${needRec ? `<div class="card" style="margin-bottom:10px"><h3>Recovery key</h3><div class="secret" style="word-break:break-all">${esc(r.recoveryKey)}</div><div class="inline" style="margin-top:8px"><button id="wRecCopy">Copy</button><button id="wRecPrint">Print</button></div><p class="muted small" style="margin:8px 0 0">Write it down or print it and keep it somewhere safe (a drawer, a safe). Anyone with it can open the vault.</p></div>` : ''}
        <label class="inline small"><input type="checkbox" id="wSaved"> I have saved ${needKf && needRec ? 'both' : needKf ? 'the key file' : needRec ? 'the recovery key' : 'this'}</label>
        <div class="actions"><span class="grow"></span><button class="primary" id="wDone" disabled>Continue</button></div>`;
      const ready = () => { $('#wDone', box).disabled = !($('#wSaved', box).checked && got.kf); };
      $('#wSaved', box).onchange = ready;
      if (needKf) $('#wKf', box).onclick = () => { SB.download(`strongbox-${r.keyFileId}.key`, r.keyFile); got.kf = true; $('#wKfOk', box).hidden = false; ready(); };
      if (needRec) {
        $('#wRecCopy', box).onclick = () => SB.writeClipboard(r.recoveryKey).then(ok => toast(ok ? 'Copied (it stays on the clipboard until you replace it)' : 'Copy blocked; write it down', !ok));
        $('#wRecPrint', box).onclick = () => { const w = window.open('', '_blank', 'width=520,height=380'); if (!w) return toast('Allow pop-ups to print', true); w.document.write(`<pre style="font:18px Consolas,monospace;padding:24px">Strongbox recovery key\n${new Date().toDateString()}\n\n${r.recoveryKey}\n\nKeep this paper somewhere safe.</pre>`); w.document.close(); w.print(); };
      }
      $('#wDone', box).onclick = () => { finish(); opts.done(); };
    };
    step1();
  }

  // ---------- the lock screen -------------------------------------------------------------------------
  function lockScreen(st, done) {
    const v = window.UI.view();
    const isAdmin = window.UI.isAdmin();
    if (st.state === 'uninitialized') {
      v.innerHTML = '<div class="lockwrap"><div class="card lockcard" id="lockBox"></div></div>';
      if (!isAdmin) { $('#lockBox').innerHTML = '<h2>The vault is not set up yet</h2><p class="muted">An admin account has to create it first.</p>'; return; }
      return wizard($('#lockBox'), { run: (o) => api().vault.create(o), done });
    }
    let useRecovery = false, kfText = null, kfName = '';
    const draw = () => {
      const m = st.mode;
      v.innerHTML = `<div class="lockwrap"><form class="card lockcard" id="lockForm"><div class="lockicon">🔒</div><h2>Vault locked</h2>
        <p class="muted">${useRecovery ? 'Enter the recovery key you saved when the vault was created.' : `Unlock with ${esc(modeName(m).toLowerCase())}.`}</p>
        ${useRecovery ? `<div class="field"><label>Recovery key</label><input type="text" id="uRec" autocomplete="off" spellcheck="false" placeholder="XXXXX-XXXXX-…"></div>` : `
          ${needsPw(m) ? `<div class="field"><label>Passphrase</label><input type="password" id="uPw" autocomplete="current-password"></div>` : ''}${needsSk(m) && !useRecovery ? `<div class="hint tiny muted" style="margin:-4px 0 8px">Your security key will ask for a touch. It is tied to <span class="mono">${esc(st.securityKey && st.securityKey.rpId)}</span>${st.securityKey && st.securityKey.rpId !== location.hostname ? ' <b class="warn">but you opened a different address, so it will not work here. Use the recovery key, or open the original address.</b>' : ''}.</div>` : ''}
          ${needsKf(m) ? `<div class="field"><label>Key file</label><div><label class="filepick" id="uFileBox"><input type="file" id="uFile" accept=".key,.txt,text/plain"><span id="uFileTxt">${kfName ? '✓ ' + esc(kfName) : 'Choose the key file…'}</span></label><div class="hint tiny muted">${st.keyFileId ? `Expecting the file with ID <span class="mono">${esc(st.keyFileId)}</span>. ` : ''}It is read in your browser and sent to the Pi only to open the vault.</div></div></div>` : ''}`}
        <div class="actions"><button type="button" class="small" id="uAlt">${useRecovery ? 'Use passphrase / key file' : (st.hasRecovery ? 'Use the recovery key' : '')}</button><span class="grow"></span><button class="primary" id="uGo">Unlock</button></div>
        <div class="bad small" id="uErr">${st.blockedMs ? `Too many failed attempts; try again in ${Math.ceil(st.blockedMs / 1000)} s` : ''}</div></form></div>`;
      if (!useRecovery && !st.hasRecovery) $('#uAlt').hidden = true;
      $('#uAlt').onclick = () => { useRecovery = !useRecovery; draw(); };
      if ($('#uFile')) $('#uFile').onchange = async (e) => { const f = e.target.files[0]; if (!f) return; if (f.size > 4096) { kfText = null; kfName = ''; $('#uFileTxt').textContent = 'That file is too large to be a key file'; return; } kfText = await f.text(); kfName = f.name; $('#uFileTxt').textContent = '✓ ' + f.name; };
      const first = $('#uPw') || $('#uRec'); if (first) first.focus();
      $('#lockForm').onsubmit = async (e) => {
        e.preventDefault();
        const err = $('#uErr'); err.textContent = 'Unlocking…'; $('#uGo').disabled = true;
        try {
          let securityKey; if (!useRecovery && st.securityKey) { err.textContent = 'Touch your security key…'; securityKey = await SB.securityKey.read(st.securityKey); err.textContent = 'Unlocking…'; }
          await api().vault.unlock(useRecovery ? { recoveryKey: $('#uRec').value } : { password: $('#uPw') ? $('#uPw').value : undefined, keyFile: kfText || undefined, securityKey });
          SB.recoveryUnlock = useRecovery; done();
        } catch (ex) {
          $('#uGo').disabled = false; err.textContent = ex.message;
          if ($('#uPw')) { $('#uPw').value = ''; $('#uPw').focus(); }
          if (/Too many/.test(ex.message)) { try { st = await api().vault.status(); } catch { /* keep */ } }
        }
      };
    };
    draw();
  }

  // ---------- the sidebar lock box ------------------------------------------------------------------------
  let lockAt = null, timer = null;
  function lockBox() {
    const box = $('#navFooter'); if (!box) return;
    const paint = () => {
      const st = SB.status || {};
      const un = st.state === 'unlocked';
      const left = lockAt ? Math.max(0, lockAt - Date.now()) : null;
      const clock = left == null ? '' : `${Math.floor(left / 60000)}:${String(Math.floor(left % 60000 / 1000)).padStart(2, '0')}`;
      box.innerHTML = `<div class="lockbox ${un ? 'open' : ''}"><span>${un ? '🔓 Unlocked' : st.state === 'uninitialized' ? '⚙ Not set up' : '🔒 Locked'}</span>${un ? `<button class="small" id="lockNow">Lock</button>` : ''}</div>${un && clock ? `<div class="tiny muted" style="padding:3px 2px">auto-locks in ${clock}</div>` : ''}`;
      if ($('#lockNow', box)) $('#lockNow', box).onclick = async () => { await api().vault.lock(); await refresh(); window.UI.route(); };
    };
    const refresh = async () => {
      try { SB.status = await api().vault.status(); lockAt = SB.status.lockInMs != null ? Date.now() + SB.status.lockInMs : null; } catch { return; }
      if (SB.status.state !== 'unlocked') SB.settings = SB.settings || null;
      paint();
    };
    SB.refreshStatus = refresh;
    refresh();
    clearInterval(timer);
    timer = setInterval(() => {
      if (lockAt && Date.now() >= lockAt && SB.status && SB.status.state === 'unlocked') { refresh().then(() => { if (SB.status.state !== 'unlocked') window.UI.route(); }); return; }
      paint();
    }, 1000);
    setInterval(refresh, 30000); // resyncs with the server (auto-lock happens there); this call does not count as activity
    // user activity keeps the vault open: tell the server at most once every 45 s
    let last = 0;
    const beat = () => { if (!SB.status || SB.status.state !== 'unlocked' || Date.now() - last < 45000) return; last = Date.now(); api().vault.touch().then(st => { SB.status = st; lockAt = st.lockInMs != null ? Date.now() + st.lockInMs : null; }).catch(() => {}); };
    ['pointerdown', 'keydown', 'wheel'].forEach(ev => window.addEventListener(ev, beat, { passive: true }));
  }

  Object.assign(SB, { wizard, lockScreen, lockBox, modeName, MODE_TEXT });
})();
