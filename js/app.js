/* =========================================================================
   App — wiring UI: input, tombol, validasi, orkestrasi proses AES
   ========================================================================= */

const els = {
  plaintext: document.getElementById('inputText'),
  key: document.getElementById('inputKey'),
  modeRadios: document.querySelectorAll('input[name="mode"]'),
  btnRun: document.getElementById('btnRun'),
  btnReset: document.getElementById('btnReset'),
  btnSample: document.getElementById('btnSample'),
  btnCopy: document.getElementById('btnCopy'),
  output: document.getElementById('outputHex'),
  errorBox: document.getElementById('errorBox'),
  detailToggle: document.getElementById('detailToggle'),
  railHost: document.getElementById('railHost'),
  detailHost: document.getElementById('detailHost'),
  inputLabel: document.getElementById('inputLabel'),
  outputLabel: document.getElementById('outputLabel'),
  runLabel: document.getElementById('runLabel'),
  heroState: document.getElementById('heroState'),
};

// Beberapa contoh nilai siap pakai (test vector resmi FIPS-197 + contoh teks biasa)
const SAMPLES = {
  encrypt: [
    { key: '000102030405060708090a0b0c0d0e0f', text: '00112233445566778899aabbccddeeff', note: 'Test vector resmi FIPS-197 (hex)' },
    { key: '2b7e151628aed2a6abf7158809cf4f3c', text: 'Kriptografi128bi', note: 'Contoh teks biasa 16 karakter' },
  ],
  decrypt: [
    { key: '000102030405060708090a0b0c0d0e0f', text: '69c4e0d86a7b0430d8cdb78070b4c55a', note: 'Hasil enkripsi FIPS-197 (dekripsi balik)' },
  ]
};
let sampleIdx = { encrypt: 0, decrypt: 0 };

function currentMode() {
  return [...els.modeRadios].find(r => r.checked).value;
}

function isHex(str) { return /^[0-9a-fA-F]*$/.test(str); }

function showError(msg) {
  els.errorBox.textContent = msg;
  els.errorBox.classList.toggle('show', !!msg);
}

function parseKey(raw) {
  const k = raw.trim();
  if (k.length !== 32 || !isHex(k)) {
    throw new Error('Kunci harus berupa 32 karakter hex (16 byte / 128-bit).');
  }
  return hexToBytes(k);
}

function parsePlainOrCipherInput(raw, mode) {
  const v = raw.trim();
  if (mode === 'decrypt') {
    if (v.length !== 32 || !isHex(v)) {
      throw new Error('Ciphertext untuk dekripsi harus 32 karakter hex (16 byte).');
    }
    return hexToBytes(v);
  }
  // mode encrypt: boleh hex 32 karakter ATAU teks biasa maks 16 karakter
  if (v.length === 32 && isHex(v)) {
    return hexToBytes(v);
  }
  if (v.length === 0) throw new Error('Plaintext tidak boleh kosong.');
  if (v.length > 16) throw new Error('Plaintext teks maksimal 16 karakter (atau gunakan 32 karakter hex).');
  const bytes = [];
  for (let i = 0; i < v.length; i++) bytes.push(v.charCodeAt(i) & 0xFF);
  while (bytes.length < 16) bytes.push(0x00); // zero-padding ke 16 byte
  return bytes;
}

function updateModeLabels() {
  const mode = currentMode();
  if (mode === 'encrypt') {
    els.inputLabel.textContent = 'Plaintext (teks ≤16 karakter atau hex 32 karakter)';
    els.outputLabel.textContent = 'Ciphertext (hex)';
    els.runLabel.textContent = 'ENCRYPT';
    els.plaintext.placeholder = 'contoh: Kriptografi128bit';
  } else {
    els.inputLabel.textContent = 'Ciphertext (hex 32 karakter)';
    els.outputLabel.textContent = 'Plaintext (hex)';
    els.runLabel.textContent = 'DECRYPT';
    els.plaintext.placeholder = 'contoh: 3925841d02dc09fbdc118597196a0b32';
  }
}

function setHeroBytes(bytes) {
  if (!els.heroState) return;
  const cells = els.heroState.querySelectorAll('td');
  cells.forEach((td, i) => { td.textContent = toHex2(bytes[i] ?? 0); });
}

function run() {
  showError('');
  const mode = currentMode();
  let keyBytes, inputBytes;
  try {
    keyBytes = parseKey(els.key.value);
    inputBytes = parsePlainOrCipherInput(els.plaintext.value, mode);
  } catch (err) {
    showError(err.message);
    els.output.value = '';
    return;
  }

  const keyExp = keyExpansion128(keyBytes);
  let resultHex, detailHtml;

  if (mode === 'encrypt') {
    const steps = aesEncryptBlock(inputBytes, keyExp.roundKeys);
    resultHex = bytesToHex(steps.ciphertext);
    detailHtml = renderKeyExpansion(keyExp) + renderEncryption(steps);
    setHeroBytes(steps.ciphertext);
  } else {
    const steps = aesDecryptBlock(inputBytes, keyExp.roundKeys);
    resultHex = bytesToHex(steps.plaintext);
    detailHtml = renderKeyExpansion(keyExp) + renderDecryption(steps);
    setHeroBytes(steps.plaintext);
  }

  els.output.value = resultHex;
  els.detailHost.innerHTML = detailHtml;
  els.railHost.innerHTML = renderRail(mode);
  els.detailHost.classList.add('has-content');
  bindRailScrollSpy();
}

function resetAll() {
  els.plaintext.value = '';
  els.key.value = '';
  els.output.value = '';
  showError('');
  els.detailHost.innerHTML = '';
  els.detailHost.classList.remove('has-content');
  els.railHost.innerHTML = '';
  setHeroBytes(new Array(16).fill(0));
}

function copyOutput() {
  if (!els.output.value) return;
  navigator.clipboard.writeText(els.output.value).then(() => {
    const old = els.btnCopy.textContent;
    els.btnCopy.textContent = 'Tersalin ✓';
    setTimeout(() => { els.btnCopy.textContent = old; }, 1200);
  });
}

function toggleDetail() {
  const detailsEls = els.detailHost.querySelectorAll('details.collapsible');
  const anyOpen = [...detailsEls].some(d => d.open);
  detailsEls.forEach(d => { d.open = !anyOpen; });
  els.detailToggle.textContent = anyOpen ? 'Tampilkan Semua Detail' : 'Sembunyikan Semua Detail';
}

function bindRailScrollSpy() {
  const sections = els.detailHost.querySelectorAll('.phase-section');
  const railItems = els.railHost.querySelectorAll('.rail-item');
  if (!sections.length) return;
  const map = {};
  railItems.forEach(a => { map[a.getAttribute('href').slice(1)] = a; });

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      const link = map[entry.target.id];
      if (!link) return;
      if (entry.isIntersecting) {
        railItems.forEach(a => a.classList.remove('active'));
        link.classList.add('active');
      }
    });
  }, { rootMargin: '-40% 0px -50% 0px', threshold: 0 });

  sections.forEach(s => observer.observe(s));
}

function fillSample() {
  const mode = currentMode();
  const list = SAMPLES[mode];
  const i = sampleIdx[mode] % list.length;
  const sample = list[i];
  sampleIdx[mode]++;

  els.key.value = sample.key;
  els.plaintext.value = sample.text;
  showError('');

  const old = els.btnSample.textContent;
  els.btnSample.textContent = sample.note;
  setTimeout(() => { els.btnSample.textContent = old; }, 1800);
}

els.btnRun.addEventListener('click', run);
els.btnReset.addEventListener('click', resetAll);
els.btnSample.addEventListener('click', fillSample);
els.btnCopy.addEventListener('click', copyOutput);
els.detailToggle.addEventListener('click', toggleDetail);
els.modeRadios.forEach(r => r.addEventListener('change', updateModeLabels));

updateModeLabels();
setHeroBytes(new Array(16).fill(0));
