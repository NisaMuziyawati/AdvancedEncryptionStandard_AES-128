/* =========================================================================
   Render — membangun markup HTML untuk visualisasi State Matrix & langkah AES
   ========================================================================= */

function toHexWordList(bytes) { return bytes.map(toHex2).join(' '); }

/**
 * Render satu State Matrix 4x4 (column-major) sebagai tabel hex.
 * @param {number[]} bytes - 16 byte
 * @param {string} variant - kelas warna: 'plain' | 'sub' | 'shift' | 'mix' | 'key' | 'cipher'
 * @param {number[]} [compareBytes] - jika ada, byte yang berbeda di-highlight
 */
function renderMatrix(bytes, variant = 'plain', compareBytes = null) {
  let rows = '';
  for (let r = 0; r < 4; r++) {
    let cells = '';
    for (let c = 0; c < 4; c++) {
      const idx = c * 4 + r;
      const changed = compareBytes && compareBytes[idx] !== bytes[idx];
      cells += `<td class="${changed ? 'cell-changed' : ''}">${toHex2(bytes[idx])}</td>`;
    }
    rows += `<tr>${cells}</tr>`;
  }
  return `<table class="state-matrix matrix-${variant}"><tbody>${rows}</tbody></table>`;
}

function matrixBlock(title, bytes, variant, compareBytes) {
  return `
    <div class="matrix-block">
      <span class="matrix-label">${title}</span>
      ${renderMatrix(bytes, variant, compareBytes)}
      <span class="matrix-hex">${bytesToHex(bytes)}</span>
    </div>`;
}

function opRow(opName, beforeLabel, beforeBytes, afterLabel, afterBytes, variant) {
  return `
    <div class="op-row">
      <div class="op-title"><span class="op-dot op-${variant}"></span>${opName}</div>
      <div class="op-matrices">
        ${matrixBlock(beforeLabel, beforeBytes, 'plain')}
        <div class="op-arrow">→</div>
        ${matrixBlock(afterLabel, afterBytes, variant, beforeBytes)}
      </div>
    </div>`;
}

/* ---------------------- Key Expansion ---------------------- */

function renderMiniWord(bytes) {
  return `<span class="mini-word">${bytes.map(toHex2).join(' ')}</span>`;
}

function renderKeyExpansion(keyExp) {
  const { roundKeys, wordSteps } = keyExp;

  // Kelompokkan word menjadi: RK0 (W0-W3), lalu grup 4 word per Round Key (W4-W7 = RK1, dst.)
  const w0to3 = wordSteps.slice(0, 4);
  const groups = [];
  for (let g = 1; g <= 10; g++) groups.push(wordSteps.slice(g * 4, g * 4 + 4));

  // ---- Tabel W[0]-W[3] (asal kunci) ----
  let initRows = '';
  w0to3.forEach(w => {
    initRows += `
      <tr>
        <td class="kx-word">W[${w.index}]</td>
        <td class="kx-mono">${bytesToHex(w.value)}</td>
        <td class="kx-note">${w.note}</td>
      </tr>`;
  });

  // ---- Tabel tiap Round Key (W[4i]..W[4i+3]) ----
  let groupsHtml = '';
  groups.forEach((grp, gi) => {
    const rkIndex = gi + 1;
    let rows = '';
    grp.forEach(w => {
      if (w.isG) {
        const d = w.gDetail;
        const rconIdx = RCON.indexOf(d.rcon);
        rows += `
          <tr class="kx-g-row">
            <td class="kx-word">W[${w.index}]</td>
            <td class="kx-mono">${bytesToHex(w.wPrevK)}</td>
            <td class="kx-g-cell">
              <div class="kx-g-line"><span>W[${w.index - 1}]</span>${renderMiniWord(d.original)}</div>
              <div class="kx-g-line"><span>RotWord</span>${renderMiniWord(d.rotated)}</div>
              <div class="kx-g-line"><span>SubWord</span>${renderMiniWord(d.subbed)}</div>
              <div class="kx-g-line"><span>⊕ Rcon[${rconIdx}]=${toHex2(d.rcon)}</span>${renderMiniWord(d.rconWord)}</div>
              <div class="kx-g-line kx-g-result"><span>g(W[${w.index - 1}])</span>${renderMiniWord(d.result)}</div>
            </td>
            <td class="kx-mono kx-result">${bytesToHex(w.value)}</td>
          </tr>`;
      } else {
        rows += `
          <tr>
            <td class="kx-word">W[${w.index}]</td>
            <td class="kx-mono">${bytesToHex(w.wPrevK)}</td>
            <td class="kx-mono">W[${w.index - 1}] = ${bytesToHex(w.gOutput)}</td>
            <td class="kx-mono kx-result">${bytesToHex(w.value)}</td>
          </tr>`;
      }
    });

    groupsHtml += `
      <details class="collapsible kx-group">
        <summary>Round Key ${rkIndex} — pembangkitan W[${gi * 4 + 4}]–W[${gi * 4 + 7}]</summary>
        <table class="kx-table">
          <thead><tr><th>Word</th><th>W[i-4]</th><th>Fungsi g / W[i-1]</th><th>Hasil</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <div class="kx-rk-preview">
          ${renderMatrix(roundKeys[rkIndex], 'key')}
          <div class="matrix-block">
            <span class="matrix-label">Round Key ${rkIndex}</span>
            <span class="matrix-hex">${bytesToHex(roundKeys[rkIndex])}</span>
          </div>
        </div>
      </details>`;
  });

  let rkHtml = '';
  roundKeys.forEach((rk, i) => {
    rkHtml += `
      <div class="rk-card" id="rk-${i}">
        <div class="rk-title">Round Key ${i}${i === 0 ? ' (dari kunci asli)' : ''}</div>
        ${renderMatrix(rk, 'key')}
        <span class="matrix-hex">${bytesToHex(rk)}</span>
      </div>`;
  });

  return `
    <section class="phase-section" id="phase-keyexp">
      <h2 class="phase-title"><span class="phase-num">00</span>Key Expansion — Pembangkitan Round Key</h2>
      <p class="phase-desc">Kunci 128-bit dipecah menjadi 4 word (W[0]–W[3]), lalu diekspansi secara rekursif hingga W[43] menghasilkan 11 Round Key (RK0–RK10).</p>

      <details class="collapsible" open>
        <summary>W[0] – W[3] (langsung dari Cipher Key)</summary>
        <table class="kx-table">
          <thead><tr><th>Word</th><th>Nilai (hex)</th><th>Keterangan</th></tr></thead>
          <tbody>${initRows}</tbody>
        </table>
      </details>

      <div class="kx-groups">${groupsHtml}</div>

      <details class="collapsible">
        <summary>Ringkasan seluruh Round Key (RK0 – RK10)</summary>
        <div class="rk-grid">${rkHtml}</div>
      </details>
    </section>`;
}

/* ---------------------- Enkripsi ---------------------- */

function renderEncryption(steps) {
  let html = `
    <section class="phase-section" id="phase-initial">
      <h2 class="phase-title"><span class="phase-num">IR</span>Initial Round</h2>
      <div class="op-row">
        <div class="op-title"><span class="op-dot op-key"></span>AddRoundKey dengan RK0</div>
        <div class="op-matrices">
          ${matrixBlock('State Awal (Plaintext)', steps.initial.plainState, 'plain')}
          <div class="op-arrow">⊕</div>
          ${matrixBlock('RK0', steps.initial.roundKey, 'key')}
          <div class="op-arrow">=</div>
          ${matrixBlock('State Setelah AddRoundKey', steps.initial.afterAddRoundKey, 'cipher')}
        </div>
      </div>
    </section>`;

  steps.rounds.forEach(rd => {
    html += `
      <section class="phase-section" id="phase-round-${rd.roundNum}">
        <h2 class="phase-title"><span class="phase-num">${String(rd.roundNum).padStart(2,'0')}</span>Round ${rd.roundNum}</h2>
        <details class="collapsible" open>
          <summary>Tampilkan 4 operasi Round ${rd.roundNum}</summary>
          ${opRow('SubBytes', 'Sebelum', rd.subBytesBefore, 'Sesudah', rd.subBytesAfter, 'sub')}
          ${opRow('ShiftRows', 'Sebelum', rd.shiftRowsBefore, 'Sesudah', rd.shiftRowsAfter, 'shift')}
          ${opRow('MixColumns', 'Sebelum', rd.mixColumnsBefore, 'Sesudah', rd.mixColumnsAfter, 'mix')}
          ${opRow(`AddRoundKey (RK${rd.roundNum})`, 'Sebelum', rd.addRoundKeyBefore, 'Sesudah', rd.addRoundKeyAfter, 'key')}
        </details>
      </section>`;
  });

  const f = steps.final;
  html += `
    <section class="phase-section" id="phase-round-10">
      <h2 class="phase-title"><span class="phase-num">10</span>Round 10 — Final Round</h2>
      <details class="collapsible" open>
        <summary>Tampilkan 3 operasi Final Round (tanpa MixColumns)</summary>
        ${opRow('SubBytes', 'Sebelum', f.subBytesBefore, 'Sesudah', f.subBytesAfter, 'sub')}
        ${opRow('ShiftRows', 'Sebelum', f.shiftRowsBefore, 'Sesudah', f.shiftRowsAfter, 'shift')}
        ${opRow('AddRoundKey (RK10)', 'Sebelum', f.addRoundKeyBefore, 'Sesudah', f.addRoundKeyAfter, 'key')}
      </details>
    </section>
    <section class="phase-section phase-result" id="phase-result">
      <h2 class="phase-title"><span class="phase-num">OK</span>Ciphertext</h2>
      ${matrixBlock('State Akhir', steps.ciphertext, 'cipher')}
    </section>`;

  return html;
}

/* ---------------------- Dekripsi ---------------------- */

function renderDecryption(steps) {
  let html = `
    <section class="phase-section" id="phase-initial">
      <h2 class="phase-title"><span class="phase-num">IR</span>Initial — AddRoundKey RK10</h2>
      <div class="op-row">
        <div class="op-title"><span class="op-dot op-key"></span>AddRoundKey dengan RK10</div>
        <div class="op-matrices">
          ${matrixBlock('State Awal (Ciphertext)', steps.initial.cipherState, 'cipher')}
          <div class="op-arrow">⊕</div>
          ${matrixBlock('RK10', steps.initial.roundKey, 'key')}
          <div class="op-arrow">=</div>
          ${matrixBlock('State Setelah AddRoundKey', steps.initial.afterAddRoundKey, 'plain')}
        </div>
      </div>
    </section>`;

  steps.rounds.forEach(rd => {
    html += `
      <section class="phase-section" id="phase-round-${rd.roundNum}">
        <h2 class="phase-title"><span class="phase-num">${String(rd.roundNum).padStart(2,'0')}</span>Round ${rd.roundNum} (Invers)</h2>
        <details class="collapsible" open>
          <summary>Tampilkan 4 operasi Round ${rd.roundNum}</summary>
          ${opRow('InvShiftRows', 'Sebelum', rd.shiftRowsBefore, 'Sesudah', rd.shiftRowsAfter, 'shift')}
          ${opRow('InvSubBytes', 'Sebelum', rd.subBytesBefore, 'Sesudah', rd.subBytesAfter, 'sub')}
          ${opRow(`AddRoundKey (RK${rd.roundNum})`, 'Sebelum', rd.addRoundKeyBefore, 'Sesudah', rd.addRoundKeyAfter, 'key')}
          ${opRow('InvMixColumns', 'Sebelum', rd.mixColumnsBefore, 'Sesudah', rd.mixColumnsAfter, 'mix')}
        </details>
      </section>`;
  });

  const f = steps.final;
  html += `
    <section class="phase-section" id="phase-round-0">
      <h2 class="phase-title"><span class="phase-num">00</span>Final Round (Ronde 0)</h2>
      <details class="collapsible" open>
        <summary>Tampilkan 3 operasi Final Round</summary>
        ${opRow('InvShiftRows', 'Sebelum', f.shiftRowsBefore, 'Sesudah', f.shiftRowsAfter, 'shift')}
        ${opRow('InvSubBytes', 'Sebelum', f.subBytesBefore, 'Sesudah', f.subBytesAfter, 'sub')}
        ${opRow('AddRoundKey (RK0)', 'Sebelum', f.addRoundKeyBefore, 'Sesudah', f.addRoundKeyAfter, 'key')}
      </details>
    </section>
    <section class="phase-section phase-result" id="phase-result">
      <h2 class="phase-title"><span class="phase-num">OK</span>Plaintext</h2>
      ${matrixBlock('State Akhir', steps.plaintext, 'plain')}
    </section>`;

  return html;
}

/* ---------------------- Rail navigasi ---------------------- */

function renderRail(mode) {
  let items = `<a href="#phase-keyexp" class="rail-item">Key</a>`;
  items += `<a href="#phase-initial" class="rail-item">IR</a>`;
  if (mode === 'encrypt') {
    for (let r = 1; r <= 9; r++) items += `<a href="#phase-round-${r}" class="rail-item">${r}</a>`;
    items += `<a href="#phase-round-10" class="rail-item">10</a>`;
  } else {
    for (let r = 9; r >= 1; r--) items += `<a href="#phase-round-${r}" class="rail-item">${r}</a>`;
    items += `<a href="#phase-round-0" class="rail-item">0</a>`;
  }
  items += `<a href="#phase-result" class="rail-item rail-final">Hasil</a>`;
  return `<nav class="round-rail">${items}</nav>`;
}
