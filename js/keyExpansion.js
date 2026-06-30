/* =========================================================================
   AES-128 — Key Expansion (Pembangkitan Round Key)
   Menghasilkan 11 Round Key (RK0..RK10) dari kunci 128-bit,
   sekaligus merekam setiap langkah (W[0]..W[43]) untuk ditampilkan di UI.
   ========================================================================= */

function subWord(word) {
  return word.map(b => SBOX[b]);
}

function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}

function xorWords(a, b) {
  return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
}

/**
 * keyExpansion128
 * @param {number[]} keyBytes - 16 byte kunci AES-128
 * @returns {{roundKeys: number[][], wordSteps: object[]}}
 *   roundKeys: array 11 elemen, masing-masing 16 byte (state-layout, column-major)
 *   wordSteps: detail pembangkitan W[0]..W[43]
 */
function keyExpansion128(keyBytes) {
  const Nk = 4, Nr = 10;
  const totalWords = 4 * (Nr + 1); // 44
  const W = new Array(totalWords);
  const wordSteps = [];

  for (let i = 0; i < Nk; i++) {
    W[i] = [keyBytes[4 * i], keyBytes[4 * i + 1], keyBytes[4 * i + 2], keyBytes[4 * i + 3]];
    wordSteps.push({
      index: i, value: W[i].slice(), isG: false,
      note: `W[${i}] = byte kunci asli (langsung dari Cipher Key)`
    });
  }

  for (let i = Nk; i < totalWords; i++) {
    let temp = W[i - 1].slice();
    let detail = null;

    if (i % Nk === 0) {
      const rotated = rotWord(temp);
      const subbed = subWord(rotated);
      const rconWord = [RCON[i / Nk], 0x00, 0x00, 0x00];
      const afterRcon = xorWords(subbed, rconWord);
      detail = {
        original: temp.slice(),
        rotated, subbed,
        rcon: RCON[i / Nk],
        rconWord,
        result: afterRcon
      };
      temp = afterRcon;
    }

    W[i] = xorWords(W[i - Nk], temp);

    wordSteps.push({
      index: i,
      value: W[i].slice(),
      isG: i % Nk === 0,
      gDetail: detail,
      wPrevK: W[i - Nk].slice(),
      gOutput: temp.slice(),
      note: i % Nk === 0
        ? `W[${i}] = W[${i - Nk}] ⊕ g(W[${i - 1}])`
        : `W[${i}] = W[${i - Nk}] ⊕ W[${i - 1}]`
    });
  }

  const roundKeys = [];
  for (let r = 0; r <= Nr; r++) {
    const rk = [];
    for (let c = 0; c < 4; c++) {
      const w = W[r * 4 + c];
      rk.push(w[0], w[1], w[2], w[3]);
    }
    roundKeys.push(rk);
  }

  return { roundKeys, wordSteps };
}
