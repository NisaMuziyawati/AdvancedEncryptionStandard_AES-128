/* =========================================================================
   AES-128 — Operasi Inti Cipher
   SubBytes, ShiftRows, MixColumns, AddRoundKey (dan inversnya)
   State disimpan sebagai array 16 byte, layout column-major:
     index:  0  1  2  3 | 4  5  6  7 | 8  9 10 11 |12 13 14 15
     posisi: kolom0      kolom1       kolom2       kolom3
   ========================================================================= */

function subBytes(state) { return state.map(b => SBOX[b]); }
function invSubBytes(state) { return state.map(b => INV_SBOX[b]); }

// State disimpan column-major: index = kolom*4 + baris.
// ShiftRows: baris r digeser ke kiri sebanyak r posisi (antar kolom).
function shiftRows(state) {
  const out = new Array(16);
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      out[c * 4 + r] = state[((c + r) % 4) * 4 + r];
    }
  }
  return out;
}

// InvShiftRows: baris r digeser ke kanan sebanyak r posisi (kebalikan ShiftRows).
function invShiftRows(state) {
  const out = new Array(16);
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      out[c * 4 + r] = state[((c - r + 4) % 4) * 4 + r];
    }
  }
  return out;
}

function mixColumns(state) {
  const out = new Array(16);
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
    out[i]   = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
    out[i+1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
    out[i+2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
    out[i+3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
  }
  return out;
}

function invMixColumns(state) {
  const out = new Array(16);
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
    out[i]   = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
    out[i+1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
    out[i+2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
    out[i+3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
  }
  return out;
}

function addRoundKey(state, roundKey) {
  return state.map((b, i) => b ^ roundKey[i]);
}

/* ============================ ENKRIPSI ============================ */

function aesEncryptBlock(plainBytes, roundKeys) {
  const steps = { rounds: [] };

  let state = plainBytes.slice();
  const initialState = state.slice();
  state = addRoundKey(state, roundKeys[0]);
  steps.initial = {
    plainState: initialState,
    roundKey: roundKeys[0].slice(),
    afterAddRoundKey: state.slice()
  };

  for (let r = 1; r <= 9; r++) {
    const sbBefore = state.slice();
    state = subBytes(state);
    const sbAfter = state.slice();

    const srBefore = state.slice();
    state = shiftRows(state);
    const srAfter = state.slice();

    const mcBefore = state.slice();
    state = mixColumns(state);
    const mcAfter = state.slice();

    const akBefore = state.slice();
    state = addRoundKey(state, roundKeys[r]);
    const akAfter = state.slice();

    steps.rounds.push({
      roundNum: r, roundKey: roundKeys[r].slice(),
      subBytesBefore: sbBefore, subBytesAfter: sbAfter,
      shiftRowsBefore: srBefore, shiftRowsAfter: srAfter,
      mixColumnsBefore: mcBefore, mixColumnsAfter: mcAfter,
      addRoundKeyBefore: akBefore, addRoundKeyAfter: akAfter
    });
  }

  // Final round (round 10): SubBytes, ShiftRows, AddRoundKey (tanpa MixColumns)
  const sbBefore = state.slice();
  state = subBytes(state);
  const sbAfter = state.slice();

  const srBefore = state.slice();
  state = shiftRows(state);
  const srAfter = state.slice();

  const akBefore = state.slice();
  state = addRoundKey(state, roundKeys[10]);
  const akAfter = state.slice();

  steps.final = {
    roundNum: 10, roundKey: roundKeys[10].slice(),
    subBytesBefore: sbBefore, subBytesAfter: sbAfter,
    shiftRowsBefore: srBefore, shiftRowsAfter: srAfter,
    addRoundKeyBefore: akBefore, addRoundKeyAfter: akAfter
  };

  steps.ciphertext = state.slice();
  return steps;
}

/* ============================ DEKRIPSI ============================ */

function aesDecryptBlock(cipherBytes, roundKeys) {
  const steps = { rounds: [] };

  let state = cipherBytes.slice();
  const initialState = state.slice();
  state = addRoundKey(state, roundKeys[10]);
  steps.initial = {
    cipherState: initialState,
    roundKey: roundKeys[10].slice(),
    afterAddRoundKey: state.slice()
  };

  // Ronde 9 turun ke 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
  for (let r = 9; r >= 1; r--) {
    const srBefore = state.slice();
    state = invShiftRows(state);
    const srAfter = state.slice();

    const sbBefore = state.slice();
    state = invSubBytes(state);
    const sbAfter = state.slice();

    const akBefore = state.slice();
    state = addRoundKey(state, roundKeys[r]);
    const akAfter = state.slice();

    const mcBefore = state.slice();
    state = invMixColumns(state);
    const mcAfter = state.slice();

    steps.rounds.push({
      roundNum: r, roundKey: roundKeys[r].slice(),
      shiftRowsBefore: srBefore, shiftRowsAfter: srAfter,
      subBytesBefore: sbBefore, subBytesAfter: sbAfter,
      addRoundKeyBefore: akBefore, addRoundKeyAfter: akAfter,
      mixColumnsBefore: mcBefore, mixColumnsAfter: mcAfter
    });
  }

  // Final round (ronde 0): InvShiftRows, InvSubBytes, AddRoundKey dengan RK0
  const srBefore = state.slice();
  state = invShiftRows(state);
  const srAfter = state.slice();

  const sbBefore = state.slice();
  state = invSubBytes(state);
  const sbAfter = state.slice();

  const akBefore = state.slice();
  state = addRoundKey(state, roundKeys[0]);
  const akAfter = state.slice();

  steps.final = {
    roundNum: 0, roundKey: roundKeys[0].slice(),
    shiftRowsBefore: srBefore, shiftRowsAfter: srAfter,
    subBytesBefore: sbBefore, subBytesAfter: sbAfter,
    addRoundKeyBefore: akBefore, addRoundKeyAfter: akAfter
  };

  steps.plaintext = state.slice();
  return steps;
}
