# AES-128 Cipher Lab

Simulasi web interaktif algoritma **AES-128** (Advanced Encryption Standard) — Tugas Individu Mata Kuliah Kriptografi.

## Struktur Proyek
```
Advanced Encryption Standard (AES-128)
 ├── index.html          ← halaman utama (UI)
 ├── css/
 │    └── style.css      ← seluruh styling (tema "Cipher Lab")
 └── js/
      ├── constants.js    ← S-Box, Invers S-Box, Rcon, operasi GF(2^8)
      ├── keyExpansion.js ← Key Expansion (W[0]..W[43], RK0..RK10)
      ├── cipher.js       ← SubBytes, ShiftRows, MixColumns, AddRoundKey + invers + encrypt/decrypt
      ├── render.js       ← membangun tampilan State Matrix & langkah per ronde
      └── app.js          ← wiring input, tombol, validasi
```

## Implementasi
Seluruh algoritma AES (SubBytes, ShiftRows, MixColumns, AddRoundKey, Key Expansion, dan
operasi inversnya) ditulis **manual dari nol** di `js/constants.js`, `js/keyExpansion.js`,
dan `js/cipher.js` — tanpa library kriptografi pihak ketiga.

Implementasi telah diverifikasi terhadap test vector resmi **FIPS-197 Appendix B**:
- Key: `000102030405060708090a0b0c0d0e0f`
- Plaintext: `00112233445566778899aabbccddeeff`
- Ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a` ✓ cocok

## Cara Menjalankan
Buka `index.html` langsung di browser (tidak butuh server/build step), atau deploy ke
hosting statis apa pun (Netlify, Vercel, GitHub Pages, atau domain `.my.id` sesuai ketentuan tugas).

## Fitur
- Mode Encrypt & Decrypt (ECB, 1 blok 128-bit)
- Input plaintext: teks ≤16 karakter (auto zero-padding) atau hex 32 karakter
- Visualisasi lengkap: Key Expansion (W[0]-W[43] + RK0-RK10), Initial Round,
  Round 1-9 (4 operasi), Round 10 (3 operasi), hasil akhir
- State Matrix 4x4 berwarna per-jenis operasi, highlight byte yang berubah
- Section collapsible per ronde + tombol "tampilkan/sembunyikan semua detail"
- Navigasi rail (breadcrumb) sticky dengan scroll-spy
- Output hex copyable

## 👨‍💻 Pengembang

Nama: [Nisa Muziyawati]

Program Studi: [Teknik Informatika]

Mata Kuliah: Kriptografi

Advanced Encryption Standard (AES-128) Cipher Lab — Kriptografi Semester Genap 2025/2026*
