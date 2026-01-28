// AES-128 (Advanced Encryption Standard) - Educational Implementation
// 128-bit block cipher with 128-bit key
// Uses Substitution-Permutation Network (SPN) with 10 rounds

// S-Box (Substitution Box) - used in SubBytes transformation
const S_BOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

// Inverse S-Box - used in InvSubBytes for decryption
const INV_S_BOX = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

// Round constants for key expansion
const RCON = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
];

// Convert hex string to byte array
function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

// Convert byte array to hex string
function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Convert string to byte array
function stringToBytes(str) {
  return str.split('').map(c => c.charCodeAt(0));
}

// Convert byte array to string
function bytesToString(bytes) {
  return bytes.map(b => String.fromCharCode(b)).join('');
}

// Convert 16-byte array to 4x4 state matrix (column-major order)
function bytesToState(bytes) {
  const state = [];
  for (let c = 0; c < 4; c++) {
    state[c] = [];
    for (let r = 0; r < 4; r++) {
      state[c][r] = bytes[c * 4 + r];
    }
  }
  return state;
}

// Convert 4x4 state matrix back to 16-byte array
function stateToBytes(state) {
  const bytes = [];
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      bytes.push(state[c][r]);
    }
  }
  return bytes;
}

// SubBytes transformation - substitute each byte using S-Box
function subBytes(state) {
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      state[c][r] = S_BOX[state[c][r]];
    }
  }
  return state;
}

// Inverse SubBytes for decryption
function invSubBytes(state) {
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      state[c][r] = INV_S_BOX[state[c][r]];
    }
  }
  return state;
}

// ShiftRows transformation - cyclically shift rows left
// Row 0: no shift, Row 1: shift 1, Row 2: shift 2, Row 3: shift 3
function shiftRows(state) {
  // Row 1: shift left by 1
  let temp = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = temp;
  
  // Row 2: shift left by 2
  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;
  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;
  
  // Row 3: shift left by 3 (same as shift right by 1)
  temp = state[3][3];
  state[3][3] = state[2][3];
  state[2][3] = state[1][3];
  state[1][3] = state[0][3];
  state[0][3] = temp;
  
  return state;
}

// Inverse ShiftRows for decryption
function invShiftRows(state) {
  // Row 1: shift right by 1
  let temp = state[3][1];
  state[3][1] = state[2][1];
  state[2][1] = state[1][1];
  state[1][1] = state[0][1];
  state[0][1] = temp;
  
  // Row 2: shift right by 2
  temp = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;
  temp = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;
  
  // Row 3: shift right by 3 (same as shift left by 1)
  temp = state[0][3];
  state[0][3] = state[1][3];
  state[1][3] = state[2][3];
  state[2][3] = state[3][3];
  state[3][3] = temp;
  
  return state;
}

// Galois Field multiplication by 2 (xtime operation)
function xtime(a) {
  return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

// Galois Field multiplication
function gmul(a, b) {
  let result = 0;
  let temp = a;
  while (b > 0) {
    if (b & 1) result ^= temp;
    temp = xtime(temp);
    b >>= 1;
  }
  return result & 0xff;
}

// MixColumns transformation - mix bytes within each column
// Matrix multiplication in GF(2^8) with fixed matrix
function mixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const a = state[c].slice();
    state[c][0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
    state[c][1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
    state[c][2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
    state[c][3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
  }
  return state;
}

// Inverse MixColumns for decryption
function invMixColumns(state) {
  for (let c = 0; c < 4; c++) {
    const a = state[c].slice();
    state[c][0] = gmul(a[0], 0x0e) ^ gmul(a[1], 0x0b) ^ gmul(a[2], 0x0d) ^ gmul(a[3], 0x09);
    state[c][1] = gmul(a[0], 0x09) ^ gmul(a[1], 0x0e) ^ gmul(a[2], 0x0b) ^ gmul(a[3], 0x0d);
    state[c][2] = gmul(a[0], 0x0d) ^ gmul(a[1], 0x09) ^ gmul(a[2], 0x0e) ^ gmul(a[3], 0x0b);
    state[c][3] = gmul(a[0], 0x0b) ^ gmul(a[1], 0x0d) ^ gmul(a[2], 0x09) ^ gmul(a[3], 0x0e);
  }
  return state;
}

// AddRoundKey transformation - XOR state with round key
function addRoundKey(state, roundKey) {
  for (let c = 0; c < 4; c++) {
    for (let r = 0; r < 4; r++) {
      state[c][r] ^= roundKey[c * 4 + r];
    }
  }
  return state;
}

// Rotate word (4 bytes) left by 1 byte
function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}

// Apply S-Box to each byte in word
function subWord(word) {
  return word.map(b => S_BOX[b]);
}

// Key Expansion - generate round keys from cipher key
// For AES-128: 16-byte key -> 176 bytes (11 round keys of 16 bytes each)
function keyExpansion(key) {
  const Nk = 4;  // Key length in 32-bit words (4 for AES-128)
  const Nr = 10; // Number of rounds (10 for AES-128)
  const Nb = 4;  // Block size in 32-bit words (always 4 for AES)
  
  const keyBytes = hexToBytes(key);
  const w = []; // Expanded key words (4 bytes each)
  
  // First Nk words are the original key
  for (let i = 0; i < Nk; i++) {
    w[i] = keyBytes.slice(i * 4, (i + 1) * 4);
  }
  
  // Generate remaining words
  for (let i = Nk; i < Nb * (Nr + 1); i++) {
    let temp = w[i - 1].slice();
    
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp));
      temp[0] ^= RCON[i / Nk];
    }
    
    w[i] = w[i - Nk].map((b, j) => b ^ temp[j]);
  }
  
  // Convert words to round keys (each round key is 16 bytes)
  const roundKeys = [];
  for (let round = 0; round <= Nr; round++) {
    const roundKey = [];
    for (let i = 0; i < 4; i++) {
      roundKey.push(...w[round * 4 + i]);
    }
    roundKeys.push(roundKey);
  }
  
  return roundKeys;
}

// AES-128 encryption of a single 128-bit block
function encryptBlock(block, roundKeys) {
  let state = bytesToState(block);
  
  // Initial round: AddRoundKey only
  state = addRoundKey(state, roundKeys[0]);
  
  // Main rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
  for (let round = 1; round <= 9; round++) {
    state = subBytes(state);
    state = shiftRows(state);
    state = mixColumns(state);
    state = addRoundKey(state, roundKeys[round]);
  }
  
  // Final round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
  state = subBytes(state);
  state = shiftRows(state);
  state = addRoundKey(state, roundKeys[10]);
  
  return stateToBytes(state);
}

// AES-128 decryption of a single 128-bit block
function decryptBlock(block, roundKeys) {
  let state = bytesToState(block);
  
  // Initial round: AddRoundKey
  state = addRoundKey(state, roundKeys[10]);
  
  // Main rounds 9-1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
  for (let round = 9; round >= 1; round--) {
    state = invShiftRows(state);
    state = invSubBytes(state);
    state = addRoundKey(state, roundKeys[round]);
    state = invMixColumns(state);
  }
  
  // Final round 0: InvShiftRows, InvSubBytes, AddRoundKey (no InvMixColumns)
  state = invShiftRows(state);
  state = invSubBytes(state);
  state = addRoundKey(state, roundKeys[0]);
  
  return stateToBytes(state);
}

// PKCS#7 padding
function padBytes(bytes, blockSize) {
  const padLen = blockSize - (bytes.length % blockSize);
  return bytes.concat(Array(padLen).fill(padLen));
}

// Remove PKCS#7 padding
function unpadBytes(bytes) {
  const padLen = bytes[bytes.length - 1];
  if (padLen > 0 && padLen <= 16) {
    return bytes.slice(0, -padLen);
  }
  return bytes;
}

// Encrypt plaintext with AES-128
// Input: plaintext (string), key (32-char hex string = 128 bits)
// Output: ciphertext (hex string)
function encrypt(plaintext, key) {
  // Validate key (must be 32 hex characters = 128 bits)
  if (!/^[0-9A-Fa-f]{32}$/.test(key)) {
    throw new Error('Key must be exactly 32 hexadecimal characters (128 bits)');
  }
  
  // Generate round keys
  const roundKeys = keyExpansion(key);
  
  // Convert plaintext to bytes and pad
  const plaintextBytes = padBytes(stringToBytes(plaintext), 16);
  
  // Process each 128-bit block
  let ciphertext = [];
  for (let i = 0; i < plaintextBytes.length; i += 16) {
    const block = plaintextBytes.slice(i, i + 16);
    const encrypted = encryptBlock(block, roundKeys);
    ciphertext.push(...encrypted);
  }
  
  return bytesToHex(ciphertext);
}

// Decrypt ciphertext with AES-128
// Input: ciphertext (hex string), key (32-char hex string = 128 bits)
// Output: plaintext (string)
function decrypt(ciphertext, key) {
  // Validate key
  if (!/^[0-9A-Fa-f]{32}$/.test(key)) {
    throw new Error('Key must be exactly 32 hexadecimal characters (128 bits)');
  }
  
  // Validate ciphertext
  if (!/^[0-9A-Fa-f]+$/.test(ciphertext) || ciphertext.length % 32 !== 0) {
    throw new Error('Ciphertext must be hex string with length multiple of 32');
  }
  
  // Generate round keys
  const roundKeys = keyExpansion(key);
  
  // Convert ciphertext hex to bytes
  const ciphertextBytes = hexToBytes(ciphertext);
  
  // Process each 128-bit block
  let plaintextBytes = [];
  for (let i = 0; i < ciphertextBytes.length; i += 16) {
    const block = ciphertextBytes.slice(i, i + 16);
    const decrypted = decryptBlock(block, roundKeys);
    plaintextBytes.push(...decrypted);
  }
  
  // Remove padding and convert to string
  return bytesToString(unpadBytes(plaintextBytes));
}

module.exports = { encrypt, decrypt };

// Example usage:
// const aes = require('./aes');
// const key = '2b7e151628aed2a6abf7158809cf4f3c';  // 128-bit key in hex
// const encrypted = aes.encrypt('HELLO', key);
// console.log('Encrypted:', encrypted);
// const decrypted = aes.decrypt(encrypted, key);
// console.log('Decrypted:', decrypted);  // HELLO
