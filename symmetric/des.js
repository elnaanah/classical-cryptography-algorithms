// DES (Data Encryption Standard) - Educational Implementation
// 64-bit block cipher with 56-bit effective key (64-bit key with 8 parity bits)
// Uses Feistel network structure with 16 rounds

// Initial Permutation (IP) table - rearranges the 64 input bits
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7
];

// Final Permutation (IP^-1) - inverse of initial permutation
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25
];

// Expansion permutation (E) - expands 32 bits to 48 bits for XOR with round key
const E = [
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1
];

// Permutation (P) - applied after S-box substitution
const P = [
  16, 7, 20, 21, 29, 12, 28, 17,
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25
];

// 8 S-Boxes - each takes 6-bit input and produces 4-bit output
const S_BOXES = [
  // S1
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
  ],
  // S2
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
  ],
  // S3
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
  ],
  // S4
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
  ],
  // S5
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
  ],
  // S6
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
  ],
  // S7
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
  ],
  // S8
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
  ]
];

// Permuted Choice 1 (PC-1) - selects 56 bits from 64-bit key (removes parity bits)
const PC1 = [
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4
];

// Permuted Choice 2 (PC-2) - selects 48 bits from 56-bit key for each round
const PC2 = [
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32
];

// Left shifts for each round (1 or 2 positions)
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// Convert hex string to binary string
function hexToBinary(hex) {
  return hex.split('').map(h => 
    parseInt(h, 16).toString(2).padStart(4, '0')
  ).join('');
}

// Convert binary string to hex string
function binaryToHex(binary) {
  let hex = '';
  for (let i = 0; i < binary.length; i += 4) {
    hex += parseInt(binary.substr(i, 4), 2).toString(16);
  }
  return hex.toUpperCase();
}

// Apply a permutation table to a binary string
function permute(input, table) {
  return table.map(pos => input[pos - 1]).join('');
}

// Left circular shift
function leftShift(bits, n) {
  return bits.slice(n) + bits.slice(0, n);
}

// XOR two binary strings
function xor(a, b) {
  return a.split('').map((bit, i) => (bit ^ b[i]).toString()).join('');
}

// Generate 16 round keys from the 64-bit key
function generateKeys(key) {
  const keyBinary = hexToBinary(key);
  
  // Apply PC-1 to get 56-bit key
  const permutedKey = permute(keyBinary, PC1);
  
  // Split into two 28-bit halves
  let C = permutedKey.slice(0, 28);
  let D = permutedKey.slice(28, 56);
  
  const roundKeys = [];
  
  // Generate 16 round keys
  for (let i = 0; i < 16; i++) {
    // Left shift both halves
    C = leftShift(C, SHIFTS[i]);
    D = leftShift(D, SHIFTS[i]);
    
    // Combine and apply PC-2 to get 48-bit round key
    const combined = C + D;
    roundKeys.push(permute(combined, PC2));
  }
  
  return roundKeys;
}

// Feistel function (f-function)
function feistel(R, roundKey) {
  // Step 1: Expand R from 32 bits to 48 bits using E table
  const expanded = permute(R, E);
  
  // Step 2: XOR with round key
  const xored = xor(expanded, roundKey);
  
  // Step 3: Apply S-boxes (48 bits -> 32 bits)
  let sBoxOutput = '';
  for (let i = 0; i < 8; i++) {
    const block = xored.substr(i * 6, 6);
    // Row = first and last bits, Column = middle 4 bits
    const row = parseInt(block[0] + block[5], 2);
    const col = parseInt(block.substr(1, 4), 2);
    sBoxOutput += S_BOXES[i][row][col].toString(2).padStart(4, '0');
  }
  
  // Step 4: Apply P permutation
  return permute(sBoxOutput, P);
}

// DES encryption/decryption core (same process, just different key order)
function desCore(block, keys) {
  // Apply initial permutation
  const permuted = permute(block, IP);
  
  // Split into two 32-bit halves
  let L = permuted.slice(0, 32);
  let R = permuted.slice(32, 64);
  
  // 16 rounds of Feistel network
  for (let i = 0; i < 16; i++) {
    const newL = R;
    const f = feistel(R, keys[i]);
    const newR = xor(L, f);
    L = newL;
    R = newR;
  }
  
  // Swap and combine (R16L16)
  const preOutput = R + L;
  
  // Apply final permutation
  return permute(preOutput, FP);
}

// Convert string to byte array
function stringToBytes(str) {
  return str.split('').map(c => c.charCodeAt(0));
}

// Convert byte array to string
function bytesToString(bytes) {
  return bytes.map(b => String.fromCharCode(b)).join('');
}

// Convert byte array to hex string
function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Convert hex string to byte array
function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

// PKCS#7 padding for 8-byte blocks
function padBytes(bytes) {
  const blockSize = 8;
  const padLen = blockSize - (bytes.length % blockSize);
  return bytes.concat(Array(padLen).fill(padLen));
}

// Remove PKCS#7 padding
function unpadBytes(bytes) {
  const padLen = bytes[bytes.length - 1];
  if (padLen > 0 && padLen <= 8) {
    return bytes.slice(0, -padLen);
  }
  return bytes;
}

// Encrypt plaintext with DES
// Input: plaintext (string), key (16-char hex string = 64 bits)
// Output: ciphertext (hex string)
function encrypt(plaintext, key) {
  // Validate key (must be 16 hex characters = 64 bits)
  if (!/^[0-9A-Fa-f]{16}$/.test(key)) {
    throw new Error('Key must be exactly 16 hexadecimal characters (64 bits)');
  }
  
  // Generate round keys
  const keys = generateKeys(key);
  
  // Convert plaintext to bytes and pad
  const plaintextBytes = padBytes(stringToBytes(plaintext));
  
  // Process each 64-bit (8-byte) block
  let ciphertext = [];
  for (let i = 0; i < plaintextBytes.length; i += 8) {
    const blockBytes = plaintextBytes.slice(i, i + 8);
    const blockHex = bytesToHex(blockBytes);
    const block = hexToBinary(blockHex);
    const encrypted = desCore(block, keys);
    ciphertext.push(...hexToBytes(binaryToHex(encrypted)));
  }
  
  return bytesToHex(ciphertext);
}

// Decrypt ciphertext with DES
// Input: ciphertext (hex string), key (16-char hex string = 64 bits)
// Output: plaintext (string)
function decrypt(ciphertext, key) {
  // Validate key
  if (!/^[0-9A-Fa-f]{16}$/.test(key)) {
    throw new Error('Key must be exactly 16 hexadecimal characters (64 bits)');
  }
  
  // Validate ciphertext
  if (!/^[0-9A-Fa-f]+$/.test(ciphertext) || ciphertext.length % 16 !== 0) {
    throw new Error('Ciphertext must be hex string with length multiple of 16');
  }
  
  // Generate round keys and reverse them for decryption
  const keys = generateKeys(key).reverse();
  
  // Convert ciphertext to bytes
  const ciphertextBytes = hexToBytes(ciphertext);
  
  // Process each 64-bit (8-byte) block
  let plaintextBytes = [];
  for (let i = 0; i < ciphertextBytes.length; i += 8) {
    const blockBytes = ciphertextBytes.slice(i, i + 8);
    const blockHex = bytesToHex(blockBytes);
    const block = hexToBinary(blockHex);
    const decrypted = desCore(block, keys);
    plaintextBytes.push(...hexToBytes(binaryToHex(decrypted)));
  }
  
  // Remove padding and convert to string
  return bytesToString(unpadBytes(plaintextBytes));
}

module.exports = { encrypt, decrypt };

// Example usage:
// const des = require('./des');
// const key = '133457799BBCDFF1';  // 64-bit key in hex
// const encrypted = des.encrypt('HELLO', key);
// console.log('Encrypted:', encrypted);
// const decrypted = des.decrypt(encrypted, key);
// console.log('Decrypted:', decrypted);  // HELLO
