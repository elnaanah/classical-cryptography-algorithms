// Caesar / Shift Cipher (Additive Cipher)
// C = (P + k) mod 26, P = (C - k) mod 26

const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

function encrypt(plaintext, key) {
  const k = mod(key, 26);
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char; // Keep non-letters unchanged
    const p = letterToNum(char);
    const c = mod(p + k, 26);
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const k = mod(key, 26);
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    const c = letterToNum(char);
    const p = mod(c - k, 26);
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const caesar = require('./caesar');
// console.log(caesar.encrypt("HELLO", 3));  // KHOOR
// console.log(caesar.decrypt("KHOOR", 3));  // HELLO

