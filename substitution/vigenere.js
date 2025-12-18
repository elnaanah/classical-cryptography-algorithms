// Vigenère Cipher (Polyalphabetic Substitution)
// C = (P + K[i]) mod 26, P = (C - K[i]) mod 26
// Key is repeated to match message length

const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

function validateKey(key) {
  const filtered = key.toUpperCase().split('').filter(c => isLetter(c));
  if (filtered.length === 0) {
    throw new Error('Key must contain at least one letter');
  }
  return filtered.join('');
}

function encrypt(plaintext, key) {
  const keyUpper = validateKey(key);
  let keyIndex = 0;
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    const p = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
    keyIndex++;
    const c = mod(p + k, 26);
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const keyUpper = validateKey(key);
  let keyIndex = 0;
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    const c = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
    keyIndex++;
    const p = mod(c - k, 26);
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const vigenere = require('./vigenere');
// console.log(vigenere.encrypt("HELLO", "KEY"));  // RIJVS
// console.log(vigenere.decrypt("RIJVS", "KEY"));  // HELLO

