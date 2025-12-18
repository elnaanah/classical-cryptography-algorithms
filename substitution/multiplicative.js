// Multiplicative Cipher
// C = (P × k) mod 26, P = (C × k⁻¹) mod 26
// k must be coprime with 26

const { letterToNum, numToLetter, isLetter, mod, modInverse, isCoprime } = require('../helpers');

function encrypt(plaintext, key) {
  if (!isCoprime(key, 26)) {
    throw new Error(`Key ${key} is not coprime with 26. Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25`);
  }
  const k = mod(key, 26);
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    const p = letterToNum(char);
    const c = mod(p * k, 26);
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  if (!isCoprime(key, 26)) {
    throw new Error(`Key ${key} is not coprime with 26. Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25`);
  }
  const k = mod(key, 26);
  const kInv = modInverse(k, 26);
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    const c = letterToNum(char);
    const p = mod(c * kInv, 26);
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const mult = require('./multiplicative');
// console.log(mult.encrypt("HELLO", 7));  // XCZZU
// console.log(mult.decrypt("XCZZU", 7));  // HELLO

