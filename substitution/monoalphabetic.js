// Monoalphabetic Substitution Cipher
// Uses a fixed permutation of the alphabet as the key
// Each plaintext letter maps to exactly one ciphertext letter

const { isLetter } = require('../helpers');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

function validateKey(key) {
  const upper = key.toUpperCase();
  if (upper.length !== 26) {
    throw new Error('Key must be exactly 26 characters');
  }
  const sorted = upper.split('').sort().join('');
  if (sorted !== ALPHABET) {
    throw new Error('Key must be a permutation of the alphabet (each letter exactly once)');
  }
  return upper;
}

function encrypt(plaintext, key) {
  const keyUpper = validateKey(key);
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    const index = ALPHABET.indexOf(char.toUpperCase());
    const encrypted = keyUpper[index];
    return char === char.toUpperCase() ? encrypted : encrypted.toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const keyUpper = validateKey(key);
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    const index = keyUpper.indexOf(char.toUpperCase());
    const decrypted = ALPHABET[index];
    return char === char.toUpperCase() ? decrypted : decrypted.toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const mono = require('./monoalphabetic');
// const key = 'QWERTYUIOPASDFGHJKLZXCVBNM';
// console.log(mono.encrypt("HELLO", key));  // ITSSG
// console.log(mono.decrypt("ITSSG", key));  // HELLO

