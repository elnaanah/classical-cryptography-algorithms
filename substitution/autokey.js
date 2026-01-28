// Autokey Cipher (Running Key Cipher)
// Key starts with a keyword, then continues with the plaintext itself
// Encryption: C = (P + K) mod 26
// Decryption: P = (C - K) mod 26, where K is built progressively

const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

function validateKey(key) {
  const filtered = key.toUpperCase().split('').filter(isLetter);
  if (filtered.length === 0) {
    throw new Error('Key must contain at least one letter');
  }
  return filtered.join('');
}

function encrypt(plaintext, key) {
  const initialKey = validateKey(key);
  
  // Build the full key: initial key + plaintext letters
  const plaintextLetters = plaintext.split('').filter(isLetter).map(c => c.toUpperCase());
  const fullKey = initialKey + plaintextLetters.join('');
  
  let keyIndex = 0;
  
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const p = letterToNum(char);
    const k = letterToNum(fullKey[keyIndex]);
    keyIndex++;
    
    const c = mod(p + k, 26);
    
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const initialKey = validateKey(key);
  
  // Key stream starts with the initial key, then we add decrypted letters
  let keyStream = initialKey.split('');
  let keyIndex = 0;
  
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const c = letterToNum(char);
    const k = letterToNum(keyStream[keyIndex]);
    
    const p = mod(c - k, 26);
    
    // Add the decrypted letter to the key stream for subsequent decryption
    keyStream.push(numToLetter(p));
    keyIndex++;
    
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const autokey = require('./autokey');
// console.log(autokey.encrypt("HELLO", "KEY"));  // Key becomes K-E-Y-H-E...
// console.log(autokey.decrypt(autokey.encrypt("HELLO", "KEY"), "KEY"));  // HELLO
