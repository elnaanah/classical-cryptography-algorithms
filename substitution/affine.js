// Affine Cipher
// Encryption: C = (aP + b) mod 26
// Decryption: P = a⁻¹(C - b) mod 26
// Key: { a, b } where gcd(a, 26) = 1

const { letterToNum, numToLetter, isLetter, mod, modInverse, isCoprime } = require('../helpers');

function validateKey(key) {
  if (typeof key !== 'object' || key === null) {
    throw new Error('Key must be an object with properties a and b');
  }
  if (typeof key.a !== 'number' || typeof key.b !== 'number') {
    throw new Error('Key properties a and b must be numbers');
  }
  if (!isCoprime(key.a, 26)) {
    throw new Error('Key "a" must be coprime with 26 (gcd(a, 26) = 1). Valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25');
  }
  return { a: mod(key.a, 26), b: mod(key.b, 26) };
}

function encrypt(plaintext, key) {
  const { a, b } = validateKey(key);
  
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const p = letterToNum(char);
    const c = mod(a * p + b, 26);
    
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const { a, b } = validateKey(key);
  const aInverse = modInverse(a, 26);
  
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const c = letterToNum(char);
    const p = mod(aInverse * (c - b), 26);
    
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const affine = require('./affine');
// console.log(affine.encrypt("HELLO", { a: 5, b: 8 }));  // RCLLA
// console.log(affine.decrypt("RCLLA", { a: 5, b: 8 }));  // HELLO
